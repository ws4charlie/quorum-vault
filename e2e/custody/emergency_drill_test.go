package custody_test

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The emergency drill (docs/runbooks/stolen-hot-key.md, "Drill"): a hot key may be stolen, with a withdrawal in flight and deposits arriving.
// The operators sign the three records ahead, `qv-rekey emergency` runs the steps in the emergency order, and the test asserts what the runbook promises:
//   - ordinary signing from the old generation is refused as soon as the mark is in the zone (the decider reads the log at every decision);
//   - a transaction "from the thief", for an outside address, is refused by the zone. The chain itself would accept it: a signature from the old key is valid
//     on chain, which is why the funds must leave the old address, and why what the thief moves before the drain lands cannot be saved;
//   - the funds end at the new generation, the ledger reconciles, and the old generation is never retired.
//
// The time of every step goes to the test log (the "drill times" lines) and to emergency.log of the work directory.
func TestEmergencyDrillStolenHotKey(t *testing.T) {
	s := rekeyShard(t)
	gen1 := s.shardAddr[0]
	dir := filepath.Join(s.dir, "emergency")
	mode := "hsm"
	if mpcMode() {
		mode = "mpc"
	}
	capETH, capUSDT := "ETH="+eth1m(), "USDT=1000000000000"
	times := map[string]time.Duration{}
	mark := func(step string, from time.Time) {
		times[step] = time.Since(from)
		t.Logf("drill times: %-34s %s", step, times[step].Round(time.Millisecond))
	}
	emergency := func(extra ...string) (string, error) {
		args := append([]string{"emergency", "-shard", s.shardID(), "-mode", mode, "-reason", "drill: the hot key may be stolen", "-cap", capETH, "-cap", capUSDT,
			"-poll", "2s", "-stall-after", scaled(300 * time.Second).String()}, extra...)
		return s.rekeyErr(dir, args...)
	}

	// Before: a withdrawal in flight (approved, not necessarily out yet) and a deposit that will arrive at its forwarder while the shard changes hands.
	inflight := s.withdrawETH("em-inflight", 1e15)
	c2 := s.newCustomer("c-em")
	s.sendETH(c2, eth(1))

	// Run 1: no new key yet, so the run makes one and stops at the first record it needs.
	t0 := time.Now()
	args1 := []string{}
	if mpcMode() {
		args1 = append(args1, "-admin-auth", s.partyAuth(s.newKeysetID(2)))
	}
	out, err := emergency(args1...)
	if err == nil || !strings.Contains(out, "candidate needs its signed record") {
		t.Fatalf("first emergency run: %v\n%s", err, out)
	}
	mark("new key made (dkg)", t0)
	plan := s.rekeyPlan(dir)
	gen2 := common.HexToAddress(plan.Address)

	// The operators sign the three records ahead, in sequence.
	t1 := time.Now()
	cand := s.signed(1, "-action", "register-candidate", "-generation", "2", "-address", plan.Address, "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey)
	comp := s.signed(2, "-action", "mark-compromised", "-generation", "1", "-successor", "2", "-cap", capETH, "-cap", capUSDT)
	act := s.signed(3, "-action", "activate", "-generation", "2")
	mark("three records signed by two operators", t1)

	// Run 2 with the candidate and the mark only: it ends at "activate", which is how a kill at that point looks. The mark is in the zone now.
	t2 := time.Now()
	out, err = emergency("-changes", cand, "-changes", comp)
	if err == nil || !strings.Contains(out, "activate needs its signed record") {
		t.Fatalf("second emergency run: %v\n%s", err, out)
	}
	mark("candidate + mark compromised (zone+core)", t2)

	// Ordinary signing from the old generation is refused, and so is the thief's transaction: for an outside address, as a withdrawal and as a "drain".
	t3 := time.Now()
	s.mustRefuse("em-w-old", "withdrawal", gen1, randAddr(), 1000, 950, "compromised")
	mark("old key's withdrawal refused after the mark", t3)
	s.mustRefuse("em-thief-wd", "withdrawal", gen1, randAddr(), 1000, 951, "compromised")
	// (a "drain" to an outside address is tried after the activation: before it the zone only waits, the successor not being active yet)

	// Work in flight at the mark that the zone refused: a sweep and a withdrawal, each with a nonce at the old address and a refused job, no signature.
	// This is what a sweep built a moment before the mark leaves behind (the zone refuses it, and refuses its cancel too). It made the drain wait for
	// ever for "transactions still in flight"; now the nonces are holes that the drain's own transfers fill.
	s.strandNonce("sweep", "sw-em-stranded", gen1)
	s.strandNonce("withdrawal", "wd-em-stranded", gen1)

	// Run 3 with everything: activate, then the drain is watched to its end. (A kill of this run costs nothing: run it again.)
	t4 := time.Now()
	out, err = emergency("-changes", cand, "-changes", comp, "-changes", act)
	if err != nil || !strings.Contains(out, "drained") {
		t.Fatalf("third emergency run: %v\n%s", err, out)
	}
	mark("activate + drain until drained", t4)
	for _, want := range []string{"candidate", "drain-start", "activate"} {
		if !strings.Contains(out, want) {
			t.Errorf("the run's output lacks the step %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "STALLED") || strings.Contains(out, "still in flight") && !strings.Contains(out, "drained") {
		t.Errorf("the drain waited for work the zone had refused:\n%s", out)
	}
	var open int
	s.pool.QueryRow(s.ctx, `SELECT count(*) FROM evm_nonce_allocations WHERE lower(address)=lower($1) AND owner_kind NOT IN ('hole','drain') AND status IN ('allocated','broadcast')`, gen1.Hex()).Scan(&open)
	if open != 0 {
		t.Errorf("%d transactions of the old address are still open after the drain", open)
	}
	s.mustRefuse("em-thief-drain", "drain", gen1, randAddr(), 1000, 952, "successor")
	// The run again changes nothing.
	if out, err = emergency("-changes", cand, "-changes", comp, "-changes", act); err != nil || !strings.Contains(out, "done") {
		t.Fatalf("a repeated run: %v\n%s", err, out)
	}

	// The cold ceremony and the zone's config edit (the steps outside the tool), then the arrivals are swept to the new address.
	t5 := time.Now()
	s.setDestination(gen2)
	s.restartZone(gen2)
	mark("set-destination + zone restart", t5)
	usdtBefore := s.usdtBalance(gen2)
	s.mintUSDT(c2, 500_000_000)
	t6 := time.Now()
	s.waitFor(240*time.Second, "the deposits swept to generation 2", func() bool {
		return s.usdtBalance(gen2).Cmp(new(big.Int).Add(usdtBefore, big.NewInt(500_000_000))) == 0
	})
	mark("deposit swept to the new key", t6)
	s.waitIdle(120 * time.Second)

	// The withdrawal in flight settled, from one key or the other; one made now goes out from the new key.
	s.waitWd(inflight.ID, "confirmed", 180*time.Second)
	if from := s.senderOfWithdrawal(inflight.ID); from != gen1 && from != gen2 {
		t.Fatalf("the in-flight withdrawal came from %s", from)
	}
	w := s.withdrawETH("em-after", 1e15)
	s.waitWd(w.ID, "confirmed", 120*time.Second)
	s.senderIs(w.ID, gen2)
	if left := s.ethBalance(gen1); left.Cmp(big.NewInt(1e16)) >= 0 || s.usdtBalance(gen1).Sign() != 0 {
		t.Fatalf("the old key still holds %s wei and %s USDT", left, s.usdtBalance(gen1))
	}
	if got := s.usdtBalance(gen2); got.Cmp(big.NewInt(usdtDeposit+500_000_000)) != 0 {
		t.Fatalf("the new key holds %s USDT", got)
	}
	s.reconcileClean()
	// The compromised generation is never retired.
	if o, err := s.rekeyErr(dir, "retire"); err == nil || !strings.Contains(o+err.Error(), "compromised") {
		t.Fatalf("retire: %v\n%s", err, o)
	}
	s.requireAudit("keyset.compromised")
	t.Logf("drill times: summary %s", fmt.Sprint(times))
	log := mustReadFile(t, filepath.Join(dir, "emergency.log"))
	t.Logf("emergency.log:\n%s", log)
}

func mustReadFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// strandNonce leaves what a refused transaction leaves at the old address once the zone refuses its cancel as well: the next nonce of the address, allocated
// to the owner, and one rejected sign job. No signature exists, so the nonce is free for anyone who can still sign: only a drain.
func (s *system) strandNonce(kind, id string, from common.Address) {
	s.t.Helper()
	o := custody.Owner{Kind: kind, ID: id, PartitionID: s.shardPart("ETH", 0)}
	tx, err := s.pool.Begin(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer tx.Rollback(s.ctx)
	var next int64
	if err := tx.QueryRow(s.ctx, `SELECT next_nonce FROM evm_nonces WHERE chain=$1 AND lower(address)=lower($2) FOR UPDATE`, s.chainName, from.Hex()).Scan(&next); err != nil {
		s.t.Fatal(err)
	}
	if _, err := tx.Exec(s.ctx, `INSERT INTO evm_nonce_allocations (chain, address, nonce, owner_kind, owner_id, status) VALUES ($1,$2,$3,$4,$5,'allocated')`,
		s.chainName, from.Hex(), next, kind, id); err != nil {
		s.t.Fatal(err)
	}
	if _, err := tx.Exec(s.ctx, `UPDATE evm_nonces SET next_nonce=$3 WHERE chain=$1 AND lower(address)=lower($2)`, s.chainName, from.Hex(), next+1); err != nil {
		s.t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(kind + id))
	job := signjob.Job{ID: custody.OwnerTrack(o).FirstJob(), PartitionID: o.PartitionID, KeyRef: "m/0", Chain: s.chainName,
		Intent: mustJSONb(signjob.Intent{Kind: kind, ID: id, PartitionID: o.PartitionID, Chain: s.chainName}), Digest: digest[:], Payload: []byte(`{}`)}
	if err := signjob.Enqueue(s.ctx, tx, job); err != nil {
		s.t.Fatal(err)
	}
	if _, err := tx.Exec(s.ctx, `UPDATE sign_jobs SET status='rejected', reject_reason='keyset_state: generation 1 is compromised: it signs nothing' WHERE id=$1`, job.ID); err != nil {
		s.t.Fatal(err)
	}
	if err := tx.Commit(s.ctx); err != nil {
		s.t.Fatal(err)
	}
}
