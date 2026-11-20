package custody_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ws4charlie/quorum-vault/e2e/idp"
	ethtx "github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A whole replacement of an EVM hot shard's key, driven by qv-rekey, in both signer modes (HSM: a second key in the token; mpc: a second 2-of-3
// keyset made by a DKG on the three parties): withdrawals before, during and after; deposits swept to the new address; the old address drained and
// retired; Reconcile clean at every step; the worker and the gateway killed in the middle; and the zone's own refusals, tried with jobs written into
// the job table the way the business zone (or an attacker who owns it) would. K2b's e2e could not do this: the zone had no way to sign from a second key.

// rekey runs qv-rekey for the system's shard; it fails the test on an error.
func (s *system) rekey(dir string, args ...string) string {
	s.t.Helper()
	out, err := s.rekeyErr(dir, args...)
	if err != nil {
		s.t.Fatalf("qv-rekey %v: %v\n%s", args, err, out)
	}
	return out
}

func (s *system) rekeyErr(dir string, args ...string) (string, error) {
	s.t.Helper()
	tok := filepath.Join(s.dir, "admin.token")
	if err := os.WriteFile(tok, []byte(strings.TrimPrefix(idp.Bearer("ops"), "Bearer ")), 0o600); err != nil { // a fresh login: the routes need step-up
		s.t.Fatal(err)
	}
	base := []string{args[0], "-dir", dir, "-config", s.gwPath, "-guard-dsn", "gateway=" + s.guardDSN,
		"-core", s.apiURL, "-core-ca", filepath.Join(pkitest.Root(), pki.ZoneBusiness, "ca.crt"), "-token-file", tok,
		"-rpc", s.rpcURL, "-factory", s.factory.Hex()}
	if mpcMode() {
		base = append(base, "-guard-dsn", "cosigner-b="+s.cosGuardDSN, "-guard-dsn", "cosigner-c="+s.cosCGuardDSN)
	}
	cmd := exec.Command(filepath.Join(binDir, "qv-rekey"), append(base, args[1:]...)...)
	// The PIN reaches the tool as a file (QV_HSM_PIN_FILE, mode 0400), the way it does in production.
	pinFile := filepath.Join(s.dir, "rekey-hsm-pin")
	if _, err := os.Stat(pinFile); err != nil {
		if err := os.WriteFile(pinFile, []byte(hsmtest.PIN(s.t)+"\n"), 0o400); err != nil {
			s.t.Fatal(err)
		}
	}
	cmd.Env = append(os.Environ(), "QV_HSM_PIN=", "QV_HSM_PIN_FILE="+pinFile, "SOFTHSM2_CONF="+os.Getenv("SOFTHSM2_CONF"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// signed makes the zone's record the way two operators do offline (qv-keysets sign, then -join) and returns the file.
func (s *system) signed(seq int, args ...string) string {
	s.t.Helper()
	bin := filepath.Join(binDir, "qv-keysets")
	f := filepath.Join(s.dir, "rk-change-"+hex.EncodeToString([]byte{byte(seq)})+".json")
	run := func(a ...string) {
		s.t.Helper()
		if out, err := exec.Command(bin, a...).CombinedOutput(); err != nil {
			s.t.Fatalf("qv-keysets %v: %v\n%s", a, err, out)
		}
	}
	run(append([]string{"sign", "-seq", intStr(seq), "-shard", s.shardID(), "-operator", "op1", "-key", filepath.Join(s.dir, "op1.key"), "-out", f}, args...)...)
	run("sign", "-operator", "op2", "-key", filepath.Join(s.dir, "op2.key"), "-join", f, "-out", f)
	return f
}

func intStr(n int) string { return big.NewInt(int64(n)).String() }

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

func (s *system) newKeysetID(gen int) string {
	return strings.Trim(slugRE.ReplaceAllString(strings.ToLower(s.shardID()), "-"), "-") + "-g" + intStr(gen)
}

type rekeyPlan struct {
	Address, KeyRef, PublicKey string
	From, To                   int
}

func (s *system) rekeyPlan(dir string) rekeyPlan {
	s.t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		s.t.Fatal(err)
	}
	var raw struct {
		Address   string `json:"address"`
		KeyRef    string `json:"key_ref"`
		PublicKey string `json:"public_key"`
		From      int    `json:"from"`
		To        int    `json:"to"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		s.t.Fatal(err)
	}
	return rekeyPlan{raw.Address, raw.KeyRef, raw.PublicKey, raw.From, raw.To}
}

// partyAuth is an operator's authorisation of the DKG on the parties (qv-keysets party-auth), made right before it is used.
func (s *system) partyAuth(keyset string) string {
	s.t.Helper()
	key := filepath.Join(s.dir, "party-admin.key")
	if err := os.WriteFile(key, []byte(s.mpc.AdminSeedHex()), 0o600); err != nil {
		s.t.Fatal(err)
	}
	f := filepath.Join(s.dir, "party-auth.json")
	if out, err := exec.Command(filepath.Join(binDir, "qv-keysets"), "party-auth", "-key", key, "-op", "dkg", "-keyset", keyset, "-out", f).CombinedOutput(); err != nil {
		s.t.Fatalf("party-auth: %v\n%s", err, out)
	}
	return f
}

// dkg is the dkg step in either mode.
func (s *system) dkg(dir string, gen int) string {
	s.t.Helper()
	if !mpcMode() {
		return s.rekey(dir, "dkg")
	}
	// Without the operator's authorisation the tool says what to make and stops.
	if out, err := s.rekeyErr(dir, "dkg"); err == nil || !strings.Contains(out+err.Error(), "party-auth") {
		s.t.Fatalf("dkg without an authorisation: %v\n%s", err, out)
	}
	out := s.rekey(dir, "dkg", "-admin-auth", s.partyAuth(s.newKeysetID(gen)))
	s.mpc.WaitReady(90 * time.Second)
	return out
}

// restartZone writes the zone configs again (the sweep destination is the one manual edit of the runbook) and restarts the gateway and the cosigners.
func (s *system) restartZone(sweepDest common.Address) {
	s.t.Helper()
	s.gf.Chains[s.chainName].EVM.SweepDestination = sweepDest.Hex()
	writeJSON(s.t, s.gwPath, s.gf)
	s.gateway.stop()
	if mpcMode() {
		cf2 := s.gf
		cf2.Signers, cf2.MPCRoute = nil, nil
		writeJSON(s.t, s.cosPath, cf2)
		writeJSON(s.t, filepath.Join(s.dir, "cosigner-c.json"), cf2)
		s.mpc.Cos.Stop()
		s.mpc.CosC.Stop()
		s.mpc.StartCosignerAgain()
		s.mpc.StartCosignerCAgain()
	}
	s.startGateway()
}

// senderOfWithdrawal is the address a confirmed withdrawal was sent from.
func (s *system) senderOfWithdrawal(id string) common.Address {
	s.t.Helper()
	w := s.getWd(id)
	if w.Tx == "" {
		s.t.Fatalf("withdrawal %s has no transaction (status %s)", id, w.Status)
	}
	tx, _, err := s.ec.TransactionByHash(s.ctx, common.HexToHash(w.Tx))
	if err != nil {
		s.t.Fatal(err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		s.t.Fatal(err)
	}
	return from
}

// hostile writes a sign job straight into the job table, as the business zone could: a transaction from `from` and the intent that goes with it, with
// valid approvals, so that the only thing between it and a signature is the zone's own rules. It returns the job's final status and reason.
func (s *system) hostile(id, kind string, from, to common.Address, amount int64, nonce uint64) (string, string) {
	s.t.Helper()
	in := signjob.Intent{Kind: kind, ID: id, Chain: s.chainName, PartitionID: s.shardPart("ETH", 0), Asset: "ETH", To: to.Hex(), Amount: intStr(int(amount)),
		NotAfter: time.Now().Add(10 * time.Minute).Unix()}
	switch kind {
	case "withdrawal":
		in.RequestedBy = "initiator"
	case signjob.KindDrain:
		in.From = from.Hex()
	}
	p := ethtx.TxParams{ChainID: big.NewInt(11155111), Nonce: nonce, To: to, Value: big.NewInt(amount), Gas: 21000, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(3e9)}
	_, d, err := ethtx.BuildTx(p)
	if err != nil {
		s.t.Fatal(err)
	}
	payload, _ := json.Marshal(evm.Payload{ChainID: 11155111, From: from.Hex(), Nonce: nonce, To: to.Hex(), Value: intStr(int(amount)), Data: "0x", Gas: 21000, Tip: "1000000000", FeeCap: "3000000000"})
	job := signjob.Job{ID: id, PartitionID: in.PartitionID, KeyRef: "m/0", Chain: s.chainName, Intent: mustJSONb(in), Digest: d[:], Payload: payload}
	if kind == "withdrawal" {
		h := in.Hash()
		job.Approvals = []signjob.Approval{{Actor: "alice", Signature: signEd(s.approv["alice"], h[:])}}
	}
	tx, err := s.pool.Begin(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := signjob.Enqueue(s.ctx, tx, job); err != nil {
		tx.Rollback(s.ctx)
		s.t.Fatal(err)
	}
	if err := tx.Commit(s.ctx); err != nil {
		s.t.Fatal(err)
	}
	var status, reason string
	s.waitFor(60*time.Second, "the zone to decide on "+id, func() bool {
		s.pool.QueryRow(s.ctx, `SELECT status, COALESCE(reject_reason,'') FROM sign_jobs WHERE id=$1`, id).Scan(&status, &reason)
		return status == "done" || status == "rejected" || status == "failed"
	})
	return status, reason
}

func (s *system) mustRefuse(id, kind string, from, to common.Address, amount int64, nonce uint64, why string) {
	s.t.Helper()
	status, reason := s.hostile(id, kind, from, to, amount, nonce)
	if status == "done" {
		s.t.Fatalf("the zone SIGNED %s (%s from %s)", id, kind, from)
	}
	if !strings.Contains(reason, why) {
		s.t.Fatalf("%s: status %s reason %q, want it to contain %q", id, status, reason, why)
	}
}

var bigCaps = []string{"-cap", "ETH=" + eth1m(), "-cap", "USDT=1000000000000"}

func eth1m() string { return eth(1_000_000).String() }

func (s *system) senderIs(id string, want common.Address) {
	s.t.Helper()
	if got := s.senderOfWithdrawal(id); got != want {
		s.t.Fatalf("withdrawal %s was sent from %s, want %s", id, got, want)
	}
}

func rekeyShard(t *testing.T) *system {
	t.Helper()
	s := shardFunded(t, opts{})
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("rekey")
		}
	})
	return s
}

// ---- the planned replacement ----

func TestRekeyFullReplacementDrivenByTheTool(t *testing.T) {
	s := rekeyShard(t)
	gen1 := s.shardAddr[0]
	dir := filepath.Join(s.dir, "rekey")
	mode := "hsm"
	if mpcMode() {
		mode = "mpc"
	}
	seq := 0

	// Before: a withdrawal goes out from generation 1.
	w0 := s.withdrawETH("rk-before", 1e15)
	s.waitWd(w0.ID, "confirmed", 90*time.Second)
	s.senderIs(w0.ID, gen1)
	s.waitIdle(60 * time.Second)
	s.reconcileClean()

	// open: the plan and the checks.
	out := s.rekey(dir, "open", "-shard", s.shardID(), "-mode", mode, "-reason", "planned cryptoperiod end (e2e)")
	if !strings.Contains(out, "generation 1") || !strings.Contains(out, "agree") {
		t.Fatal(out)
	}
	s.rekey(dir, "status")

	// dkg: a new key; run again, it is the same key.
	s.dkg(dir, 2)
	plan := s.rekeyPlan(dir)
	if plan.Address == "" || plan.From != 1 || plan.To != 2 || common.HexToAddress(plan.Address) == gen1 {
		t.Fatalf("plan %+v", plan)
	}
	gen2 := common.HexToAddress(plan.Address)
	if mpcMode() {
		s.rekey(dir, "dkg", "-admin-auth", s.partyAuth(s.newKeysetID(2))) // not asked for again: the keyset exists, the tool finds it
	} else {
		s.rekey(dir, "dkg")
	}
	if again := s.rekeyPlan(dir); again.Address != plan.Address {
		t.Fatal("dkg made a second key")
	}

	// candidate: the tool prints what to sign, then applies the signed change to the zone and the core.
	out = s.rekey(dir, "candidate")
	if !strings.Contains(out, "qv-keysets sign") || !strings.Contains(out, "-seq 1 ") || !strings.Contains(out, plan.Address) {
		t.Fatalf("candidate prints:\n%s", out)
	}
	seq++
	cand := s.signed(seq, "-action", "register-candidate", "-generation", "2", "-address", plan.Address, "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey)
	s.rekey(dir, "candidate", "-change", cand)
	s.rekey(dir, "status")
	s.reconcileClean()
	// A candidate signs nothing, although the zone can reach its key.
	s.mustRefuse("rk-h-cand", "withdrawal", gen2, randAddr(), 1000, 900, "candidate")
	// Generation 1 is untouched by it.
	w1 := s.withdrawETH("rk-with-candidate", 1e15)
	s.waitWd(w1.ID, "confirmed", 90*time.Second)
	s.senderIs(w1.ID, gen1)

	// The gateway dies here and comes back: the replacement is in the zone's database, nothing is lost.
	s.gateway.kill()
	s.startGateway()

	// The worker is armed to die after the first drain broadcast.
	s.worker.stop()
	s.startWorker("drain.after_broadcast")

	// drain-start: generation 1 drains into 2. The shard has no active key until activate: a withdrawal waits.
	out = s.rekey(dir, "drain-start", bigCaps[0], bigCaps[1], bigCaps[2], bigCaps[3])
	if !strings.Contains(out, "-seq 2 ") || !strings.Contains(out, "start-draining") {
		t.Fatalf("drain-start prints:\n%s", out)
	}
	seq++
	drain := s.signed(seq, "-action", "start-draining", "-generation", "1", "-successor", "2", "-cap", "ETH="+eth1m(), "-cap", "USDT=1000000000000")
	// A change file for another step is refused, and nothing is applied.
	if o, err := s.rekeyErr(dir, "drain-start", "-cap", "ETH="+eth1m(), "-cap", "USDT=1000000000000", "-change", cand); err == nil {
		t.Fatalf("the tool took the candidate file for drain-start:\n%s", o)
	}
	s.rekey(dir, "drain-start", "-cap", "ETH="+eth1m(), "-cap", "USDT=1000000000000", "-change", drain)
	during := s.withdrawETH("rk-during", 1e15)
	s.holds(6*time.Second, "the withdrawal waits for an active key", func() bool { return s.getWd(during.ID).Tx == "" && s.getWd(during.ID).Status != "failed" })

	// The zone's rules while generation 1 is draining: no normal withdrawal from it, no drain anywhere but to its successor.
	s.mustRefuse("rk-h-draining", "withdrawal", gen1, randAddr(), 1000, 901, "draining")

	// Retiring too early is refused, by the tool.
	if o, err := s.rekeyErr(dir, "retire"); err == nil {
		t.Fatalf("retire before the drain:\n%s", o)
	}

	// activate: the successor is active. The shard now has one active key, the drain starts, and the worker dies after its first broadcast.
	seq++
	act := s.signed(seq, "-action", "activate", "-generation", "2")
	out = s.rekey(dir, "activate", "-change", act)
	if !strings.Contains(out, "set-destination") {
		t.Fatalf("activate does not say what the cold ceremony needs:\n%s", out)
	}
	if code, ok := s.worker.exitCode(scaled(120 * time.Second)); !ok || code != 137 {
		t.Fatalf("the worker did not die after the drain broadcast (exited=%v code=%d)", ok, code)
	}
	// The cold ceremony (set-destination, here the admin key directly: the ceremony itself is tested in cold_test.go) and the zone's one config edit,
	// with the gateway and the cosigners restarted: all in the middle of the drain.
	s.setDestination(gen2)
	s.restartZone(gen2)
	s.startWorker("")
	// A drain to any address but the successor is refused (before activation it would only wait: the successor was not active yet).
	s.mustRefuse("rk-h-evil", "drain", gen1, randAddr(), 1000, 902, "successor")
	s.waitFor(300*time.Second, "generation 1 to be drained", func() bool { st, _ := s.drainView(1); return st == "drained" })
	s.waitIdle(90 * time.Second)

	// The withdrawal that waited goes out from generation 2; the old key holds only dust.
	s.waitWd(during.ID, "confirmed", 120*time.Second)
	s.senderIs(during.ID, gen2)
	if left := s.ethBalance(gen1); left.Cmp(big.NewInt(1e16)) >= 0 || s.usdtBalance(gen1).Sign() != 0 {
		t.Fatalf("generation 1 still holds %s wei and %s USDT", left, s.usdtBalance(gen1))
	}
	if got := s.usdtBalance(gen2); got.Cmp(big.NewInt(usdtDeposit)) != 0 {
		t.Fatalf("generation 2 holds %s USDT, want %d", got, usdtDeposit)
	}
	s.reconcileClean()
	if out := s.rekey(dir, "status"); !strings.Contains(out, "next step: retire") || !strings.Contains(out, "the ceremony is done") {
		t.Fatalf("status:\n%s", out)
	}

	// After: a withdrawal, and a deposit that is swept to the new address.
	w2 := s.withdrawETH("rk-after", 1e15)
	s.waitWd(w2.ID, "confirmed", 120*time.Second)
	s.senderIs(w2.ID, gen2)
	usdtBefore := s.usdtBalance(gen2)
	c2 := s.newCustomer("c-after")
	s.sendETH(c2, eth(1))
	s.mintUSDT(c2, 700_000_000)
	s.waitAvailable("c-after", "USDT", big.NewInt(700_000_000), 60*time.Second)
	s.waitFor(180*time.Second, "the new deposit swept to generation 2", func() bool {
		return s.usdtBalance(gen2).Cmp(new(big.Int).Add(usdtBefore, big.NewInt(700_000_000))) == 0
	})
	s.waitIdle(90 * time.Second)
	s.reconcileClean()
	// A late arrival at the old address is not swept anywhere by the zone's rules (the old key signs nothing but its drain) and is not hidden either.
	// (not exercised here: a deposit address pays the factory's destination, so nothing reaches the old address by itself)

	// retire.
	seq++
	ret := s.signed(seq, "-action", "retire", "-generation", "1")
	s.rekey(dir, "retire", "-change", ret)
	out = s.rekey(dir, "status")
	if !strings.Contains(out, "complete") {
		t.Fatalf("status after retire:\n%s", out)
	}
	s.rekey(dir, "retire") // run again: nothing to do
	s.reconcileClean()
	// A retired key signs nothing, not even a drain.
	s.mustRefuse("rk-h-retired", "withdrawal", gen1, randAddr(), 1000, 903, "retired")
	s.requireAudit("keyset.retired", "drain.started")
}

// ---- the emergency order ----

func TestRekeyCompromisedGenerationOnlyDrains(t *testing.T) {
	s := rekeyShard(t)
	gen1 := s.shardAddr[0]
	dir := filepath.Join(s.dir, "rekey")
	mode := "hsm"
	if mpcMode() {
		mode = "mpc"
	}
	seq := 0
	s.rekey(dir, "open", "-shard", s.shardID(), "-mode", mode, "-reason", "the hot key may be stolen (e2e)")
	s.dkg(dir, 2)
	plan := s.rekeyPlan(dir)
	gen2 := common.HexToAddress(plan.Address)
	seq++
	s.rekey(dir, "candidate", "-change", s.signed(seq, "-action", "register-candidate", "-generation", "2", "-address", plan.Address, "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey))

	// Emergency: the old key is marked compromised, the record names the successor and the caps. It signs no withdrawal.
	seq++
	s.rekey(dir, "drain-start", "-compromised", "-cap", "ETH="+eth1m(), "-cap", "USDT=1000000000000",
		"-change", s.signed(seq, "-action", "mark-compromised", "-generation", "1", "-successor", "2", "-cap", "ETH="+eth1m(), "-cap", "USDT=1000000000000"))
	s.mustRefuse("rk-c-wd", "withdrawal", gen1, randAddr(), 1000, 910, "compromised")
	seq++
	s.rekey(dir, "activate", "-change", s.signed(seq, "-action", "activate", "-generation", "2"))
	s.setDestination(gen2)
	s.restartZone(gen2)
	// It drains, to its successor only.
	s.mustRefuse("rk-c-evil", "drain", gen1, randAddr(), 1000, 911, "successor")
	s.waitFor(300*time.Second, "the compromised generation to be drained", func() bool { st, _ := s.drainView(1); return st == "drained" })
	s.waitIdle(90 * time.Second)
	if got := s.usdtBalance(gen2); got.Cmp(big.NewInt(usdtDeposit)) != 0 {
		t.Fatalf("generation 2 holds %s USDT", got)
	}
	w := s.withdrawETH("rk-c-after", 1e15)
	s.waitWd(w.ID, "confirmed", 120*time.Second)
	s.senderIs(w.ID, gen2)
	// It is never retired: not by the tool, and not by the zone.
	if o, err := s.rekeyErr(dir, "retire"); err == nil || !strings.Contains(o+err.Error(), "compromised") {
		t.Fatalf("retire of a compromised generation: %v\n%s", err, o)
	}
	s.reconcileClean()
}

// ---- the tool refuses to go on when the zone and the core disagree ----

func TestRekeyRefusesWhenTheZoneAndTheCoreDisagree(t *testing.T) {
	s := rekeyShard(t)
	dir := filepath.Join(s.dir, "rekey")
	mode := "hsm"
	if mpcMode() {
		mode = "mpc"
	}
	s.rekey(dir, "open", "-shard", s.shardID(), "-mode", mode, "-reason", "disagreement (e2e)")
	s.dkg(dir, 2)
	plan := s.rekeyPlan(dir)
	// The core is told first (wrong order): it has a candidate the zone does not know.
	s.coreStep("candidates", map[string]any{"shard_id": s.shardID(), "address": plan.Address, "key_ref": plan.KeyRef}, 201)
	out, err := s.rekeyErr(dir, "candidate")
	if err == nil || !strings.Contains(out+err.Error(), "behind") {
		t.Fatalf("expected a refusal naming the lagging side: %v\n%s", err, out)
	}
	if o, err := s.rekeyErr(dir, "status"); err == nil || !strings.Contains(o, "DISAGREEMENT") {
		t.Fatalf("status of a disagreement: %v\n%s", err, o)
	}
}

func mustJSONb(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func signEd(k ed25519.PrivateKey, msg []byte) []byte { return ed25519.Sign(k, msg) }
