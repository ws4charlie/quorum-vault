package sole2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// ---- direct jobs, for the attacks on the signing zone ----

func (s *wdSys) partSOL() string { return s.cfg.PartitionKey("SOL", 0).String() }

// nonceValue is what pool account i holds now (finalized).
func (s *wdSys) nonceValue(i int) [32]byte {
	s.t.Helper()
	st, err := s.adapter.RPC().GetNonce(s.ctx, sol.Address(sol.NonceAddress(s.hot, i)), sol.Finalized)
	if err != nil {
		s.t.Fatal(err)
	}
	return st.Value
}

// wdMsg is a withdrawal message on pool account nonceIdx signing value.
func (s *wdSys) wdMsg(nonceIdx int, value [32]byte, price uint64, limit uint32, to [32]byte, amount uint64, extra ...sol.Ix) []byte {
	n := sol.NonceAddress(s.hot, nonceIdx)
	ixs := []sol.Ix{sol.AdvanceNonceIx(n, s.hot), sol.SetLimitIx(limit)}
	if price > 0 {
		ixs = append(ixs, sol.SetPriceIx(price))
	}
	ixs = append(ixs, sol.TransferIx(s.hot, to, amount))
	return sol.Compile(s.hot, value, append(ixs, extra...)...)
}

func (s *wdSys) cancelMsg(nonceIdx int, value [32]byte, price uint64) []byte {
	n := sol.NonceAddress(s.hot, nonceIdx)
	return sol.Compile(s.hot, value, sol.AdvanceNonceIx(n, s.hot), sol.SetLimitIx(5_000), sol.SetPriceIx(price))
}

func (s *wdSys) wdIntent(id string, to [32]byte, amount uint64) signjob.Intent {
	return signjob.Intent{Kind: "withdrawal", ID: id, PartitionID: s.partSOL(), Chain: s.chain, Asset: "SOL", To: sol.Address(to), Amount: fmt.Sprint(amount),
		NotAfter: time.Now().Add(time.Hour).Unix()}
}

// signJob hands a job straight to the signing zone's queue and waits for the gateway: the way a compromised business zone would.
func (s *wdSys) signJob(id string, in signjob.Intent, msg []byte, approvers ...string) signjob.Job {
	s.t.Helper()
	p, _ := json.Marshal(sol.Payload{Message: msg})
	ib, _ := json.Marshal(in)
	var apps []signjob.Approval
	h := in.Hash()
	for _, a := range approvers {
		apps = append(apps, signjob.Approval{Actor: a, Signature: ed25519.Sign(s.approv[a], h[:])})
	}
	tx, err := s.pool.Begin(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := signjob.Enqueue(s.ctx, tx, signjob.Job{ID: id, PartitionID: in.PartitionID, KeyRef: "", Chain: s.chain, Intent: ib, Digest: msg, Payload: p, Approvals: apps}); err != nil {
		tx.Rollback(s.ctx)
		s.t.Fatal(err)
	}
	if err := tx.Commit(s.ctx); err != nil {
		s.t.Fatal(err)
	}
	var j signjob.Job
	s.waitFor(90*time.Second, "the gateway to answer job "+id, func() bool {
		j, err = signjob.Get(s.ctx, s.pool, id)
		return err == nil && j.Status != signjob.StatusPending && j.Status != signjob.StatusSigning
	})
	return j
}

func (s *wdSys) mustSign(id string, in signjob.Intent, msg []byte, approvers ...string) {
	s.t.Helper()
	if j := s.signJob(id, in, msg, approvers...); j.Status != signjob.StatusDone {
		s.t.Fatalf("job %s: %s %s\ngateway: %s", id, j.Status, j.RejectReason, tail(s.gateway.Output()))
	}
}

func (s *wdSys) mustRefuse(id string, in signjob.Intent, msg []byte, code string, approvers ...string) {
	s.t.Helper()
	j := s.signJob(id, in, msg, approvers...)
	if j.Status == signjob.StatusDone || !strings.HasPrefix(j.RejectReason, code) {
		s.t.Fatalf("job %s: %s %q, want a refusal %q", id, j.Status, j.RejectReason, code)
	}
}

func exitCodeOf(p *proc, timeout time.Duration) (int, bool) {
	select {
	case <-p.done:
	case <-time.After(timeout):
		return 0, false
	}
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, p.err == nil
}

// ---- faults ----

func TestWdFaults(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 4, noPool: true, stuckAfter: "10m"})

	s.sub(t, "the_operator_command_creates_the_pool_through_the_signing_zone", func(t *testing.T) {
		keyFile := filepath.Join(s.dir, "carol.key")
		if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(s.approv["carol"])), 0o600); err != nil {
			t.Fatal(err)
		}
		run := func(approver string) string {
			cmd := exec.Command(filepath.Join(binDir, "qv-sol-nonces"), "-config", s.cfgPath, "-dsn", s.bizDSN, "-shard", "0", "-approver", approver, "-approver-key", keyFile, "-wait", "2m")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("qv-sol-nonces: %v\n%s", err, out)
			}
			return string(out)
		}
		// an operator who is not in the zone's approver list is refused, and nothing is created
		cmd := exec.Command(filepath.Join(binDir, "qv-sol-nonces"), "-config", s.cfgPath, "-dsn", s.bizDSN, "-shard", "0", "-approver", "mallory", "-approver-key", keyFile, "-wait", "30s")
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "approval") {
			t.Fatalf("an unknown approver: err=%v\n%s", err, out)
		}
		if missing, err := s.adapter.MissingNonces(s.ctx, s.partSOL()); err != nil || len(missing) != 4 {
			t.Fatalf("missing %v, %v: the refused setup created accounts", missing, err)
		}
		if out := run("carol"); !strings.Contains(out, "nonce accounts created") || !strings.Contains(out, "count=4") {
			t.Fatalf("%s", out)
		}
		if missing, err := s.adapter.MissingNonces(s.ctx, s.partSOL()); err != nil || len(missing) != 0 {
			t.Fatalf("missing %v, %v after the setup", missing, err)
		}
		if out := run("carol"); !strings.Contains(out, "the pool is complete") {
			t.Fatalf("a second run: %s", out)
		}
		// the rent and the fee of the creation left the shard and are booked as a cost: the books and the chain agree
		s.reconcileClean("after the pool was created")
		for i := 0; i < 4; i++ {
			st, err := s.adapter.RPC().GetNonce(s.ctx, sol.Address(sol.NonceAddress(s.hot, i)), sol.Finalized)
			if err != nil || st.Authority != s.hot || st.Lamports != sol.DefaultNonceRent {
				t.Fatalf("pool account %d: %+v %v", i, st, err)
			}
		}
	})

	custs := []string{"f-1", "f-2", "f-3", "f-4", "f-5", "f-6"}
	for _, c := range custs {
		s.deposit(c, 20*oneSOL, 0)
	}
	for _, c := range custs {
		s.waitDeposits(c, 20*oneSOL, 0)
	}

	s.sub(t, "the_signing_zone_refuses_every_attack_on_the_nonce", func(t *testing.T) {
		X, Y := newKey(t).pub, newKey(t).pub
		v := s.nonceValue(3)
		in := s.wdIntent("atk-1", X, oneSOL)
		first := s.wdMsg(3, v, 1000, 100_000, X, oneSOL)
		s.mustSign("atk-a1", in, first, "alice")
		// a version with a higher price and nothing else different is the one thing that is signed again
		s.mustSign("atk-a2", in, s.wdMsg(3, v, 1500, 100_000, X, oneSOL), "alice")
		// everything else is refused
		s.mustRefuse("atk-low", in, s.wdMsg(3, v, 900, 100_000, X, oneSOL), "replay_fee_not_higher", "alice")
		s.mustRefuse("atk-limit", in, s.wdMsg(3, v, 4000, 50_000, X, oneSOL), "replay_fee_not_higher", "alice")
		s.mustRefuse("atk-acct", in, s.wdMsg(2, s.nonceValue(2), 4000, 100_000, X, oneSOL), "replay_nonce_changed", "alice")
		other := newKey(t).pub // a value the account does not hold: another nonce, not a version
		s.mustRefuse("atk-value", in, s.wdMsg(3, other, 4000, 100_000, X, oneSOL), "replay_nonce_changed", "alice")
		s.mustRefuse("atk-dest", in, s.wdMsg(3, v, 4000, 100_000, Y, oneSOL), "tx_mismatch", "alice")
		s.mustRefuse("atk-amount", in, s.wdMsg(3, v, 4000, 100_000, X, 2*oneSOL), "tx_mismatch", "alice")
		hot, evil := s.hot, newKey(t).pub
		s.mustRefuse("atk-authority", in, sol.Compile(hot, v, sol.AdvanceNonceIx(sol.NonceAddress(hot, 3), evil), sol.SetLimitIx(100_000), sol.SetPriceIx(4000), sol.TransferIx(hot, X, oneSOL)),
			"tx_mismatch", "alice")
		nonce3 := sol.NonceAddress(hot, 3)
		withdrawNonce := sol.Ix{Program: mustAddr(sol.SystemProgram), Data: append([]byte{5, 0, 0, 0}, le64(1_000_000)...),
			Accts: []sol.Meta{{Key: nonce3, Writable: true}, {Key: evil, Writable: true}, {Key: mustAddr(sol.SysvarRecentBlockhashes)}, {Key: mustAddr(sol.SysvarRent)}, {Key: hot, Signer: true}}}
		s.mustRefuse("atk-nonce-withdraw", in, s.wdMsg(3, v, 4000, 100_000, X, oneSOL, withdrawNonce), "tx_mismatch", "alice")
		authorizeNonce := sol.Ix{Program: mustAddr(sol.SystemProgram), Data: append([]byte{7, 0, 0, 0}, evil[:]...), Accts: []sol.Meta{{Key: nonce3, Writable: true}, {Key: hot, Signer: true}}}
		s.mustRefuse("atk-nonce-authorize", in, s.wdMsg(3, v, 4000, 100_000, X, oneSOL, authorizeNonce), "tx_mismatch", "alice")
		// without an approval nothing is signed at all
		s.mustRefuse("atk-noapproval", s.wdIntent("atk-2", X, oneSOL), s.wdMsg(2, s.nonceValue(2), 1000, 100_000, X, oneSOL), "approval_invalid")

		// a cancel may only advance a nonce an intent holds: another nonce, or another value of this one, is refused
		cin := signjob.Intent{Kind: "cancel", ID: "cancel:atk", PartitionID: s.partSOL(), Chain: s.chain, Asset: "SOL", To: s.hotAddr(), Amount: "0"}
		s.mustRefuse("atk-cancel-other-acct", cin, s.cancelMsg(2, s.nonceValue(2), 2000), "replay_cancel_claims")
		s.mustRefuse("atk-cancel-other-value", cin, s.cancelMsg(3, other, 2000), "replay_cancel_claims")
		// the cancel of the nonce the intent holds is signed; after it no version of the intent is
		s.mustSign("atk-cancel", cin, s.cancelMsg(3, v, 2000))
		s.mustRefuse("atk-late", in, s.wdMsg(3, v, 9000, 100_000, X, oneSOL), "replay_nonce_cancel", "alice")

		// creating nonce accounts needs an operator, only the pool's own accounts, and the rent the config names
		sin := signjob.Intent{Kind: sol.KindNonceSetup, ID: "setup-atk", PartitionID: s.partSOL(), Chain: s.chain, Asset: "SOL", To: s.hotAddr(), Amount: fmt.Sprint(sol.DefaultNonceRent)}
		bh, err := s.adapter.RPC().LatestBlockhash(s.ctx, sol.Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		create := sol.CreateNonceIxs(hot, 9, sol.DefaultNonceRent) // outside the pool of 4
		msg := sol.Compile(hot, bh, append([]sol.Ix{sol.SetLimitIx(30_000)}, create...)...)
		inPool := sol.Compile(hot, bh, append([]sol.Ix{sol.SetLimitIx(30_000)}, sol.CreateNonceIxs(hot, 1, sol.DefaultNonceRent)...)...)
		s.mustRefuse("atk-setup-noapproval", sin, inPool, "approval_invalid")
		s.mustRefuse("atk-setup-outside-pool", sin, msg, "tx_mismatch", "alice")
	})

	s.sub(t, "an_operator_cancel_of_a_stuck_withdrawal_pays_nothing_and_voids", func(t *testing.T) {
		dest := newKey(t).addr()
		s.proxy.hold.Store(true)
		w := s.request("initiator", "k-cancel", "f-1", "SOL", dest, oneSOL)
		s.waitFor(60*time.Second, "the broadcast", func() bool { return s.attempts(w.ID) >= 1 })
		ow := custody.Owner{Kind: "withdrawal", ID: w.ID, PartitionID: s.partSOL()}
		cj, err := s.svc.EnqueueCancel(s.ctx, ow)
		if err != nil || cj == "" {
			t.Fatalf("enqueue cancel: %q %v", cj, err)
		}
		s.waitFor(60*time.Second, "the cancel to be signed", func() bool {
			st, _, err := s.svc.JobStatus(s.ctx, cj)
			return err == nil && st == custody.JobDone
		})
		if _, err := s.svc.SubmitJob(s.ctx, cj, ow); err != nil { // straight to the validator
			t.Fatal(err)
		}
		got := s.waitWd(w.ID, "failed", 90*time.Second)
		if got.Reason != "cancelled" {
			t.Fatalf("reason %q", got.Reason)
		}
		if got.Fee == "" || got.Fee == "0" {
			t.Fatalf("the fee of the cancel is not booked: %q", got.Fee)
		}
		// the withdrawal itself can never land now
		for _, j := range s.jobsOf(w.ID) {
			s.sendDirect(rawOfJob(t, j))
		}
		time.Sleep(3 * time.Second)
		for _, j := range s.jobsOf(w.ID) {
			if s.statusOf(sigOf(rawOfJob(t, j))) != nil {
				t.Fatalf("version %s landed after the cancel", j.ID)
			}
		}
		if s.lamports(dest) != 0 {
			t.Fatal("paid out a cancelled withdrawal")
		}
		if al := s.allocs(w.ID); len(al) != 1 || al[0].Status != "cancelled" {
			t.Fatalf("allocation %+v", al)
		}
		if a, h, _ := s.balances("f-1", "SOL"); a.Cmp(bigU(20*oneSOL)) != 0 || h.Sign() != 0 {
			t.Fatalf("available %s held %s", a, h)
		}
		s.proxy.hold.Store(false)
		s.reconcileClean("after an operator cancel")
		w2 := s.request("initiator", "k-after-cancel", "f-1", "SOL", s.freshAddr(), oneSOL)
		s.waitWd(w2.ID, "confirmed", 90*time.Second)
	})

	for _, role := range []string{"A", "B", "C"} {
		role := role
		s.sub(t, "withdrawals_settle_with_party_"+role+"_down", func(t *testing.T) {
			s.m3.Party(role).Kill()
			dest := newKey(t).addr()
			cust := map[string]string{"A": "f-2", "B": "f-3", "C": "f-4"}[role]
			w := s.request("initiator", "k-down-"+role, cust, "SOL", dest, oneSOL)
			s.waitWd(w.ID, "confirmed", 120*time.Second)
			if s.lamports(dest) != oneSOL {
				t.Fatalf("destination holds %d", s.lamports(dest))
			}
			s.m3.Party(role).Start(t)
			s.m3.WaitSigning(120 * time.Second)
			s.reconcileClean("after party " + role + " was down")
		})
	}

	if t.Failed() {
		s.dump()
	}
}

func le64(n uint64) []byte {
	b := make([]byte, 8)
	for i := range b {
		b[i] = byte(n >> (8 * i))
	}
	return b
}

func mustAddr(a string) [32]byte {
	r, err := sol.ParseAddress(a)
	if err != nil {
		panic(err)
	}
	return r
}

// ---- crash at every boundary ----

func TestWdCrash(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 3})
	s.deposit("c-1", 40*oneSOL, 0)
	s.waitDeposits("c-1", 40*oneSOL, 0)
	s.reconcileClean("start")
	only := os.Getenv("QV_CRASH_BOUNDARIES")
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			s.t.Logf("failed at %s", current)
			s.dump()
		}
	})
	for i, p := range []string{"after_build", "after_job", "after_broadcast", "after_confirm", "after_settle"} {
		fp := "withdrawal." + p
		if only != "" && !strings.Contains(","+only+",", ","+fp+",") {
			continue
		}
		current = fp
		s.worker.stop()
		s.startWorker(fp)
		dest := newKey(t).addr()
		w := s.request("initiator", fmt.Sprintf("k-crash-%d", i), "c-1", "SOL", dest, oneSOL)
		if w.Code != 201 {
			t.Fatalf("%s: %d %v", fp, w.Code, w.Raw)
		}
		s.requireDiedAt(fp, scale(120*time.Second))
		// with the worker dead, the books and the chain are in the middle of the withdrawal: Reconcile still agrees
		s.reconcileClean("worker dead at " + fp)
		s.startWorker("")
		s.waitWd(w.ID, "confirmed", 150*time.Second)
		if got := s.lamports(dest); got != oneSOL {
			t.Fatalf("%s: destination holds %d, want exactly %d", fp, got, oneSOL)
		}
		if n, c := s.count(`SELECT count(*) FROM ledger_txns WHERE id LIKE 'wd-out:%'`), s.count(`SELECT count(*) FROM withdrawals WHERE status='confirmed'`); n != c {
			t.Fatalf("%s: %d wd-out entries for %d confirmed withdrawals", fp, n, c)
		}
		if al := s.allocs(w.ID); len(al) != 1 || al[0].Status != "confirmed" {
			t.Fatalf("%s: allocation %+v", fp, al)
		}
		s.reconcileClean("after " + fp)
		t.Logf("crash %-26s ok: one payout, Reconcile clean", fp)
	}
}

var _ context.Context
