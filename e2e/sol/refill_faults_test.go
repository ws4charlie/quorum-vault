package sole2e

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// reconfigure stops the worker, edits the business config, and starts the worker again with a failpoint armed ("" arms nothing).
func (s *wdSys) reconfigure(mod func(cf *custody.File), failpoint string) {
	s.t.Helper()
	s.worker.stop()
	if mod != nil {
		mod(&s.cf)
	}
	writeJSONFile(s.t, s.cfgPath, s.cf)
	s.startWorker(failpoint)
}

// setSOLBand changes the SOL band of every hot shard.
func setSOLBand(low, high, target uint64) func(cf *custody.File) {
	return func(cf *custody.File) {
		cf.Cold.Limits["SOL"] = custody.LimitFile{Low: fmt.Sprint(low), High: fmt.Sprint(high), Target: fmt.Sprint(target)}
	}
}

func (s *wdSys) ledgerEntries(like string) int {
	return s.count(`SELECT count(*) FROM ledger_txns WHERE id LIKE $1`, like)
}

// A refill that is broadcast and cannot mine, because something else used the cold nonce: it parks with an ALERT, never retries on another nonce, and an
// operator closes it. The books give the broadcast booking back and the next request goes through.
func TestColdRefillParked(t *testing.T) {
	k := newSolKit(t)
	s := newWdSystem(t, refillOpts(k, "3s"))
	s.coldReady(k)
	stop := s.watchReconcile()

	r := s.waitRefill("SOL", "requested", 90*time.Second)
	s.proxy.hold.Store(true) // the broadcast is answered and the transaction is not sent: it is "on its way" and never lands
	rf := s.refillCeremony(k, r.ID)
	s.waitRefill("SOL", "broadcast", 60*time.Second)
	s.waitFor(60*time.Second, "the ALERT for a refill that does not confirm", func() bool {
		return fileContains(s.worker.log, "ALERT: a cold refill was broadcast and has not confirmed")
	})
	s.reconcileClean("a refill is on its way and not final")
	if code, _ := s.call("POST", "/v2/refills/"+r.ID+"/close", map[string]string{"reason": "too early"}); code != 400 {
		t.Fatalf("an operator closed a refill that was not parked: %d", code)
	}

	// something else uses the cold nonce (the cold key signs an advance of it, paid by another account, as a misuse of the key would)
	cold := addrBytes(t, k.addr)
	nonce := addrBytes(t, rf.Request.NonceAccount)
	value := addrBytes(t, rf.Request.NonceValue)
	msg := sol.Compile(s.funder.pub, value, sol.AdvanceNonceIx(nonce, cold))
	if msg[0] != 2 || [32]byte(msg[4:36]) != s.funder.pub || [32]byte(msg[36:68]) != cold {
		t.Fatalf("unexpected account order in the message: %x", msg[:70])
	}
	csig, err := k.tok.SignEd25519(t.Context(), k.keyID, msg)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(append([]byte{2}, ed25519.Sign(s.funder.priv, msg)...), csig...)
	s.sendDirect(append(raw, msg...))
	s.waitFinalized("the nonce to move", func() bool {
		v, err := s.adapter.ColdNonceValue(s.ctx, rf.Request.NonceAccount)
		return err == nil && v != rf.Request.NonceValue
	})
	s.waitFor(60*time.Second, "the refill to park", func() bool {
		for _, x := range s.refills() {
			if x.ID == r.ID && strings.HasPrefix(x.Reason, "parked:") {
				return true
			}
		}
		return false
	})
	if !fileContains(s.worker.log, "ALERT: an input of a signed cold refill") {
		t.Fatal("no ALERT for the consumed nonce")
	}
	s.reconcileClean("a parked refill")
	if code, _ := s.call("POST", "/v2/refills/"+r.ID+"/close", map[string]string{"reason": ""}); code != 400 {
		t.Fatalf("a close without a reason: %d", code)
	}
	if code, out := s.call("POST", "/v2/refills/"+r.ID+"/close", map[string]string{"reason": "the nonce was used by a transaction this system did not make; investigated"}); code != 200 {
		t.Fatalf("close: %d %v", code, out)
	}
	if st := s.refills()[0]; st.Status != "failed" || !strings.Contains(st.Reason, "closed by ops") {
		t.Fatalf("after the close: %+v", st)
	}
	if code, _ := s.call("POST", "/v2/refills/"+r.ID+"/close", map[string]string{"reason": "again"}); code != 400 {
		t.Fatalf("a closed refill closed again: %d", code)
	}
	s.reconcileClean("after the close")

	// the planner asks again and the ceremony now goes through, on the nonce value the other transaction left
	s.proxy.hold.Store(false)
	r2 := s.waitRefill("SOL", "requested", 90*time.Second)
	if r2.ID == r.ID {
		t.Fatal("no new request")
	}
	rf2 := s.refillCeremony(k, r2.ID)
	if rf2.Request.NonceValue == rf.Request.NonceValue && rf2.Request.NonceAccount == rf.Request.NonceAccount {
		t.Fatal("the new request reuses the consumed nonce value")
	}
	s.waitRefill("SOL", "confirmed", 120*time.Second)
	if bad := stop(); len(bad) > 0 {
		t.Fatalf("Reconcile failed: %v", bad)
	}
	s.reconcileClean("after the second refill")
	s.requireAudit("refill.closed")
}

func (s *wdSys) requireAudit(types ...string) {
	s.t.Helper()
	for _, ty := range types {
		if s.count(`SELECT count(*) FROM audit_log WHERE type=$1`, ty) == 0 {
			s.t.Fatalf("no audit entry %q", ty)
		}
	}
}

// Crash at every boundary of a refill: the books and the chain agree while the worker is dead, the refill settles once after it restarts, and the cold
// address pays exactly once.
func TestColdRefillCrash(t *testing.T) {
	k := newSolKit(t)
	s := newWdSystem(t, refillOpts(k, ""))
	s.coldReady(k)
	// the first refill settles without a crash, which leaves the shard at its target
	r := s.waitRefill("SOL", "requested", 90*time.Second)
	s.refillCeremony(k, r.ID)
	s.waitRefill("SOL", "confirmed", 120*time.Second)
	s.reconcileClean("after the first refill")

	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("failed at %s", current)
			s.dump()
		}
	})
	for i, p := range []string{"after_send", "after_record", "after_confirm", "after_settle"} {
		fp := "refill." + p
		current = fp
		before := s.shardBalance(0, "SOL")
		coldBefore := s.coldBalance("SOL")
		done := len(s.refills())
		// the shard is made to want 3 SOL more: its low-water mark moves above it and its target 3 SOL up
		s.reconfigure(setSOLBand(before+oneSOL, 1_000*oneSOL, before+3*oneSOL), fp)
		var id string
		s.waitFor(90*time.Second, "refill "+fp+" to be requested", func() bool {
			rs := s.refills()
			if len(rs) > done && rs[len(rs)-1].Status == "requested" {
				id = rs[len(rs)-1].ID
				return true
			}
			return false
		})
		s.refillCeremony(k, id)
		if code, ok := exitCodeOf(s.worker, scale(120*time.Second)); !ok || code != 137 {
			t.Fatalf("%s: the worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		s.reconcileClean("worker dead at " + fp)
		s.startWorker("")
		s.waitFor(120*time.Second, fp+": the refill to confirm", func() bool {
			for _, x := range s.refills() {
				if x.ID == id {
					return x.Status == "confirmed"
				}
			}
			return false
		})
		moved := coldBefore - s.coldBalance("SOL")
		if got := s.shardBalance(0, "SOL") - before; got != moved || moved < 2*oneSOL || moved > 3*oneSOL+oneSOL/2 {
			t.Fatalf("%s: the cold address paid %d lamports and the shard gained %d: one payment, to the shard, was expected", fp, moved, got)
		}
		for _, like := range []string{"rf-bcast:" + id, "rf-hot:" + id} {
			if n := s.ledgerEntries(like); n != 1 {
				t.Fatalf("%s: %d ledger entries %s, want 1", fp, n, like)
			}
		}
		s.reconcileClean("after " + fp)
		t.Logf("crash %-20s ok: one payment of %d lamports, Reconcile clean (round %d)", fp, moved, i)
	}
}

// Crash at every boundary of a move to cold and of a rebalance.
func TestColdCrash(t *testing.T) {
	s := newWdSystem(t, wdOpts{
		pool: 4, shards: 2,
		seedSOL: []uint64{60 * oneSOL, 6 * oneSOL}, seedTKN: []uint64{0, 0},
		cold: map[string]coldBand{
			"SOL": {low: fmt.Sprint(oneSOL), high: fmt.Sprint(1000 * oneSOL), target: fmt.Sprint(500 * oneSOL)},
			"TKN": {low: "0", high: fmt.Sprint(1_000_000 * tknUnit), target: fmt.Sprint(500_000 * tknUnit)},
		},
	})
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("failed at %s", current)
			s.dump()
		}
	})
	s.reconcileClean("start")
	points := []string{"after_build", "after_job", "after_broadcast", "after_confirm", "after_settle"}

	// moves to cold: the high-water mark is lowered under the shard, which then sends the excess to the cold address
	for i, p := range points {
		fp := "to-cold." + p
		current = fp
		bal, cold, done := s.shardBalance(0, "SOL"), s.coldBalance("SOL"), s.movesDone("cold_moves")
		s.reconfigure(setSOLBand(oneSOL, bal-2*oneSOL, bal-5*oneSOL), fp)
		if code, ok := exitCodeOf(s.worker, scale(150*time.Second)); !ok || code != 137 {
			t.Fatalf("%s: the worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		s.reconcileClean("worker dead at " + fp)
		s.reconfigure(nil, "")
		s.waitFor(150*time.Second, fp+": the move to settle", func() bool { return s.openMoves() == 0 && s.movesDone("cold_moves") == done+1 })
		gain := s.coldBalance("SOL") - cold
		if lost := bal - s.shardBalance(0, "SOL"); gain < 2*oneSOL || gain > 3*oneSOL+oneSOL/2 || lost < gain || lost-gain > 100_000 {
			t.Fatalf("%s: the cold address gained %d and the shard lost %d: one move was expected", fp, gain, lost)
		}
		s.reconcileClean("after " + fp)
		t.Logf("crash %-22s ok: one move of %d lamports (round %d)", fp, gain, i)
	}

	// rebalances: shard 1 is given a higher target, shard 0 feeds it
	s.reconfigure(setSOLBand(oneSOL, 1000*oneSOL, 500*oneSOL), "")
	for i, p := range points {
		fp := "rebal." + p
		current = fp
		b0, b1, done := s.shardBalance(0, "SOL"), s.shardBalance(1, "SOL"), s.movesDone("rebalance_moves")
		s.reconfigure(func(cf *custody.File) {
			cf.Cold.Rebalance.Targets = map[string]string{"SOL": fmt.Sprint(b1 + 2*oneSOL)}
		}, fp)
		if code, ok := exitCodeOf(s.worker, scale(150*time.Second)); !ok || code != 137 {
			t.Fatalf("%s: the worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		s.reconcileClean("worker dead at " + fp)
		s.reconfigure(nil, "")
		s.waitFor(150*time.Second, fp+": the rebalance to settle", func() bool { return s.openMoves() == 0 && s.movesDone("rebalance_moves") == done+1 })
		gain, lost := s.shardBalance(1, "SOL")-b1, b0-s.shardBalance(0, "SOL")
		if gain < oneSOL || gain > 2*oneSOL+oneSOL/2 || lost < gain || lost-gain > 100_000 {
			t.Fatalf("%s: shard 1 gained %d and shard 0 lost %d: one rebalance was expected", fp, gain, lost)
		}
		s.reconcileClean("after " + fp)
		t.Logf("crash %-22s ok: one rebalance of %d lamports (round %d)", fp, gain, i)
	}
}
