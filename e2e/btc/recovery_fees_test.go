package btce2e

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Fee escalation. A replacement the node refuses for a fee that is too low must not be built again at the same fee: the next one pays more than the
// highest refused one, up to the caps, across restarts. These tests make a real regtest node refuse transactions below a minimum fee (feeProxy:
// the node's own message, and a mempool minimum fee that the system can see), on real mpc-party, gateway and cosigner.
//
// The fee rate is the fallback of 1 sat/vB (the proxy hides the node's estimate), so a replacement pays the old fee plus its size at 1 sat/vB
// (BIP125 rules 3 and 4): the first attempt pays f0, and the following ones pay 2 x f0, 3 x f0, 4 x f0 and so on.

func (s *system) workerLogCount(sub string) int {
	b, err := os.ReadFile(s.worker.log)
	if err != nil {
		s.t.Fatal(err)
	}
	return strings.Count(string(b), sub)
}

// feesWith lists the fees of the transactions the proxy gave verdict, in order.
func (p *feeProxy) feesWith(verdict string) []int64 {
	var out []int64
	for _, s := range p.offered() {
		if s.Verdict == verdict {
			out = append(out, s.Fee)
		}
	}
	return out
}

// firstFee waits for the first transaction the node took and returns what it paid.
func (s *system) firstFee(p *feeProxy) int64 {
	s.t.Helper()
	var f int64
	s.waitFor(90*time.Second, "the first transaction is taken by the node", func() bool {
		for _, o := range p.offered() {
			if o.Verdict == "taken" {
				f = o.Fee
				return true
			}
		}
		return false
	})
	return f
}

// strictlyAbove checks the property of the design on the proxy's record: every transaction offered after a refusal for the fee paid more than the
// highest fee refused before it.
func strictlyAbove(t *testing.T, sends []proxySend) {
	t.Helper()
	var top int64
	for i, o := range sends {
		if o.Verdict == "known" {
			continue // the same transaction offered again
		}
		if o.Fee <= top {
			t.Fatalf("offer %d pays %d, not more than the highest refused fee %d: %+v", i, o.Fee, top, sends)
		}
		if o.Verdict == "fee" || o.Verdict == "node" {
			top = max(top, o.Fee)
		}
	}
}

func (s *system) stuckWithdrawal(p *feeProxy) (w wd, dest string) {
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	dest = s.node.fresh()
	w = s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitWd(w.ID, "broadcast", 60*time.Second)
	return w, dest
}

// A stuck withdrawal whose bumps the node refuses for the fee gets out: each attempt pays more than the last refused one, six refusals (more than
// max_replacements, which counts replacements the node took) are survived, the core and the worker are restarted in the middle and the next attempt still pays
// more than the highest refused fee, the node takes one above its minimum, and the withdrawal settles once with that transaction's fee booked.
func TestRecoveryFeeRefusedBumpsEscalateAcrossARestartAndPastMaxReplacements(t *testing.T) {
	px := newFeeProxy(t)
	s := newSystem(t, opts{withdraw: true, proxy: px, fallbackRate: 1, stuckAfter: "4s"})
	w, dest := s.stuckWithdrawal(px)
	f0 := s.firstFee(px)
	px.setMin(f0*15/2 + 1) // 7.5 x f0: refuses 2, 3, 4, 5, 6 and 7 x f0, takes 8 x f0
	s.waitFor(120*time.Second, "two refusals", func() bool { return len(px.feesWith("fee")) >= 2 })
	before := px.feesWith("fee")
	s.core.stop()
	s.restartWorker()
	s.startCore()
	s.waitFor(240*time.Second, "the node takes a replacement", func() bool {
		for _, o := range px.offered() {
			if o.Verdict == "taken" && o.Fee > f0 {
				return true
			}
		}
		return false
	})
	refused := px.feesWith("fee")
	if len(refused) < 6 {
		t.Fatalf("%d refusals: %v (the design needs more than max_replacements = 5 of them to show they are not counted)", len(refused), refused)
	}
	for i := 1; i < len(refused); i++ {
		if refused[i] <= refused[i-1] {
			t.Fatalf("refused fees %v: each attempt must pay more than the last refused one", refused)
		}
	}
	strictlyAbove(t, px.offered())
	for _, o := range px.offered() {
		if o.Fee > 50_000 || o.Fee > 50*f0 { // max_tx_fee_sats, and max_fee_rate 50 sat/vB: f0 is the size of the transaction at 1 sat/vB
			t.Fatalf("a fee of %d is above the caps", o.Fee)
		}
		if o.Verdict == "taken" && o.Fee > f0 && o.Fee <= before[len(before)-1] {
			t.Fatalf("the node took %d, not above the highest refused fee %d before the restart", o.Fee, before[len(before)-1])
		}
	}
	if n := s.workerLogCount("replacements exhausted"); n != 0 {
		t.Fatalf("refused replacements were counted against max_replacements (%d)", n)
	}
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	taken := px.feesWith("taken")
	last := taken[len(taken)-1]
	if got := s.withdrawalFee(w.ID); got != last {
		t.Fatalf("booked fee %d, the confirmed transaction paid %d", got, last)
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+10_000_000+last {
		t.Fatalf("hot mirror %d", got)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// The caps are the limit: a node that wants more than the fee cap allows makes the system stop at the cap with one ALERT, never above it, and nothing
// is voided; once the node's minimum falls, the refusals made in the old market are forgotten, a fee under the cap goes through, and the withdrawal
// settles.
func TestRecoveryFeeRefusedAboveTheCapAlertsOnceAndRetriesWhenTheMinimumFalls(t *testing.T) {
	px := newFeeProxy(t)
	const cap = 450 // sats: 3 x 141 fits, 4 x 141 does not
	s := newSystem(t, opts{withdraw: true, proxy: px, fallbackRate: 1, stuckAfter: "4s", maxTxFee: cap})
	w, dest := s.stuckWithdrawal(px)
	f0 := s.firstFee(px)
	if 3*f0 > cap || 4*f0 <= cap {
		t.Fatalf("the first attempt pays %d: the cap of %d is meant to fit three times that and not four", f0, cap)
	}
	px.setMin(1000) // far above the cap
	s.waitFor(120*time.Second, "the ALERT at the cap", func() bool { return s.workerLogCount("cannot be replaced") >= 1 })
	s.holds(15*time.Second, "waiting at the cap: nothing voided, one ALERT, no fee above the cap", func() bool {
		return s.getWd(w.ID).Status == "broadcast" && s.workerLogCount("cannot be replaced") == 1
	})
	refused := px.feesWith("fee")
	if len(refused) != 2 || refused[1] <= refused[0] || refused[1] > cap {
		t.Fatalf("refused %v: want two increasing fees, then nothing above the cap of %d", refused, cap)
	}
	for _, o := range px.offered() {
		if o.Fee > cap {
			t.Fatalf("a fee of %d is above the cap of %d", o.Fee, cap)
		}
	}
	// The node's minimum falls to 2.5 x f0: what was refused in the old market is forgotten, the next replacement is built from the accepted
	// transaction again (2 x f0, refused once more), then 3 x f0 passes, under the cap.
	px.setMin(f0 * 5 / 2)
	s.waitFor(120*time.Second, "the node takes a replacement", func() bool {
		for _, o := range px.offered() {
			if o.Verdict == "taken" && o.Fee > f0 {
				return true
			}
		}
		return false
	})
	for _, o := range px.offered() {
		if o.Fee > cap {
			t.Fatalf("a fee of %d is above the cap of %d", o.Fee, cap)
		}
	}
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// A consolidation is held to its own ceiling (consolidate_max_fee_rate) the same way: refused for the fee up to the ceiling, one ALERT, never above,
// not cancelled or voided; and it goes through once the minimum falls.
func TestRecoveryFeeRefusedConsolidationStopsAtItsCeilingAndRetries(t *testing.T) {
	px := newFeeProxy(t)
	s := consolidateSystem(t, opts{consolidateAbove: 6, consolidateMaxRate: 3, fallbackRate: 1, stuckAfter: "4s", proxy: px})
	s.fundHotOutputs(repeat(100_000, 7)...)
	f0 := s.firstFee(px) // 1 sat/vB: the size of the transaction in satoshis
	px.setMin(10 * f0)
	s.waitFor(120*time.Second, "the ALERT at the ceiling", func() bool { return s.workerLogCount("cannot be replaced") >= 1 })
	s.holds(15*time.Second, "waiting at the ceiling: one ALERT, the consolidation is neither failed nor cancelled", func() bool {
		cs := s.consolidations()
		return len(cs) == 1 && cs[0].Status == "broadcast" && s.workerLogCount("cannot be replaced") == 1 && s.attempts("cancel") == 0
	})
	refused := px.feesWith("fee")
	ceiling := 3*f0 + 3 // 3 sat/vB of the transaction, which the builder sizes a byte or two differently from the first attempt's estimate
	if len(refused) != 2 || refused[1] <= refused[0] || refused[1] > ceiling {
		t.Fatalf("refused %v: want two increasing fees, then nothing above the ceiling of 3 sat/vB (%d)", refused, ceiling)
	}
	for _, o := range px.offered() {
		if o.Fee > ceiling {
			t.Fatalf("a fee of %d is above the ceiling of %d", o.Fee, ceiling)
		}
	}
	px.setMin(f0 * 5 / 2)
	s.waitFor(120*time.Second, "the node takes a replacement", func() bool { // before any block: the original must not be the one that is mined
		for _, o := range px.offered() {
			if o.Verdict == "taken" && o.Fee > f0 {
				return true
			}
		}
		return false
	})
	s.untilConsolidations(1, 180*time.Second)
	c := s.consolidations()[0]
	taken := px.feesWith("taken")
	if last := taken[len(taken)-1]; c.Fee != last || c.Fee > ceiling || c.Fee <= f0 {
		t.Fatalf("consolidation %+v: want the fee of the transaction the node took last (%d), above the first (%d) and under the ceiling (%d)", c, last, f0, ceiling)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// A refusal that a higher fee does not cure does not raise the fee: the same replacement is built again, one ALERT says so, the withdrawal waits and
// is not voided, and it settles when the node takes a transaction.
func TestRecoveryNonFeeRefusalDoesNotEscalate(t *testing.T) {
	px := newFeeProxy(t)
	s := newSystem(t, opts{withdraw: true, proxy: px, fallbackRate: 1, stuckAfter: "4s"})
	w, dest := s.stuckWithdrawal(px)
	f0 := s.firstFee(px)
	px.setOther("too-long-mempool-chain, too many unconfirmed ancestors [limit: 25]")
	s.waitFor(120*time.Second, "three refusals", func() bool { return len(px.feesWith("other")) >= 3 })
	s.waitFor(30*time.Second, "the ALERT", func() bool { return s.workerLogCount("does not cure") >= 1 })
	if n := s.workerLogCount("does not cure"); n != 1 {
		t.Fatalf("%d ALERTs, want one", n)
	}
	for _, f := range px.feesWith("other") {
		if f != px.feesWith("other")[0] || f <= f0 {
			t.Fatalf("refused fees %v: a refusal that is not about the fee must not change the fee (the same replacement every time, above %d)", px.feesWith("other"), f0)
		}
	}
	if got := s.getWd(w.ID).Status; got != "broadcast" {
		t.Fatalf("the withdrawal is %s: it waits", got)
	}
	px.setOther("")
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	s.ledgerOK()
	s.reconcileClean()
}
