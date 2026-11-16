package btce2e

import (
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// Cancel escalation. A cancel (the same coins spent back to the hot wallet, built when one input of a withdrawal was refused after another was signed)
// raises its own fee like a send: a cancel the node refuses for the fee, or one that sits in the mempool, is followed by a cancel that pays strictly
// more than every accepted attempt and every refused cancel, within the same caps, across restarts. These tests use the fee proxy (rpcproxy_test.go)
// on real mpc-party, gateway and cosigner. The fee rate is the fallback of 1 sat/vB, so fees are small and grow by the replacement rule.

// brokenWithdrawal starts a withdrawal of two inputs whose second job the gateway refuses (so a signature exists and a cancel is needed).
func (s *system) brokenWithdrawal() (w wd, dest string) {
	s.fundHot(5_000_000)
	s.fundHot(5_000_000)
	s.deposit("c1", 20_000_000)
	s.breakSecondJob()
	dest = s.node.fresh()
	w = s.withdraw("ini", "k1", "c1", dest, 7_000_000)
	return w, dest
}

// sendFee is what the withdrawal's own (never broadcast) transaction pays: the live fee a cancel has to beat at least.
func (s *system) sendFee() int64 {
	var f int64
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(max(fee),0) FROM btc_attempts WHERE chain=$1 AND kind='send'`, s.chain).Scan(&f); err != nil {
		s.t.Fatal(err)
	}
	return f
}

// cancelsEscalate checks the property on the proxy's record: every cancel offered pays more than the highest refused one before it and more than the send.
func cancelsEscalate(t *testing.T, sends []proxySend, sendFee int64) {
	t.Helper()
	var top int64
	seen := map[string]bool{}
	for i, o := range sends {
		if o.Verdict == "known" || seen[o.Txid] {
			continue // the same transaction offered again (the first attempt is sent again when the node forgot it)
		}
		seen[o.Txid] = true
		if o.Fee <= sendFee || o.Fee <= top {
			t.Fatalf("offer %d pays %d: not above the send (%d) and the highest refused cancel (%d): %+v", i, o.Fee, sendFee, top, sends)
		}
		if o.Verdict == "fee" || o.Verdict == "node" {
			top = max(top, o.Fee)
		}
	}
}

func (s *system) assertVoidedOnce(w wd, dest string) {
	s.t.Helper()
	got := s.waitWd(w.ID, "failed", 90*time.Second)
	if !strings.Contains(got.Reason, "gateway refused") {
		s.t.Fatalf("reason %q", got.Reason)
	}
	if a := s.available("c1").Int64(); a != 20_000_000 {
		s.t.Fatalf("customer has %d after the void: the hold must be released once", a)
	}
	if got := s.received(dest, 0); got != 0 {
		s.t.Fatalf("the destination received %d", got)
	}
	if s.attempts("send") != 0 || s.utxoCount("reserved") != 0 {
		s.t.Fatalf("%d sends broadcast, %d outputs reserved", s.attempts("send"), s.utxoCount("reserved"))
	}
	s.ledgerOK()
	s.reconcileClean()
}

// A cancel the node refuses for the fee twice: each next cancel pays more than the last refused one and than the send, the core and the worker are
// restarted in between and it still holds, the node takes one above its minimum, and the withdrawal is voided once with holds released, Reconcile clean.
func TestRecoveryCancelRefusedForTheFeeEscalatesAcrossARestart(t *testing.T) {
	px := newFeeProxy(t)
	s := newSystem(t, opts{withdraw: true, proxy: px, fallbackRate: 1, stuckAfter: "2s"})
	px.setMin(100_000) // refuses every cancel until lowered
	w, dest := s.brokenWithdrawal()
	s.waitFor(120*time.Second, "two cancel refusals", func() bool { return len(px.feesWith("fee")) >= 2 })
	s.core.stop()
	s.restartWorker()
	s.startCore()
	s.waitFor(180*time.Second, "four cancel refusals", func() bool { return len(px.feesWith("fee")) >= 4 })
	refused := px.feesWith("fee")
	px.setMin(refused[len(refused)-1] + 1) // the next cancel is above every refused fee and so above this minimum
	s.waitFor(180*time.Second, "the node takes a cancel", func() bool { return len(px.feesWith("taken")) >= 1 })
	cancelsEscalate(t, px.offered(), s.sendFee())
	if n := s.attempts("send"); n != 0 {
		t.Fatalf("a send was broadcast (%d): the cancel track must not bump the send", n)
	}
	s.node.mine(2, "")
	s.assertVoidedOnce(w, dest)
	taken := px.feesWith("taken")
	if got := int64(-10_000_000) + taken[len(taken)-1]; s.hotPosted().Int64() != got {
		t.Fatalf("hot mirror %d, want %d (the confirmed cancel's fee is the only cost)", s.hotPosted().Int64(), got)
	}
	if n := s.workerLogCount("replacements exhausted"); n != 0 {
		t.Fatalf("refused cancels were counted against max_replacements (%d)", n)
	}
}

// A cancel the node took but that is not mined is replaced by a higher cancel until one confirms; the send is never bumped.
func TestRecoveryStuckCancelIsReplacedByAHigherCancel(t *testing.T) {
	px := newFeeProxy(t)
	s := newSystem(t, opts{withdraw: true, proxy: px, fallbackRate: 1, stuckAfter: "2s"})
	w, dest := s.brokenWithdrawal()
	s.waitAttempts("cancel", 3, 150*time.Second) // nothing is mined: each is replaced by the next
	cancelsEscalate(t, px.offered(), s.sendFee())
	if n := s.attempts("send"); n != 0 {
		t.Fatalf("%d sends broadcast", n)
	}
	s.node.mine(2, "")
	s.assertVoidedOnce(w, dest)
	last := s.lastAttempt("cancel")
	if got := s.hotPosted().Int64(); got != -10_000_000+s.attemptFee(last) {
		t.Fatalf("hot mirror %d, want the fee of the cancel that confirmed (%d)", got, s.attemptFee(last))
	}
}

// A node that asks for more than the fee cap allows: the cancel stops at the cap with one ALERT, never above it, the withdrawal is not voided and the
// money stays held; once the node's minimum falls, the cancel goes through.
func TestRecoveryCancelRefusedAboveTheCapAlertsOnceAndGoesThroughWhenTheMinimumFalls(t *testing.T) {
	px := newFeeProxy(t)
	s := newSystem(t, opts{withdraw: true, proxy: px, fallbackRate: 1, stuckAfter: "2s", maxFeeRate: 4})
	// The cap of the cancel (two inputs, one output) is max_fee_rate x its size; it was a fixed 700 sats before (a valid config keeps the total cap at
	// or above the rate ceiling for the largest transaction, so the rate is what binds).
	cancelTx := wire.NewMsgTx(2)
	cancelTx.AddTxIn(&wire.TxIn{})
	cancelTx.AddTxIn(&wire.TxIn{})
	script, _ := btc.OutputScript(s.hotAddr, s.acct.Params)
	cancelTx.AddTxOut(wire.NewTxOut(1, script))
	cap := 4 * btc.EstimateVSize(cancelTx)
	px.setMin(10_000)
	w, dest := s.brokenWithdrawal()
	s.waitFor(150*time.Second, "the ALERT at the cap", func() bool { return s.workerLogCount("cannot be replaced") >= 1 })
	s.holds(15*time.Second, "waiting at the cap: nothing voided, one ALERT, the money held", func() bool {
		return s.getWd(w.ID).Status != "failed" && s.workerLogCount("cannot be replaced") == 1 && s.available("c1").Int64() == 13_000_000
	})
	for _, o := range px.offered() {
		if o.Fee > cap {
			t.Fatalf("a fee of %d is above the cap of %d", o.Fee, cap)
		}
	}
	cancelsEscalate(t, px.offered(), s.sendFee())
	px.setMin(1) // the market falls: refusals made in the old one are forgotten, a cancel under the cap goes through
	s.waitFor(180*time.Second, "the node takes a cancel", func() bool { return len(px.feesWith("taken")) >= 1 })
	for _, o := range px.offered() {
		if o.Fee > cap {
			t.Fatalf("a fee of %d is above the cap of %d", o.Fee, cap)
		}
	}
	s.node.mine(2, "")
	s.assertVoidedOnce(w, dest)
}

// A refusal that a higher fee does not cure: the cancel is built again as it was, one ALERT says so, the withdrawal waits (money held, not voided),
// and the cancel confirms when the node takes one.
func TestRecoveryCancelNonFeeRefusalDoesNotEscalate(t *testing.T) {
	px := newFeeProxy(t)
	s := newSystem(t, opts{withdraw: true, proxy: px, fallbackRate: 1, stuckAfter: "2s"})
	px.setOther("too-long-mempool-chain, too many unconfirmed ancestors [limit: 25]")
	w, dest := s.brokenWithdrawal()
	s.waitFor(150*time.Second, "three refusals", func() bool { return len(px.feesWith("other")) >= 3 })
	s.waitFor(30*time.Second, "the ALERT", func() bool { return s.workerLogCount("does not cure") >= 1 })
	if n := s.workerLogCount("does not cure"); n != 1 {
		t.Fatalf("%d ALERTs, want one", n)
	}
	refused := px.feesWith("other")
	refused = refused[1:] // the first cancel stays as the owner's first attempt (stuck, not forgotten); the replacements after it are the refused ones
	for _, f := range refused {
		if f != refused[0] || f <= s.sendFee() {
			t.Fatalf("refused fees %v: a refusal that is not about the fee must not change the fee (above the send's %d)", refused, s.sendFee())
		}
	}
	if got := s.getWd(w.ID).Status; got == "failed" {
		t.Fatalf("the withdrawal is %s: it waits for the cancel", got)
	}
	px.setOther("")
	s.waitFor(120*time.Second, "the node takes a cancel", func() bool { return len(px.feesWith("taken")) >= 1 })
	s.node.mine(2, "")
	s.assertVoidedOnce(w, dest)
}
