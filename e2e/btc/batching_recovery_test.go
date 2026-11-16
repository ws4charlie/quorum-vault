package btce2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A batch is bumped as a whole: the same inputs, the same payments, less change. With a fee rate ceiling of 2 sat/vB and a start at 1, one replacement
// reaches the cap exactly; a second is not built (one alert), and the replacement confirms: the fee booked is the replacement's and the shares add up to it.
func TestBatchRecoveryBumpedToTheCap(t *testing.T) {
	s := batchSystem(t, opts{noEstimate: true, fallbackRate: 1, stuckAfter: "5s", maxFeeRate: 2}, batchingOpts{outputs: 3, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000), s.payQ(7_000_000)}
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	orig, _ := s.firstAttempt("send")
	s.waitAttempts("send", 2, 60*time.Second)
	repl := s.lastAttempt("send")
	fo, fr := s.attemptFee(orig), s.attemptFee(repl)
	if fr != 2*fo {
		t.Fatalf("the replacement pays %d, the original %d: want the cap, twice the original at 1 sat/vB", fr, fo)
	}
	po, pr := s.payloadOf(orig), s.payloadOf(repl)
	if len(pr.Inputs) != len(po.Inputs) || len(pr.Outputs) != 4 {
		t.Fatalf("inputs %d/%d outputs %d", len(po.Inputs), len(pr.Inputs), len(pr.Outputs))
	}
	for i := range po.Inputs {
		if po.Inputs[i].TxID != pr.Inputs[i].TxID || po.Inputs[i].Vout != pr.Inputs[i].Vout || po.Inputs[i].Value != pr.Inputs[i].Value {
			t.Fatal("the replacement spends other inputs")
		}
	}
	for i := 0; i < 3; i++ {
		if po.Outputs[i] != pr.Outputs[i] {
			t.Fatalf("payment %d changed: %+v then %+v", i, po.Outputs[i], pr.Outputs[i])
		}
	}
	if po.Outputs[3].Value-pr.Outputs[3].Value != uint64(fr-fo) {
		t.Fatalf("the change fell by %d, the fee rose by %d", po.Outputs[3].Value-pr.Outputs[3].Value, fr-fo)
	}
	s.holds(8*time.Second, "no replacement beyond the cap", func() bool { return s.attempts("send") == 2 })
	if !s.workerLogHas("transaction is stuck and cannot be replaced") {
		t.Fatal("no ALERT that the batch cannot be bumped further")
	}
	got := s.mineBatch(b.ID)
	if got.Fee != fr {
		t.Fatalf("booked fee %d, the confirmed replacement paid %d", got.Fee, fr)
	}
	s.assertBooked(got, ws...)
	s.ledgerOK()
}

// Any attempt may be the one that confirms: here the original does, after a replacement was built. The books use the original's fee and its outputs.
func TestBatchRecoveryAnEarlierAttemptConfirms(t *testing.T) {
	s := batchSystem(t, opts{noEstimate: true, fallbackRate: 1, stuckAfter: "5s"}, batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	orig, rawOrig := s.firstAttempt("send")
	s.waitAttempts("send", 2, 60*time.Second)
	repl := s.lastAttempt("send")
	if repl == orig {
		t.Fatal("no replacement")
	}
	var out any
	if err := s.node.root.Call(s.ctx, &out, "generateblock", s.node.fresh(), []string{fmt.Sprintf("%x", rawOrig)}); err != nil {
		t.Fatalf("a block with the original: %v", err)
	}
	s.node.mine(1, s.node.fresh())
	got := s.untilBatches("confirmed", 1, 90*time.Second)[0]
	if got.ID != b.ID || got.Tx != orig || got.Fee != s.attemptFee(orig) {
		t.Fatalf("batch %+v, want the original %s at fee %d", got, orig, s.attemptFee(orig))
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2`, s.chain, repl); n != 0 {
		t.Fatal("the replacement's change was recorded though it never confirmed")
	}
	s.assertBooked(got, ws...)
	s.ledgerOK()
}

// One withdrawal can be cancelled while it waits in the queue and while its batch is not signed (the unsigned batch is discarded, its coins released, the
// others return in the same order); once the batch is signed the cancel of one withdrawal is refused.
func TestBatchRecoveryCancelOneWithdrawalAtEachMoment(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	// 1. In the queue: it leaves, its hold goes, nobody else is touched.
	w1 := s.payQ(2_000_000)
	s.waitFor(30*time.Second, "w1 is queued", func() bool { return s.wdRow(w1.ID).Queued })
	if code, out := s.reject(w1.ID, "changed my mind"); code != http.StatusOK {
		t.Fatalf("cancel in the queue: %d %v", code, out)
	}
	if r := s.wdRow(w1.ID); r.Status != "failed" || !strings.Contains(r.Reason, "cancelled") {
		t.Fatalf("w1 %+v", r)
	}
	if a := s.available("c1").Int64(); a != batchDeposit {
		t.Fatalf("the customer has %d, the hold of the cancelled withdrawal should be released", a)
	}

	// 2. Sealed, built, not signed (the signing gateway is down): the batch is discarded, its coins released, the other member back in the queue.
	s.gateway.stop()
	w2, w3 := s.payQ(2_100_000), s.payQ(2_200_000)
	b := s.untilBatches("signing", 1, 90*time.Second)[0]
	if s.utxoCount("reserved") == 0 {
		t.Fatal("the built batch holds no coins")
	}
	if code, out := s.reject(w2.ID, "wrong address"); code != http.StatusOK {
		t.Fatalf("cancel of an unsigned batch's member: %d %v", code, out)
	}
	if got := s.batchesIn("discarded"); len(got) != 1 || got[0].ID != b.ID {
		t.Fatalf("batches %+v", s.batchRows())
	}
	if s.utxoCount("reserved") != 0 || s.utxoCount("available") != 1 {
		t.Fatalf("coins not released: reserved %d available %d", s.utxoCount("reserved"), s.utxoCount("available"))
	}
	if r := s.wdRow(w3.ID); r.Batch != "" || r.Status != "approved" || !r.Queued {
		t.Fatalf("w3 %+v: it should wait in the queue again", r)
	}
	if r := s.wdRow(w2.ID); r.Status != "failed" {
		t.Fatalf("w2 %+v", r)
	}

	// 3. The gateway is back; w4 fills the batch with w3 (first in, first out); once it is broadcast one withdrawal cannot be cancelled alone.
	s.startGateway()
	w4 := s.payQ(2_300_000)
	b2 := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	if len(b2.Members) != 2 || b2.Members[0] != w3.ID || b2.Members[1] != w4.ID {
		t.Fatalf("members %v, want w3 then w4", b2.Members)
	}
	if code, out := s.reject(w3.ID, "too late"); code != http.StatusConflict {
		t.Fatalf("cancel of one withdrawal of a broadcast batch: %d %v, want 409", code, out)
	}
	s.assertBooked(s.mineBatch(b2.ID), w3, w4)
	if got := s.received(w2.dest, 0); got != 0 {
		t.Fatalf("the cancelled withdrawal was paid %d", got)
	}
	s.ledgerOK()
}

// The whole batch is cancelled after broadcast: the same coins go back to the shard with a cancel; when it confirms the members return to the queue at
// their place and a new batch that spends the cancel's output (the signing zone insists) pays each of them once. The first batch never confirms.
func TestBatchRecoveryCancelTheWholeBatchAndTheSurvivorsAreSentOnce(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
	b1 := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	if code, out := s.reject(ws[0].ID, "x"); code != http.StatusConflict {
		t.Fatalf("one withdrawal of a broadcast batch: %d %v", code, out)
	}
	if code, out := s.cancelBatch(b1.ID); code != http.StatusAccepted {
		t.Fatalf("cancel the batch: %d %v", code, out)
	}
	s.waitAttempts("cancel", 1, 90*time.Second)
	s.node.mine(2, "")
	got := s.untilBatches("cancelled", 1, 90*time.Second)[0]
	if got.ID != b1.ID || got.Cancel == "" {
		t.Fatalf("batch %+v", got)
	}
	for _, w := range ws {
		if r := s.wdRow(w.ID); r.Status == "failed" || r.Status == "confirmed" {
			t.Fatalf("withdrawal %s is %+v: it should be waiting for the next batch", w.ID, r)
		}
	}
	b2 := s.untilBatches("broadcast", 1, 120*time.Second)[0]
	if b2.ID == b1.ID || len(b2.Members) != 2 || b2.Members[0] != ws[0].ID || b2.Members[1] != ws[1].ID {
		t.Fatalf("the new batch %+v: same members, same order", b2)
	}
	if !s.hasInput(s.payloadOf(b2.Tx), got.Cancel) {
		t.Fatal("the new batch does not spend the cancel's output")
	}
	b2 = s.mineBatch(b2.ID)
	s.assertBooked(b2, ws...)
	var x struct{ Txid string }
	if err := s.node.root.Call(s.ctx, &x, "getrawtransaction", b1.Tx, true); err == nil {
		t.Fatal("the cancelled batch's transaction is known to the node")
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+11_000_000+got0(s, b1.ID)+b2.Fee {
		t.Fatalf("hot mirror %d: the funding, the payments, the cancel's fee and the new batch's fee", got)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// got0 is the fee the cancel of a batch paid (kept in the batch row).
func got0(s *system, id string) int64 {
	var f int64
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(fee,0)::bigint FROM btc_batches WHERE id=$1`, id).Scan(&f); err != nil {
		s.t.Fatal(err)
	}
	return f
}

// A cancel that races the broadcast: the worker dies when the batch is signed and not yet broadcast, an operator cancels, the worker comes back. The batch is
// sent and at once replaced by its cancel; whichever way the race goes, the members are paid exactly once.
func TestBatchRecoveryCancelRacesTheBroadcast(t *testing.T) {
	s := batchSystem(t, opts{failpoint: "batch.after_job"}, batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
	b := s.untilBatches("signing", 1, 90*time.Second)[0]
	s.waitExit(s.worker, "the worker after the batch was signed")
	if code, out := s.cancelBatch(b.ID); code != http.StatusAccepted {
		t.Fatalf("cancel the batch: %d %v", code, out)
	}
	s.restartWorker()
	s.waitAttempts("cancel", 1, 120*time.Second)
	s.node.mine(2, "")
	s.untilBatches("cancelled", 1, 90*time.Second)
	b2 := s.untilBatches("broadcast", 1, 120*time.Second)[0]
	s.assertBooked(s.mineBatch(b2.ID), ws...)
	s.ledgerOK()
}

// The worker dies at every boundary of a batch (built, signed, sent, final, booked) and comes back: the members are paid once, the books balance.
func TestBatchRecoveryCrashAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		failpoint string
		mineFirst bool // the boundary comes after the transaction is final
	}{
		{"batch.after_build", false},
		{"batch.after_job", false},
		{"batch.after_broadcast", false},
		{"batch.after_confirm", true},
		{"batch.after_settle", true},
	} {
		t.Run(tc.failpoint, func(t *testing.T) {
			s := batchSystem(t, opts{failpoint: tc.failpoint}, batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
			ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
			if tc.mineFirst {
				s.untilBatches("broadcast", 1, 90*time.Second)
				s.node.mine(2, "")
			}
			s.waitExit(s.worker, "the worker at "+tc.failpoint)
			s.restartWorker()
			var id string
			if tc.mineFirst {
				id = s.untilBatches("confirmed", 1, 90*time.Second)[0].ID
			} else {
				id = s.untilBatches("broadcast", 1, 90*time.Second)[0].ID
			}
			b := s.mineBatch(id)
			s.assertBooked(b, ws...)
			if n := s.attempts("send"); n != 1 {
				t.Fatalf("%d send attempts", n)
			}
			if got := s.hotPosted().Int64(); got != -100_000_000+11_000_000+b.Fee {
				t.Fatalf("hot mirror %d", got)
			}
			s.ledgerOK()
		})
	}
}
