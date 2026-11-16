package btce2e

import (
	"strings"
	"testing"
	"time"
)

// A batch seals when max_outputs withdrawals are queued: one transaction pays all of them, in the order they were approved, each is booked once with its
// share of the fee, the shares add up to the fee the transaction paid, and the books balance.
func TestBatchSealsByCountAndBooksEveryMemberOnce(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 3, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000), s.payQ(7_000_000)}
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	if len(b.Members) != 3 {
		t.Fatalf("members %v", b.Members)
	}
	for i, w := range ws {
		if b.Members[i] != w.ID {
			t.Fatalf("payment order %v, requested %v %v %v", b.Members, ws[0].ID, ws[1].ID, ws[2].ID)
		}
	}
	if n := s.outputsOf(b.Tx); n != 4 {
		t.Fatalf("the transaction has %d outputs: three payments and a change", n)
	}
	b = s.mineBatch(b.ID)
	s.assertBooked(b, ws...)
	if n := s.attempts("send"); n != 1 {
		t.Fatalf("%d send attempts", n)
	}
	fee := b.Fee
	if got := s.hotPosted().Int64(); got != -100_000_000+18_000_000+fee {
		t.Fatalf("hot mirror %d, want %d", got, -100_000_000+18_000_000+fee)
	}
	if s.utxoCount("spent") != 1 || s.utxoCount("reserved") != 0 || s.utxoCount("available") != 1 {
		t.Fatalf("outputs: spent %d reserved %d available %d", s.utxoCount("spent"), s.utxoCount("reserved"), s.utxoCount("available"))
	}
	s.ledgerOK()
	s.reconcileClean()
}

// A batch seals when the oldest withdrawal has waited max_wait since its approval, not before.
func TestBatchSealsByAge(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 5, wait: "8s", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
	s.holds(3*time.Second, "no batch before max_wait", func() bool { return len(s.batchRows()) == 0 })
	b := s.untilBatches("broadcast", 1, 60*time.Second)[0]
	if len(b.Members) != 2 {
		t.Fatalf("members %v", b.Members)
	}
	var waited float64
	if err := s.pool.QueryRow(s.ctx, `SELECT EXTRACT(EPOCH FROM (b.sealed_at - w.queued_at)) FROM btc_batches b, withdrawals w WHERE b.id=$1 AND w.id=$2`, b.ID, ws[0].ID).Scan(&waited); err != nil {
		t.Fatal(err)
	}
	if waited < 7.5 {
		t.Fatalf("sealed %.1fs after the oldest was queued, max_wait is 8s", waited)
	}
	s.assertBooked(s.mineBatch(b.ID), ws...)
}

// Count and age together: the first two fill a batch at once, the third waits for its own age. With two batches in flight the second may seal while
// the first is unconfirmed (it spends other, confirmed coins).
func TestBatchSealsByCountThenByAge(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 2, wait: "8s", inFlight: 2}, 50_000_000, 50_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000), s.payQ(7_000_000)}
	bs := s.untilBatches("broadcast", 2, 90*time.Second)
	if len(bs[0].Members) != 2 || len(bs[1].Members) != 1 || bs[1].Members[0] != ws[2].ID {
		t.Fatalf("batches %+v", bs)
	}
	var first, third float64
	s.pool.QueryRow(s.ctx, `SELECT EXTRACT(EPOCH FROM (b.sealed_at - w.queued_at)) FROM btc_batches b, withdrawals w WHERE b.id=$1 AND w.id=$2`, bs[0].ID, ws[0].ID).Scan(&first)
	s.pool.QueryRow(s.ctx, `SELECT EXTRACT(EPOCH FROM (b.sealed_at - w.queued_at)) FROM btc_batches b, withdrawals w WHERE b.id=$1 AND w.id=$2`, bs[1].ID, ws[2].ID).Scan(&third)
	if first > 6 || third < 7.5 {
		t.Fatalf("the full batch sealed after %.1fs and the third withdrawal after %.1fs", first, third)
	}
	s.node.mine(2, "")
	s.untilBatches("confirmed", 2, 90*time.Second)
	got := s.batchRows()
	s.assertBooked(got[0], ws[0], ws[1])
	s.assertBooked(got[1], ws[2])
	s.ledgerOK()
}

// First in, first out: withdrawals approved at the same time are ordered by id, and a head that cannot be funded holds everyone behind it, however small.
func TestBatchFIFOWithEqualApprovalTimes(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 3, wait: "10m", inFlight: 1}, 100_000_000)
	a, b := s.payQ(1_000_000), s.payQ(1_100_000)
	for _, w := range []bw{a, b} {
		id := w.ID
		s.waitFor(60*time.Second, "withdrawal "+id+" is queued", func() bool { r := s.wdRow(id); return r.Queued && r.Status == "approved" })
	}
	if _, err := s.pool.Exec(s.ctx, `UPDATE withdrawals SET queued_at = date_trunc('second', now()) - interval '30 seconds' WHERE id = ANY($1)`, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	c := s.payQ(1_200_000) // the third fills the batch
	bt := s.untilBatches("broadcast", 1, 60*time.Second)[0]
	first, second := a.ID, b.ID
	if second < first {
		first, second = second, first
	}
	if len(bt.Members) != 3 || bt.Members[0] != first || bt.Members[1] != second || bt.Members[2] != c.ID {
		t.Fatalf("members %v, want %s %s then %s", bt.Members, first, second, c.ID)
	}
}

func TestBatchAnUnfundableHeadBlocksTheOnesBehindIt(t *testing.T) {
	// Twelve outputs of 1,000,000 and a transaction that takes two: the ledger holds enough for the head (10,000,000), the coins cannot carry it.
	s := batchSystem(t, opts{maxInputs: 2}, batchingOpts{outputs: 5, wait: "6s", inFlight: 1})
	vals := make([]int64, 12)
	for i := range vals {
		vals[i] = 1_000_000
	}
	s.fundHotOutputs(vals...)
	big, small := s.payQ(10_000_000), s.payQ(100_000)
	s.untilBatches("sealed", 1, 90*time.Second)
	s.holds(8*time.Second, "nothing is paid while the head cannot be funded", func() bool {
		return s.attempts("send") == 0 && s.utxoCount("reserved") == 0 && s.wdRow(small.ID).Status == "approved" && s.wdRow(big.ID).Status == "approved"
	})
	s.fundHot(30_000_000)
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	if len(b.Members) != 2 || b.Members[0] != big.ID || b.Members[1] != small.ID {
		t.Fatalf("members %v, want the big one first", b.Members)
	}
	s.assertBooked(s.mineBatch(b.ID), big, small)
}

// The prefix shrinks under max_inputs: a transaction takes two inputs, which fund two of the three members; the third goes back to the queue at its place
// and is paid by the next batch.
func TestBatchPrefixShrinksUnderMaxInputs(t *testing.T) {
	s := batchSystem(t, opts{maxInputs: 2}, batchingOpts{outputs: 3, wait: "10s", inFlight: 1}, 3_000_000, 3_000_000, 3_000_000)
	ws := []bw{s.payQ(2_500_000), s.payQ(2_500_000), s.payQ(2_500_000)}
	b1 := s.untilBatches("broadcast", 1, 60*time.Second)[0]
	if len(b1.Members) != 2 || b1.Members[0] != ws[0].ID || b1.Members[1] != ws[1].ID {
		t.Fatalf("first batch %v", b1.Members)
	}
	if r := s.wdRow(ws[2].ID); r.Batch != "" || r.Status != "approved" || !r.Queued {
		t.Fatalf("the third is %+v: it should be back in the queue", r)
	}
	s.assertBooked(s.mineBatch(b1.ID), ws[0], ws[1])
	b2 := s.untilBatches("broadcast", 1, 90*time.Second)[0] // the first is confirmed now
	if len(b2.Members) != 1 || b2.Members[0] != ws[2].ID {
		t.Fatalf("second batch %v", b2.Members)
	}
	s.assertBooked(s.mineBatch(b2.ID), ws[2])
}

// max_in_flight 2: two batches are signed and unconfirmed; the third waits until one confirms.
func TestBatchMaxInFlightHoldsTheThirdBatch(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 1, wait: "10m", inFlight: 2}, 20_000_000, 20_000_000, 20_000_000)
	ws := []bw{s.payQ(1_000_000), s.payQ(1_100_000), s.payQ(1_200_000)}
	s.untilBatches("broadcast", 2, 90*time.Second)
	s.holds(6*time.Second, "the third batch waits", func() bool {
		return len(s.batchRows()) == 2 && s.wdRow(ws[2].ID).Batch == ""
	})
	s.node.mine(2, "")
	s.untilBatches("confirmed", 2, 90*time.Second)
	s.untilBatches("broadcast", 1, 90*time.Second) // the third seals once a slot is free
	s.node.mine(2, "")
	s.untilBatches("confirmed", 3, 90*time.Second)
	for i, b := range s.batchRows() {
		s.assertBooked(b, ws[i])
	}
	s.ledgerOK()
}

// max_wait 0 is today's behaviour: no queue, one transaction per withdrawal, no batch.
func TestBatchMaxWaitZeroIsOneWithdrawalPerTransaction(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 3, wait: "0s", inFlight: 1}, 100_000_000)
	a, b := s.pay(5_000_000), s.pay(6_000_000)
	s.settle(a.ID)
	s.settle(b.ID)
	if n := len(s.batchRows()); n != 0 {
		t.Fatalf("%d batches", n)
	}
	if n := s.count(`SELECT count(*) FROM withdrawals WHERE queued_at IS NOT NULL`); n != 0 {
		t.Fatalf("%d queued withdrawals", n)
	}
	if n := s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND owner_kind='withdrawal'`, s.chain); n != 2 {
		t.Fatalf("%d withdrawal attempts", n)
	}
	if s.received(a.dest, 1) != 5_000_000 || s.received(b.dest, 1) != 6_000_000 {
		t.Fatal("the payments did not arrive")
	}
	s.ledgerOK()
}

// The core's destination rule is applied again when a batch is sealed: a withdrawal that fails it leaves the queue, parked with an alert, and the rest are paid.
func TestBatchRescreenRemovesAWithdrawalAtSealTime(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 3, wait: "10m", inFlight: 1}, 100_000_000)
	a, bad := s.payQ(5_000_000), s.payQ(6_000_000)
	if _, err := s.pool.Exec(s.ctx, `UPDATE withdrawals SET to_address='not-an-address' WHERE id=$1`, bad.ID); err != nil {
		t.Fatal(err)
	}
	c := s.payQ(7_000_000)
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	if len(b.Members) != 2 || b.Members[0] != a.ID || b.Members[1] != c.ID {
		t.Fatalf("members %v: the bad withdrawal should not be in it", b.Members)
	}
	r := s.wdRow(bad.ID)
	if !strings.HasPrefix(r.Reason, "parked:") || !strings.Contains(r.Reason, "destination check at seal time") {
		t.Fatalf("the bad withdrawal: %+v", r)
	}
	if !s.workerLogHas("failed the destination check when its batch was sealed") {
		t.Fatal("no ALERT in the worker log")
	}
	s.assertBooked(s.mineBatch(b.ID), a, c)
	if got := s.received(bad.dest, 0); got != 0 {
		t.Fatalf("the parked withdrawal was paid %d", got)
	}
}

// The signing zone has its own ceiling on a batch's payments, which the core cannot raise: a batch above it is refused, nothing is signed, its coins
// are released and its members return to the queue; after three refusals none of which names a withdrawal they are parked, with an alert.
func TestBatchRefusedByTheZoneIsDiscardedThenParked(t *testing.T) {
	s := batchSystem(t, opts{}, batchingOpts{outputs: 3, wait: "10m", inFlight: 1, zoneOutputs: 2}, 100_000_000)
	ws := []bw{s.payQ(1_000_000), s.payQ(1_100_000), s.payQ(1_200_000)}
	s.waitFor(120*time.Second, "all three withdrawals are parked", func() bool {
		for _, w := range ws {
			if !strings.HasPrefix(s.wdRow(w.ID).Reason, "parked:") {
				return false
			}
		}
		return true
	})
	if n := len(s.batchesIn("discarded")); n < 3 {
		t.Fatalf("%d discarded batches", n)
	}
	if s.attempts("send") != 0 || s.utxoCount("reserved") != 0 || s.utxoCount("available") != 1 {
		t.Fatalf("sends %d reserved %d available %d: nothing should have left the shard", s.attempts("send"), s.utxoCount("reserved"), s.utxoCount("available"))
	}
	if !s.workerLogHas("parked after the signing zone refused its batch") {
		t.Fatal("no ALERT in the worker log")
	}
	s.ledgerOK()
}

// The second look at every destination, right before the batch is built: a withdrawal that passed when the batch was sealed and fails now is taken out
// of the batch before anything is signed for it, parked with an alert; the rest of the batch goes out. (The batch waits for coins, sealed, when the
// destination changes.)
func TestBatchRescreenRemovesAWithdrawalBeforeSigning(t *testing.T) {
	s := batchSystem(t, opts{maxInputs: 2}, batchingOpts{outputs: 5, wait: "6s", inFlight: 1})
	vals := make([]int64, 12)
	for i := range vals {
		vals[i] = 1_000_000
	}
	s.fundHotOutputs(vals...)
	head, mid, bad := s.payQ(10_000_000), s.payQ(100_000), s.payQ(110_000)
	b := s.untilBatches("sealed", 1, 90*time.Second)[0]
	if len(b.Members) != 3 || b.Members[2] != bad.ID {
		t.Fatalf("members %v: all three pass the check at seal time", b.Members)
	}
	if _, err := s.pool.Exec(s.ctx, `UPDATE withdrawals SET to_address='not-an-address' WHERE id=$1`, bad.ID); err != nil {
		t.Fatal(err)
	}
	s.waitFor(60*time.Second, "the bad withdrawal is parked", func() bool { return strings.HasPrefix(s.wdRow(bad.ID).Reason, "parked:") })
	if r := s.wdRow(bad.ID); !strings.Contains(r.Reason, "destination check before signing") || r.Batch != "" {
		t.Fatalf("the bad withdrawal: %+v", r)
	}
	if !s.workerLogHas("failed the destination check before its batch was signed") {
		t.Fatal("no ALERT in the worker log")
	}
	if s.attempts("send") != 0 || s.utxoCount("reserved") != 0 {
		t.Fatal("something was built or signed while the head still could not be funded")
	}
	s.fundHot(30_000_000)
	got := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	if got.ID != b.ID || len(got.Members) != 2 || got.Members[0] != head.ID || got.Members[1] != mid.ID {
		t.Fatalf("batch %+v: the same batch without the bad withdrawal", got)
	}
	s.assertBooked(s.mineBatch(got.ID), head, mid)
	if n := s.received(bad.dest, 0); n != 0 {
		t.Fatalf("the parked withdrawal was paid %d", n)
	}
}
