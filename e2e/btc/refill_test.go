package btce2e

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func refillSystem(t *testing.T, o opts) *system {
	t.Helper()
	o.withdraw, o.refill = true, true
	s := newSystem(t, o)
	s.cf.Withdrawal.HotWait = "3m"
	return s
}

// lowShard sets up a shard that has just fallen below its low-water mark with money waiting on the cold address: the hot shard is funded with 20M and has
// a customer with 20M; the cold address was funded from outside with coldSats; a withdrawal of 10M takes the shard to 10M, below the low mark of 12M.
// It returns the refill the planner opened.
func lowShard(t *testing.T, o opts, coldSats int64) (*system, rfRow) {
	t.Helper()
	if o.coldLow == "" {
		o.coldLow, o.coldHigh, o.coldTarget = "12000000", "40000000", "20000000"
	}
	s := refillSystem(t, o)
	s.fundHot(20_000_000)
	s.deposit("c1", 20_000_000)
	s.node.pay(map[string]string{s.coldAddr: btcAmount(coldSats)})
	s.node.mine(6, "")
	s.waitFor(60*time.Second, "the cold output is recorded", func() bool { return s.coldRows("available") == 1 })
	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 10_000_000)
	s.settle(w.ID)
	return s, s.refillIn("requested", 60*time.Second)
}

func (s *system) untilRefillConfirmed(id string, timeout time.Duration) rfRow {
	s.t.Helper()
	stop := s.keepMining()
	defer stop()
	var got rfRow
	s.waitFor(timeout, "refill "+id+" confirmed", func() bool {
		for _, r := range s.refillRows() {
			if r.ID == id && r.Status == "confirmed" {
				got = r
			}
		}
		return got.ID != ""
	})
	return got
}

// The whole cycle: a shard above its high mark sends the excess to cold (the move's output is a cold output), withdrawals drain the shard below its low
// mark, a refill opens (only one), the request crosses the air gap, two operators approve it on qv-cold, the signed file comes back and is imported, the
// transaction is broadcast and settled. The cold change is spent by the second refill. Ledger, outputs and Reconcile are clean throughout.
func TestRefillFullCycleToColdThenRefillTwice(t *testing.T) {
	s := refillSystem(t, opts{coldLow: "12000000", coldHigh: "40000000", coldTarget: "20000000"})
	s.fundHot(60_000_000)
	s.deposit("c1", 50_000_000)
	s.untilColdMoves(1, 150*time.Second) // the excess goes to cold
	s.waitFor(60*time.Second, "the move's output is a cold output", func() bool { return s.coldRows("available") == 1 })
	if v := s.coldValue("available"); v != 40_000_000 {
		t.Fatalf("cold output %d", v)
	}
	if got := s.onChain(s.coldAddr); got != 40_000_000 {
		t.Fatalf("the cold address holds %d", got)
	}
	s.node.mine(8, "")
	s.reconcileClean()

	var cold1 int64 = 40_000_000
	for round := 1; round <= 2; round++ {
		hotBefore := s.hotPosted().Int64()
		coldBefore := s.posted("cold:" + s.part).Int64()
		w := s.withdraw("ini", "k-r"+string(rune('0'+round)), "c1", s.node.fresh(), 12_000_000)
		s.settle(w.ID)
		rf := s.refillIn("requested", 60*time.Second)
		s.holds(4*time.Second, "one refill is open for the shard, not a second", func() bool { return s.refillsOpen() == 1 })
		hotBefore = s.hotPosted().Int64() // after the withdrawal
		s.ceremony(rf.ID, "full-"+string(rune('0'+round)))
		done := s.untilRefillConfirmed(rf.ID, 120*time.Second)
		if done.ID != rf.ID || done.Fee <= 0 || done.Amount <= 0 {
			t.Fatalf("refill %+v (opened: %s); all: %+v", done, rf.ID, s.refillRows())
		}
		if got := s.hotPosted().Int64(); got != hotBefore-done.Amount {
			t.Fatalf("round %d: hot mirror %d, want %d (it received %d)", round, got, hotBefore-done.Amount, done.Amount)
		}
		_ = coldBefore
		cold1 = cold1 - done.Amount - done.Fee
		if got := s.posted("cold:" + s.part).Int64(); got != -cold1 {
			t.Fatalf("round %d: cold account %d, want %d", round, got, -cold1)
		}
		if got := s.posted("refill:" + s.chain + ":BTC").Int64(); got != 0 {
			t.Fatalf("refill clearing account %d", got)
		}
		if s.coldRows("available") != 1 || s.coldValue("available") != cold1 || s.coldRows("spent") != round {
			t.Fatalf("round %d: cold outputs available %d (%d sats, want %d) spent %d", round, s.coldRows("available"), s.coldValue("available"), cold1, s.coldRows("spent"))
		}
		if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2 AND NOT cold AND NOT deposit AND status='available' AND value=$3`, s.chain, done.Tx, done.Amount) != 1 {
			t.Fatal("the refill's payment is not an available hot output")
		}
		if got := s.onChain(s.coldAddr); got != cold1 {
			t.Fatalf("the cold address holds %d, want %d", got, cold1)
		}
		s.ledgerOK()
		s.node.mine(8, "")
		s.reconcileClean()
	}
	// Our own outputs were never booked as funding.
	if got := s.posted("opfund:" + s.chain + ":BTC").Int64(); got != 60_000_000 {
		t.Fatalf("operator funding %d: an output of ours was booked as funding", got)
	}
}

// Several cold outputs funded from outside, one refill that needs three of them, with change back to the cold address.
func TestRefillSeveralInputsWithColdChange(t *testing.T) {
	s := refillSystem(t, opts{coldLow: "12000000", coldHigh: "80000000", coldTarget: "30000000"})
	s.fundHot(15_000_000)
	s.deposit("c1", 15_000_000)
	for i := 0; i < 3; i++ {
		s.node.pay(map[string]string{s.coldAddr: btcAmount(10_000_000)})
	}
	s.node.mine(6, "")
	s.waitFor(60*time.Second, "the cold outputs are recorded", func() bool { return s.coldRows("available") == 3 })
	if got := s.posted("cold:" + s.part).Int64(); got != -30_000_000 {
		t.Fatalf("cold account %d after the outside funding", got)
	}
	s.node.mine(8, "")
	s.reconcileClean()
	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 5_000_000)
	s.settle(w.ID)
	rf := s.refillIn("requested", 60*time.Second)
	s.ceremony(rf.ID, "several")
	done := s.untilRefillConfirmed(rf.ID, 120*time.Second)
	var req struct {
		Inputs  []struct{ TxID string }
		Outputs []struct {
			Address string
			Value   int64
		}
	}
	var raw []byte
	s.pool.QueryRow(s.ctx, `SELECT request FROM refills WHERE id=$1`, rf.ID).Scan(&raw)
	json.Unmarshal(raw, &req)
	if len(req.Inputs) != 3 || len(req.Outputs) != 2 || req.Outputs[1].Address != s.coldAddr {
		t.Fatalf("request %+v: want three inputs and change to the cold address", req)
	}
	if want := 30_000_000 - done.Amount - done.Fee; s.coldRows("available") != 1 || s.coldValue("available") != want || s.coldRows("spent") != 3 {
		t.Fatalf("cold outputs: available %d (%d sats, want %d) spent %d", s.coldRows("available"), s.coldValue("available"), want, s.coldRows("spent"))
	}
	s.node.mine(8, "")
	s.reconcileClean()
}

// A refill file that is not the current request, a changed signed file, a request the offline side refuses, and a request that is never signed: none of
// them reserves anything or moves a coin, and the request ends when its time is up.
func TestRefillStaleTamperedAndUnsignedRequestsEndWithNothingStuck(t *testing.T) {
	s, rf := lowShard(t, opts{refillTTL: "30s"}, 15_000_000)
	cold0 := s.coldValue("available")

	// A request the offline side refuses (the file was changed on the way): no signature, nothing to import.
	req := s.exportRefill(rf.ID, "tamper")
	b, _ := os.ReadFile(req)
	bad := strings.Replace(string(b), s.hotAddr, s.coldAddr, 1)
	badPath := req + ".bad.json"
	os.WriteFile(badPath, []byte(bad), 0o600)
	if _, out, err := s.signRefill(badPath); err == nil || !strings.Contains(out+err.Error(), "damaged") && !strings.Contains(out+err.Error(), "refused") {
		t.Fatalf("the offline side signed a changed request: %v\n%s", err, out)
	}

	// A good signed file, changed on the way home, is refused at import.
	signed, _, err := s.signRefill(req)
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := os.ReadFile(signed)
	var sg map[string]any
	json.Unmarshal(sb, &sg)
	raw := sg["raw_tx"].(string)
	flip := []byte(raw)
	flip[len(flip)-20] ^= 1 // a byte inside the lock time / last witness region
	sg["raw_tx"] = string(flip)
	tb, _ := json.Marshal(sg)
	tampered := signed + ".tampered.json"
	os.WriteFile(tampered, tb, 0o600)
	if code, body := s.importRefill(rf.ID, tampered); code == 200 {
		t.Fatalf("a changed signed file was imported: %s", body)
	}
	// A file for another request: the request was exported again, so the old answer no longer fits it.
	s.exportRefill(rf.ID, "second")
	if code, body := s.importRefill(rf.ID, signed); code == 200 {
		t.Fatalf("a signed file for an old export was imported: %s", body)
	}
	if s.coldRows("reserved") != 0 || s.coldValue("available") != cold0 {
		t.Fatal("something is reserved though nothing was imported")
	}

	// Never signed: the request ends when its time is up, with nothing reserved and no coin moved.
	got := s.refillIn("failed", 120*time.Second)
	if !strings.Contains(got.Reason, "not imported") || got.ID != rf.ID {
		t.Fatalf("refill %+v", got)
	}
	if s.coldRows("reserved") != 0 || s.onChain(s.coldAddr) != cold0 || s.attempts("send") != 1 { // the one send is the withdrawal
		t.Fatalf("reserved %d, cold on chain %d, %d sends", s.coldRows("reserved"), s.onChain(s.coldAddr), s.attempts("send"))
	}
	s.ledgerOK()
}

// The crash boundaries: the worker is stopped or killed at each, restarted, and the refill ends once, with the books right.
func TestRefillCrashAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct{ name, failpoint, stopAt string }{
		{"after export", "", "export"},
		{"after import", "", "import"},
		{"after broadcast", "refill.after_send", ""},
		{"after confirm before settle", "refill.after_confirm", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rf := lowShard(t, opts{failpoint: tc.failpoint}, 15_000_000)
			hotBefore := s.hotPosted().Int64()
			req := s.exportRefill(rf.ID, "crash")
			if tc.stopAt == "export" {
				s.worker.stop()
			}
			signed, out, err := s.signRefill(req)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if code, body := s.importRefill(rf.ID, signed); code != 200 {
				t.Fatalf("import: %d %s", code, body)
			}
			if tc.stopAt == "import" {
				s.worker.stop()
			}
			if tc.stopAt != "" {
				s.startWorker()
			}
			stop := s.keepMining()
			if tc.failpoint != "" {
				s.waitExit(s.worker, "the worker at "+tc.failpoint)
				if tc.failpoint == "refill.after_confirm" {
					s.node.mine(2, "")
				}
				s.restartWorker()
			}
			done := s.untilRefillConfirmed(rf.ID, 150*time.Second)
			stop()
			if n := s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND owner_kind='refill'`, s.chain); n != 1 {
				t.Fatalf("%d refill attempts", n)
			}
			if got := s.hotPosted().Int64(); got != hotBefore-done.Amount {
				t.Fatalf("hot mirror %d, want %d: it must have received %d once", got, hotBefore-done.Amount, done.Amount)
			}
			if s.coldRows("reserved") != 0 {
				t.Fatal("a cold output is still reserved")
			}
			s.ledgerOK()
			s.node.mine(8, "")
			s.reconcileClean()
		})
	}
}

// Reconcile is clean with a refill in flight, at each stage: requested, signed and reserved but not sent, in the mempool, one confirmation, at and past
// the spend depth but not settled, and settled.
func TestRefillReconcileCleanAtEveryStage(t *testing.T) {
	s, rf := lowShard(t, opts{}, 15_000_000)
	s.node.mine(8, "")
	s.mustBeClean("requested")
	s.worker.stop() // from here the stages are looked at one by one
	req := s.exportRefill(rf.ID, "stages")
	signed, out, err := s.signRefill(req)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code, body := s.importRefill(rf.ID, signed); code != 200 {
		t.Fatalf("import: %d %s", code, body)
	}
	if s.coldRows("reserved") != 1 {
		t.Fatal("the imported refill did not reserve its input")
	}
	s.mustBeClean("signed, reserved, not sent")
	s.startWorker()
	s.waitFor(60*time.Second, "the refill is broadcast", func() bool { return s.refillIn("broadcast", time.Second).ID == rf.ID })
	s.worker.stop() // settlement waits
	s.mustBeClean("in the mempool")
	s.node.mine(1, "")
	s.mustBeClean("one confirmation")
	s.node.mine(1, "")
	s.mustBeClean("at the spend depth, not settled")
	s.node.mine(1, "")
	s.mustBeClean("past the spend depth, not settled")
	s.startWorker()
	s.refillIn("confirmed", 90*time.Second)
	s.node.mine(8, "")
	s.reconcileClean()
}
