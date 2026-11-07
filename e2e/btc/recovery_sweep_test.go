package btce2e

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// breakSweepJobs makes the business database give the jobs of sweeps a key reference that is not their input's: the gateway refuses them. With
// onlySecond only the second input's job (".1") is broken, so the first is signed: one input refused after another was signed.
func (s *system) breakSweepJobs(onlySecond bool) {
	s.t.Helper()
	cond := "NEW.id LIKE 'sweep:%'"
	if onlySecond {
		cond = "NEW.id LIKE 'sweep:%.1'"
	}
	for _, q := range []string{
		`CREATE FUNCTION qv_break_sweep() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ` + cond + ` THEN NEW.key_ref := '1/9'; END IF; RETURN NEW; END $$`,
		`CREATE TRIGGER qv_break_sw BEFORE INSERT ON sign_jobs FOR EACH ROW EXECUTE FUNCTION qv_break_sweep()`,
	} {
		if _, err := s.pool.Exec(s.ctx, q); err != nil {
			s.t.Fatal(err)
		}
	}
}

func (s *system) unbreakSweepJobs() {
	s.t.Helper()
	if _, err := s.pool.Exec(s.ctx, `DROP TRIGGER qv_break_sw ON sign_jobs`); err != nil {
		s.t.Fatal(err)
	}
}

func (s *system) logCount(sub string) int {
	b, _ := os.ReadFile(s.worker.log)
	return strings.Count(string(b), sub)
}

// waitSweeps waits until n sweeps are in the status.
func (s *system) waitSweeps(status string, n int, timeout time.Duration) {
	s.t.Helper()
	s.waitFor(timeout, fmt.Sprintf("%d sweeps %s", n, status), func() bool { return s.sweepsIn(status) >= n })
}

// settledSweep mines blocks until one sweep is settled and returns it.
func (s *system) settledSweep() swp {
	s.t.Helper()
	stop := s.keepMining()
	defer stop()
	s.waitSweeps("confirmed", 1, 90*time.Second)
	for _, w := range s.sweepRows() {
		if w.Status == "confirmed" {
			return w
		}
	}
	s.t.Fatal("unreachable")
	return swp{}
}

// A sweep that sticks at a low fee is replaced by one that pays more (same inputs, a lower output). Both can end the race; the fee booked is that of
// the transaction that confirmed.
func TestRecoverySweepStuckIsBumpedAndTheReplacementConfirms(t *testing.T) {
	s := sweepSystem(t, opts{fallbackRate: 1, stuckAfter: "6s"}, 0)
	s.requireNoEstimate()
	s.deposit("c1", 30_000_000)
	s.waitSweeps("broadcast", 1, 60*time.Second)
	orig, _ := s.firstAttempt("send")
	s.waitAttempts("send", 2, 60*time.Second)
	repl := s.lastAttempt("send")
	fo, fr := s.attemptFee(orig), s.attemptFee(repl)
	if repl == orig || fr <= fo {
		t.Fatalf("no replacement that pays more: %d vs %d", fr, fo)
	}
	s.node.mine(2, "")
	s.waitSweeps("confirmed", 1, 60*time.Second)
	sw := s.sweepRows()[0]
	if sw.Fee != fr || sw.Tx != repl || sw.Moved != 30_000_000 {
		t.Fatalf("sweep %+v, the replacement %s paid %d", sw, repl, fr)
	}
	if got := s.hotPosted().Int64(); got != -(30_000_000 - fr) {
		t.Fatalf("hot mirror %d", got)
	}
	if got := s.feePosted(); got != -fr {
		t.Fatalf("fee account %d, want %d", got, -fr)
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2`, s.chain, orig) != 0 {
		t.Fatal("the original's output was recorded though it never confirmed")
	}
	s.ledgerOK()
}

func TestRecoverySweepStuckAndTheOriginalConfirms(t *testing.T) {
	s := sweepSystem(t, opts{fallbackRate: 1, stuckAfter: "6s"}, 0)
	s.requireNoEstimate()
	s.deposit("c1", 30_000_000)
	s.waitSweeps("broadcast", 1, 60*time.Second)
	orig, rawOrig := s.firstAttempt("send")
	s.waitAttempts("send", 2, 60*time.Second)
	repl := s.lastAttempt("send")
	var out json.RawMessage
	if err := s.node.root.Call(s.ctx, &out, "generateblock", s.node.fresh(), []string{fmt.Sprintf("%x", rawOrig)}); err != nil {
		t.Fatalf("a block with the original: %v", err)
	}
	s.node.mine(1, s.node.fresh())
	s.waitSweeps("confirmed", 1, 60*time.Second)
	fo := s.attemptFee(orig)
	sw := s.sweepRows()[0]
	if sw.Fee != fo || sw.Tx != orig {
		t.Fatalf("sweep %+v, the original %s paid %d (a replacement paid %d)", sw, orig, fo, s.attemptFee(repl))
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2 AND status='available' AND NOT deposit AND NOT cold`, s.chain, orig) != 1 ||
		s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2`, s.chain, repl) != 0 {
		t.Fatal("the original's output is not the one recorded")
	}
	if got := s.hotPosted().Int64(); got != -(30_000_000 - fo) {
		t.Fatalf("hot mirror %d", got)
	}
	s.ledgerOK()
}

// A bump that would break the sweep rule is not made: an ALERT, the sweep keeps waiting, it is not voided, and it settles when mined.
func TestRecoverySweepBumpThatBreaksTheRuleAlertsAndWaits(t *testing.T) {
	// At 1 sat/vB a one-input sweep pays about 110 sats: 1.5M passes k = 10000 (1.1M needed) but the first bump (about 220 sats) would need 2.2M.
	s := sweepSystem(t, opts{fallbackRate: 1, stuckAfter: "5s", sweepK: 10000}, 0)
	s.requireNoEstimate()
	s.deposit("c1", 1_500_000)
	s.waitSweeps("broadcast", 1, 60*time.Second)
	s.waitFor(60*time.Second, "the ALERT that it cannot be replaced", func() bool { return s.workerLogHas("cannot be replaced") })
	s.holds(8*time.Second, "the sweep waits, it is not voided and not replaced", func() bool {
		return s.sweepsIn("broadcast") == 1 && s.attempts("send") == 1
	})
	s.node.mine(2, "")
	s.waitSweeps("confirmed", 1, 60*time.Second)
	s.ledgerOK()
}

// One input of a sweep is refused after another was signed: a signature exists, so a cancel is sent. It spends the same inputs to the hot shard, so the
// coins arrive anyway: the sweep settles through the cancel, with the cancel's fee, and the customer's credit and the sweep account are right.
func TestRecoverySweepOneInputRefusedAfterAnotherWasSignedSendsACancel(t *testing.T) {
	s := sweepSystem(t, opts{}, 0)
	s.breakSweepJobs(true)
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: btcAmount(12_000_000)})
	s.node.pay(map[string]string{addr: btcAmount(8_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("c1", 20_000_000, 60*time.Second)
	s.waitAttempts("cancel", 1, 90*time.Second)
	s.holds(4*time.Second, "not settled before the cancel confirms", func() bool { return s.sweepsIn("confirmed") == 0 && s.sweepsIn("failed") == 0 })
	if n := s.attempts("send"); n != 0 {
		t.Fatalf("%d sweep transactions were broadcast", n)
	}
	s.node.mine(2, "")
	s.waitSweeps("confirmed", 1, 60*time.Second)
	cancel := s.lastAttempt("cancel")
	fee := s.attemptFee(cancel)
	sw := s.sweepRows()[0]
	if sw.Tx != cancel || sw.Moved != 20_000_000 || sw.Fee != fee || sw.Amount != 20_000_000 {
		t.Fatalf("sweep %+v, cancel %s fee %d", sw, cancel, fee)
	}
	if a := s.available("c1").Int64(); a != 20_000_000 {
		t.Fatalf("customer has %d", a)
	}
	if got := s.posted("sweep:" + s.chain + ":BTC").Int64(); got != 0 {
		t.Fatalf("sweep account %d", got)
	}
	if got := s.feePosted(); got != -fee {
		t.Fatalf("fee account %d, want %d", got, -fee)
	}
	if got := s.hotPosted().Int64(); got != -(20_000_000 - fee) {
		t.Fatalf("hot mirror %d, want %d", got, -(20_000_000 - fee))
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status='spent'`, s.chain) != 2 ||
		s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND status='available' AND value=$2`, s.chain, 20_000_000-fee) != 1 {
		t.Fatal("the cancel's output is not the hot output")
	}
	s.ledgerOK()
	// The cancel's output is spendable by a withdrawal.
	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 5_000_000)
	s.settle(w.ID)
}

// The worker dies right after it sent the sweep's cancel: after the restart the same cancel is found, confirmed, and settled once.
func TestRecoverySweepCrashAfterTheCancelWasSent(t *testing.T) {
	s := sweepSystem(t, opts{failpoint: "cancel.after_broadcast"}, 0)
	s.breakSweepJobs(true)
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: btcAmount(12_000_000)})
	s.node.pay(map[string]string{addr: btcAmount(8_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("c1", 20_000_000, 60*time.Second)
	s.waitExit(s.worker, "the worker after the cancel")
	s.restartWorker()
	s.node.mine(2, "")
	s.waitSweeps("confirmed", 1, 90*time.Second)
	if s.attempts("cancel") != 1 || s.attempts("send") != 0 || len(s.sweepRows()) != 1 {
		t.Fatalf("%d cancels, %d sends, %d sweeps", s.attempts("cancel"), s.attempts("send"), len(s.sweepRows()))
	}
	fee := s.attemptFee(s.lastAttempt("cancel"))
	if got := s.hotPosted().Int64(); got != -(20_000_000 - fee) {
		t.Fatalf("hot mirror %d", got)
	}
	s.ledgerOK()
}

// A sweep the gateway refuses with nothing signed gives its outputs back as deposit outputs; the planner backs off (it does not plan again at every
// pass), and when the cause is gone it plans the address again and the coins move.
func TestRecoverySweepRefusedWithNothingSignedGivesTheOutputsBack(t *testing.T) {
	s := sweepSystem(t, opts{retryAfter: "6s"}, 0)
	s.breakSweepJobs(false)
	s.deposit("c1", 5_000_000)
	s.waitSweeps("failed", 1, 60*time.Second)
	if r := s.sweepRows()[0]; !strings.Contains(r.Reason, "gateway refused") {
		t.Fatalf("reason %q", r.Reason)
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status='available' AND value=5000000`, s.chain) != 1 {
		t.Fatal("the deposit output was not given back as a deposit output")
	}
	s.holds(3*time.Second, "the planner leaves the address alone for a while", func() bool { return len(s.sweepRows()) == 1 })
	s.unbreakSweepJobs()
	s.waitSweeps("broadcast", 1, 60*time.Second) // after the backoff it plans the address again
	s.node.mine(2, "")
	s.waitSweeps("confirmed", 1, 60*time.Second)
	if a := s.available("c1").Int64(); a != 5_000_000 {
		t.Fatalf("customer has %d", a)
	}
	if got := s.posted("sweep:" + s.chain + ":BTC").Int64(); got != 0 {
		t.Fatalf("sweep account %d", got)
	}
	s.ledgerOK()
}

// An output a sweep reserved is spent by something outside this system: the sweep is parked with an ALERT, nothing is released, and a withdrawal from the
// hot shard keeps working meanwhile.
func TestRecoverySweepOutsideSpendOfADepositOutputParksAndWithdrawalsGoOn(t *testing.T) {
	s := sweepSystem(t, opts{}, 50_000_000)
	_ = s.gateway.cmd.Process.Signal(syscall.SIGSTOP) // our gateway has not seen the sweep's jobs yet
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: btcAmount(30_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("c1", 30_000_000, 60*time.Second)
	s.waitFor(60*time.Second, "the sweep is built", func() bool {
		return s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status='reserved'`, s.chain) == 1
	})
	var u struct {
		txid string
		vout uint32
		val  int64
		idx  uint32
	}
	if err := s.pool.QueryRow(s.ctx, `SELECT u.txid, u.vout, u.value, d.derivation_index FROM btc_utxos u JOIN deposit_addresses d ON d.address=u.address
		WHERE u.chain=$1 AND u.deposit AND u.status='reserved'`, s.chain).Scan(&u.txid, &u.vout, &u.val, &u.idx); err != nil {
		t.Fatal(err)
	}
	s.outsideSweepSpend(u.txid, u.vout, uint64(u.val), addr, u.idx)
	s.node.mine(2, "")
	_ = s.gateway.cmd.Process.Signal(syscall.SIGCONT)
	s.waitFor(90*time.Second, "the sweep is parked", func() bool {
		r := s.sweepRows()
		return len(r) == 1 && strings.HasPrefix(r[0].Reason, "parked:")
	})
	if !s.workerLogHas("ALERT") {
		t.Fatal("no ALERT")
	}
	s.holds(3*time.Second, "parked, not failed or settled", func() bool {
		r := s.sweepRows()
		return len(r) == 1 && r[0].Status != "failed" && r[0].Status != "confirmed"
	})
	// A withdrawal from the funded hot shard still goes through.
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.settle(w.ID)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	s.ledgerOK()
}

// The crash boundaries of a sweep: the worker dies at each, is restarted, and the sweep ends once: one transaction, books balanced.
func TestRecoverySweepCrashAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		failpoint string
		mineFirst bool
	}{
		{"sweep.after_build", false},
		{"sweep.after_job", false},
		{"sweep.after_broadcast", false},
		{"sweep.after_confirm", true},
	} {
		t.Run(tc.failpoint, func(t *testing.T) {
			s := sweepSystem(t, opts{failpoint: tc.failpoint}, 0)
			addr := s.newCustomer("c1")
			s.node.pay(map[string]string{addr: btcAmount(30_000_000)})
			s.node.mine(6, "")
			if tc.mineFirst {
				s.waitSweeps("broadcast", 1, 60*time.Second)
				s.node.mine(2, "")
			}
			s.waitExit(s.worker, "the worker at "+tc.failpoint)
			s.restartWorker()
			sw := s.settledSweep()
			if n := s.attempts("send"); n != 1 || len(s.sweepRows()) != 1 {
				t.Fatalf("%d send attempts, %d sweeps", n, len(s.sweepRows()))
			}
			if sw.Moved != 30_000_000 || sw.Fee <= 0 {
				t.Fatalf("sweep %+v", sw)
			}
			if got := s.hotPosted().Int64(); got != -(30_000_000 - sw.Fee) {
				t.Fatalf("hot mirror %d", got)
			}
			if got := s.posted("sweep:" + s.chain + ":BTC").Int64(); got != 0 {
				t.Fatalf("sweep account %d", got)
			}
			if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND status='reserved'`, s.chain) != 0 {
				t.Fatal("an output is still reserved")
			}
			if a := s.available("c1").Int64(); a != 30_000_000 {
				t.Fatalf("customer has %d", a)
			}
			s.ledgerOK()
		})
	}
}
