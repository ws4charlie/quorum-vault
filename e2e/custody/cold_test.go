package custody_test

import (
	"bytes"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

// Hot to cold: the excess above a hot wallet's high-water mark goes to the cold address by itself. These run in both signer
// modes; in mpc mode the move is signed by the two parties and checked by the gateway AND the cosigner.

func (s *system) hotPart(asset string) string { return s.cfg.PartitionKey(asset, 0).String() }

// ledgerBalance is the on-chain balance a ledger account mirrors (minus its posted amount).
func (s *system) mirrored(acct string) *big.Int { return new(big.Int).Neg(s.posted(acct)) }

func (s *system) coldMoves(status string) int {
	return s.count(`SELECT count(*) FROM cold_moves WHERE status=$1`, status)
}

// setLimits changes the in-process service's limits (the worker's planner reads its own config file, which the test left
// without a reachable high-water mark, so only this service plans).
func (s *system) setLimits(asset string, low, high, target *big.Int) {
	s.svc.Cfg.ColdLimits[s.hotPart(asset)] = custody.HotLimits{Low: low, High: high, Target: target}
}

var (
	hugeMark = "1000000000000000000000000" // a mark the tests never reach
	nullLog  = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
)

func TestColdMoveExcessEthAndToken(t *testing.T) {
	s := newSystem(t, opts{cold: &coldOpts{
		ethLow: "5000000000000000000", ethHigh: "20000000000000000000", ethTarget: "10000000000000000000",
		usdtHigh: "500000000", usdtTarget: "200000000",
	}})
	// The seed of 100 ETH is above 20: 90 ETH go to cold, 10 stay.
	s.waitFor(90*time.Second, "the ETH excess in the cold address", func() bool { return s.ethBalance(s.coldAddr).Cmp(eth(90)) == 0 })
	s.waitIdle(60 * time.Second)
	if hot := s.ethBalance(s.shardAddr[0]); hot.Cmp(eth(10)) > 0 || hot.Cmp(new(big.Int).Sub(eth(10), big.NewInt(1e16))) < 0 {
		t.Fatalf("hot ETH = %s, want 10 ETH less the fee", hot)
	}
	if got := s.mirrored(custody.ColdAccount(s.hotPart("ETH"))); got.Cmp(eth(90)) != 0 {
		t.Fatalf("cold ETH account mirrors %s", got)
	}
	s.reconcileClean()

	// A customer's USDT deposit is swept to hot and puts hot USDT (800) over its 500 mark: 600 go to cold, 200 stay.
	addr := s.newCustomer("c-cold")
	s.mintUSDT(addr, 800_000_000)
	s.waitAvailable("c-cold", "USDT", big.NewInt(800_000_000), 30*time.Second)
	s.waitFor(120*time.Second, "the USDT excess in the cold address", func() bool { return s.usdtBalance(s.coldAddr).Cmp(big.NewInt(600_000_000)) == 0 })
	s.waitIdle(60 * time.Second)
	if got := s.usdtBalance(s.shardAddr[0]); got.Cmp(big.NewInt(200_000_000)) != 0 {
		t.Fatalf("hot USDT = %s, want 200000000", got)
	}
	if got := s.mirrored(custody.ColdAccount(s.hotPart("USDT"))); got.Cmp(big.NewInt(600_000_000)) != 0 {
		t.Fatalf("cold USDT account mirrors %s", got)
	}
	// Nothing is left in transit, nothing failed, and the ledger says what the chain says.
	for _, asset := range []string{"ETH", "USDT"} {
		if p := s.posted(custody.ToColdAccount(s.chainName, asset)); p.Sign() != 0 {
			t.Fatalf("%s clearing account holds %s", asset, p)
		}
	}
	if n := s.coldMoves("failed"); n != 0 {
		t.Fatalf("%d failed moves", n)
	}
	rep := s.reconcileClean()
	cold := 0
	for _, c := range rep.Checks {
		if c.Name == "cold" {
			cold++
		}
	}
	if cold != 2 {
		t.Fatalf("Reconcile made %d cold checks, want 2 (ETH and USDT)", cold)
	}
	// The customer's money is still the customer's: moving it to cold is the operator's choice, not a debit.
	if a, _, _ := s.balance("c-cold", "USDT"); a.Cmp(big.NewInt(800_000_000)) != 0 {
		t.Fatalf("customer available %s", a)
	}
	s.requireAudit("cold_move.started")
}

// The amount a move may take is the hot balance less the liquidity open withdrawals have reserved on it.
func TestColdMoveRespectsOpenWithdrawals(t *testing.T) {
	s, _ := funded(t, opts{cold: &coldOpts{ethHigh: hugeMark, usdtHigh: hugeMark}}, "c-resv", 40)
	// A 30 ETH withdrawal needs two approvals; with mining off it stays open with its liquidity reserved.
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	dest := randAddr()
	w := s.withdraw("initiator", "k-resv", "c-resv", "ETH", dest, eth(30))
	for _, a := range []string{"alice", "bob"} {
		if code, out := s.approve(a, w.ID); code != 200 {
			t.Fatalf("approve %s: %d %v", a, code, out)
		}
	}
	s.waitBroadcast(w.ID)

	hotBefore := s.mirrored(custody.HotAccount(s.hotPart("ETH")))
	target := eth(10)
	s.setLimits("ETH", new(big.Int), eth(20), target)
	moved, err := s.svc.PlanColdMoves(s.ctx, nullLog)
	if err != nil || len(moved) != 1 {
		t.Fatalf("PlanColdMoves = %v, %v", moved, err)
	}
	want := new(big.Int).Sub(new(big.Int).Sub(hotBefore, eth(30)), target)
	if moved[0].Amount.Cmp(want) != 0 {
		t.Fatalf("planned %s, want hot %s - reserved 30 ETH - target %s = %s", moved[0].Amount, hotBefore, target, want)
	}
	// And a second pass plans nothing while one is open.
	if again, err := s.svc.PlanColdMoves(s.ctx, nullLog); err != nil || len(again) != 0 {
		t.Fatalf("a second move while one is open: %v %v", again, err)
	}

	s.automine(true)
	s.mine()
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	s.waitFor(120*time.Second, "the move to confirm", func() bool { return s.coldMoves("confirmed") == 1 })
	s.waitIdle(60 * time.Second)
	if got := s.ethBalance(s.coldAddr); got.Cmp(want) != 0 {
		t.Fatalf("cold address holds %s, want %s", got, want)
	}
	if got := s.ethBalance(dest); got.Cmp(eth(30)) != 0 {
		t.Fatalf("withdrawal destination holds %s", got)
	}
	s.reconcileClean()
}

// The worker is killed at every boundary of a move; each restart finishes it once.
func TestColdMoveCrashAtEveryBoundary(t *testing.T) {
	s, _ := funded(t, opts{cold: &coldOpts{ethHigh: hugeMark, usdtHigh: hugeMark}}, "c-ccrash", 30)
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("cold move crash test, at " + current)
		}
	})
	five := eth(5)
	moved := new(big.Int)
	for _, point := range []string{"after_build", "after_job", "after_broadcast", "after_confirm", "after_settle"} {
		fp := "to-cold." + point
		current = fp
		s.worker.stop()
		s.startWorker(fp)
		// Make the hot wallet exceed its mark by exactly 5 ETH.
		free := s.mirrored(custody.HotAccount(s.hotPart("ETH")))
		s.setLimits("ETH", new(big.Int), new(big.Int).Sub(free, big.NewInt(1)), new(big.Int).Sub(free, five))
		mv, err := s.svc.PlanColdMoves(s.ctx, nullLog)
		if err != nil || len(mv) != 1 || mv[0].Amount.Cmp(five) != 0 {
			t.Fatalf("%s: planned %v, %v", fp, mv, err)
		}
		if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
			t.Fatalf("%s: worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		s.startWorker("")
		moved.Add(moved, five)
		s.waitFor(150*time.Second, fp+": the move to confirm", func() bool { return s.coldMoves("confirmed") == countDone(point) })
		s.waitIdle(90 * time.Second)
		if got := s.ethBalance(s.coldAddr); got.Cmp(moved) != 0 {
			t.Fatalf("%s: cold address holds %s, want exactly %s (one transfer)", fp, got, moved)
		}
		if n := s.coldMoves("failed"); n != 0 {
			t.Fatalf("%s: %d failed moves", fp, n)
		}
		s.reconcileClean()
		t.Logf("to-cold crash %-22s ok: recovered, one transfer of 5 ETH, Reconcile clean", fp)
	}
}

func countDone(point string) int {
	for i, p := range []string{"after_build", "after_job", "after_broadcast", "after_confirm", "after_settle"} {
		if p == point {
			return i + 1
		}
	}
	return 0
}

// Below the low-water mark the planner logs one ALERT per outage, not one per pass.
func TestColdMoveBelowLowRaisesOneAlert(t *testing.T) {
	s := newSystem(t, opts{cold: &coldOpts{ethLow: "500000000000000000000", ethHigh: "900000000000000000000", usdtHigh: hugeMark}})
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	alerts := func() int {
		return strings.Count(buf.String(), "ALERT") + strings.Count(readFile(s.worker.log), "ALERT: hot wallet is below")
	}

	// Hot holds 100 ETH, the low mark is 500: the first pass alerts, later passes (the worker's planner runs every second, and
	// so do these) stay quiet.
	s.waitFor(30*time.Second, "the first ALERT", func() bool { return alerts() == 1 })
	for i := 0; i < 5; i++ {
		if _, err := s.svc.PlanColdMoves(s.ctx, log); err != nil {
			t.Fatal(err)
		}
		s.waitPasses(workflow.ColdPlannerID(s.chainName), 3) // several planner passes in the worker too
	}
	if n := alerts(); n != 1 {
		t.Fatalf("%d ALERTs for one outage, want 1\nworker: %s", n, readFile(s.worker.log))
	}
	if n := s.count(`SELECT count(*) FROM hot_low_alerts`); n != 1 {
		t.Fatalf("%d low-water flags", n)
	}

	// Back above the mark: the flag clears. Below it again: a second outage, a second ALERT.
	s.setLimits("ETH", eth(50), eth(900), eth(100))
	if _, err := s.svc.PlanColdMoves(s.ctx, log); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM hot_low_alerts`); n != 0 {
		t.Fatalf("the flag did not clear above the mark")
	}
	s.setLimits("ETH", eth(500), eth(900), eth(600))
	if _, err := s.svc.PlanColdMoves(s.ctx, log); err != nil {
		t.Fatal(err)
	}
	if n := alerts(); n != 2 { // the worker's planner may be the one that raised it: it counts the same
		t.Fatalf("%d ALERTs after two outages, want 2\nworker: %s\nhere: %s", n, readFile(s.worker.log), buf.String())
	}
	if n := s.coldMoves("planned") + s.coldMoves("signing") + s.coldMoves("confirmed"); n != 0 {
		t.Fatalf("%d moves below the low mark", n)
	}
}
