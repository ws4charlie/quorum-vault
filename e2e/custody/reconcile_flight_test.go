package custody_test

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Reconcile while things are in flight (EVM). A live custody system is never quiet, so the control must give an exact answer at every stage of
// a transaction: planned, signed, in the mempool, mined and not settled, settled. The stages are held by arming a failpoint in the worker (it
// dies at that boundary and the next stage is reached by starting a worker armed with the next one), by turning automine off for the
// mempool, and by keeping the worker dead while blocks are mined. With the worker dead nothing scans, so a test advances the scan itself.

// reconcileNow reads the report once, without waiting for anything to settle.
func (s *system) reconcileNow() custody.Report {
	s.t.Helper()
	rep, err := s.svc.Reconcile(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	return rep
}

// scanUp runs the scan until its cursor is past the safe height (the worker does it when it is alive).
func (s *system) scanUp() {
	s.t.Helper()
	for i := 0; i < 20; i++ {
		if _, err := s.svc.ScanOnce(s.ctx); err != nil {
			s.t.Fatal(err)
		}
		h, err := s.svc.Reader.SafeHead(s.ctx)
		if err != nil {
			s.t.Fatal(err)
		}
		if cur, err := s.svc.Cursor(s.ctx); err == nil && cur > h {
			return
		}
	}
	s.t.Fatal("the scan did not catch up")
}

// requireCleanIn demands a clean, complete report with wantOpen items in flight: nothing skipped, every kind of check made.
func (s *system) requireCleanIn(stage string, wantOpen int) custody.Report {
	s.t.Helper()
	rep := s.reconcileNow()
	if !rep.Clean || rep.SkippedChainChecks != 0 || rep.InFlight != wantOpen {
		b, _ := json.MarshalIndent(rep.Failures(), "", "  ")
		s.t.Fatalf("%s: Reconcile clean=%v skipped=%d in flight=%d (want %d), height %d cursor %d\n%s", stage, rep.Clean, rep.SkippedChainChecks, rep.InFlight, wantOpen, rep.Height, rep.ScanCursor, b)
	}
	names := map[string]int{}
	for _, c := range rep.Checks {
		if c.Skipped {
			s.t.Fatalf("%s: check %s %s was skipped: %s", stage, c.Name, c.Subject, c.Detail)
		}
		names[c.Name]++
	}
	for _, want := range []string{"hot", "deposit_addresses", "clearing_residual", "ledger_invariants", "scan_caught_up"} {
		if names[want] == 0 {
			s.t.Fatalf("%s: no %s check was made", stage, want)
		}
	}
	return rep
}

// adjusted reports whether the check of this name and subject had to take unsettled transactions into account: the proof that a stage tested
// the explanation and not a quiet cell.
func adjusted(rep custody.Report, name, subject string) bool {
	for _, c := range rep.Checks {
		if c.Name == name && (subject == "" || strings.EqualFold(c.Subject, subject)) && strings.Contains(c.Detail, "adjusted") {
			return true
		}
	}
	return false
}

// runUntil restarts the worker armed with failpoint fp and waits for it to die there.
func (s *system) runUntil(fp string) {
	s.t.Helper()
	s.worker.stop()
	s.startWorker(fp)
	if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
		s.t.Fatalf("worker did not die at %s (exited=%v code=%d)", fp, ok, code)
	}
}

// stopWorker leaves the system without a worker: nothing settles and nothing scans.
func (s *system) stopWorker() { s.worker.stop() }

// failure returns the failed check of this name, or fails the test.
func failure(t *testing.T, rep custody.Report, name, asset string) custody.Check {
	t.Helper()
	for _, c := range rep.Failures() {
		if c.Name == name && c.Asset == asset {
			return c
		}
	}
	b, _ := json.MarshalIndent(rep.Checks, "", "  ")
	t.Fatalf("no failed %s check for %s in the report\n%s", name, asset, b)
	return custody.Check{}
}

// A withdrawal reconciles clean at every stage of its life, and a real difference during it is caught.
func TestReconcileCleanAtEveryStageOfAWithdrawal(t *testing.T) {
	s, _ := funded(t, opts{}, "c-rwd", 10)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: withdrawal")
		}
	})
	dest := randAddr()
	amount := new(big.Int).Div(eth(1), big.NewInt(10))
	s.automine(false) // nothing mines until a stage asks for it
	t.Cleanup(func() { s.automine(true) })

	s.stopWorker()
	s.startWorker("withdrawal.after_build")
	w := s.withdraw("initiator", "k-rwd", "c-rwd", "ETH", dest, amount)
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
		t.Fatalf("worker did not die after the build (exited=%v code=%d)", ok, code)
	}
	s.requireCleanIn("planned: built, nonce allocated, not signed", 1)

	s.runUntil("withdrawal.after_job")
	s.requireCleanIn("signed, not sent", 1)

	s.runUntil("withdrawal.after_broadcast")
	s.requireCleanIn("sent, in the mempool", 1)

	// A real difference while it is in the mempool: someone sends ETH to the hot address behind our back.
	hot := s.shardAddr[0]
	before := s.ethBalance(hot)
	s.fundETH(hot, new(big.Int).Add(before, eth(1)))
	rep := s.reconcileNow()
	f := failure(t, rep, "hot", "ETH")
	if rep.Clean || f.Ledger == f.Chain {
		t.Fatalf("a difference of 1 ETH on the hot address during an open withdrawal was not caught: %+v", f)
	}
	diff := new(big.Int)
	l, _ := new(big.Int).SetString(f.Ledger, 10)
	c, _ := new(big.Int).SetString(f.Chain, 10)
	if diff.Sub(c, l); diff.Cmp(eth(1)) != 0 {
		t.Fatalf("hot ETH differs by %s, want exactly 1 ETH: %+v", diff, f)
	}
	s.fundETH(hot, before)
	s.requireCleanIn("sent, in the mempool, difference removed", 1)

	// Mined, with the worker dead: the chain has the payout and the fee, the books have neither.
	s.automine(true)
	s.mine()
	s.scanUp()
	rep = s.requireCleanIn("mined, not settled", 1)
	if !adjusted(rep, "hot", hot.Hex()) {
		t.Fatalf("the hot check made no adjustment for a mined, unsettled withdrawal: %+v", rep.Checks)
	}
	if s.ethBalance(dest).Cmp(amount) != 0 {
		t.Fatalf("destination holds %s", s.ethBalance(dest))
	}
	// The same difference is caught now too: the explanation covers the withdrawal, nothing else.
	s.fundETH(hot, new(big.Int).Add(s.ethBalance(hot), big.NewInt(1)))
	if rep := s.reconcileNow(); rep.Clean || failure(t, rep, "hot", "ETH").Subject == "" {
		t.Fatal("1 wei on the hot address during a mined, unsettled withdrawal was not caught")
	}
	s.fundETH(hot, new(big.Int).Sub(s.ethBalance(hot), big.NewInt(1)))
	s.requireCleanIn("mined, not settled, difference removed", 1)

	// Settled.
	s.startWorker("")
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("settled", 0)
}

// A sweep reconciles clean at every stage, for ETH and for a token, and a difference at a deposit address during it is caught.
func TestReconcileCleanAtEveryStageOfASweep(t *testing.T) {
	s, _ := funded(t, opts{}, "c-rsw", 5)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: sweep")
		}
	})
	s.waitIdle(60 * time.Second)
	for round, asset := range []string{"ETH", "USDT"} {
		stage := func(what string) string { return asset + " sweep " + what }
		cust := "c-rsw-" + asset
		addr := s.newCustomer(cust)
		s.automine(true)
		s.stopWorker()
		s.startWorker("sweep.after_build")
		if asset == "ETH" {
			s.sendETH(addr, eth(2))
		} else {
			s.mintUSDT(addr, 300_000_000)
		}
		if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
			t.Fatalf("worker did not die after the sweep build (exited=%v code=%d)", ok, code)
		}
		s.requireCleanIn(stage("planned: built, nonce allocated, not signed"), 1)

		s.runUntil("sweep.after_job")
		s.requireCleanIn(stage("signed, not sent"), 1)

		s.automine(false)
		s.runUntil("sweep.after_broadcast")
		s.requireCleanIn(stage("sent, not recorded, in the mempool"), 1)
		s.startWorker("")
		s.waitFor(60*time.Second, stage("recorded as broadcast"), func() bool {
			return s.count(`SELECT count(*) FROM sweeps WHERE from_address=$1 AND status='broadcast'`, addr.Hex()) == 1
		})
		s.requireCleanIn(stage("booked at broadcast, in the mempool"), 1)
		if p := s.posted(custody.SweepAccount(s.chainName, asset)); p.Sign() >= 0 {
			t.Fatalf("%s: the sweep clearing account holds %s while the sweep is in the mempool, want a negative amount", asset, p)
		}
		s.stopWorker()

		// ETH at the deposit address that the books know nothing of, while the sweep is open: a real difference.
		if asset == "ETH" {
			before := s.ethBalance(addr)
			s.fundETH(addr, new(big.Int).Add(before, eth(1)))
			rep := s.reconcileNow()
			f := failure(t, rep, "deposit_addresses", "ETH")
			l, _ := new(big.Int).SetString(f.Ledger, 10)
			c, _ := new(big.Int).SetString(f.Chain, 10)
			if rep.Clean || new(big.Int).Sub(c, l).Cmp(eth(1)) != 0 {
				t.Fatalf("1 ETH behind our back at a deposit address during an open sweep: %+v", f)
			}
			s.fundETH(addr, before)
			s.requireCleanIn(stage("sent, difference removed"), 1)
		}

		s.automine(true)
		s.mine()
		s.scanUp()
		rep := s.requireCleanIn(stage("mined, not settled"), 1)
		if !adjusted(rep, "hot", s.shardAddr[0].Hex()) {
			t.Fatalf("%s: the hot check made no adjustment for a mined, unsettled sweep: %+v", asset, rep.Checks)
		}

		s.startWorker("")
		s.waitFor(120*time.Second, stage("confirmed"), func() bool {
			return s.count(`SELECT count(*) FROM sweeps WHERE from_address=$1 AND status='confirmed'`, addr.Hex()) >= 1
		})
		s.waitIdle(90 * time.Second)
		s.scanUp()
		s.requireCleanIn(stage("settled"), 0)
		_ = round
	}
}

// A token that arrives at the hot address behind our back is caught while a withdrawal is open.
func TestReconcileCatchesATokenDifferenceInFlight(t *testing.T) {
	s, _ := funded(t, opts{}, "c-rtok", 5)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: token difference")
		}
	})
	s.stopWorker()
	s.startWorker("withdrawal.after_job")
	w := s.withdraw("initiator", "k-rtok", "c-rtok", "ETH", randAddr(), new(big.Int).Div(eth(1), big.NewInt(10)))
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
		t.Fatalf("worker did not die after the job (exited=%v code=%d)", ok, code)
	}
	s.requireCleanIn("signed, not sent", 1)
	s.mintUSDT(s.shardAddr[0], 1234)
	s.scanUp()
	rep := s.reconcileNow()
	f := failure(t, rep, "hot", "USDT")
	l, _ := new(big.Int).SetString(f.Ledger, 10)
	c, _ := new(big.Int).SetString(f.Chain, 10)
	if rep.Clean || new(big.Int).Sub(c, l).Int64() != 1234 || rep.InFlight != 1 {
		t.Fatalf("1234 USDT at the hot address during an open withdrawal: clean=%v in flight=%d %+v", rep.Clean, rep.InFlight, f)
	}
	for _, c := range rep.Failures() {
		if c.Name != "hot" || c.Asset != "USDT" {
			t.Fatalf("something else differs: %+v", c)
		}
	}
}

// A hot-to-cold move reconciles clean at every stage, mined or reverted: it is booked at broadcast, so the books are ahead of the chain
// until it mines, and the chain is ahead of the books after it mines and before it settles.
func TestReconcileCleanAtEveryStageOfAColdMove(t *testing.T) {
	s, _ := funded(t, opts{cold: &coldOpts{ethHigh: hugeMark, usdtHigh: hugeMark}}, "c-rcm", 30)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: cold move")
		}
	})
	plan := func(fp string) {
		free := s.mirrored(custody.HotAccount(s.hotPart("ETH")))
		s.setLimits("ETH", new(big.Int), new(big.Int).Sub(free, big.NewInt(1)), new(big.Int).Sub(free, eth(5)))
		s.stopWorker()
		s.startWorker(fp)
		mv, err := s.svc.PlanColdMoves(s.ctx, nullLog)
		if err != nil || len(mv) != 1 || mv[0].Amount.Cmp(eth(5)) != 0 {
			t.Fatalf("planned %v, %v", mv, err)
		}
		if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
			t.Fatalf("worker did not die at %s (exited=%v code=%d)", fp, ok, code)
		}
	}

	plan("to-cold.after_build")
	s.requireCleanIn("move planned: built, nonce allocated", 1)
	s.runUntil("to-cold.after_job")
	s.requireCleanIn("move signed, not sent", 1)
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	s.runUntil("to-cold.after_broadcast")
	s.requireCleanIn("move sent, not recorded, in the mempool", 1)
	// Recorded: the move is booked at broadcast (tocold -> hot), so the books are ahead of the chain until it mines.
	s.startWorker("")
	s.waitFor(60*time.Second, "the move to be recorded as broadcast", func() bool { return s.coldMoves("broadcast") == 1 })
	s.requireCleanIn("move booked at broadcast, in the mempool", 1)
	if p := s.posted(custody.ToColdAccount(s.chainName, "ETH")); p.Cmp(new(big.Int).Neg(eth(5))) != 0 {
		t.Fatalf("the clearing account holds %s while the move is in the mempool, want -5 ETH", p)
	}
	s.stopWorker()
	s.automine(true)
	s.mine()
	s.scanUp()
	rep := s.requireCleanIn("move mined, not settled", 1)
	if !adjusted(rep, "hot", s.shardAddr[0].Hex()) || !adjusted(rep, "cold", "") {
		t.Fatalf("no adjustment for a mined, unsettled move: %+v", rep.Checks)
	}
	s.startWorker("")
	s.waitFor(120*time.Second, "the move to confirm", func() bool { return s.coldMoves("confirmed") == 1 })
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("move settled", 0)

	// A move that reverts (the cold address turned into a contract that reverts): only the fee is spent.
	s.automine(false)
	plan("to-cold.after_broadcast")
	s.startWorker("")
	s.waitFor(60*time.Second, "the second move to be recorded as broadcast", func() bool { return s.coldMoves("broadcast") == 1 })
	s.requireCleanIn("second move booked at broadcast, in the mempool", 1)
	s.stopWorker()
	if err := s.rc.CallContext(s.ctx, nil, "anvil_setCode", s.coldAddr, "0x60006000fd"); err != nil {
		t.Fatal(err)
	}
	s.automine(true)
	s.mine()
	s.scanUp()
	rep = s.requireCleanIn("move reverted, not settled", 1)
	if !adjusted(rep, "hot", s.shardAddr[0].Hex()) {
		t.Fatalf("no adjustment for a reverted, unsettled move: %+v", rep.Checks)
	}
	s.startWorker("")
	s.waitFor(120*time.Second, "the move to fail", func() bool { return s.coldMoves("failed") == 1 })
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("reverted move settled", 0)
}

// A hot-shard rebalance reconciles clean at every stage.
func TestReconcileCleanAtEveryStageOfARebalance(t *testing.T) {
	s := newSystem(t, opts{shards: 2})
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: rebalance")
		}
	})
	f0 := s.mirrored(custody.HotAccount(s.shardPart("ETH", 0)))
	f1 := s.mirrored(custody.HotAccount(s.shardPart("ETH", 1)))
	s.setRebalance("ETH", new(big.Int).Sub(f0, eth(5)), new(big.Int).Add(f1, eth(5)))
	s.stopWorker()
	s.startWorker("rebalance.after_build")
	mv, err := s.svc.PlanRebalances(s.ctx, nullLog)
	if err != nil || len(mv) != 1 || mv[0].Amount.Cmp(eth(5)) != 0 {
		t.Fatalf("planned %v, %v", mv, err)
	}
	if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
		t.Fatalf("worker did not die after the build (exited=%v code=%d)", ok, code)
	}
	s.requireCleanIn("rebalance planned", 1)
	s.runUntil("rebalance.after_job")
	s.requireCleanIn("rebalance signed, not sent", 1)
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	s.runUntil("rebalance.after_broadcast")
	s.requireCleanIn("rebalance sent, not recorded, in the mempool", 1)
	s.startWorker("")
	s.waitFor(60*time.Second, "the rebalance to be recorded as broadcast", func() bool { return s.rebalances("broadcast") == 1 })
	s.requireCleanIn("rebalance booked at broadcast, in the mempool", 1)
	if p := s.posted(custody.RebalanceAccount(s.chainName, "ETH")); p.Cmp(new(big.Int).Neg(eth(5))) != 0 {
		t.Fatalf("the clearing account holds %s while the rebalance is in the mempool, want -5 ETH", p)
	}
	s.stopWorker()
	s.automine(true)
	s.mine()
	s.scanUp()
	rep := s.requireCleanIn("rebalance mined, not settled", 1)
	if !adjusted(rep, "hot", s.shardAddr[0].Hex()) || !adjusted(rep, "hot", s.shardAddr[1].Hex()) {
		t.Fatalf("no adjustment on both shards for a mined, unsettled rebalance: %+v", rep.Checks)
	}
	s.startWorker("")
	s.waitFor(120*time.Second, "the rebalance to confirm", func() bool { return s.rebalances("confirmed") == 1 })
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("rebalance settled", 0)
}

// A refill (the cold ceremony's transaction, not one of our nonces) reconciles clean at every stage.
func TestReconcileCleanAtEveryStageOfARefill(t *testing.T) {
	s := newSystem(t, refillOpts(""))
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: refill")
		}
	})
	s.fundedCold("cold-funding-1")
	s.reconcileClean()
	id := s.openRefill()
	s.requireCleanIn("refill requested", 0)
	rf := s.exportRefill(id)
	signed := s.ceremonyOK("rcl", rf, "alice", "bob")
	s.requireCleanIn("refill signed offline, not imported", 0)

	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	s.stopWorker()
	s.startWorker("refill.after_send")
	if code, res := s.importRefill(id, signed); code != 200 {
		t.Fatalf("import: %d %v", code, res)
	}
	if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
		t.Fatalf("worker did not die after the send (exited=%v code=%d)", ok, code)
	}
	s.requireCleanIn("refill imported and sent, not recorded", 1)
	s.runUntil("refill.after_record")
	s.requireCleanIn("refill recorded as broadcast, in the mempool", 1)
	s.automine(true)
	s.mine()
	s.scanUp()
	rep := s.requireCleanIn("refill mined, not settled", 1)
	if !adjusted(rep, "hot", s.shardAddr[0].Hex()) || !adjusted(rep, "cold", "") {
		t.Fatalf("no adjustment on hot and cold for a mined, unsettled refill: %+v", rep.Checks)
	}
	s.startWorker("")
	s.waitFor(90*time.Second, "the refill to confirm", func() bool { return s.refillStatus(id) == "confirmed" })
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("refill settled", 0)
}

// A withdrawal whose transaction is replaced with a higher fee: every attempt is ours, one mines, and the books follow that one.
func TestReconcileCleanWhileAWithdrawalIsReplaced(t *testing.T) {
	s, _ := funded(t, opts{stuckAfter: sd(2 * time.Second)}, "c-rrep", 5)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: replacement")
		}
	})
	dest := randAddr()
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	w := s.withdraw("initiator", "k-rrep", "c-rrep", "ETH", dest, half())
	s.waitFor(60*time.Second, "a replacement to be broadcast", func() bool { return s.attempts(w.ID) >= 2 })
	s.requireCleanIn("original and replacement in the mempool", 1)
	s.stopWorker()
	n := s.attempts(w.ID)
	s.automine(true)
	s.mine()
	s.scanUp()
	rep := s.requireCleanIn("a replacement mined, not settled", 1)
	if !adjusted(rep, "hot", s.shardAddr[0].Hex()) {
		t.Fatalf("no adjustment for a mined, unsettled replacement (%d attempts): %+v", n, rep.Checks)
	}
	s.startWorker("")
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("replacement settled", 0)
}

// A withdrawal the gateway refuses is cancelled with a transaction at its nonce: the cancel's gas leaves the hot wallet before the hold is voided.
func TestReconcileCleanWhileAWithdrawalIsCancelled(t *testing.T) {
	s, _ := funded(t, opts{gwETHPerTx: "3000000000000000000", businessOneTier: true}, "c-rcan", 10)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: cancel")
		}
	})
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	w := s.withdraw("initiator", "k-rcan", "c-rcan", "ETH", randAddr(), eth(4)) // over the gateway's 3 ETH cap
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	s.waitFor(90*time.Second, "the cancel to be broadcast", func() bool {
		return s.count(`SELECT count(*) FROM evm_tx_attempts WHERE kind='cancel'`) >= 1
	})
	s.requireCleanIn("refused, cancel in the mempool", 1)
	s.stopWorker()
	s.automine(true)
	s.mine()
	s.scanUp()
	rep := s.requireCleanIn("cancel mined, hold not voided", 1)
	if !adjusted(rep, "hot", s.shardAddr[0].Hex()) {
		t.Fatalf("no adjustment for the gas of a mined cancel: %+v", rep.Checks)
	}
	s.startWorker("")
	s.waitWd(w.ID, "failed", 90*time.Second)
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("cancelled and voided", 0)
}

// A withdrawal that mines with status 0 paid its gas and nothing else.
func TestReconcileCleanWhileAWithdrawalReverts(t *testing.T) {
	s, _ := funded(t, opts{stuckAfter: "90s"}, "c-rrev", 5)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("reconcile in flight: revert")
		}
	})
	dest := randAddr()
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	w := s.withdraw("initiator", "k-rrev", "c-rrev", "ETH", dest, half())
	s.waitBroadcast(w.ID)
	if err := s.rc.CallContext(s.ctx, nil, "anvil_setCode", dest, "0x60006000fd"); err != nil {
		t.Fatal(err)
	}
	s.requireCleanIn("sent, destination will revert", 1)
	s.stopWorker()
	s.automine(true)
	s.mine()
	s.scanUp()
	rep := s.requireCleanIn("reverted, not settled", 1)
	if !adjusted(rep, "hot", s.shardAddr[0].Hex()) {
		t.Fatalf("no adjustment for the gas of a reverted, unsettled withdrawal: %+v", rep.Checks)
	}
	s.startWorker("")
	s.waitWd(w.ID, "failed", 90*time.Second)
	s.waitIdle(60 * time.Second)
	s.scanUp()
	s.requireCleanIn("reverted and voided", 0)
}
