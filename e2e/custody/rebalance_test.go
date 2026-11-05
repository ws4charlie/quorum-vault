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

// Hot shard rebalance: sweeps all land on shard 0, so the other shards run dry. A shard below its target receives from the fullest
// shard by itself. These run in both signer modes; in mpc mode the move is signed by the two parties and checked by the gateway AND
// the cosigner, each against its own list of hot shards.

func (s *system) shardPart(asset string, shard int) string {
	return s.cfg.PartitionKey(asset, shard).String()
}

func (s *system) rebalances(status string) int {
	return s.count(`SELECT count(*) FROM rebalance_moves WHERE status=$1`, status)
}

// setRebalance sets the in-process service's targets (the worker plans from its own config file, which a test leaves without
// rebalance targets unless it asks for them with opts.rebalance).
func (s *system) setRebalance(asset string, targets ...*big.Int) {
	if s.svc.Cfg.RebalanceTargets == nil {
		s.svc.Cfg.RebalanceTargets = map[string]*big.Int{}
	}
	for i, t := range targets {
		s.svc.Cfg.RebalanceTargets[s.shardPart(asset, i)] = t
	}
}

// An empty shard is fed by the shard the sweeps fill, by itself, and then serves withdrawals: the nonce load is on both.
func TestRebalanceFeedsADryShardAndWithdrawalsGoThere(t *testing.T) {
	s := newSystem(t, opts{shards: 2, seed: []int64{100, 0}, rebalance: &rebalOpts{targets: map[string]string{
		"ETH/0": eth(20).String(), "ETH/1": eth(80).String()}}})
	// Shard 1 is 80 ETH below its target and shard 0 is 80 above its own: one rebalance of exactly 80 ETH.
	s.waitFor(120*time.Second, "the rebalance to confirm", func() bool { return s.rebalances("confirmed") == 1 })
	s.waitIdle(60 * time.Second)
	if got := s.ethBalance(s.shardAddr[1]); got.Cmp(eth(80)) != 0 {
		t.Fatalf("shard 1 holds %s, want 80 ETH", got)
	}
	if got := s.mirrored(custody.HotAccount(s.shardPart("ETH", 1))); got.Cmp(eth(80)) != 0 {
		t.Fatalf("shard 1 mirrors %s", got)
	}
	if p := s.posted(custody.RebalanceAccount(s.chainName, "ETH")); p.Sign() != 0 {
		t.Fatalf("clearing account holds %s", p)
	}
	s.reconcileClean()
	// Gas is paid by the source: shard 0 is 80 plus the fee down, shard 1 got exactly the amount.
	if hot := s.ethBalance(s.shardAddr[0]); hot.Cmp(eth(20)) >= 0 || hot.Cmp(new(big.Int).Sub(eth(20), big.NewInt(1e16))) < 0 {
		t.Fatalf("shard 0 holds %s, want 20 ETH less the fee", hot)
	}
	// Nothing moves back: shard 0 is below its target by the fee, but the fullest shard (shard 1) is not above its own.
	s.waitPasses(workflow.ColdPlannerID(s.chainName), 3)
	if n := s.count(`SELECT count(*) FROM rebalance_moves`); n != 1 {
		t.Fatalf("%d rebalances after the first", n)
	}

	// A customer's deposit is swept to shard 0 (the factory's destination).
	before0 := s.ethBalance(s.shardAddr[0])
	addr := s.newCustomer("c-rb")
	s.sendETH(addr, eth(10))
	s.waitAvailable("c-rb", "ETH", eth(10), 30*time.Second)
	s.waitFor(90*time.Second, "the deposit swept", func() bool { return s.sweepsConfirmed() >= 1 })
	s.waitIdle(60 * time.Second)
	if got := s.ethBalance(s.shardAddr[0]); got.Cmp(before0) <= 0 {
		t.Fatalf("shard 0 did not receive the sweep: %s -> %s", before0, got)
	}

	// A withdrawal goes to the shard with the most free funds: the shard that was dry.
	dest := randAddr()
	w := s.withdraw("initiator", "k-rb", "c-rb", "ETH", dest, eth(2))
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	for _, a := range []string{"alice", "bob"} {
		if code, out := s.approve(a, w.ID); code != 200 {
			t.Fatalf("approve %s: %d %v", a, code, out)
		}
	}
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	var part string
	if err := s.pool.QueryRow(s.ctx, `SELECT partition_id FROM withdrawals WHERE id=$1`, w.ID).Scan(&part); err != nil {
		t.Fatal(err)
	}
	if part != s.shardPart("ETH", 1) {
		t.Fatalf("the withdrawal was paid by %s, want shard 1", part)
	}
	if got := s.ethBalance(dest); got.Cmp(eth(2)) != 0 {
		t.Fatalf("destination holds %s", got)
	}
	s.waitIdle(90 * time.Second) // the withdrawal's fee may bring shard 1 under its target: a small top-up from shard 0 is right
	if n := s.rebalances("failed"); n != 0 {
		t.Fatalf("%d failed rebalances", n)
	}
	s.reconcileClean()
}

// A rebalance and a move to cold do not fight: the rebalance is planned first and feeds the dry shard, so no refill is asked for
// it; the shard that was over its high-water mark is brought down to its cold target by the move to cold, and nothing moves again.
func TestRebalanceAndToColdDoNotFight(t *testing.T) {
	s := newSystem(t, opts{shards: 2, seed: []int64{100, 0},
		cold:      &coldOpts{ethLow: eth(5).String(), ethHigh: eth(60).String(), ethTarget: eth(40).String(), usdtHigh: hugeMark},
		rebalance: &rebalOpts{targets: map[string]string{"ETH": eth(30).String()}}})
	// Shard 0 holds 100: 30 go to shard 1 (its target), and what is left (70) is over the high mark 60, so 30 go to cold (target 40).
	s.waitFor(150*time.Second, "the rebalance and the move to cold", func() bool {
		return s.rebalances("confirmed") == 1 && s.coldMoves("confirmed") == 1
	})
	s.waitIdle(90 * time.Second)
	if got := s.ethBalance(s.shardAddr[1]); got.Cmp(eth(30)) != 0 {
		t.Fatalf("shard 1 holds %s, want 30 ETH", got)
	}
	if got := s.ethBalance(s.coldAddr); got.Cmp(eth(30)) != 0 {
		t.Fatalf("cold address holds %s, want 30 ETH", got)
	}
	// Stable: several more planner passes plan nothing, in either direction, and no refill was asked for the shard that was dry.
	s.waitPasses(workflow.ColdPlannerID(s.chainName), 4)
	s.holds(3*time.Second, "no further move", func() bool {
		return s.count(`SELECT count(*) FROM rebalance_moves`) == 1 && s.count(`SELECT count(*) FROM cold_moves`) == 1
	})
	if n := s.count(`SELECT count(*) FROM refills`) + s.count(`SELECT count(*) FROM hot_low_alerts`); n != 0 {
		t.Fatalf("%d refills or low-water flags for a shard that a rebalance fed", n)
	}
	for _, st := range []string{"failed", "planned", "signing", "broadcast"} {
		if s.rebalances(st) != 0 || s.coldMoves(st) != 0 {
			t.Fatalf("a move is %s", st)
		}
	}
	s.reconcileClean()
}

// The amount a rebalance may take is the source's balance less what open withdrawals reserved there, and only one is open per
// source and per receiver.
func TestRebalanceNeverMovesReservedFunds(t *testing.T) {
	s, _ := funded(t, opts{shards: 2, seed: []int64{100, 0}}, "c-rbresv", 40)
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	dest := randAddr()
	w := s.withdraw("initiator", "k-rbresv", "c-rbresv", "ETH", dest, eth(30))
	for _, a := range []string{"alice", "bob"} {
		if code, out := s.approve(a, w.ID); code != 200 {
			t.Fatalf("approve %s: %d %v", a, code, out)
		}
	}
	s.waitBroadcast(w.ID)
	hot0 := s.mirrored(custody.HotAccount(s.shardPart("ETH", 0)))
	s.setRebalance("ETH", eth(10), eth(200))
	moved, err := s.svc.PlanRebalances(s.ctx, nullLog)
	if err != nil || len(moved) != 1 {
		t.Fatalf("PlanRebalances = %v, %v", moved, err)
	}
	// 30 ETH of shard 0 are reserved by the open withdrawal: the rebalance takes what is above them and the target.
	want := new(big.Int).Sub(new(big.Int).Sub(hot0, eth(30)), eth(10))
	if m := moved[0]; m.Amount.Cmp(want) != 0 || m.PartitionID != s.shardPart("ETH", 0) || m.ToPartitionID != s.shardPart("ETH", 1) {
		t.Fatalf("planned %+v, want %s from shard 0 to shard 1", m, want)
	}
	if again, err := s.svc.PlanRebalances(s.ctx, nullLog); err != nil || len(again) != 0 {
		t.Fatalf("a second rebalance while one is open: %v %v", again, err)
	}
	s.automine(true)
	s.mine()
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	s.waitFor(120*time.Second, "the rebalance to confirm", func() bool { return s.rebalances("confirmed") == 1 })
	s.waitIdle(60 * time.Second)
	if got := s.ethBalance(dest); got.Cmp(eth(30)) != 0 {
		t.Fatalf("withdrawal destination holds %s", got)
	}
	if got := s.ethBalance(s.shardAddr[1]); got.Cmp(want) != 0 {
		t.Fatalf("shard 1 holds %s, want %s", got, want)
	}
	s.reconcileClean()
}

// A token rebalance needs gas on the source shard: without it the move is skipped with one ALERT per outage, and goes ahead once the
// shard has gas again.
func TestRebalanceTokenNeedsGasOnSource(t *testing.T) {
	s := newSystem(t, opts{shards: 2, seed: []int64{100, 0}})
	addr := s.newCustomer("c-rbtok")
	s.mintUSDT(addr, 800_000_000)
	s.waitAvailable("c-rbtok", "USDT", big.NewInt(800_000_000), 30*time.Second)
	s.waitFor(120*time.Second, "the deposit swept to shard 0", func() bool { return s.usdtBalance(s.shardAddr[0]).Cmp(big.NewInt(800_000_000)) == 0 })
	s.waitIdle(60 * time.Second)

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	usdt300 := big.NewInt(300_000_000)
	s.setRebalance("USDT", usdt300, usdt300)
	// Worst-case fee above anything shard 0 holds: no gas.
	realFee := s.svc.Cfg.EVM.MaxTxFeeWei
	s.svc.Cfg.EVM.MaxTxFeeWei = eth(1000)
	for i := 0; i < 5; i++ {
		if moved, err := s.svc.PlanRebalances(s.ctx, log); err != nil || len(moved) != 0 {
			t.Fatalf("pass %d: %v %v", i, moved, err)
		}
	}
	if n := strings.Count(buf.String(), "ALERT"); n != 1 {
		t.Fatalf("%d ALERTs for one outage, want 1\n%s", n, buf.String())
	}
	if n := s.count(`SELECT count(*) FROM rebalance_gas_alerts`); n != 1 {
		t.Fatalf("%d gas flags", n)
	}
	if n := s.count(`SELECT count(*) FROM rebalance_moves`); n != 0 {
		t.Fatalf("%d rebalances without gas", n)
	}

	// The source has gas again: the flag clears and the move goes ahead.
	s.svc.Cfg.EVM.MaxTxFeeWei = realFee
	ethBefore := s.ethBalance(s.shardAddr[0])
	moved, err := s.svc.PlanRebalances(s.ctx, log)
	if err != nil || len(moved) != 1 || moved[0].Amount.Cmp(usdt300) != 0 || moved[0].Asset != "USDT" {
		t.Fatalf("PlanRebalances = %v, %v", moved, err)
	}
	if n := s.count(`SELECT count(*) FROM rebalance_gas_alerts`); n != 0 {
		t.Fatalf("the gas flag did not clear")
	}
	s.waitFor(120*time.Second, "the token rebalance to confirm", func() bool { return s.rebalances("confirmed") == 1 })
	s.waitIdle(60 * time.Second)
	if got := s.usdtBalance(s.shardAddr[1]); got.Cmp(usdt300) != 0 {
		t.Fatalf("shard 1 holds %s USDT", got)
	}
	if got := s.ethBalance(s.shardAddr[0]); got.Cmp(ethBefore) >= 0 {
		t.Fatalf("the source did not pay the gas: %s -> %s", ethBefore, got)
	}
	if got := s.ethBalance(s.shardAddr[1]); got.Sign() != 0 {
		t.Fatalf("the receiver paid gas: %s", got)
	}
	s.reconcileClean()
}

// The worker is killed at every boundary of a rebalance; each restart finishes it once.
func TestRebalanceCrashAtEveryBoundary(t *testing.T) {
	s := newSystem(t, opts{shards: 2})
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("rebalance crash test, at " + current)
		}
	})
	five := eth(5)
	moved := new(big.Int)
	start1 := s.ethBalance(s.shardAddr[1])
	for _, point := range []string{"after_build", "after_job", "after_broadcast", "after_confirm", "after_settle"} {
		fp := "rebalance." + point
		current = fp
		s.worker.stop()
		s.startWorker(fp)
		// Shard 1 is 5 ETH below its target and shard 0 has exactly 5 ETH above its own.
		f0 := s.mirrored(custody.HotAccount(s.shardPart("ETH", 0)))
		f1 := s.mirrored(custody.HotAccount(s.shardPart("ETH", 1)))
		s.setRebalance("ETH", new(big.Int).Sub(f0, five), new(big.Int).Add(f1, five))
		mv, err := s.svc.PlanRebalances(s.ctx, nullLog)
		if err != nil || len(mv) != 1 || mv[0].Amount.Cmp(five) != 0 {
			t.Fatalf("%s: planned %v, %v", fp, mv, err)
		}
		if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
			t.Fatalf("%s: worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		s.startWorker("")
		moved.Add(moved, five)
		s.waitFor(150*time.Second, fp+": the rebalance to confirm", func() bool { return s.rebalances("confirmed") == countDone(point) })
		s.waitIdle(90 * time.Second)
		if got := new(big.Int).Sub(s.ethBalance(s.shardAddr[1]), start1); got.Cmp(moved) != 0 {
			t.Fatalf("%s: shard 1 gained %s, want exactly %s (one transfer)", fp, got, moved)
		}
		if n := s.rebalances("failed"); n != 0 {
			t.Fatalf("%s: %d failed rebalances", fp, n)
		}
		s.reconcileClean()
		t.Logf("rebalance crash %-22s ok: recovered, one transfer of 5 ETH, Reconcile clean", fp)
	}
}
