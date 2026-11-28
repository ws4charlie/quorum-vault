package custody

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// GS1: a Gate shard is Gate's alone. The signing zone governs the whole shard (every asset) and refuses every job on it without a Gate credential, so
// Vault's own flows (withdrawals, sweeps, rebalances, moves to cold) never use it: the config refuses what would need one, and the planners skip it.

const gs1Shard2 = "0x00000000000000000000000000000000000000a3"

// gateShardFile is rebalFile with a third hot shard that a Gate wallet pays from (USDT on shard 2, with x402 on it as the gate section needs).
func gateShardFile(mut func(*File)) File {
	return rebalFile(func(f *File) {
		f.Chain.HotShards = append(f.Chain.HotShards, gs1Shard2)
		f.Chain.X402 = map[string]X402File{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "500000", Shard: 2}}
		f.Gate = &GateFile{Audience: "qv-test", Wallets: map[string]GateWalletFile{gateWallet: {Partition: "qv-us/" + testChain + "/USDT/hot/omnibus/2"}}}
		if mut != nil {
			mut(f)
		}
	})
}

func TestGateShardConfig(t *testing.T) {
	c, err := gateShardFile(nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	if !c.GateShard(2) || c.GateShard(0) || c.GateShard(1) {
		t.Fatalf("gate shards: 0 %v, 1 %v, 2 %v", c.GateShard(0), c.GateShard(1), c.GateShard(2))
	}
	// A per-asset rebalance target and per-asset cold limits cover Vault's shards only: a Gate shard is never a source or a destination.
	for _, sym := range []string{"ETH", "USDT"} {
		if tgt, ok := c.RebalanceTargets[c.PartitionKey(sym, 2).String()]; ok {
			t.Errorf("%s shard 2 (Gate's) has rebalance target %v", sym, tgt)
		}
	}
	if _, ok := c.RebalanceTargets[c.PartitionKey("ETH", 1).String()]; !ok {
		t.Error("ETH shard 1 lost its rebalance target")
	}
	if lim, ok := c.ColdLimits[c.PartitionKey("ETH", 2).String()]; ok {
		t.Errorf("ETH shard 2 (Gate's) has cold limits %+v: a move to cold from it is refused by the zone", lim)
	}
	if _, ok := c.ColdLimits[c.PartitionKey("ETH", 0).String()]; !ok {
		t.Error("ETH shard 0 lost its cold limits")
	}
	// Without a gate section nothing is Gate's.
	if c, err = rebalFile(nil).Build(); err != nil || c.GateShard(0) || c.GateShard(1) {
		t.Fatalf("no gate: %v %v %v", err, c.GateShard(0), c.GateShard(1))
	}
}

func TestGateShardConfigRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(*File)
		want string
	}{
		"sweeps land on the Gate shard": {
			func(f *File) { f.Chain.SweepDestination = gs1Shard2 }, "sweep_destination is hot shard 2, which is Gate's"},
		"every hot shard is Gate's": {
			func(f *File) {
				f.Chain.HotShards = f.Chain.HotShards[2:]
				f.Chain.SweepDestination = gs1Shard2
				f.Chain.X402["USDT"] = X402File{Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "500000"}
				f.Cold.Rebalance = RebalanceFile{}
				f.Gate.Wallets = map[string]GateWalletFile{gateWallet: {Partition: "qv-us/" + testChain + "/USDT/hot/omnibus/0"}}
			}, "every hot shard is Gate's"},
		"a rebalance target names the Gate shard": {
			func(f *File) { f.Cold.Rebalance.Targets["ETH/2"] = "300" }, `rebalance target "ETH/2": shard 2 is Gate's`},
		"rebalancing with one shard of Vault's own": {
			func(f *File) { // shard 1 is Gate's too: only shard 0 is left
				f.Gate.Wallets["aaaaaaaa-0000-4000-8000-000000000001"] = GateWalletFile{Partition: "qv-us/" + testChain + "/USDT/hot/omnibus/1"}
			}, "at least two hot shards that are not Gate's"},
		"cold limits name the Gate shard": {
			func(f *File) { f.Cold.ShardLimits = map[string]LimitFile{"ETH/2": {Low: "100", High: "1000", Target: "500"}} }, "shard_limits ETH/2: shard 2 is Gate's"},
	} {
		_, err := gateShardFile(tc.mut).Build()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}
}

func newGateShardSvc(t *testing.T) (*Service, *Config) {
	t.Helper()
	cfg, err := gateShardFile(nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	s := New(dbtest.New(t), cfg, refillChain{&fakeChain{fee: big.NewInt(0), statuses: map[string]chain.TxStatus{}}}, fakeReader{block: 50})
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, cfg
}

// A withdrawal takes the shard with the most free liquidity of its asset, but never a Gate shard, however rich: the zone would refuse its job forever.
func TestPickShardSkipsGateShard(t *testing.T) {
	ctx := context.Background()
	s, cfg := newGateShardSvc(t)
	for i, amt := range []int64{100, 50, 1_000_000} { // shard 2 (Gate's) is by far the richest
		if err := s.FundHotAsset(ctx, "seed-"+itoa(i), i, "USDT", big.NewInt(amt)); err != nil {
			t.Fatal(err)
		}
	}
	var part string
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		part, err = s.pickShard(ctx, tx, "USDT", big.NewInt(10))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if want := cfg.PartitionKey("USDT", 0).String(); part != want {
		t.Fatalf("picked %s, want %s (the richest shard that is not Gate's)", part, want)
	}
	// Through the request: the withdrawal is pinned to shard 0.
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "pre", depAcct(testChain, "USDT"), custAcct("c1", testChain, "USDT"), big.NewInt(1000), nil)
	}); err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7").Hex()
	w, _, err := s.RequestWithdrawal(ctx, WithdrawalRequest{Actor: "ini", IdempotencyKey: "k1", Customer: "c1", Asset: "USDT", To: to, Amount: big.NewInt(10)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GateShard(mustShard(t, cfg, w.PartitionID)) {
		t.Fatalf("withdrawal on Gate shard %s", w.PartitionID)
	}
}

func mustShard(t *testing.T, c *Config, p string) int {
	t.Helper()
	i, err := c.ShardIndex(p)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// The rebalance planner never moves from or to a Gate shard: shard 2 (Gate's) is the fullest, yet a dry shard 1 is fed from shard 0.
func TestRebalancePlannerSkipsGateShard(t *testing.T) {
	ctx := context.Background()
	s, cfg := newGateShardSvc(t)
	for i, amt := range []int64{450, 0, 900} { // ETH targets 300: shard 0 has 150 to spare, shard 1 is dry, shard 2 (Gate's) is fullest
		if amt > 0 {
			if err := s.FundHot(ctx, "seed-"+itoa(i), i, big.NewInt(amt)); err != nil {
				t.Fatal(err)
			}
		}
	}
	moves, err := s.PlanRebalances(ctx, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if len(moves) == 0 {
		t.Fatal("no move planned: the dry shard 1 should be fed from shard 0")
	}
	for _, m := range moves {
		if cfg.GateShard(mustShard(t, cfg, m.PartitionID)) || cfg.GateShard(mustShard(t, cfg, m.ToPartitionID)) {
			t.Errorf("move %s: %s -> %s touches a Gate shard", m.ID, m.PartitionID, m.ToPartitionID)
		}
	}
	if m := moves[0]; m.PartitionID != cfg.PartitionKey("ETH", 0).String() || m.ToPartitionID != cfg.PartitionKey("ETH", 1).String() {
		t.Errorf("move %s -> %s, want shard 0 -> shard 1", m.PartitionID, m.ToPartitionID)
	}
}

// set-destination refuses a Gate shard: swept funds would land where only a Gate credential spends them. Another hot shard is still accepted.
func TestSetDestinationRefusesGateShard(t *testing.T) {
	ctx := context.Background()
	s, _ := newGateShardSvc(t)
	_, err := s.RequestAction(ctx, coldsign.KindSetDestination, gs1Shard2, "")
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "Gate shard") {
		t.Fatalf("set-destination to the Gate shard: %v, want ErrInvalid naming the Gate shard", err)
	}
	if _, err := s.RequestAction(ctx, coldsign.KindSetDestination, "0x00000000000000000000000000000000000000a2", ""); err != nil {
		t.Fatalf("set-destination to shard 1: %v", err)
	}
}

// The cold planner never moves to cold from a Gate shard, even if limits reach it (the config gives it none): only a Gate credential spends from it.
func TestColdPlannerSkipsGateShard(t *testing.T) {
	ctx := context.Background()
	s, cfg := newGateShardSvc(t)
	gp := cfg.PartitionKey("ETH", 2).String()
	cfg.ColdLimits[gp] = cfg.ColdLimits[cfg.PartitionKey("ETH", 0).String()] // what a config without the guard gave it: high 1000
	if err := s.FundHot(ctx, "seed", 2, big.NewInt(5000)); err != nil {
		t.Fatal(err)
	}
	moves, err := s.PlanColdMoves(ctx, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range moves {
		if m.PartitionID == gp {
			t.Fatalf("move %s to cold from the Gate shard", m.ID)
		}
	}
}
