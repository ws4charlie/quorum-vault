package custody

import (
	"context"
	"io"
	"log/slog"
	"math/big"
	"testing"
)

// GC2b: the planner never plans a rebalance out of a Gate-governed wallet to a shard that is not Gate-governed (the zone would refuse it), and backs
// off from a source the zone refused as policy_gate_rebalance (the core's gate.wallets and the zone's signed setting differ), instead of planning the
// same refusal at every pass.
func TestPlanRebalancesKeepsGateMoneyUnderGate(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p0, p1 := s.Cfg.PartitionKey("ETH", 0).String(), s.Cfg.PartitionKey("ETH", 1).String()
	s.Cfg.RebalanceTargets = map[string]*big.Int{p0: big.NewInt(20), p1: big.NewInt(80)}
	// A hot account holds minus the on-chain balance (freeHot negates it): 100 on shard 0.
	if _, err := s.Pool.Exec(ctx, `UPDATE ledger_accounts SET posted=-100 WHERE id=$1`, hotAcct(p0)); err != nil {
		t.Fatal(err)
	}
	plan := func(what string, want int) {
		t.Helper()
		made, err := s.PlanRebalances(ctx, log)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if len(made) != want {
			t.Fatalf("%s: planned %d, want %d", what, len(made), want)
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE rebalance_moves SET status='failed', failure_reason='test: cleared', updated_at=now() - interval '2 hours' WHERE status='planned'`); err != nil {
			t.Fatal(err)
		}
	}
	gate := func(parts ...string) {
		s.Cfg.Gate = &GateConfig{Audience: "qv-test", Wallets: map[string]GateWallet{}}
		for i, p := range parts {
			id := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}[i]
			s.Cfg.Gate.Wallets[id] = GateWallet{ID: id, Partition: p, Asset: "ETH"}
		}
	}

	plan("no gate section", 1)
	gate(p0) // the source is Gate-governed, the destination is not
	plan("governed to not governed", 0)
	gate(s.Cfg.PartitionKey("USDT", 0).String()) // another asset of the same shard: the whole shard is governed
	plan("governed shard, other asset named", 0)
	gate(p1) // only the destination is governed
	plan("not governed to governed", 1)
	gate(p0, p1)
	plan("governed to governed", 1)

	// The zone refused a rebalance from shard 0 as policy_gate_rebalance a moment ago: the planner backs off for an hour.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO rebalance_moves (id, chain, asset, partition_id, to_partition_id, to_address, amount, status, failure_reason)
		VALUES ('rb-refused', $1, 'ETH', $2, $3, '0x00000000000000000000000000000000000000a2', 1, 'failed', 'gateway refused: policy_gate_rebalance: test')`, s.Cfg.Chain, p0, p1); err != nil {
		t.Fatal(err)
	}
	plan("after a policy_gate_rebalance refusal", 0)
	if _, err := s.Pool.Exec(ctx, `UPDATE rebalance_moves SET updated_at=now() - interval '61 minutes' WHERE id='rb-refused'`); err != nil {
		t.Fatal(err)
	}
	plan("an hour later", 1)
}
