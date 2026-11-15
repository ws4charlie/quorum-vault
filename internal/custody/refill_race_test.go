package custody

import (
	"context"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// refillChain is a fake chain cell that can do refills: every refill transaction is final and successful.
type refillChain struct{ *fakeChain }

func (refillChain) ColdTxParams(context.Context, common.Address) (uint64, *big.Int, *big.Int, error) {
	return 0, big.NewInt(1), big.NewInt(1), nil
}
func (refillChain) SendRaw(context.Context, []byte) (string, error) { return "", nil }
func (refillChain) RefillTxState(context.Context, string) (evm.RefillState, *big.Int, error) {
	return evm.RefillConfirmed, new(big.Int), nil
}
func (refillChain) FactoryRead(context.Context, string) (common.Address, error) {
	return common.Address{}, nil
}
func (refillChain) FactoryAddress() common.Address { return common.Address{} }

func newRefillSvc(t *testing.T) (*Service, *fakeChain, *Config) {
	t.Helper()
	cfg, err := rebalFile(nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeChain{fee: big.NewInt(0), statuses: map[string]chain.TxStatus{}}
	s := New(dbtest.New(t), cfg, refillChain{fc}, fakeReader{block: 50})
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, fc, cfg
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func (s *Service) refillRows(t *testing.T, partitionID string) int {
	t.Helper()
	var n int
	if err := s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM refills WHERE chain=$1 AND partition_id=$2`, testChain, partitionID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The cold planner reads every input of a pass from one snapshot. A refill that settles in the middle of a pass (its status and the hot balance change
// in one transaction) is seen whole or not at all: read statement by statement, a pass saw the hot balance from before the settlement and the open
// refills from after it, and asked for a second refill for money that had already arrived.
func TestPlannerPassSeesARefillSettlementWholeOrNotAtAll(t *testing.T) {
	ctx := context.Background()
	s, _, cfg := newRefillSvc(t)
	p0 := cfg.PartitionKey("ETH", 0).String()
	cold, _ := cfg.ColdAddressOf(p0, "ETH")
	if err := s.FundHot(ctx, "seed", 0, big.NewInt(50)); err != nil { // below the low-water mark of 100
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO refills (id, chain, asset, partition_id, cold_address, to_address, amount, status, raw_tx, tx_hash)
		VALUES ('rf-1',$1,'ETH',$2,$3,'0x00000000000000000000000000000000000000a1',300,'signed','aa','0xh1')`, testChain, p0, cold); err != nil {
		t.Fatal(err)
	}
	if err := s.recordRefillBroadcast(ctx, "rf-1", "0xh1"); err != nil {
		t.Fatal(err)
	}
	first := true
	s.planHook = func(stage string) {
		if stage != "balance read" || !first {
			return
		}
		first = false
		// every input of this pass has been read; now the refill settles
		if err := s.SettleRefill(ctx, "rf-1", false); err != nil {
			t.Error(err)
		}
	}
	if _, err := s.PlanColdMoves(ctx, quietLog()); err != nil {
		t.Fatal(err)
	}
	if first {
		t.Fatal("the hook never ran")
	}
	if n := s.refillRows(t, p0); n != 1 {
		t.Fatalf("%d refills for the shard after a pass that a settlement interrupted, want 1", n)
	}
	// and the next pass sees the settled refill with the hot balance that includes it
	s.planHook = nil
	if _, err := s.PlanColdMoves(ctx, quietLog()); err != nil {
		t.Fatal(err)
	}
	if n := s.refillRows(t, p0); n != 1 {
		t.Fatalf("%d refills for the shard after the settlement, want 1", n)
	}
	if got, _ := s.freeHot(ctx, s.Pool, p0); got.Cmp(big.NewInt(350)) != 0 {
		t.Fatalf("free after the settlement: %v", got)
	}
}

// A sweep settles with an UPDATE of its row, which takes a lock on the partition the planner holds for a pass: it waits for the pass, so a sweep
// cannot raise the hot balance in the middle of one. The next pass sees it whole.
func TestSweepSettlementWaitsForAPlannerPass(t *testing.T) {
	ctx := context.Background()
	s, fc, cfg := newRefillSvc(t)
	p0 := cfg.PartitionKey("ETH", 0).String()
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "pre", depAcct(testChain, "ETH"), custAcct("c1", testChain, "ETH"), big.NewInt(500), nil)
	}); err != nil {
		t.Fatal(err)
	}
	setupSweep(t, s, "sw1", "ETH", 500)
	fc.moved = []chain.MovedAsset{{Address: "0xADDR", Asset: "ETH", Amount: big.NewInt(500)}}
	done := make(chan error, 1)
	first, settledInPass := true, false
	s.planHook = func(stage string) {
		if stage != "balance read" || !first {
			return
		}
		first = false
		go func() { done <- s.SettleSweep(ctx, "sw1", "0xtx", chain.TxConfirmed) }()
		select {
		case <-done:
			settledInPass = true
		case <-time.After(700 * time.Millisecond):
		}
	}
	if _, err := s.PlanColdMoves(ctx, quietLog()); err != nil {
		t.Fatal(err)
	}
	if first {
		t.Fatal("the hook never ran")
	}
	if settledInPass {
		t.Fatal("a sweep settled in the middle of a planner pass")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep did not settle after the pass")
	}
	// the pass saw the shard low and asked for a refill (the sweep was not booked yet); the next pass sees the sweep and asks for nothing more
	before := s.refillRows(t, p0)
	s.planHook = nil
	if _, err := s.PlanColdMoves(ctx, quietLog()); err != nil {
		t.Fatal(err)
	}
	if n := s.refillRows(t, p0); n != before {
		t.Fatalf("the next pass opened another refill (%d, was %d)", n, before)
	}
}

// On EVM (and Bitcoin) the cold address has one account nonce (one set of outputs): two refill requests exported side by side would take the same one, so
// one refill is open per cold address whatever the asset. Only Solana, where each refill signs a nonce account of its own, opens one per asset.
func TestEVMKeepsOneOpenRefillPerColdAddress(t *testing.T) {
	ctx := context.Background()
	cfg, err := rebalFile(func(f *File) {
		f.Cold.Limits["USDT"] = LimitFile{Low: "100", High: "10000", Target: "500"}
		f.Cold.Rebalance = RebalanceFile{}
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeChain{fee: big.NewInt(0), statuses: map[string]chain.TxStatus{}}
	s := New(dbtest.New(t), cfg, refillChain{fc}, fakeReader{block: 50})
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	// every hot partition holds nothing: ETH and USDT of both shards are below their low marks
	if _, err := s.PlanColdMoves(ctx, quietLog()); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM refills WHERE chain=$1 AND status NOT IN ('confirmed','failed')`, testChain).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 1 {
		t.Fatalf("%d open refills for one cold address, want 1", open)
	}
	if s.refillsPerAsset() {
		t.Fatal("an EVM service allows a refill per asset")
	}
}
