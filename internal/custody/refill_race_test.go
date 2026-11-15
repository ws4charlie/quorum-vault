package custody

import (
	"context"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

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

// The cold planner decides from the open refills and the hot balance in one pass. SettleRefill changes both (the status and the hot booking) in one
// transaction, so it must not run in the middle of a pass: it waits for the planner's hold on the partition. A pass that read the hot balance before
// the settlement and the open refills after it would open a second refill for money that has already arrived.
func TestSettleRefillWaitsForAPlannerPass(t *testing.T) {
	ctx := context.Background()
	cfg, err := rebalFile(nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	pool := dbtest.New(t)
	s := New(pool, cfg, refillChain{&fakeChain{fee: big.NewInt(0), statuses: map[string]chain.TxStatus{}}}, fakeReader{block: 50})
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	p0 := cfg.PartitionKey("ETH", 0).String()
	cold, _ := cfg.ColdAddressOf(p0, "ETH")
	if err := s.FundHot(ctx, "seed", 0, big.NewInt(50)); err != nil { // below the low-water mark of 100
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO refills (id, chain, asset, partition_id, cold_address, to_address, amount, status, raw_tx, tx_hash)
		VALUES ('rf-1',$1,'ETH',$2,$3,'0x00000000000000000000000000000000000000a1',300,'signed','aa','0xh1')`, testChain, p0, cold); err != nil {
		t.Fatal(err)
	}
	if err := s.recordRefillBroadcast(ctx, "rf-1", "0xh1"); err != nil {
		t.Fatal(err)
	}

	// a planner pass: it holds the partition and reads
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT asset FROM partitions WHERE id=$1 FOR UPDATE`, p0); err != nil {
		t.Fatal(err)
	}
	free, err := s.freeHot(ctx, tx, p0)
	if err != nil || free.Cmp(big.NewInt(50)) != 0 {
		t.Fatalf("free %v %v", free, err)
	}
	done := make(chan error, 1)
	go func() { done <- s.SettleRefill(ctx, "rf-1", false) }()
	select {
	case err := <-done:
		t.Fatalf("the refill settled while a planner pass held its partition (err %v)", err)
	case <-time.After(700 * time.Millisecond):
	}
	// the rest of the pass still sees the refill as open: the view is consistent with the balance it read
	if _, open, err := s.openRefillFor(ctx, tx, cold); err != nil || !open {
		t.Fatalf("the open refill disappeared in the middle of a pass: open=%v err=%v", open, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the settlement did not finish after the pass ended")
	}

	// the next pass sees the settled refill and the hot balance that includes it: nothing to ask for
	if _, err := s.PlanColdMoves(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM refills WHERE chain=$1 AND partition_id=$2`, testChain, p0).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d refills for the shard after the settlement, want 1 (err %v)", n, err)
	}
	if got, _ := s.freeHot(ctx, pool, p0); got.Cmp(big.NewInt(350)) != 0 {
		t.Fatalf("free after the settlement: %v", got)
	}
}
