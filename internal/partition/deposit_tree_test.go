package partition

import (
	"context"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

func TestDepositTreeID(t *testing.T) {
	id, err := DepositTreeID("qv-us", "btc")
	if err != nil || id != "qv-us/btc/deposit-tree/0" || !id.IsDepositTree() {
		t.Fatalf("%q %v", id, err)
	}
	if _, err := DepositTreeID("", "btc"); err == nil {
		t.Fatal("empty entity accepted")
	}
	if shard, _ := NewShardID("qv-us", "btc", PoolOmnibus, 0); shard.IsDepositTree() {
		t.Fatal("a hot shard is not a deposit tree")
	}
	if got := DepositTreeLike("btc"); got != "%/btc/deposit-tree/0" {
		t.Fatal(got)
	}
}

// The registry holds the generations of a deposit tree like a shard's: one active, activation through draining, retiring last; the lookups by chain find it.
func TestDepositTreeGenerationsInTheRegistry(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	id, _ := DepositTreeID("qv-us", "btc")
	other, _ := DepositTreeID("qv-us", "sol")
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := RegisterInitial(ctx, tx, "t", id, "xpubA", "", []byte{2}); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterInitial(ctx, tx, "t", other, "solA", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterCandidate(ctx, tx, "t", id, "xpubB", "", nil); err != nil {
		t.Fatal(err)
	}
	if k, err := ActiveDeposit(ctx, tx, "btc"); err != nil || k.Generation != 1 || k.Address != "xpubA" {
		t.Fatalf("active %+v %v", k, err)
	}
	if k, err := DepositGeneration(ctx, tx, "btc", 2); err != nil || k.State != StateCandidate || k.Address != "xpubB" {
		t.Fatalf("generation 2 %+v %v", k, err)
	}
	if _, err := DepositGeneration(ctx, tx, "btc", 3); err == nil {
		t.Fatal("generation 3 found")
	}
	sp, _ := tx.Begin(ctx)
	if _, err := Activate(ctx, sp, "t", id, 2); err == nil {
		t.Fatal("activated beside an active generation")
	}
	sp.Rollback(ctx)
	if _, err := StartDraining(ctx, tx, "t", id, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := Activate(ctx, tx, "t", id, 2); err != nil {
		t.Fatal(err)
	}
	if k, err := ActiveDeposit(ctx, tx, "btc"); err != nil || k.Generation != 2 {
		t.Fatalf("active after the change %+v %v", k, err)
	}
	if k, err := ActiveDeposit(ctx, tx, "sol"); err != nil || k.Address != "solA" {
		t.Fatalf("another chain's tree %+v %v", k, err)
	}
}
