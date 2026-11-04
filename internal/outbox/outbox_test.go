package outbox_test

import (
	"context"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

func TestWriteCommitsAndRollsBack(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Write(ctx, tx, outbox.TopicDeposits, "k1", map[string]any{"amount": "5"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("after rollback: count=%d err=%v, want 0", n, err)
	}

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Write(ctx, tx, outbox.TopicWithdrawals, "w1", map[string]any{"amount": "7"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var topic, key, amount string
	var published bool
	err = pool.QueryRow(ctx, `SELECT topic, key, payload->>'amount', published_at IS NOT NULL FROM outbox`).
		Scan(&topic, &key, &amount, &published)
	if err != nil {
		t.Fatal(err)
	}
	if topic != "qv.withdrawals" || key != "w1" || amount != "7" || published {
		t.Errorf("got %q %q %q published=%v", topic, key, amount, published)
	}
}

func TestWriteRejectsUnmarshalable(t *testing.T) {
	pool := dbtest.New(t)
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := outbox.Write(context.Background(), tx, outbox.TopicAudit, "k", make(chan int)); err == nil {
		t.Error("want marshal error")
	}
}
