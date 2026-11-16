package auditchain

import (
	"context"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// Pruning the outbox leaves audit_log whole: the chain still verifies and every entry is still there.
func TestPruningTheOutboxLeavesTheChainVerifiable(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	writeAudit(t, pool, 6)
	drain(t, NewChainer(pool, ChainerOptions{BatchSize: 4}))
	// Backdate five rows to "published and chained 40 days ago" (the trigger forbids it, so switch it off for the setup only);
	// the sixth stays recent.
	for _, q := range []string{`ALTER TABLE outbox DISABLE TRIGGER outbox_no_edit`, `UPDATE outbox SET published_at = now() - interval '40 days', chained_at = now() - interval '40 days' WHERE seq <= 5`, `ALTER TABLE outbox ENABLE TRIGGER outbox_no_edit`} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	p, err := outbox.NewPruner(pool, outbox.PruneOptions{Retention: 30 * 24 * time.Hour, Batch: 2, Pause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := p.PruneOnce(ctx); err != nil || n != 5 {
		t.Fatalf("pruned %d, err %v; want 5", n, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM outbox`); n != 1 {
		t.Fatalf("outbox rows left = %d, want 1", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 6 {
		t.Fatalf("audit entries = %d, want 6", n)
	}
	mustVerify(t, pool)
	// New events chain and verify on top of the untouched chain.
	writeAudit(t, pool, 2)
	drain(t, NewChainer(pool, ChainerOptions{}))
	mustVerify(t, pool)
}
