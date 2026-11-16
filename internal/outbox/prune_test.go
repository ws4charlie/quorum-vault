package outbox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// seedRow inserts one outbox row with the given ages (0 = unset). published/chained are how long ago each happened.
func seedRow(t *testing.T, pool *pgxpool.Pool, topic string, published, chained time.Duration) int64 {
	t.Helper()
	var seq int64
	err := pool.QueryRow(context.Background(), `INSERT INTO outbox (id, topic, key, payload, created_at, published_at, chained_at)
		VALUES ($1, $2, 'k', '{}', now() - interval '400 days',
			CASE WHEN $3::float8 > 0 THEN now() - make_interval(secs => $3) END,
			CASE WHEN $4::float8 > 0 THEN now() - make_interval(secs => $4) END) RETURNING seq`,
		uuid.New(), topic, published.Seconds(), chained.Seconds()).Scan(&seq)
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

func exists(t *testing.T, pool *pgxpool.Pool, seq int64) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE seq = $1`, seq).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

const day = 24 * time.Hour

func TestPruneDeletesOnlyEligibleRows(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	oldUnpublished := seedRow(t, pool, TopicDeposits, 0, 0)
	oldPublished := seedRow(t, pool, TopicDeposits, 60*day, 0)
	youngPublished := seedRow(t, pool, TopicDeposits, 10*day, 0)
	unchainedAudit := seedRow(t, pool, TopicAudit, 60*day, 0)
	chainedAudit := seedRow(t, pool, TopicAudit, 60*day, 59*day)
	chainedYoung := seedRow(t, pool, TopicAudit, 60*day, 5*day) // chained recently: age runs from chained_at
	heads := seedRow(t, pool, TopicAuditHeads, 60*day, 0)       // never chained, no need to be

	p, err := NewPruner(pool, PruneOptions{Retention: 30 * day})
	if err != nil {
		t.Fatal(err)
	}
	n, err := p.PruneOnce(ctx)
	if err != nil || n != 3 {
		t.Fatalf("deleted %d, err %v; want 3", n, err)
	}
	for name, c := range map[string]struct {
		seq  int64
		keep bool
	}{
		"unpublished of any age": {oldUnpublished, true}, "published inside retention": {youngPublished, true},
		"unchained audit": {unchainedAudit, true}, "audit chained inside retention": {chainedYoung, true},
		"old published": {oldPublished, false}, "old chained audit": {chainedAudit, false}, "old heads": {heads, false},
	} {
		if exists(t, pool, c.seq) != c.keep {
			t.Errorf("%s: kept=%v, want %v", name, !c.keep, c.keep)
		}
	}
	// The oldest published row left is the unchained audit row, published 60 days ago.
	m := p.Metrics()
	if !strings.Contains(m, "qv_outbox_pruned_rows_total 3") || !strings.Contains(m, "qv_outbox_oldest_published_age_seconds 51840") {
		t.Errorf("metrics:\n%s", m)
	}
}

func TestDirectDeleteStaysRefused(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	seq := seedRow(t, pool, TopicDeposits, 365*day, 0) // eligible by every rule, but not through the function
	if _, err := pool.Exec(ctx, `DELETE FROM outbox WHERE seq = $1`, seq); err == nil || !strings.Contains(err.Error(), "not deleted") {
		t.Fatalf("direct delete: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE outbox`); err == nil {
		t.Fatal("truncate allowed")
	}
	// Setting the flag by hand still does not open recent or unpublished rows.
	young := seedRow(t, pool, TopicDeposits, 2*day, 0)
	unpub := seedRow(t, pool, TopicDeposits, 0, 0)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('qv.outbox_prune', 'on', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM outbox WHERE seq = ANY($1)`, []int64{young, unpub}); err == nil {
		t.Fatal("flag opened rows that are not eligible")
	}
}

func TestPruneFunctionKeepsHardMinimum(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	young := seedRow(t, pool, TopicDeposits, 3*day, 0)
	old := seedRow(t, pool, TopicDeposits, 8*day, 0)
	var n int64
	if err := pool.QueryRow(ctx, `SELECT outbox_prune(interval '0', 100)`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !exists(t, pool, young) || exists(t, pool, old) {
		t.Fatal("hard minimum not kept")
	}
	if err := pool.QueryRow(ctx, `SELECT outbox_prune(interval '-5 days', 100)`).Scan(&n); err != nil || n != 0 || !exists(t, pool, young) {
		t.Fatalf("negative retention: n=%d err=%v", n, err)
	}
}

func TestPruneBatches(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	for range 25 {
		seedRow(t, pool, TopicSweeps, 40*day, 0)
	}
	keep := seedRow(t, pool, TopicSweeps, 1*day, 0)
	p, err := NewPruner(pool, PruneOptions{Retention: 30 * day, Batch: 10, Pause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := p.PruneOnce(ctx); err != nil || n != 25 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var left int
	pool.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&left)
	if left != 1 || !exists(t, pool, keep) {
		t.Fatalf("left %d", left)
	}
	var one int64
	if err := pool.QueryRow(ctx, `SELECT outbox_prune(interval '30 days', 10)`).Scan(&one); err != nil || one != 0 {
		t.Fatalf("second call deleted %d err %v", one, err)
	}
}

func TestNewPrunerRefusesBelowMinimum(t *testing.T) {
	if _, err := NewPruner(nil, PruneOptions{Retention: 24 * time.Hour}); err == nil || !strings.Contains(err.Error(), "minimum") {
		t.Fatalf("err = %v", err)
	}
	p, err := NewPruner(nil, PruneOptions{})
	if err != nil || p.opt.Retention != DefaultRetention {
		t.Fatalf("default: %v %v", p, err)
	}
	if _, err := NewPruner(nil, PruneOptions{Retention: MinRetention}); err != nil {
		t.Fatal(err)
	}
}

func TestRelayKeepsPublishingWhilePruning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := dbtest.New(t)
	for range 300 {
		seedRow(t, pool, TopicSweeps, 40*day, 0)
	}
	writeEvents(t, pool, TopicDeposits, make([]string, 50)...)
	pub := &fakePub{}
	r := NewRelay(pool, pub, RelayOptions{BatchSize: 10, Idle: 5 * time.Millisecond})
	p, err := NewPruner(pool, PruneOptions{Retention: 30 * day, Batch: 20, Pause: time.Millisecond, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 2)
	go func() { r.Run(ctx); done <- struct{}{} }()
	go func() { p.Run(ctx); done <- struct{}{} }()
	for {
		var pending, old int
		pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE published_at IS NULL), count(*) FILTER (WHERE created_at < now() - interval '300 days') FROM outbox`).Scan(&pending, &old)
		if pending == 0 && old == 0 {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("pending %d, old rows %d", pending, old)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	<-done
	if len(pub.events) != 50 {
		t.Fatalf("published %d, want 50", len(pub.events))
	}
}
