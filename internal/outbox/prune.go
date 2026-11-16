package outbox

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Retention limits. The database enforces MinRetention too (outbox_prune and the outbox trigger), whatever is configured.
const (
	MinRetention     = 7 * 24 * time.Hour
	DefaultRetention = 30 * 24 * time.Hour
)

// PruneOptions tunes a Pruner.
type PruneOptions struct {
	Retention time.Duration // 0 means DefaultRetention; below MinRetention is refused
	Interval  time.Duration // between runs, default 1h
	Batch     int           // rows per DELETE statement (the database caps it at 10000), default 1000
	Pause     time.Duration // between batches of one run, default 100ms
	Logger    *slog.Logger
}

// Pruner removes old published outbox rows through outbox_prune(): only rows that are published, chained (audit topic) and
// older than the retention, in bounded batches. It never touches unpublished rows or audit_log.
type Pruner struct {
	pool *pgxpool.Pool
	opt  PruneOptions

	deleted atomic.Int64 // rows deleted since start
	runs    atomic.Int64
	oldest  atomic.Int64 // age in seconds of the oldest published row left at the last run, -1 if none or unknown
}

// NewPruner validates the options and returns a Pruner.
func NewPruner(pool *pgxpool.Pool, opt PruneOptions) (*Pruner, error) {
	if opt.Retention == 0 {
		opt.Retention = DefaultRetention
	}
	if opt.Retention < MinRetention {
		return nil, fmt.Errorf("outbox: prune retention %s is below the minimum %s", opt.Retention, MinRetention)
	}
	if opt.Interval <= 0 {
		opt.Interval = time.Hour
	}
	if opt.Batch <= 0 {
		opt.Batch = 1000
	}
	if opt.Pause <= 0 {
		opt.Pause = 100 * time.Millisecond
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	p := &Pruner{pool: pool, opt: opt}
	p.oldest.Store(-1)
	return p, nil
}

// PruneOnce deletes eligible rows batch by batch until a batch comes back short, and returns the total.
func (p *Pruner) PruneOnce(ctx context.Context) (int64, error) {
	var total int64
	for {
		var n int64
		err := p.pool.QueryRow(ctx, `SELECT outbox_prune(make_interval(secs => $1), $2)`,
			p.opt.Retention.Seconds(), p.opt.Batch).Scan(&n)
		if err != nil {
			p.deleted.Add(total)
			return total, fmt.Errorf("outbox: prune: %w", err)
		}
		total += n
		if n < int64(min(p.opt.Batch, 10000)) {
			break
		}
		select {
		case <-ctx.Done():
			p.deleted.Add(total)
			return total, ctx.Err()
		case <-time.After(p.opt.Pause):
		}
	}
	p.deleted.Add(total)
	p.runs.Add(1)
	var age *float64
	if err := p.pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM now() - min(published_at)) FROM outbox WHERE published_at IS NOT NULL`).Scan(&age); err == nil {
		if age == nil {
			p.oldest.Store(-1)
		} else {
			p.oldest.Store(int64(*age))
		}
	}
	return total, nil
}

// Run prunes once at start and then every Interval until ctx is cancelled. A failed run is logged and retried at the next tick.
func (p *Pruner) Run(ctx context.Context) {
	for {
		n, err := p.PruneOnce(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			p.opt.Logger.Warn("outbox prune failed", "deleted", n, "error", err.Error())
		default:
			p.opt.Logger.Info("outbox pruned", "deleted", n, "retention", p.opt.Retention.String(),
				"oldest_published_age_seconds", p.oldest.Load())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.opt.Interval):
		}
	}
}

// MetricsHandler serves the pruner's numbers in the Prometheus text format.
func (p *Pruner) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		io.WriteString(w, p.Metrics())
	})
}

// Metrics renders the Prometheus text exposition.
func (p *Pruner) Metrics() string {
	return fmt.Sprintf(`# HELP qv_outbox_pruned_rows_total Outbox rows deleted by the pruner since start.
# TYPE qv_outbox_pruned_rows_total counter
qv_outbox_pruned_rows_total %d
# HELP qv_outbox_prune_runs_total Completed prune runs since start.
# TYPE qv_outbox_prune_runs_total counter
qv_outbox_prune_runs_total %d
# HELP qv_outbox_oldest_published_age_seconds Age of the oldest published outbox row left after the last prune run (-1: none or not yet known).
# TYPE qv_outbox_oldest_published_age_seconds gauge
qv_outbox_oldest_published_age_seconds %d
`, p.deleted.Load(), p.runs.Load(), p.oldest.Load())
}
