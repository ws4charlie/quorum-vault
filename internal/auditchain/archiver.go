package auditchain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// ArchiverOptions tunes an Archiver.
type ArchiverOptions struct {
	Brokers   []string
	Group     string        // consumer group, default "qv-anchor-archiver"
	Topic     string        // default outbox.TopicAuditHeads
	Retention time.Duration // the bucket's default COMPLIANCE retention must be at least this; checked at start
	Retry     time.Duration // wait after a failed store before the same head is tried again, default 2s
	Logger    *slog.Logger
}

// Archiver copies every head published on qv.audit.heads into an Archive, one object per head. It runs outside the signing zones: it holds
// credentials to the archive only (read and put) and reads the topic, and nothing a zone does waits for it.
//
// A record's Kafka offset is committed only after its head is stored (or was already), so a crash or restart replays records, and a
// replay writes the same keys: nothing is lost and nothing is stored twice.
type Archiver struct {
	arch Archive
	opt  ArchiverOptions

	stored, duplicates atomic.Int64
	storeErrors        atomic.Int64
	badRecords         atomic.Int64
	lagRecords         atomic.Int64
	lastProgress       atomic.Int64 // unix nanoseconds of the last commit, or the start
	mu                 sync.Mutex
	lastArchived       map[string]time.Time // per source: the At of the newest archived head
}

// NewArchiver does not touch the archive; Run checks the bucket first.
func NewArchiver(arch Archive, opt ArchiverOptions) *Archiver {
	if opt.Group == "" {
		opt.Group = "qv-anchor-archiver"
	}
	if opt.Topic == "" {
		opt.Topic = outbox.TopicAuditHeads
	}
	if opt.Retry <= 0 {
		opt.Retry = 2 * time.Second
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	a := &Archiver{arch: arch, opt: opt, lastArchived: map[string]time.Time{}}
	a.lastProgress.Store(time.Now().UnixNano())
	return a
}

// CheckBucket refuses a bucket that is not locked in COMPLIANCE mode with a retention of at least the configured one.
func (a *Archiver) CheckBucket(ctx context.Context) error {
	if a.opt.Retention <= 0 {
		return errors.New("archiver: a retention is required")
	}
	return a.arch.CheckLock(ctx, a.opt.Retention)
}

// Handle archives the head in one record value. A value that is not a head is counted and skipped (permanent: retrying cannot help);
// a store that fails returns the error, to be retried with the same value.
func (a *Archiver) Handle(ctx context.Context, value []byte) error {
	as, err := audit.ReadAnchors(strings.NewReader(string(value)), "")
	if err != nil || len(as) != 1 {
		a.badRecords.Add(1)
		a.opt.Logger.Warn("record on the heads topic is not a head; skipped", "bytes", len(value))
		return nil
	}
	h := as[0]
	if _, err := ArchiveKey(h); err != nil {
		a.badRecords.Add(1)
		a.opt.Logger.Warn("record on the heads topic is not an archivable head; skipped", "error", err.Error())
		return nil
	}
	stored, err := a.arch.Put(ctx, h)
	if err != nil {
		a.storeErrors.Add(1)
		return err
	}
	if stored {
		a.stored.Add(1)
	} else {
		a.duplicates.Add(1)
	}
	a.mu.Lock()
	if h.At.After(a.lastArchived[h.Source]) {
		a.lastArchived[h.Source] = h.At
	}
	a.mu.Unlock()
	return nil
}

// Run checks the bucket, then consumes until ctx ends. It returns an error only when the bucket is refused or the consumer cannot start.
func (a *Archiver) Run(ctx context.Context) error {
	if err := a.CheckBucket(ctx); err != nil {
		return err
	}
	cl, err := kgo.NewClient(kgo.SeedBrokers(a.opt.Brokers...), kgo.ConsumerGroup(a.opt.Group), kgo.ConsumeTopics(a.opt.Topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()), kgo.DisableAutoCommit(), kgo.BlockRebalanceOnPoll())
	if err != nil {
		return fmt.Errorf("archiver: kafka client: %w", err)
	}
	defer cl.Close()
	defer cl.AllowRebalance() // runs before Close: a poll that was cut short leaves rebalances blocked, and Close would wait for them
	go a.watchLag(ctx, kadm.NewClient(cl))
	a.opt.Logger.Info("qv-anchor-archiver started", "topic", a.opt.Topic, "group", a.opt.Group)
	for ctx.Err() == nil {
		fetches := cl.PollRecords(ctx, 200)
		if ctx.Err() != nil {
			break
		}
		fetches.EachError(func(topic string, p int32, err error) {
			a.opt.Logger.Warn("kafka fetch failed", "topic", topic, "partition", p, "error", err.Error())
		})
		recs := fetches.Records()
		for _, r := range recs {
			for {
				err := a.Handle(ctx, r.Value)
				if err == nil || ctx.Err() != nil {
					break
				}
				a.opt.Logger.Warn("head not archived; will retry", "error", err.Error())
				select {
				case <-ctx.Done():
				case <-time.After(a.opt.Retry):
				}
			}
			if ctx.Err() != nil {
				break
			}
		}
		if ctx.Err() == nil && len(recs) > 0 {
			// the offset moves only now, after every head of the batch is in the archive
			if err := cl.CommitRecords(ctx, recs...); err != nil {
				a.opt.Logger.Warn("offset commit failed; the batch will be replayed", "error", err.Error())
			} else {
				a.lastProgress.Store(time.Now().UnixNano())
			}
		}
		cl.AllowRebalance()
	}
	return nil
}

// watchLag keeps the lag between the end of the topic and the committed offset.
func (a *Archiver) watchLag(ctx context.Context, adm *kadm.Client) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		if lags, err := adm.Lag(lctx, a.opt.Group); err == nil {
			var n int64
			if l, ok := lags[a.opt.Group]; ok && l.Error() == nil {
				n = l.Lag.Total()
			}
			a.lagRecords.Store(n)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Metrics renders the Prometheus text exposition.
func (a *Archiver) Metrics() string {
	var b strings.Builder
	lag := a.lagRecords.Load()
	var lagSec float64
	if lag > 0 { // how long nothing has been committed while heads wait
		lagSec = time.Since(time.Unix(0, a.lastProgress.Load())).Seconds()
	}
	fmt.Fprintf(&b, "# HELP qv_audit_archive_lag_records Heads published on the topic and not yet archived (end of topic minus committed offset).\n# TYPE qv_audit_archive_lag_records gauge\nqv_audit_archive_lag_records %d\n", lag)
	fmt.Fprintf(&b, "# HELP qv_audit_archive_lag_seconds Seconds since the last archived batch while heads wait; 0 when none waits.\n# TYPE qv_audit_archive_lag_seconds gauge\nqv_audit_archive_lag_seconds %.0f\n", lagSec)
	fmt.Fprintf(&b, "# HELP qv_audit_archive_heads_stored_total Heads written to the archive since start.\n# TYPE qv_audit_archive_heads_stored_total counter\nqv_audit_archive_heads_stored_total %d\n", a.stored.Load())
	fmt.Fprintf(&b, "# HELP qv_audit_archive_heads_duplicate_total Heads that were already in the archive (replays, repeated heads) since start.\n# TYPE qv_audit_archive_heads_duplicate_total counter\nqv_audit_archive_heads_duplicate_total %d\n", a.duplicates.Load())
	fmt.Fprintf(&b, "# HELP qv_audit_archive_errors_total Failures since start: store (the archive refused or was unreachable, retried) and record (a value on the topic that is not a head, skipped).\n# TYPE qv_audit_archive_errors_total counter\nqv_audit_archive_errors_total{kind=\"store\"} %d\nqv_audit_archive_errors_total{kind=\"record\"} %d\n", a.storeErrors.Load(), a.badRecords.Load())
	a.mu.Lock()
	srcs := make([]string, 0, len(a.lastArchived))
	for s := range a.lastArchived {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	b.WriteString("# HELP qv_audit_archive_last_head_timestamp_seconds Publication time of the newest archived head, per source.\n# TYPE qv_audit_archive_last_head_timestamp_seconds gauge\n")
	for _, s := range srcs {
		fmt.Fprintf(&b, "qv_audit_archive_last_head_timestamp_seconds{source=%q} %d\n", s, a.lastArchived[s].Unix())
	}
	a.mu.Unlock()
	return b.String()
}

// MetricsHandler serves Metrics.
func (a *Archiver) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		io.WriteString(w, a.Metrics())
	})
}
