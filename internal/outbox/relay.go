package outbox

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
)

// Event is one outbox row ready to publish.
type Event struct {
	Seq     int64
	ID      string // event UUID; consumers dedupe on it
	Topic   string
	Key     string
	Payload []byte
}

// Publisher delivers one event and returns only when the broker acknowledged it.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
	Close()
}

// HeaderID is the record header that carries the event ID.
const HeaderID = "id"

// KafkaPublisher publishes with franz-go: idempotent producer (franz-go's
// default, left on), acks from all in-sync replicas, key = outbox key.
type KafkaPublisher struct{ cl *kgo.Client }

// NewKafkaPublisher connects to brokers. Extra options may override defaults.
func NewKafkaPublisher(brokers []string, opts ...kgo.Opt) (*KafkaPublisher, error) {
	base := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.AllowAutoTopicCreation(),
	}
	cl, err := kgo.NewClient(append(base, opts...)...)
	if err != nil {
		return nil, fmt.Errorf("outbox: kafka client: %w", err)
	}
	return &KafkaPublisher{cl: cl}, nil
}

// Publish implements Publisher.
func (p *KafkaPublisher) Publish(ctx context.Context, e Event) error {
	rec := &kgo.Record{
		Topic: e.Topic, Key: []byte(e.Key), Value: e.Payload,
		Headers: []kgo.RecordHeader{{Key: HeaderID, Value: []byte(e.ID)}},
	}
	return p.cl.ProduceSync(ctx, rec).FirstErr()
}

// Close implements Publisher.
func (p *KafkaPublisher) Close() { p.cl.Close() }

// RelayOptions tunes a Relay.
type RelayOptions struct {
	BatchSize   int           // rows per transaction, default 100
	Idle        time.Duration // wait when the outbox is empty, default 500ms
	MinBackoff  time.Duration // first wait after an error, default 200ms
	MaxBackoff  time.Duration // cap of the exponential backoff, default 10s
	PublishWait time.Duration // per-event publish timeout, default 15s
	Logger      *slog.Logger
}

// Relay moves unpublished outbox rows to Kafka, at least once.
//
// It claims rows in seq order with FOR UPDATE SKIP LOCKED inside a
// transaction, publishes them one at a time, and sets published_at for the
// ones acknowledged. If a publish fails it stops: later rows of the batch are
// not sent, so an event never overtakes an earlier one. A crash after a
// publish but before the commit leaves the row unpublished, so the next run
// sends it again with the same event ID (header "id"); consumers dedupe on it.
//
// Several relays may run; they take disjoint batches, so ordering is
// guaranteed within a batch (and so per key for a single relay), not between
// batches of different relays.
type Relay struct {
	pool *pgxpool.Pool
	pub  Publisher
	opt  RelayOptions

	beforeMark func() error // test hook: simulates a crash after publishing
}

// NewRelay returns a Relay.
func NewRelay(pool *pgxpool.Pool, pub Publisher, opt RelayOptions) *Relay {
	if opt.BatchSize <= 0 {
		opt.BatchSize = 100
	}
	if opt.Idle <= 0 {
		opt.Idle = 500 * time.Millisecond
	}
	if opt.MinBackoff <= 0 {
		opt.MinBackoff = 200 * time.Millisecond
	}
	if opt.MaxBackoff <= 0 {
		opt.MaxBackoff = 10 * time.Second
	}
	if opt.PublishWait <= 0 {
		opt.PublishWait = 15 * time.Second
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	return &Relay{pool: pool, pub: pub, opt: opt}
}

// RunOnce publishes one batch and returns how many rows were marked published.
// On a publish error it still marks the events sent before it, then returns
// the error.
func (r *Relay) RunOnce(ctx context.Context) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("outbox: begin: %w", err)
	}
	defer tx.Rollback(context.Background())
	rows, err := tx.Query(ctx, `SELECT seq, id::text, topic, key, payload::text FROM outbox
		WHERE published_at IS NULL ORDER BY seq LIMIT $1 FOR UPDATE SKIP LOCKED`, r.opt.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("outbox: claim: %w", err)
	}
	var batch []Event
	for rows.Next() {
		var e Event
		var payload string
		if err := rows.Scan(&e.Seq, &e.ID, &e.Topic, &e.Key, &payload); err != nil {
			rows.Close()
			return 0, err
		}
		e.Payload = []byte(payload)
		batch = append(batch, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, nil
	}

	var sent []int64
	var pubErr error
	for _, e := range batch {
		pctx, cancel := context.WithTimeout(ctx, r.opt.PublishWait)
		err := r.pub.Publish(pctx, e)
		cancel()
		if err != nil {
			pubErr = fmt.Errorf("outbox: publish seq %d: %w", e.Seq, err)
			break
		}
		sent = append(sent, e.Seq)
	}
	if r.beforeMark != nil {
		if err := r.beforeMark(); err != nil {
			return 0, err // transaction rolls back: rows stay unpublished
		}
	}
	if len(sent) > 0 {
		// Mark with a context that survives shutdown, so a delivered batch is recorded.
		mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, err := tx.Exec(mctx, `UPDATE outbox SET published_at = now() WHERE seq = ANY($1)`, sent); err != nil {
			return 0, fmt.Errorf("outbox: mark published: %w", err)
		}
		if err := tx.Commit(mctx); err != nil {
			return 0, fmt.Errorf("outbox: commit: %w", err)
		}
	}
	return len(sent), pubErr
}

// Run publishes until ctx is cancelled: it drains the outbox, waits Idle when
// it is empty, and backs off exponentially while publishing or the database
// fails. Rows are never dropped; they stay unpublished until delivered.
func (r *Relay) Run(ctx context.Context) error {
	backoff := r.opt.MinBackoff
	for {
		n, err := r.RunOnce(ctx)
		var wait time.Duration
		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			r.opt.Logger.Warn("relay batch failed", "published", n, "error", err.Error(), "retry_in", backoff.String())
			wait = backoff
			if n == 0 {
				backoff = min(backoff*2, r.opt.MaxBackoff)
			} else {
				backoff = r.opt.MinBackoff
			}
		case n == 0:
			backoff, wait = r.opt.MinBackoff, r.opt.Idle
		default:
			backoff = r.opt.MinBackoff
			continue // more may be waiting
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
