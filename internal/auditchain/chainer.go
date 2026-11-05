// Package auditchain moves audit events from the outbox into the hash chain, publishes the chain's head, and checks a chain
// against published heads.
//
// Business code writes an audit event to the outbox (topic qv.audit) inside its own transaction, so the event exists exactly
// when the change committed. Taking the chain head inside those transactions would make every one of them wait for the
// previous one, so a single chainer does it afterwards: it picks the rows not yet chained (never "everything after a
// watermark", because a row with a lower seq may commit later) and appends them in seq order.
package auditchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// chainerLock makes sure one chainer works at a time.
const chainerLock = 0x71760011

// ChainerOptions tunes a Chainer.
type ChainerOptions struct {
	BatchSize int           // default 200
	Idle      time.Duration // wait when nothing is waiting, default 500ms
	Backoff   time.Duration // wait after an error, default 1s
	Logger    *slog.Logger
}

// Chainer appends unchained qv.audit outbox rows to audit_log.
type Chainer struct {
	pool *pgxpool.Pool
	opt  ChainerOptions

	beforeCommit func() error // test hook: a crash after appending, before committing
}

// NewChainer returns a Chainer on the business database.
func NewChainer(pool *pgxpool.Pool, opt ChainerOptions) *Chainer {
	if opt.BatchSize <= 0 {
		opt.BatchSize = 200
	}
	if opt.Idle <= 0 {
		opt.Idle = 500 * time.Millisecond
	}
	if opt.Backoff <= 0 {
		opt.Backoff = time.Second
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	return &Chainer{pool: pool, opt: opt}
}

// RunOnce chains one batch and returns how many entries it appended. It returns 0 when another chainer holds the lock.
// Everything happens in one transaction: a crash anywhere leaves the rows unchained and the chain untouched, and the next run
// does the same work again.
func (c *Chainer) RunOnce(ctx context.Context) (int, error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("auditchain: begin: %w", err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, chainerLock).Scan(&got); err != nil {
		return 0, fmt.Errorf("auditchain: lock: %w", err)
	}
	if !got {
		return 0, nil
	}
	type row struct {
		seq     int64
		id, key string
		payload []byte
		at      time.Time
	}
	rows, err := tx.Query(ctx, `SELECT seq, id::text, key, payload::text, created_at FROM outbox
		WHERE topic = $1 AND chained_at IS NULL ORDER BY seq LIMIT $2`, outbox.TopicAudit, c.opt.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("auditchain: select: %w", err)
	}
	var batch []row
	for rows.Next() {
		var r row
		var p string
		if err := rows.Scan(&r.seq, &r.id, &r.key, &p, &r.at); err != nil {
			rows.Close()
			return 0, err
		}
		r.payload = []byte(p)
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range batch {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log WHERE source_id = $1)`, r.id).Scan(&exists); err != nil {
			return 0, err
		}
		if !exists {
			ev, err := Event(r.key, r.payload, r.at)
			if err != nil {
				return 0, fmt.Errorf("auditchain: outbox row %d: %w", r.seq, err)
			}
			if _, err := audit.AppendTx(ctx, tx, ev, r.id); err != nil {
				return 0, fmt.Errorf("auditchain: outbox row %d: %w", r.seq, err)
			}
			n++
		}
		if _, err := tx.Exec(ctx, `UPDATE outbox SET chained_at = now() WHERE seq = $1`, r.seq); err != nil {
			return 0, fmt.Errorf("auditchain: mark chained: %w", err)
		}
	}
	if c.beforeCommit != nil {
		if err := c.beforeCommit(); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("auditchain: commit: %w", err)
	}
	return n, nil
}

// Run chains until ctx ends.
func (c *Chainer) Run(ctx context.Context) error {
	for {
		n, err := c.RunOnce(ctx)
		wait := c.opt.Idle
		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			c.opt.Logger.Warn("audit chainer failed", "error", err.Error())
			wait = c.opt.Backoff
		case n > 0:
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// Event turns an outbox audit payload into a chain entry. The payload must carry "type"; "actor" names who did it (the system
// itself is "system"). The entry keeps the rest of the payload and adds the outbox key as "subject" and the time the business
// transaction wrote the row as "occurred_at".
func Event(key string, payload []byte, at time.Time) (domain.AuditEvent, error) {
	var p map[string]any
	if err := json.Unmarshal(payload, &p); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("payload is not a JSON object: %w", err)
	}
	typ, _ := p["type"].(string)
	if typ == "" {
		return domain.AuditEvent{}, errors.New("payload has no type")
	}
	actor, _ := p["actor"].(string)
	if actor == "" {
		actor = "system"
	}
	delete(p, "actor")
	delete(p, "type")
	p["subject"] = key
	p["occurred_at"] = at.UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(p)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	return domain.AuditEvent{Actor: actor, Type: typ, Payload: b}, nil
}
