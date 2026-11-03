// Package audit is the hash-chained, append-only audit log.
//
// Every row stores prev_hash and
//
//	hash = SHA-256(prev_hash || canonical JSON of {seq, at, actor, type, request_id, wallet_id, key_id, payload})
//
// where canonical JSON is encoding/json of the canonical struct below (fixed
// field order, at as RFC3339Nano UTC). The genesis prev_hash is 32 zero bytes.
// Appends are serialized with a transaction-scoped advisory lock, so seq is
// gap-free and every row links to the one before it. The DB trigger from
// migrations/0001_init.sql rejects UPDATE/DELETE/TRUNCATE; the chain makes any
// edit that bypasses the trigger detectable by Verify.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// appendLockID serializes Append calls across every connection and process.
const appendLockID = 0x71760002

// genesis is the prev_hash of seq 1.
var genesis = make([]byte, sha256.Size)

// Log implements domain.Auditor on the audit_log table.
type Log struct {
	pool *pgxpool.Pool
}

var _ domain.Auditor = (*Log)(nil)

// New returns a Log backed by pool.
func New(pool *pgxpool.Pool) *Log { return &Log{pool: pool} }

// Filter narrows List. Empty fields match everything; Limit 0 = no limit.
type Filter struct {
	RequestID string
	WalletID  string
	Limit     int
}

// canonical is the hashed form of an event. Field order is part of the format.
type canonical struct {
	Seq       int64           `json:"seq"`
	At        string          `json:"at"`
	Actor     string          `json:"actor"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id"`
	WalletID  string          `json:"wallet_id"`
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
}

// computeHash returns SHA-256(prev || canonical JSON of ev).
func computeHash(prev []byte, ev domain.AuditEvent) ([]byte, error) {
	payload := ev.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("null")
	}
	b, err := json.Marshal(canonical{
		Seq:       ev.Seq,
		At:        ev.At.UTC().Format(time.RFC3339Nano),
		Actor:     ev.Actor,
		Type:      ev.Type,
		RequestID: ev.RequestID,
		WalletID:  ev.WalletID,
		KeyID:     ev.KeyID,
		Payload:   payload,
	})
	if err != nil {
		return nil, fmt.Errorf("audit: canonical json: %w", err)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return h.Sum(nil), nil
}

// normUUID returns the canonical lowercase form of an optional UUID.
func normUUID(field, s string) (string, error) {
	if s == "" {
		return "", nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return "", fmt.Errorf("audit: %s %q: %w", field, s, err)
	}
	return u.String(), nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Append stores ev at the end of the chain. Seq, At, PrevHash and Hash are set
// by Append (At = now, truncated to microseconds so it round-trips through
// Postgres exactly); the returned event is exactly what was stored.
func (l *Log) Append(ctx context.Context, ev domain.AuditEvent) (domain.AuditEvent, error) {
	if ev.Actor == "" || ev.Type == "" {
		return domain.AuditEvent{}, errors.New("audit: actor and type are required")
	}
	var err error
	if ev.RequestID, err = normUUID("request_id", ev.RequestID); err != nil {
		return domain.AuditEvent{}, err
	}
	if ev.WalletID, err = normUUID("wallet_id", ev.WalletID); err != nil {
		return domain.AuditEvent{}, err
	}
	if ev.KeyID, err = normUUID("key_id", ev.KeyID); err != nil {
		return domain.AuditEvent{}, err
	}

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return domain.AuditEvent{}, fmt.Errorf("audit: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Store payload in jsonb's normalized text form and hash that same form,
	// so Verify (which reads payload::text back) recomputes identical bytes.
	if len(ev.Payload) == 0 || bytes.Equal(bytes.TrimSpace(ev.Payload), []byte("null")) {
		ev.Payload = nil
	} else {
		var norm string
		if err := tx.QueryRow(ctx, `SELECT $1::jsonb::text`, string(ev.Payload)).Scan(&norm); err != nil {
			return domain.AuditEvent{}, fmt.Errorf("audit: payload is not valid JSON: %w", err)
		}
		ev.Payload = json.RawMessage(norm)
	}

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, appendLockID); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("audit: lock: %w", err)
	}
	var lastSeq int64
	prev := genesis
	err = tx.QueryRow(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return domain.AuditEvent{}, fmt.Errorf("audit: read tail: %w", err)
	}

	ev.Seq = lastSeq + 1
	ev.At = time.Now().UTC().Truncate(time.Microsecond)
	ev.PrevHash = prev
	if ev.Hash, err = computeHash(prev, ev); err != nil {
		return domain.AuditEvent{}, err
	}

	var payload any
	if ev.Payload != nil {
		payload = string(ev.Payload)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(seq, at, actor, type, request_id, wallet_id, key_id, payload, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)`,
		ev.Seq, ev.At, ev.Actor, ev.Type, nullable(ev.RequestID), nullable(ev.WalletID), nullable(ev.KeyID),
		payload, ev.PrevHash, ev.Hash); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("audit: commit: %w", err)
	}
	return ev, nil
}

const selectCols = `seq, at, actor, type, coalesce(request_id::text, ''), coalesce(wallet_id::text, ''),
	coalesce(key_id::text, ''), payload::text, prev_hash, hash`

func scanEvent(row pgx.Row) (domain.AuditEvent, error) {
	var ev domain.AuditEvent
	var payload *string
	if err := row.Scan(&ev.Seq, &ev.At, &ev.Actor, &ev.Type, &ev.RequestID, &ev.WalletID, &ev.KeyID,
		&payload, &ev.PrevHash, &ev.Hash); err != nil {
		return ev, err
	}
	ev.At = ev.At.UTC()
	if payload != nil {
		ev.Payload = json.RawMessage(*payload)
	}
	return ev, nil
}

// List returns the events matching f, ordered by seq.
func (l *Log) List(ctx context.Context, f Filter) ([]domain.AuditEvent, error) {
	q := `SELECT ` + selectCols + ` FROM audit_log
		WHERE ($1 = '' OR request_id::text = $1) AND ($2 = '' OR wallet_id::text = $2)
		ORDER BY seq`
	args := []any{f.RequestID, f.WalletID}
	if f.Limit > 0 {
		q += ` LIMIT $3`
		args = append(args, f.Limit)
	}
	rows, err := l.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("audit: list scan: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// Verify recomputes the chain from genesis. It returns ok=false and the first
// seq whose prev_hash, hash or position (seq must be 1, 2, 3, ...) is wrong.
// An empty log is valid.
func (l *Log) Verify(ctx context.Context) (ok bool, firstBadSeq int64, err error) {
	rows, err := l.pool.Query(ctx, `SELECT `+selectCols+` FROM audit_log ORDER BY seq`)
	if err != nil {
		return false, 0, fmt.Errorf("audit: verify: %w", err)
	}
	defer rows.Close()
	prev := genesis
	var want int64 = 1
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return false, 0, fmt.Errorf("audit: verify scan: %w", err)
		}
		if ev.Seq != want || !bytes.Equal(ev.PrevHash, prev) {
			return false, ev.Seq, nil
		}
		h, err := computeHash(prev, ev)
		if err != nil {
			return false, 0, err
		}
		if !bytes.Equal(h, ev.Hash) {
			return false, ev.Seq, nil
		}
		prev = ev.Hash
		want++
	}
	if err := rows.Err(); err != nil {
		return false, 0, fmt.Errorf("audit: verify: %w", err)
	}
	return true, 0, nil
}
