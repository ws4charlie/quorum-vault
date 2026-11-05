// Package outbox writes events to the transactional outbox. Write runs inside
// the caller's transaction, so an event exists if and only if the business
// change committed. The polling relay to Kafka is P3.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Topics.
const (
	TopicDeposits    = "qv.deposits"
	TopicWithdrawals = "qv.withdrawals"
	TopicSweeps      = "qv.sweeps"
	TopicColdMoves   = "qv.cold-moves"
	TopicAudit       = "qv.audit"
	// TopicAuditHeads carries the head of each audit chain (audit.Anchor), keyed by source. It leaves the database, so a
	// rewrite of the table disagrees with what was already published.
	TopicAuditHeads = "qv.audit.heads"
)

// Write inserts one event. payload is marshaled to JSON; key is the Kafka
// message key (events with the same key stay ordered).
func Write(ctx context.Context, tx pgx.Tx, topic, key string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("outbox: marshal payload: %w", err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox (id, topic, key, payload) VALUES ($1, $2, $3, $4)`,
		uuid.New(), topic, key, b)
	if err != nil {
		return fmt.Errorf("outbox: insert: %w", err)
	}
	return nil
}

// WriteOnce is Write with an event ID derived from seed, so repeating the same business step (an idempotent call that
// runs again) leaves one row, not two. Use it for an event that has no state change of its own to guard it.
func WriteOnce(ctx context.Context, tx pgx.Tx, seed, topic, key string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("outbox: marshal payload: %w", err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox (id, topic, key, payload) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`,
		uuid.NewSHA1(uuid.NameSpaceOID, []byte(topic+"\x00"+seed)), topic, key, b)
	if err != nil {
		return fmt.Errorf("outbox: insert: %w", err)
	}
	return nil
}
