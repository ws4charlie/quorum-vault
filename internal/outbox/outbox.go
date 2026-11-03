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
	TopicAudit       = "qv.audit"
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
