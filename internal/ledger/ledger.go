// Package ledger defines the double-entry ledger interface. Frozen after P0;
// changes go through the lead. The Postgres implementation lives in this
// package (P1).
//
// Every write takes the caller's pgx.Tx so business rows, ledger entries and
// the outbox row commit or roll back together. Every request carries an
// idempotency ID: repeating an ID with the same body returns nil and changes
// nothing; repeating it with a different body returns ErrIdempotencyConflict.
// All amounts are base units, always positive in requests.
package ledger

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrInsufficientFunds: the debited account would have a negative available balance.
	ErrInsufficientFunds = errors.New("ledger: insufficient funds")
	// ErrIdempotencyConflict: the ID was used before with a different request body.
	ErrIdempotencyConflict = errors.New("ledger: idempotency key reused with a different request")
	// ErrHoldNotPending: Post or Void on a hold that is already posted or voided.
	ErrHoldNotPending = errors.New("ledger: hold is not pending")
)

// Account kinds, matching ledger_accounts.kind.
const (
	KindCustomer = "customer"
	KindHot      = "hot"
	KindCold     = "cold"
	KindClearing = "clearing"
	KindSuspense = "suspense"
	KindFee      = "fee"
)

// Account is a ledger account. EnsureAccount creates it if missing and is a
// no-op when an identical account exists.
type Account struct {
	ID            string
	Kind          string
	Chain         string
	Asset         string
	CustomerID    string // empty = none
	PartitionID   string // empty = none
	AllowNegative bool
}

// Balance of an account. Available = Posted - Held.
type Balance struct {
	Posted *big.Int
	Held   *big.Int
}

// Available returns Posted - Held.
func (b Balance) Available() *big.Int { return new(big.Int).Sub(b.Posted, b.Held) }

// TransferReq moves Amount from From to To in one balanced transaction.
type TransferReq struct {
	ID       string // idempotency key; becomes ledger_txns.id
	From, To string // account IDs
	Amount   *big.Int
	Metadata map[string]any
}

// HoldReq reserves Amount on Account (reducing its available balance) for a
// later Post to CounterAccount or Void.
type HoldReq struct {
	ID             string // idempotency key; becomes ledger_holds.id and the hold txn ID
	Account        string
	CounterAccount string
	Amount         *big.Int
	ExpiresAt      *time.Time
	Metadata       map[string]any
}

// Querier is the minimal read interface, satisfied by pgx.Tx and *pgxpool.Pool.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Ledger is the double-entry ledger. Keep it narrow enough to swap in another
// backend (e.g. TigerBeetle) if load tests demand it.
type Ledger interface {
	EnsureAccount(ctx context.Context, tx pgx.Tx, a Account) error
	Transfer(ctx context.Context, tx pgx.Tx, r TransferReq) error
	Hold(ctx context.Context, tx pgx.Tx, r HoldReq) error
	// Post settles a pending hold: moves its amount to the counter account
	// under txnID and releases the hold.
	Post(ctx context.Context, tx pgx.Tx, holdID, txnID string) error
	// Void releases a pending hold without moving funds; txnID is the idempotency key.
	Void(ctx context.Context, tx pgx.Tx, holdID, txnID string) error
	Balance(ctx context.Context, q Querier, accountID string) (Balance, error)
}
