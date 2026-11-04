package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// Errors beyond the frozen sentinels in ledger.go.
var (
	ErrAccountNotFound = errors.New("ledger: account not found")
	ErrHoldNotFound    = errors.New("ledger: hold not found")
	ErrInvalidRequest  = errors.New("ledger: invalid request")
	ErrAccountMismatch = errors.New("ledger: account exists with different fields")
)

// bodyHashKey is the reserved ledger_txns.metadata key holding the request
// body hash. Callers may not use it.
const bodyHashKey = "_qv_body_hash"

// Postgres implements Ledger on the 0002 schema. It is stateless; every call
// runs inside the caller's transaction and never commits or rolls it back.
// Each operation runs in a savepoint, so a failed operation leaves no trace
// (not even its ledger_txns row) even if the caller continues the transaction.
type Postgres struct{}

var _ Ledger = (*Postgres)(nil)

// New returns the Postgres ledger.
func New() *Postgres { return &Postgres{} }

// inSavepoint runs fn in a nested transaction (savepoint) of tx.
func inSavepoint(ctx context.Context, tx pgx.Tx, fn func(pgx.Tx) error) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ledger: savepoint: %w", err)
	}
	if err := fn(sp); err != nil {
		_ = sp.Rollback(ctx)
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return fmt.Errorf("ledger: release savepoint: %w", err)
	}
	return nil
}

func positive(a *big.Int) error {
	if a == nil || a.Sign() <= 0 {
		return fmt.Errorf("%w: amount must be positive", ErrInvalidRequest)
	}
	return nil
}

// bodyHash is the canonical hash of a request body. encoding/json sorts map
// keys, and amounts are hashed as canonical decimal strings, so equal numbers
// hash equally.
func bodyHash(body map[string]any) string {
	b, _ := json.Marshal(body)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func metaOrEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func storedMeta(m map[string]any, hash string) (map[string]any, error) {
	if _, ok := m[bodyHashKey]; ok {
		return nil, fmt.Errorf("%w: metadata key %q is reserved", ErrInvalidRequest, bodyHashKey)
	}
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out[bodyHashKey] = hash
	return out, nil
}

// beginTxn inserts the ledger_txns row. It returns replay=true when the ID
// already exists with an identical body (nothing to do), and
// ErrIdempotencyConflict when the body differs. A concurrent duplicate blocks
// on the unique key until the first transaction finishes.
func beginTxn(ctx context.Context, tx pgx.Tx, id, kind string, meta map[string]any, hash string) (replay bool, err error) {
	if id == "" {
		return false, fmt.Errorf("%w: empty ID", ErrInvalidRequest)
	}
	stored, err := storedMeta(meta, hash)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO ledger_txns (id, kind, metadata) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
		id, kind, stored)
	if err != nil {
		return false, fmt.Errorf("ledger: insert txn: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return false, nil
	}
	var have *string
	err = tx.QueryRow(ctx, `SELECT metadata->>$2 FROM ledger_txns WHERE id = $1`, id, bodyHashKey).Scan(&have)
	if err != nil {
		// Conflicting row not visible (e.g. repeatable read): let the caller retry.
		return false, fmt.Errorf("ledger: read existing txn %q: %w", id, err)
	}
	if have != nil && *have == hash {
		return true, nil
	}
	return false, ErrIdempotencyConflict
}

type lockedAccount struct {
	id            string
	chain, asset  string
	allowNegative bool
	posted, held  *big.Int
}

func (a *lockedAccount) available() *big.Int { return new(big.Int).Sub(a.posted, a.held) }

// lockAccounts takes row locks in sorted ID order and returns the locked rows.
func lockAccounts(ctx context.Context, tx pgx.Tx, ids ...string) (map[string]*lockedAccount, error) {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	out := make(map[string]*lockedAccount, len(sorted))
	for _, id := range sorted {
		if _, dup := out[id]; dup {
			continue
		}
		a := &lockedAccount{id: id}
		var posted, held string
		err := tx.QueryRow(ctx,
			`SELECT chain, asset, allow_negative, posted::text, held::text
			   FROM ledger_accounts WHERE id = $1 FOR UPDATE`, id).
			Scan(&a.chain, &a.asset, &a.allowNegative, &posted, &held)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %q", ErrAccountNotFound, id)
		}
		if err != nil {
			return nil, fmt.Errorf("ledger: lock account %q: %w", id, err)
		}
		var ok1, ok2 bool
		a.posted, ok1 = new(big.Int).SetString(posted, 10)
		a.held, ok2 = new(big.Int).SetString(held, 10)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("ledger: bad numeric for account %q", id)
		}
		out[id] = a
	}
	return out, nil
}

func sameAsset(a, b *lockedAccount) error {
	if a.chain != b.chain || a.asset != b.asset {
		return fmt.Errorf("%w: accounts %q (%s/%s) and %q (%s/%s) differ in chain/asset",
			ErrInvalidRequest, a.id, a.chain, a.asset, b.id, b.chain, b.asset)
	}
	return nil
}

func addPosted(ctx context.Context, tx pgx.Tx, id string, delta *big.Int) error {
	_, err := tx.Exec(ctx, `UPDATE ledger_accounts SET posted = posted + $2::numeric WHERE id = $1`, id, delta.String())
	if err != nil {
		return fmt.Errorf("ledger: update posted %q: %w", id, err)
	}
	return nil
}

func insertEntries(ctx context.Context, tx pgx.Tx, txnID, debit, credit string, amount *big.Int) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO ledger_entries (txn_id, account_id, amount) VALUES ($1, $2, $4::numeric), ($1, $3, $5::numeric)`,
		txnID, debit, credit, new(big.Int).Neg(amount).String(), amount.String())
	if err != nil {
		return fmt.Errorf("ledger: insert entries: %w", err)
	}
	return nil
}

func (Postgres) EnsureAccount(ctx context.Context, tx pgx.Tx, a Account) error {
	if a.ID == "" {
		return fmt.Errorf("%w: empty account ID", ErrInvalidRequest)
	}
	return inSavepoint(ctx, tx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO ledger_accounts (id, kind, chain, asset, customer_id, partition_id, allow_negative)
			 VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7)
			 ON CONFLICT (id) DO NOTHING`,
			a.ID, a.Kind, a.Chain, a.Asset, a.CustomerID, a.PartitionID, a.AllowNegative)
		if err != nil {
			return fmt.Errorf("ledger: ensure account %q: %w", a.ID, err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var have Account
		err = tx.QueryRow(ctx,
			`SELECT kind, chain, asset, COALESCE(customer_id, ''), COALESCE(partition_id, ''), allow_negative
			   FROM ledger_accounts WHERE id = $1`, a.ID).
			Scan(&have.Kind, &have.Chain, &have.Asset, &have.CustomerID, &have.PartitionID, &have.AllowNegative)
		if err != nil {
			return fmt.Errorf("ledger: read account %q: %w", a.ID, err)
		}
		have.ID = a.ID
		if have != a {
			return fmt.Errorf("%w: %q", ErrAccountMismatch, a.ID)
		}
		return nil
	})
}

func (Postgres) Transfer(ctx context.Context, tx pgx.Tx, r TransferReq) error {
	if r.From == r.To {
		return fmt.Errorf("%w: from and to are the same account", ErrInvalidRequest)
	}
	if err := positive(r.Amount); err != nil {
		return err
	}
	hash := bodyHash(map[string]any{
		"kind": "transfer", "from": r.From, "to": r.To,
		"amount": r.Amount.String(), "metadata": metaOrEmpty(r.Metadata),
	})
	return inSavepoint(ctx, tx, func(tx pgx.Tx) error {
		replay, err := beginTxn(ctx, tx, r.ID, "transfer", r.Metadata, hash)
		if err != nil || replay {
			return err
		}
		accts, err := lockAccounts(ctx, tx, r.From, r.To)
		if err != nil {
			return err
		}
		from, to := accts[r.From], accts[r.To]
		if err := sameAsset(from, to); err != nil {
			return err
		}
		if !from.allowNegative && from.available().Cmp(r.Amount) < 0 {
			return ErrInsufficientFunds
		}
		if err := insertEntries(ctx, tx, r.ID, r.From, r.To, r.Amount); err != nil {
			return err
		}
		if err := addPosted(ctx, tx, r.From, new(big.Int).Neg(r.Amount)); err != nil {
			return err
		}
		return addPosted(ctx, tx, r.To, r.Amount)
	})
}

func (Postgres) Hold(ctx context.Context, tx pgx.Tx, r HoldReq) error {
	if r.Account == r.CounterAccount {
		return fmt.Errorf("%w: account and counter account are the same", ErrInvalidRequest)
	}
	if err := positive(r.Amount); err != nil {
		return err
	}
	var exp any
	if r.ExpiresAt != nil {
		exp = r.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	hash := bodyHash(map[string]any{
		"kind": "hold", "account": r.Account, "counter": r.CounterAccount,
		"amount": r.Amount.String(), "expires_at": exp, "metadata": metaOrEmpty(r.Metadata),
	})
	return inSavepoint(ctx, tx, func(tx pgx.Tx) error {
		replay, err := beginTxn(ctx, tx, r.ID, "hold", r.Metadata, hash)
		if err != nil || replay {
			return err
		}
		accts, err := lockAccounts(ctx, tx, r.Account, r.CounterAccount)
		if err != nil {
			return err
		}
		acct, counter := accts[r.Account], accts[r.CounterAccount]
		if err := sameAsset(acct, counter); err != nil {
			return err
		}
		if !acct.allowNegative && acct.available().Cmp(r.Amount) < 0 {
			return ErrInsufficientFunds
		}
		if _, err := tx.Exec(ctx, `UPDATE ledger_accounts SET held = held + $2::numeric WHERE id = $1`,
			r.Account, r.Amount.String()); err != nil {
			return fmt.Errorf("ledger: raise held: %w", err)
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO ledger_holds (id, account_id, counter_account_id, amount, expires_at)
			 VALUES ($1, $2, $3, $4::numeric, $5)`,
			r.ID, r.Account, r.CounterAccount, r.Amount.String(), r.ExpiresAt)
		if err != nil {
			return fmt.Errorf("ledger: insert hold: %w", err)
		}
		return nil
	})
}

func (Postgres) Post(ctx context.Context, tx pgx.Tx, holdID, txnID string) error {
	return settleHold(ctx, tx, holdID, txnID, "post")
}

func (Postgres) Void(ctx context.Context, tx pgx.Tx, holdID, txnID string) error {
	return settleHold(ctx, tx, holdID, txnID, "void")
}

// settleHold implements Post and Void. Lock order: the hold row, then the
// accounts in sorted ID order.
func settleHold(ctx context.Context, tx pgx.Tx, holdID, txnID, kind string) error {
	if txnID == "" {
		return fmt.Errorf("%w: empty ID", ErrInvalidRequest)
	}
	hash := bodyHash(map[string]any{"kind": kind, "hold": holdID})
	return inSavepoint(ctx, tx, func(tx pgx.Tx) error {
		var acctID, counterID, amountStr, status string
		err := tx.QueryRow(ctx,
			`SELECT account_id, counter_account_id, amount::text, status
			   FROM ledger_holds WHERE id = $1 FOR UPDATE`, holdID).
			Scan(&acctID, &counterID, &amountStr, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %q", ErrHoldNotFound, holdID)
		}
		if err != nil {
			return fmt.Errorf("ledger: lock hold %q: %w", holdID, err)
		}
		if status != "pending" {
			var have *string
			err := tx.QueryRow(ctx, `SELECT metadata->>$2 FROM ledger_txns WHERE id = $1`, txnID, bodyHashKey).Scan(&have)
			if err == nil && have != nil && *have == hash {
				return nil // same txnID, same outcome
			}
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("ledger: read txn %q: %w", txnID, err)
			}
			return ErrHoldNotPending
		}
		amount, ok := new(big.Int).SetString(amountStr, 10)
		if !ok {
			return fmt.Errorf("ledger: bad hold amount %q", amountStr)
		}
		// The hold is pending, so an existing txn with this ID is something else.
		replay, err := beginTxn(ctx, tx, txnID, kind, nil, hash)
		if err != nil {
			return err
		}
		if replay {
			return ErrIdempotencyConflict // unreachable in practice: a replay means the hold is settled
		}
		if _, err := lockAccounts(ctx, tx, acctID, counterID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ledger_accounts SET held = held - $2::numeric WHERE id = $1`,
			acctID, amount.String()); err != nil {
			return fmt.Errorf("ledger: lower held: %w", err)
		}
		newStatus := "voided"
		if kind == "post" {
			newStatus = "posted"
			if err := insertEntries(ctx, tx, txnID, acctID, counterID, amount); err != nil {
				return err
			}
			if err := addPosted(ctx, tx, acctID, new(big.Int).Neg(amount)); err != nil {
				return err
			}
			if err := addPosted(ctx, tx, counterID, amount); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE ledger_holds SET status = $2, settled_at = now() WHERE id = $1`,
			holdID, newStatus); err != nil {
			return fmt.Errorf("ledger: settle hold: %w", err)
		}
		return nil
	})
}

func (Postgres) Balance(ctx context.Context, q Querier, accountID string) (Balance, error) {
	var posted, held string
	err := q.QueryRow(ctx, `SELECT posted::text, held::text FROM ledger_accounts WHERE id = $1`, accountID).
		Scan(&posted, &held)
	if errors.Is(err, pgx.ErrNoRows) {
		return Balance{}, fmt.Errorf("%w: %q", ErrAccountNotFound, accountID)
	}
	if err != nil {
		return Balance{}, fmt.Errorf("ledger: balance %q: %w", accountID, err)
	}
	p, ok1 := new(big.Int).SetString(posted, 10)
	h, ok2 := new(big.Int).SetString(held, 10)
	if !ok1 || !ok2 {
		return Balance{}, fmt.Errorf("ledger: bad numeric for account %q", accountID)
	}
	return Balance{Posted: p, Held: h}, nil
}
