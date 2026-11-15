package sol

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Retiring and closing a hot shard's nonce accounts, to get the rent back. Retire takes the account out of the pool: nothing is allocated on it
// any more. Once it is idle (no owner holds it, and the node no longer shows the value of the last owner) it may be closed: the shard withdraws the
// whole balance of the account to itself, signed by the signing zone under an operator's approval.

func (a *Adapter) retiredNonces(ctx context.Context) (map[string]bool, error) {
	rows, err := a.pool.Query(ctx, `SELECT address FROM sol_nonce_accounts WHERE chain=$1 AND retired_at IS NOT NULL`, a.cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out[s] = true
	}
	return out, rows.Err()
}

// RetireNonce takes pool account idx of the partition's shard out of the pool. The last account of a pool is never retired. Repeating it changes
// nothing.
func (a *Adapter) RetireNonce(ctx context.Context, partitionID string, idx int) error {
	hot, ok := a.cfg.hot[partitionID]
	if !ok {
		return fmt.Errorf("sol: partition %q has no hot shard", partitionID)
	}
	if idx < 0 || idx >= a.cfg.NoncePool {
		return fmt.Errorf("sol: pool account %d: the pool has %d", idx, a.cfg.NoncePool)
	}
	addr := Address(NonceAddress(hot, idx))
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var active int
	// every row of the shard is locked, so two retirements cannot each see the other's account as still active
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM sol_nonce_accounts WHERE chain=$1 AND hot_address=$2 AND retired_at IS NULL AND address<>$3 FOR UPDATE) x`,
		a.cfg.Chain, Address(hot), addr).Scan(&active); err != nil {
		return err
	}
	var already bool
	if err := tx.QueryRow(ctx, `SELECT retired_at IS NOT NULL FROM sol_nonce_accounts WHERE chain=$1 AND address=$2 FOR UPDATE`, a.cfg.Chain, addr).Scan(&already); err != nil {
		return fmt.Errorf("sol: pool account %d (%s): %w", idx, addr, err)
	}
	if already {
		return nil
	}
	if active < 1 {
		return fmt.Errorf("sol: pool account %d is the last of its shard's pool: retiring it would leave withdrawals without a nonce", idx)
	}
	if _, err := tx.Exec(ctx, `UPDATE sol_nonce_accounts SET retired_at=now() WHERE chain=$1 AND address=$2`, a.cfg.Chain, addr); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// NonceIdle says whether a retired account may be closed now, and if not why.
func (a *Adapter) NonceIdle(ctx context.Context, partitionID string, idx int) (bool, string, error) {
	hot, ok := a.cfg.hot[partitionID]
	if !ok {
		return false, "", fmt.Errorf("sol: partition %q has no hot shard", partitionID)
	}
	if idx < 0 || idx >= a.cfg.NoncePool {
		return false, "", fmt.Errorf("sol: pool account %d: the pool has %d", idx, a.cfg.NoncePool)
	}
	addr := Address(NonceAddress(hot, idx))
	var retired bool
	var closed *string
	if err := a.pool.QueryRow(ctx, `SELECT retired_at IS NOT NULL, closed_at::text FROM sol_nonce_accounts WHERE chain=$1 AND address=$2`, a.cfg.Chain, addr).Scan(&retired, &closed); err != nil {
		return false, "", err
	}
	if !retired {
		return false, "the account is still in the pool: retire it first", nil
	}
	var open int
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM sol_nonce_allocations WHERE chain=$1 AND address=$2 AND status IN ('allocated','broadcast')`, a.cfg.Chain, addr).Scan(&open); err != nil {
		return false, "", err
	}
	if open > 0 {
		return false, "an owner (a withdrawal, sweep or move) still holds the account", nil
	}
	st, err := a.rpc.GetNonce(ctx, addr, Finalized)
	if errors.Is(err, ErrNoAccount) {
		return true, "", nil
	}
	if err != nil {
		return false, "", err
	}
	// the last owner landed and the node still shows the value it signed: it has not caught up, and a version may still be on its way
	var last string
	if err := a.pool.QueryRow(ctx, `SELECT nonce_value FROM sol_nonce_allocations WHERE chain=$1 AND address=$2 AND status IN ('confirmed','cancelled') ORDER BY id DESC LIMIT 1`,
		a.cfg.Chain, addr).Scan(&last); err == nil && last == Address(st.Value) {
		return false, "the node still shows the value the last owner signed", nil
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, "", err
	}
	return true, "", nil
}

// BuildNonceClose builds the withdrawal of the whole balance of a retired, idle account back to its hot shard, on a recent blockhash, and returns the
// unsigned transaction with the lamports the intent must name.
func (a *Adapter) BuildNonceClose(ctx context.Context, partitionID string, idx int) (chain.UnsignedTx, *big.Int, error) {
	idle, why, err := a.NonceIdle(ctx, partitionID, idx)
	if err != nil {
		return chain.UnsignedTx{}, nil, err
	}
	if !idle {
		return chain.UnsignedTx{}, nil, fmt.Errorf("sol: pool account %d cannot be closed: %s", idx, why)
	}
	hot := a.cfg.hot[partitionID]
	nonce := NonceAddress(hot, idx)
	acct, err := a.rpc.GetAccount(ctx, Address(nonce), Finalized)
	if errors.Is(err, ErrNoAccount) {
		return chain.UnsignedTx{}, nil, ErrNonceGone
	}
	if err != nil {
		return chain.UnsignedTx{}, nil, err
	}
	st, err := ParseNonceAccount(acct.Data)
	if err != nil {
		return chain.UnsignedTx{}, nil, err
	}
	if acct.Owner != SystemProgram || st.Authority != hot {
		return chain.UnsignedTx{}, nil, fmt.Errorf("sol: pool account %d is not a nonce account of its shard", idx)
	}
	bh, err := a.rpc.LatestBlockhash(ctx, Confirmed)
	if err != nil {
		return chain.UnsignedTx{}, nil, err
	}
	ixs := []Ix{SetLimitIx(10_000)}
	if a.cfg.ComputeUnitPrice > 0 {
		ixs = append(ixs, SetPriceIx(a.cfg.ComputeUnitPrice))
	}
	ixs = append(ixs, WithdrawNonceIx(nonce, hot, hot, acct.Lamports))
	msg := Compile(hot, bh, ixs...)
	u, err := a.unsigned(partitionID, msg)
	return u, new(big.Int).SetUint64(acct.Lamports), err
}

// ErrNonceGone: the account to close does not exist (it was closed already).
var ErrNonceGone = errors.New("sol: the nonce account does not exist")

// MarkNonceClosed records that the account is closed.
func (a *Adapter) MarkNonceClosed(ctx context.Context, partitionID string, idx int) error {
	hot := a.cfg.hot[partitionID]
	_, err := a.pool.Exec(ctx, `UPDATE sol_nonce_accounts SET closed_at=COALESCE(closed_at, now()) WHERE chain=$1 AND address=$2 AND retired_at IS NOT NULL`,
		a.cfg.Chain, Address(NonceAddress(hot, idx)))
	return err
}

// RecordNonceCloseTx stores the signature of the close before it is sent, so that a crash after the send can still be booked.
func (a *Adapter) RecordNonceCloseTx(ctx context.Context, partitionID string, idx int, sig string) error {
	hot := a.cfg.hot[partitionID]
	_, err := a.pool.Exec(ctx, `UPDATE sol_nonce_accounts SET close_tx=$3 WHERE chain=$1 AND address=$2 AND retired_at IS NOT NULL`, a.cfg.Chain, Address(NonceAddress(hot, idx)), sig)
	return err
}

// NonceCloseTx is the recorded signature of the close of an account ("" if none).
func (a *Adapter) NonceCloseTx(ctx context.Context, partitionID string, idx int) (string, error) {
	hot := a.cfg.hot[partitionID]
	var s *string
	if err := a.pool.QueryRow(ctx, `SELECT close_tx FROM sol_nonce_accounts WHERE chain=$1 AND address=$2`, a.cfg.Chain, Address(NonceAddress(hot, idx))).Scan(&s); err != nil {
		return "", err
	}
	if s == nil {
		return "", nil
	}
	return *s, nil
}
