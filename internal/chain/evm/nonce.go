package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
)

// allocateNonce hands out a nonce for from inside the caller's transaction.
//
//   - One writer per address: the evm_nonces row is locked FOR UPDATE until the
//     caller commits or rolls back. The row is created from the chain's pending
//     nonce on first use.
//   - The allocation is a row in evm_nonce_allocations, so the nonce and the
//     counter move together: a rollback releases both and leaves no gap.
//   - The same (ownerKind, ownerID) gets the same nonce back, never a second one.
func (a *Adapter) allocateNonce(ctx context.Context, tx pgx.Tx, from common.Address, ownerKind, ownerID string, tip, feeCap *big.Int) (uint64, error) {
	addr := from.Hex()
	pending, err := a.ec.PendingNonceAt(ctx, from)
	if err != nil {
		return 0, fmt.Errorf("evm: pending nonce: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO evm_nonces (chain, address, next_nonce) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		a.cfg.Chain, addr, int64(pending)); err != nil {
		return 0, fmt.Errorf("evm: init nonce row: %w", err)
	}
	var next int64
	if err := tx.QueryRow(ctx, `SELECT next_nonce FROM evm_nonces WHERE chain=$1 AND address=$2 FOR UPDATE`,
		a.cfg.Chain, addr).Scan(&next); err != nil {
		return 0, fmt.Errorf("evm: lock nonce row: %w", err)
	}
	var have int64
	var status string
	err = tx.QueryRow(ctx, `SELECT nonce, status FROM evm_nonce_allocations
		WHERE chain=$1 AND address=$2 AND owner_kind=$3 AND owner_id=$4 AND status IN ('allocated','broadcast','confirmed')
		ORDER BY nonce LIMIT 1`, a.cfg.Chain, addr, ownerKind, ownerID).Scan(&have, &status)
	switch {
	case err == nil:
		if status == "confirmed" {
			return 0, fmt.Errorf("evm: %s %s already confirmed at nonce %d", ownerKind, ownerID, have)
		}
		if status == "allocated" {
			if _, err := tx.Exec(ctx, `UPDATE evm_nonce_allocations SET max_priority_fee_per_gas=$4, max_fee_per_gas=$5, updated_at=now()
				WHERE chain=$1 AND address=$2 AND nonce=$3`, a.cfg.Chain, addr, have, tip.String(), feeCap.String()); err != nil {
				return 0, err
			}
		}
		return uint64(have), nil
	case !errors.Is(err, pgx.ErrNoRows):
		return 0, fmt.Errorf("evm: look up allocation: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO evm_nonce_allocations
		(chain, address, nonce, owner_kind, owner_id, status, max_priority_fee_per_gas, max_fee_per_gas)
		VALUES ($1,$2,$3,$4,$5,'allocated',$6,$7)`,
		a.cfg.Chain, addr, next, ownerKind, ownerID, tip.String(), feeCap.String()); err != nil {
		return 0, fmt.Errorf("evm: insert allocation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE evm_nonces SET next_nonce=$3, updated_at=now() WHERE chain=$1 AND address=$2`,
		a.cfg.Chain, addr, next+1); err != nil {
		return 0, fmt.Errorf("evm: advance nonce: %w", err)
	}
	return uint64(next), nil
}

// Allocation is one evm_nonce_allocations row as Reconcile reports it.
type Allocation struct {
	Address   string
	Nonce     uint64
	OwnerKind string
	OwnerID   string
	Status    string
	TxHash    string // comma-separated when the transaction was replaced
	UpdatedAt time.Time
}

// Reconciliation is what Reconcile found.
type Reconciliation struct {
	// Gaps: allocated or broadcast nonces below the chain's confirmed nonce
	// that are not confirmed: someone else used the nonce, or the hash was lost.
	Gaps []Allocation
	// Stuck: allocations at or above the confirmed nonce that have not moved
	// for StuckAfterBlocks blocks (measured by the timestamp of the block that
	// many blocks behind the head, since the table stores a time, not a height).
	Stuck []Allocation
}

// Reconcile compares allocations with the chain. Allocations whose recorded
// transaction has mined (even reverted) are marked confirmed instead of
// reported.
func (a *Adapter) Reconcile(ctx context.Context) (Reconciliation, error) {
	var out Reconciliation
	head, safe, ok, err := a.safeHead(ctx)
	if err != nil {
		return out, err
	}
	var cutoff *time.Time
	if head >= a.cfg.StuckAfterBlocks {
		h, err := a.ec.HeaderByNumber(ctx, new(big.Int).SetUint64(head-a.cfg.StuckAfterBlocks))
		if err != nil {
			return out, fmt.Errorf("evm: header: %w", err)
		}
		t := time.Unix(int64(h.Time), 0)
		cutoff = &t
	}
	rows, err := a.pool.Query(ctx, `SELECT address, nonce, owner_kind, owner_id, status, COALESCE(tx_hash,''), updated_at
		FROM evm_nonce_allocations WHERE chain=$1 AND status IN ('allocated','broadcast') ORDER BY address, nonce`, a.cfg.Chain)
	if err != nil {
		return out, err
	}
	var all []Allocation
	for rows.Next() {
		var al Allocation
		var n int64
		if err := rows.Scan(&al.Address, &n, &al.OwnerKind, &al.OwnerID, &al.Status, &al.TxHash, &al.UpdatedAt); err != nil {
			rows.Close()
			return out, err
		}
		al.Nonce = uint64(n)
		all = append(all, al)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	confirmed := map[string]uint64{}
	for _, al := range all {
		cn, seen := confirmed[al.Address]
		if !seen {
			if ok {
				if cn, err = a.ec.NonceAt(ctx, common.HexToAddress(al.Address), new(big.Int).SetUint64(safe)); err != nil {
					return out, fmt.Errorf("evm: nonce: %w", err)
				}
			}
			confirmed[al.Address] = cn
		}
		if al.Nonce < cn {
			if a.mined(ctx, al.TxHash, safe) {
				a.markConfirmed(ctx, lastHash(al.TxHash))
				continue
			}
			out.Gaps = append(out.Gaps, al)
			continue
		}
		if cutoff != nil && !al.UpdatedAt.After(*cutoff) {
			out.Stuck = append(out.Stuck, al)
		}
	}
	return out, nil
}

func lastHash(csv string) string {
	for i := len(csv) - 1; i >= 0; i-- {
		if csv[i] == ',' {
			return csv[i+1:]
		}
	}
	return csv
}

// mined reports whether any recorded hash has a receipt at or below safe.
func (a *Adapter) mined(ctx context.Context, csv string, safe uint64) bool {
	for len(csv) > 0 {
		h := lastHash(csv)
		if h != "" {
			if r, err := a.ec.TransactionReceipt(ctx, common.HexToHash(h)); err == nil && r.BlockNumber.Uint64() <= safe {
				return true
			}
		}
		if len(csv) <= len(h) {
			break
		}
		csv = csv[:len(csv)-len(h)-1]
	}
	return false
}
