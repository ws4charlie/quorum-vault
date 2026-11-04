package custody

import (
	"context"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// Cursor returns the next height Scan should start from.
func (s *Service) Cursor(ctx context.Context) (uint64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT next_height FROM chain_cursors WHERE chain=$1`, s.Cfg.Chain).Scan(&n)
	if isNoRows(err) {
		return s.Cfg.StartHeight, nil
	}
	return uint64(n), err
}

// ScanOnce reads the chain from the stored cursor and, in one transaction,
// inserts every deposit by dedup key, credits the new ones and advances the
// cursor. A crash anywhere repeats the scan from the old cursor; deposits
// already inserted are skipped, so each is credited exactly once.
// It returns the number of deposits newly credited (or sent to suspense).
func (s *Service) ScanOnce(ctx context.Context) (int, error) {
	from, err := s.Cursor(ctx)
	if err != nil {
		return 0, err
	}
	res, err := s.Chain.Scan(ctx, from)
	if err != nil {
		return 0, fmt.Errorf("custody: scan: %w", err)
	}
	return s.ApplyScan(ctx, from, res)
}

// ApplyScan is the transactional half of ScanOnce.
func (s *Service) ApplyScan(ctx context.Context, from uint64, res chain.ScanResult) (int, error) {
	c := s.Cfg
	n := 0
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		n = 0
		if _, err := tx.Exec(ctx, `INSERT INTO chain_cursors (chain, next_height) VALUES ($1,$2) ON CONFLICT DO NOTHING`, c.Chain, int64(from)); err != nil {
			return err
		}
		var cur int64
		if err := tx.QueryRow(ctx, `SELECT next_height FROM chain_cursors WHERE chain=$1 FOR UPDATE`, c.Chain).Scan(&cur); err != nil {
			return err
		}
		if uint64(cur) != from {
			return ErrCursorMoved
		}
		for _, d := range res.Deposits {
			credited, err := s.creditDeposit(ctx, tx, d)
			if err != nil {
				return err
			}
			if credited {
				n++
			}
		}
		if next := res.SafeHeadHeight + 1; next > from {
			if _, err := tx.Exec(ctx, `UPDATE chain_cursors SET next_height=$2, updated_at=now() WHERE chain=$1`, c.Chain, int64(next)); err != nil {
				return err
			}
		}
		return nil
	})
	return n, err
}

// creditDeposit books one observed deposit. Returns false if it was seen before.
func (s *Service) creditDeposit(ctx context.Context, tx pgx.Tx, d chain.ObservedDeposit) (bool, error) {
	c := s.Cfg
	a, ok := c.Assets[d.Asset]
	if !ok {
		return false, fmt.Errorf("custody: deposit %s in unconfigured asset %q", d.DedupKey, d.Asset)
	}
	var customer *string
	err := tx.QueryRow(ctx, `SELECT customer_id FROM deposit_addresses WHERE chain=$1 AND address=$2`, d.Chain, d.Address).Scan(&customer)
	if err != nil && !isNoRows(err) {
		return false, err
	}
	id := "dep:" + d.DedupKey
	status := "credited"
	if customer == nil || d.Amount.Cmp(a.MinDeposit) < 0 {
		status = "suspense"
	}
	tag, err := tx.Exec(ctx, `INSERT INTO deposits (id, chain, asset, address, amount, dedup_key, status, block_height, customer_id, tx_hash)
		VALUES ($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,$10) ON CONFLICT (dedup_key) DO NOTHING`,
		id, d.Chain, d.Asset, d.Address, d.Amount.String(), d.DedupKey, status, int64(d.BlockHeight), customer, d.TxHash)
	if err != nil {
		return false, fmt.Errorf("custody: insert deposit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	to := suspenseAcct(c.Chain, d.Asset)
	if status == "credited" {
		if err := s.ensureCustomerAccount(ctx, tx, *customer, d.Asset); err != nil {
			return false, err
		}
		to = custAcct(*customer, c.Chain, d.Asset)
	}
	meta := map[string]any{"deposit": id, "tx": d.TxHash}
	if err := s.transfer(ctx, tx, "dep-credit:"+id, depAcct(c.Chain, d.Asset), to, d.Amount, meta); err != nil {
		return false, err
	}
	ev := map[string]any{"chain": d.Chain, "asset": d.Asset, "address": d.Address, "amount": d.Amount.String(), "status": status, "tx": d.TxHash, "height": d.BlockHeight}
	if customer != nil {
		ev["customer"] = *customer
	}
	return true, emit(ctx, tx, outbox.TopicDeposits, id, "deposit."+status, ev)
}

func bigOrZero(s *string) *big.Int {
	if s == nil {
		return new(big.Int)
	}
	return parseBig(*s)
}
