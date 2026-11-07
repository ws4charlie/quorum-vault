package custody

import (
	"context"
	"encoding/json"
	"errors"
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
	if halted, reason, err := s.ScanHalted(ctx); err != nil {
		return 0, err
	} else if halted {
		return 0, fmt.Errorf("%w: %s", ErrScanHalted, reason)
	}
	from, err := s.Cursor(ctx)
	if err != nil {
		return 0, err
	}
	res, err := s.Chain.Scan(ctx, from)
	if errors.Is(err, chain.ErrReorgTooDeep) {
		// The chain no longer holds blocks that were read and credited from. Nothing is reversed: scanning for this chain stops
		// and an operator looks. The row is the stop; deleting it resumes.
		if herr := s.haltScan(ctx, err.Error()); herr != nil {
			return 0, herr
		}
		return 0, fmt.Errorf("%w: %s", ErrScanHalted, err.Error())
	}
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
		for _, f := range res.Funding {
			rec, ok := s.Chain.(chain.FundingRecorder)
			if !ok {
				return fmt.Errorf("custody: the scan found funding of %s but the chain cell cannot record it", f.Address)
			}
			inserted, err := rec.RecordFunding(ctx, tx, f)
			if err != nil {
				return err
			}
			if !inserted {
				continue // seen before: booked before
			}
			key := fmt.Sprintf("%s:%s:%d", f.Chain, f.TxHash, f.Vout)
			if f.Cold {
				// The operator put its own money on a cold address: the cold account falls by the amount (cold holds minus its balance).
				if err := s.transfer(ctx, tx, "cold-fund:"+key, coldAcct(f.PartitionID), opFundAcct(c.Chain, f.Asset), f.Amount, map[string]any{"tx": f.TxHash, "vout": f.Vout, "kind": "cold_funding"}); err != nil {
					return err
				}
				if err := emit(ctx, tx, outbox.TopicDeposits, "cold-fund:"+key, "cold.funded", map[string]any{"chain": f.Chain, "asset": f.Asset, "partition": f.PartitionID,
					"address": f.Address, "amount": f.Amount.String(), "tx": f.TxHash, "vout": f.Vout, "height": f.BlockHeight}); err != nil {
					return err
				}
				n++
				continue
			}
			// The operator put its own money on a hot address: the hot mirror falls by the amount, the operator's account rises.
			if err := s.transfer(ctx, tx, "hot-fund:"+key, hotAcct(f.PartitionID), opFundAcct(c.Chain, f.Asset), f.Amount, map[string]any{"tx": f.TxHash, "vout": f.Vout, "kind": "hot_funding"}); err != nil {
				return err
			}
			if err := emit(ctx, tx, outbox.TopicDeposits, "hot-fund:"+key, "hot.funded", map[string]any{"chain": f.Chain, "asset": f.Asset, "partition": f.PartitionID,
				"address": f.Address, "amount": f.Amount.String(), "tx": f.TxHash, "vout": f.Vout, "height": f.BlockHeight}); err != nil {
				return err
			}
			n++
		}
		for _, b := range res.Blocks {
			if _, err := tx.Exec(ctx, `INSERT INTO scanned_blocks (chain, height, hash) VALUES ($1,$2,$3)
				ON CONFLICT (chain, height) DO UPDATE SET hash = EXCLUDED.hash, scanned_at = now()`, c.Chain, int64(b.Height), b.Hash); err != nil {
				return err
			}
		}
		for _, d := range res.Deferred {
			raw, err := json.Marshal(d.Deposit)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO deferred_deposits (dedup_key, chain, release_at, deposit) VALUES ($1,$2,$3,$4::jsonb)
				ON CONFLICT (dedup_key) DO NOTHING`, d.Deposit.DedupKey, c.Chain, int64(d.ReleaseAt), string(raw)); err != nil {
				return err
			}
		}
		covered := int64(from) - 1
		if next := res.SafeHeadHeight + 1; next > from {
			covered = int64(res.SafeHeadHeight)
			if _, err := tx.Exec(ctx, `UPDATE chain_cursors SET next_height=$2, updated_at=now() WHERE chain=$1`, c.Chain, int64(next)); err != nil {
				return err
			}
		}
		// Deferred deposits whose release height the scan now covers are credited, once.
		rows, err := tx.Query(ctx, `SELECT dedup_key, deposit FROM deferred_deposits WHERE chain=$1 AND release_at <= $2 ORDER BY release_at, dedup_key`, c.Chain, covered)
		if err != nil {
			return err
		}
		var due []chain.ObservedDeposit
		for rows.Next() {
			var key string
			var raw []byte
			if err := rows.Scan(&key, &raw); err != nil {
				rows.Close()
				return err
			}
			var d chain.ObservedDeposit
			if err := json.Unmarshal(raw, &d); err != nil {
				rows.Close()
				return fmt.Errorf("custody: deferred deposit %s: %w", key, err)
			}
			due = append(due, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, d := range due {
			credited, err := s.creditDeposit(ctx, tx, d)
			if err != nil {
				return err
			}
			if credited {
				n++
			}
			if _, err := tx.Exec(ctx, `DELETE FROM deferred_deposits WHERE dedup_key=$1`, d.DedupKey); err != nil {
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
	if status == "credited" {
		if rec, ok := s.Chain.(chain.DepositRecorder); ok { // the cell keeps the output a sweep will spend (Bitcoin); suspense stays where it is
			if err := rec.RecordDeposit(ctx, tx, d); err != nil {
				return false, err
			}
		}
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

// ErrScanHalted is returned while scanning of the chain is stopped by an operator-visible halt (see haltScan).
var ErrScanHalted = errors.New("custody: scanning is halted")

// ScanHalted reports whether scanning of this chain was stopped, and why.
func (s *Service) ScanHalted(ctx context.Context) (bool, string, error) {
	var reason string
	err := s.Pool.QueryRow(ctx, `SELECT reason FROM scan_halts WHERE chain=$1`, s.Cfg.Chain).Scan(&reason)
	if isNoRows(err) {
		return false, "", nil
	}
	return err == nil, reason, err
}

// haltScan records that the chain was rewritten below the safe depth. Already credited deposits stay as they are.
func (s *Service) haltScan(ctx context.Context, reason string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO scan_halts (chain, reason) VALUES ($1,$2) ON CONFLICT (chain) DO NOTHING`, s.Cfg.Chain, reason)
	return err
}
