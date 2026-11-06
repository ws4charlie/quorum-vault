package btc

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// safeHeight is the highest block with Confirmations confirmations when the tip is at height tip: tip - confirmations + 1.
// ok is false while the chain is shorter than that.
func (a *Adapter) safeHeight(tip int64) (uint64, bool) {
	s := tip - int64(a.cfg.Confirmations) + 1
	if s < 0 {
		return 0, false
	}
	return uint64(s), true
}

// SafeHead is the highest block with enough confirmations to credit.
func (a *Adapter) SafeHead(ctx context.Context) (uint64, error) {
	tip, err := a.rpc.BlockCount(ctx)
	if err != nil {
		return 0, err
	}
	h, _ := a.safeHeight(tip)
	return h, nil
}

// Scan reads whole blocks from fromHeight up to the safe head (and at most BatchBlocks of them) and returns the outputs that
// pay a deposit address. Dedup key chain:txid:vout, so two outputs of one transaction are two deposits.
//
// It is repeatable: the same blocks give the same deposits. Before reading, it checks that the chain still contains the block
// the previous scan ended on, and that every block's parent is the block before it. A block that is gone is a reorganization
// deeper than the safe depth: Scan returns chain.ErrReorgTooDeep and credits nothing.
//
// A coinbase output is credited only at CoinbaseMaturity confirmations: while it is younger it is returned in Deferred, with the
// height the scan must cover before it is credited.
//
// When nothing can be read yet, SafeHeadHeight is fromHeight-1 (the cursor does not move); at fromHeight 0 it is 0, which skips
// the genesis block, whose output cannot be spent.
func (a *Adapter) Scan(ctx context.Context, fromHeight uint64) (chain.ScanResult, error) {
	tip, err := a.rpc.BlockCount(ctx)
	if err != nil {
		return chain.ScanResult{}, err
	}
	var prevHash string
	if fromHeight > 0 {
		var stored string
		err := a.pool.QueryRow(ctx, `SELECT hash FROM scanned_blocks WHERE chain=$1 AND height=$2`, a.cfg.Chain, int64(fromHeight-1)).Scan(&stored)
		switch {
		case err == nil:
			now, err := a.rpc.BlockHash(ctx, fromHeight-1)
			if err != nil {
				return chain.ScanResult{}, err
			}
			if now != stored {
				return chain.ScanResult{}, fmt.Errorf("%w: block %d was %s, the node now has %s", chain.ErrReorgTooDeep, fromHeight-1, stored, now)
			}
			prevHash = stored
		case errors.Is(err, pgx.ErrNoRows): // the first scan, from a configured start height
		default:
			return chain.ScanResult{}, err
		}
	}
	res := chain.ScanResult{SafeHeadHeight: fromHeight}
	if fromHeight > 0 {
		res.SafeHeadHeight = fromHeight - 1
	}
	safe, ok := a.safeHeight(tip)
	if !ok || fromHeight > safe {
		return res, nil
	}
	end := min(safe, fromHeight+a.cfg.BatchBlocks-1)
	for h := fromHeight; h <= end; h++ {
		hash, err := a.rpc.BlockHash(ctx, h)
		if err != nil {
			return chain.ScanResult{}, err
		}
		blk, err := a.rpc.GetBlock(ctx, hash)
		if err != nil {
			return chain.ScanResult{}, err
		}
		if blk.Hash != hash || (prevHash != "" && blk.Previous != prevHash) {
			return chain.ScanResult{}, fmt.Errorf("%w: block %d (%s) does not follow %s", chain.ErrReorgTooDeep, h, blk.Hash, prevHash)
		}
		if err := a.matchBlock(ctx, blk, h, tip, &res); err != nil {
			return chain.ScanResult{}, err
		}
		res.Blocks = append(res.Blocks, chain.ScannedBlock{Height: h, Hash: blk.Hash})
		res.SafeHeadHeight = h
		prevHash = blk.Hash
	}
	return res, nil
}

// matchBlock adds the outputs of blk that pay a deposit address to res.
func (a *Adapter) matchBlock(ctx context.Context, blk Block, h uint64, tip int64, res *chain.ScanResult) error {
	var cands []string
	for _, tx := range blk.Tx {
		for _, o := range tx.Vout {
			if o.ScriptPubKey.Address != "" { // OP_RETURN and other scripts without an address are ignored
				cands = append(cands, o.ScriptPubKey.Address)
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	rows, err := a.pool.Query(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 AND address = ANY($2)`, a.cfg.Chain, cands)
	if err != nil {
		return fmt.Errorf("btc: read deposit addresses: %w", err)
	}
	ours := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		ours[s] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, tx := range blk.Tx {
		coinbase := len(tx.Vin) > 0 && tx.Vin[0].Coinbase != ""
		for _, o := range tx.Vout {
			if !ours[o.ScriptPubKey.Address] {
				continue
			}
			amt, err := Sats(o.Value.String())
			if err != nil {
				return fmt.Errorf("btc: tx %s output %d: %w", tx.Txid, o.N, err)
			}
			if amt.Sign() <= 0 {
				continue
			}
			d := chain.ObservedDeposit{Chain: a.cfg.Chain, Asset: Native, Address: o.ScriptPubKey.Address, Amount: new(big.Int).Set(amt),
				BlockHeight: h, TxHash: tx.Txid, DedupKey: fmt.Sprintf("%s:%s:%d", a.cfg.Chain, tx.Txid, o.N)}
			if coinbase && tip-int64(h)+1 < CoinbaseMaturity {
				// Mature when the tip is at h+CoinbaseMaturity-1; the scan covers up to tip-Confirmations+1 by then.
				rel := int64(h) + CoinbaseMaturity - int64(a.cfg.Confirmations)
				res.Deferred = append(res.Deferred, chain.DeferredDeposit{Deposit: d, ReleaseAt: uint64(max(rel, int64(h)))})
				continue
			}
			res.Deposits = append(res.Deposits, d)
		}
	}
	return nil
}
