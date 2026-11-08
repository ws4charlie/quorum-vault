package btc

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// What the node refused, per owner (btc_refusals). A replacement the node refuses is deleted from btc_attempts, because a row that was never in
// the mempool must not be the newest attempt: it would hide the earlier ones from the rebroadcast and from the outcome check. Deleting it also
// forgets its fee, and the next bump would start again from the last accepted fee and build the same transaction for ever. So the refusal is
// recorded here instead, in a table nothing else reads, and the next fee is built above the highest fee refused for being too low.
//
// Only a refusal about the fee raises the next fee (classifySend). Any other refusal (non-standard, a too long chain of unconfirmed parents,
// anything unknown) is recorded as text for an ALERT and changes nothing else: a higher fee does not cure it.

// market is the fee market as the node reports it, in sat/kvB: the minimum fee its mempool takes now, and its estimate for the next blocks (0: it
// has none).
type market struct {
	MempoolMin int64
	Estimate   int64
}

// marketNow reads the node's fee market. A node that cannot answer gives the zero market, which never counts as a change.
func (a *Adapter) marketNow(ctx context.Context) market {
	var m market
	var info struct {
		MinFee float64 `json:"mempoolminfee"` // BTC per kvB
	}
	if err := a.rpc.Call(ctx, &info, "getmempoolinfo"); err == nil {
		m.MempoolMin = int64(math.Round(info.MinFee * 1e8))
	}
	var est struct {
		FeeRate float64  `json:"feerate"`
		Errors  []string `json:"errors"`
	}
	if err := a.rpc.Call(ctx, &est, "estimatesmartfee", 2); err == nil && est.FeeRate > 0 && len(est.Errors) == 0 {
		m.Estimate = int64(math.Round(est.FeeRate * 1e8))
	}
	return m
}

// lowerThan reports whether the market asks for less than it did at then: the node's minimum fee or its estimate fell. A market that was unknown
// then, or is unknown now, is not lower.
func (m market) lowerThan(then market) bool {
	return (then.MempoolMin > 0 && m.MempoolMin > 0 && m.MempoolMin < then.MempoolMin) ||
		(then.Estimate > 0 && m.Estimate > 0 && m.Estimate < then.Estimate)
}

// refusals is the row of an owner.
type refusals struct {
	Fee         uint64 // the highest fee the node refused for being too low; 0: none (or forgotten, see escalate)
	FeeRefusals int    // how many replacements were refused for the fee
	Other       string // the last refusal that a higher fee does not cure
	Market      market // the fee market at the last fee refusal
}

func (a *Adapter) refusalsOf(ctx context.Context, q chain.Querier, ownerKind, ownerID string) (refusals, error) {
	var r refusals
	var fee int64
	err := q.QueryRow(ctx, `SELECT refused_fee, fee_refusals, other_refusal, mempool_min, estimate FROM btc_refusals WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3`,
		a.cfg.Chain, ownerKind, ownerID).Scan(&fee, &r.FeeRefusals, &r.Other, &r.Market.MempoolMin, &r.Market.Estimate)
	if errors.Is(err, pgx.ErrNoRows) {
		return refusals{}, nil
	}
	r.Fee = uint64(fee)
	return r, err
}

// recordRefusal remembers a refusal of an attempt of the owner. replacement says the refused attempt was deleted (it was not the owner's first).
func (a *Adapter) recordRefusal(ctx context.Context, ownerKind, ownerID string, fee uint64, serr error, replacement bool) error {
	if errors.Is(serr, chain.ErrFeeTooLow) {
		m := a.marketNow(ctx)
		n := 0
		if replacement {
			n = 1
		}
		_, err := a.pool.Exec(ctx, `INSERT INTO btc_refusals (chain, owner_kind, owner_id, refused_fee, fee_refusals, mempool_min, estimate) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (chain, owner_kind, owner_id) DO UPDATE SET refused_fee = GREATEST(btc_refusals.refused_fee, EXCLUDED.refused_fee),
			fee_refusals = btc_refusals.fee_refusals + EXCLUDED.fee_refusals, mempool_min = EXCLUDED.mempool_min, estimate = EXCLUDED.estimate, updated_at = now()`,
			a.cfg.Chain, ownerKind, ownerID, int64(fee), n, m.MempoolMin, m.Estimate)
		return err
	}
	_, err := a.pool.Exec(ctx, `INSERT INTO btc_refusals (chain, owner_kind, owner_id, other_refusal) VALUES ($1,$2,$3,$4)
		ON CONFLICT (chain, owner_kind, owner_id) DO UPDATE SET other_refusal = EXCLUDED.other_refusal, updated_at = now()`,
		a.cfg.Chain, ownerKind, ownerID, serr.Error())
	return err
}

// forgetRefusals removes the row of an owner that is settled or released.
func (a *Adapter) forgetRefusals(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) error {
	_, err := tx.Exec(ctx, `DELETE FROM btc_refusals WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3`, a.cfg.Chain, ownerKind, ownerID)
	return err
}

// escalate is the fee of the owner's next replacement: the replacement rule applied to the higher of the last accepted fee (oldFee) and the highest
// refused one, so that every attempt pays strictly more than any the node refused. within is the builder's own caps (the fee cap and the fee rate
// ceiling, and a sweep's or a consolidation's own ceiling): it returns chain.ErrCannotBump for a fee over one of them, and a fee is never above them.
//
// The cap is the limit, not the step, with or without refusals: when the next step is over it, the highest fee every cap allows (limit) is tried, if it
// is strictly above the accepted and the highest refused fee and meets the replacement rule against the accepted attempt. A cap at or below the highest refused fee, or below what the rule
// needs, leaves nothing to try; then the following applies.
//
// When the refusals are what pushes the fee past a cap (the next fee from the accepted one would still fit), the cap is not the whole story: the
// refusals were made in a market that may be gone. While the node's minimum fee and its estimate have not fallen, the answer is chain.ErrCannotBump
// (one ALERT in the workflow, and it keeps waiting, nothing is voided). Once either has fallen, the refusals are forgotten and the fee is built
// from the accepted attempt again, so that a fee under the cap may now be accepted.
func (a *Adapter) escalate(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string, oldFee, vs, limit uint64, within func(fee uint64) error) (uint64, error) {
	r, err := a.refusalsOf(ctx, tx, ownerKind, ownerID)
	if err != nil {
		return 0, err
	}
	fee := a.nextFee(ctx, max(oldFee, r.Fee), vs)
	err = within(fee)
	if err == nil {
		return fee, nil
	}
	if limit > max(oldFee, r.Fee) && limit >= oldFee+vs*incrementalRate && within(limit) == nil {
		return limit, nil
	}
	if r.Fee <= oldFee {
		return 0, err // no refusal is involved: the market rule below is about refusals
	}
	if !a.marketNow(ctx).lowerThan(r.Market) {
		return 0, fmt.Errorf("%w: the node refused %d sats as too little and the next step, %d sats, is over a limit (%v); waiting for the fee market to change",
			chain.ErrCannotBump, r.Fee, fee, err)
	}
	fee = a.nextFee(ctx, oldFee, vs)
	if werr := within(fee); werr != nil {
		return 0, werr
	}
	if _, err := tx.Exec(ctx, `UPDATE btc_refusals SET refused_fee = 0, updated_at = now() WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3`, a.cfg.Chain, ownerKind, ownerID); err != nil {
		return 0, err
	}
	return fee, nil
}
