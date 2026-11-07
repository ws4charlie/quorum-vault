package btc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// OwnerKindConsolidate is the owner kind (attempt owner, sign-job track, intent kind) of a consolidation.
const OwnerKindConsolidate = "consolidate"

// ErrConsolidateWait: the fee rate is above consolidate_max_fee_rate, or consolidation is off. Not retryable: the consolidation ends and the planner
// decides again later.
var ErrConsolidateWait = errors.New("btc: consolidation waits")

const waitConsolidateAboveRate = "the fee rate is above consolidate_max_fee_rate: consolidation waits"

// noteConsolidateWait logs a change in why consolidation waits, once per change (nothing is wrong: the fee is high).
func (a *Adapter) noteConsolidateWait(why string) {
	a.waitMu.Lock()
	defer a.waitMu.Unlock()
	if why == a.consolidateWhy {
		return
	}
	a.consolidateWhy = why
	if why == "" {
		slog.Info("btc consolidation resumes: the fee rate allows it again")
		return
	}
	slog.Warn("btc consolidation waits", "why", why)
}

// smallestWorthSpending reads the partition's available hot outputs that are worth spending at the rate (more than one input costs to add), smallest
// first, at most limit of them.
func (a *Adapter) smallestWorthSpending(ctx context.Context, partitionID string, rate uint64, limit int) ([]uint64, error) {
	rows, err := a.pool.Query(ctx, `SELECT value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit AND NOT cold AND value > $3
		ORDER BY value, created_at, txid, vout LIMIT $4`, a.cfg.Chain, partitionID, int64(inputVSize*rate), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, uint64(v))
	}
	return out, rows.Err()
}

// PlanConsolidation says what a consolidation of the partition's shard would take now. It takes the smallest available outputs that are worth spending
// at the current rate (an output that costs more to spend than it carries stays where it is), at most max_inputs of them, and only when the shard holds
// more than consolidate_above available outputs, the rate is at or below consolidate_max_fee_rate, at least two outputs are worth spending and what
// they leave after the fee is above dust. The largest outputs stay free for withdrawals.
func (a *Adapter) PlanConsolidation(ctx context.Context, partitionID string) (chain.Consolidation, error) {
	none := chain.Consolidation{Amount: new(big.Int)}
	if a.cfg.ConsolidateAbove <= 0 {
		return none, nil
	}
	sh, err := a.shardOf(partitionID)
	if err != nil {
		return none, err
	}
	var held int
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit AND NOT cold`,
		a.cfg.Chain, partitionID).Scan(&held); err != nil {
		return none, err
	}
	if held <= a.cfg.ConsolidateAbove {
		return none, nil
	}
	rate := a.rawFeeRate(ctx)
	if rate > a.cfg.ConsolidateMaxFeeRate {
		a.noteConsolidateWait(waitConsolidateAboveRate)
		return chain.Consolidation{Amount: new(big.Int), Wait: waitConsolidateAboveRate}, nil
	}
	a.noteConsolidateWait("")
	vals, err := a.smallestWorthSpending(ctx, partitionID, rate, a.cfg.MaxInputs)
	if err != nil {
		return none, err
	}
	if len(vals) < 2 {
		return none, nil
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	if fee := vsize(len(vals), sh.script) * rate; sum < fee+DustLimit(KindP2WPKH)+1 {
		return none, nil // what is left after the fee would not be above dust
	}
	return chain.Consolidation{Amount: new(big.Int).SetUint64(sum), Inputs: len(vals)}, nil
}

// BuildConsolidation builds the consolidation inside the caller's transaction: it reserves the partition's smallest worthwhile available outputs, one at
// a time with FOR UPDATE SKIP LOCKED, until they add up to exactly the intent's amount (the signing zone requires the amount to be the sum of the
// inputs), and pays the sum less the fee to the shard's own address in one output. If they do not add up (the set changed since the plan, or a withdrawal
// took one) it returns chain.ErrNotEnoughOutputs and reserves nothing: the consolidation ends and the planner plans it again.
func (a *Adapter) BuildConsolidation(ctx context.Context, tx pgx.Tx, c chain.ConsolidateIntent) (chain.UnsignedTx, error) {
	if a.cfg.ConsolidateAbove <= 0 {
		return chain.UnsignedTx{}, fmt.Errorf("%w: consolidate_above is 0", ErrConsolidateWait)
	}
	sh, err := a.shardOf(c.PartitionID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if c.Amount == nil || !c.Amount.IsUint64() || c.Amount.Sign() <= 0 {
		return chain.UnsignedTx{}, fmt.Errorf("btc: consolidation amount %v out of range", c.Amount)
	}
	want := c.Amount.Uint64()
	rate := a.rawFeeRate(ctx)
	if rate > a.cfg.ConsolidateMaxFeeRate {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %s", ErrConsolidateWait, waitConsolidateAboveRate)
	}
	var picked []utxo
	var sum uint64
	for sum < want {
		if len(picked) >= a.cfg.MaxInputs {
			return chain.UnsignedTx{}, fmt.Errorf("%w: %d inputs of at most %d do not add up to %d", chain.ErrNotEnoughOutputs, len(picked), a.cfg.MaxInputs, want)
		}
		var u utxo
		var v int64
		err := tx.QueryRow(ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit AND NOT cold AND value > $3
			ORDER BY value, created_at, txid, vout LIMIT 1 FOR UPDATE SKIP LOCKED`, a.cfg.Chain, c.PartitionID, int64(inputVSize*rate)).Scan(&u.txid, &u.vout, &v)
		if errors.Is(err, pgx.ErrNoRows) {
			return chain.UnsignedTx{}, fmt.Errorf("%w: %d of %d sats in %s", chain.ErrNotEnoughOutputs, sum, want, c.PartitionID)
		}
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		u.value = uint64(v)
		if _, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='reserved', owner_kind=$5, owner_id=$4, updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3`,
			a.cfg.Chain, u.txid, u.vout, c.ID, OwnerKindConsolidate); err != nil {
			return chain.UnsignedTx{}, err
		}
		picked = append(picked, u)
		sum += u.value
	}
	if sum != want {
		return chain.UnsignedTx{}, fmt.Errorf("%w: the smallest outputs add up to %d, not %d", chain.ErrNotEnoughOutputs, sum, want)
	}
	if len(picked) < 2 {
		return chain.UnsignedTx{}, fmt.Errorf("btc: a consolidation spends at least two outputs, not %d", len(picked))
	}
	fee := vsize(len(picked), sh.script) * rate
	if fee > a.cfg.MaxTxFeeSats {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %d sats against the cap %d", ErrFeeTooHigh, fee, a.cfg.MaxTxFeeSats)
	}
	if sum < fee+DustLimit(KindP2WPKH)+1 {
		return chain.UnsignedTx{}, fmt.Errorf("btc: %d sats cannot pay a %d sat fee and leave an output above dust", sum, fee)
	}
	p := Payload{Version: PayloadVersion}
	for _, u := range picked {
		p.Inputs = append(p.Inputs, PayloadInput{TxID: u.txid, Vout: u.vout, Value: u.value, Path: sh.path, Sequence: SequenceRBF})
	}
	p.Outputs = []PayloadOutput{{Address: sh.address, Value: sum - fee}}
	built, raw, err := a.record(ctx, tx, OwnerKindConsolidate, c.ID, "send", p, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, built, raw, sh.partition, p), nil
}

var _ chain.Consolidator = (*Adapter)(nil)
