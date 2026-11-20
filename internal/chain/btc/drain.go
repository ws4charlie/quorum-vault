package btc

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// OwnerKindDrain is the owner kind (attempt owner, sign-job track, intent kind) of the move of a hot shard's coins from an old generation of the account
// key to its successor's. It has the shape of a consolidation (the shard's own outputs, one output) with the output at the successor's address.
const OwnerKindDrain = "drain"

// DrainRequest is what the core asks the cell to build: the move of the partition's outputs under the key of From to the address To (the same
// partition's shard under the successor generation), Amount being what PlanDrain found.
type DrainRequest struct {
	ID          string
	PartitionID string
	From, To    string
	Amount      *big.Int
}

// DrainPlan is what a draining generation's shard holds: Amount satoshis in Inputs outputs that one transaction can spend (at most max_inputs of them,
// the oldest first), and More when there are further outputs for the next move. Wait says why nothing can move now.
type DrainPlan struct {
	Amount *big.Int
	Inputs int
	More   bool
	Wait   string
}

// genOfShardAddr says which generation's shard of the partition has this address.
func (a *Adapter) genOfShardAddr(ctx context.Context, partitionID, addr string) (int, error) {
	t, err := a.treeStates(ctx, a.pool)
	if err != nil {
		return 0, err
	}
	gens := []int{1}
	for g := range t {
		if g > 1 {
			gens = append(gens, g)
		}
	}
	for _, g := range gens {
		sh, err := a.shardOfGen(partitionID, g)
		if err == nil && sh.address == addr {
			return g, nil
		}
	}
	return 0, fmt.Errorf("btc: %s is no shard address of %s under any key generation", addr, partitionID)
}

// drainInputs reads the available outputs of a partition's shard under gen, oldest first, up to max_inputs+1 (one more than a move can take).
func (a *Adapter) drainInputs(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, sh shard, lock bool) ([]utxo, bool, error) {
	sql := `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit AND NOT cold AND path=$3
		ORDER BY created_at, txid, vout LIMIT $4`
	if lock {
		sql += ` FOR UPDATE SKIP LOCKED`
	}
	rows, err := q.Query(ctx, sql, a.cfg.Chain, sh.partition, sh.keyPath(), a.cfg.MaxInputs+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []utxo
	for rows.Next() {
		var u utxo
		var v int64
		if err := rows.Scan(&u.txid, &u.vout, &v); err != nil {
			return nil, false, err
		}
		u.value = uint64(v)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > a.cfg.MaxInputs
	if more {
		out = out[:a.cfg.MaxInputs]
	}
	return out, more, nil
}

// PlanDrain says what the next drain move of the partition's shard under the generation of address from would spend. Outputs that cost more to spend
// than they carry at the current rate are left (they are dust: the generation retires with them).
func (a *Adapter) PlanDrain(ctx context.Context, partitionID, from string) (DrainPlan, error) {
	none := DrainPlan{Amount: new(big.Int)}
	if err := a.refreshCaps(ctx); err != nil {
		return none, err
	}
	gen, err := a.genOfShardAddr(ctx, partitionID, from)
	if err != nil {
		return none, err
	}
	sh, err := a.shardOfGen(partitionID, gen)
	if err != nil {
		return none, err
	}
	us, more, err := a.drainInputs(ctx, a.pool, sh, false)
	if err != nil {
		return none, err
	}
	rate := a.rawFeeRate(ctx)
	if rate > a.caps().MaxFeeRate {
		return DrainPlan{Amount: new(big.Int), Wait: waitAboveCap}, nil
	}
	var picked int
	var sum uint64
	for _, u := range us {
		if u.value > inputVSize*rate {
			picked++
			sum += u.value
		}
	}
	if picked == 0 {
		return none, nil
	}
	return DrainPlan{Amount: new(big.Int).SetUint64(sum), Inputs: picked, More: more}, nil
}

// BuildDrain builds the move: the outputs PlanDrain found, spent in one transaction to the successor's shard address, the fee out of the amount. The
// signing zone judges it by its own signed records (the source draining or compromised, the successor active, the cap).
func (a *Adapter) BuildDrain(ctx context.Context, tx pgx.Tx, d DrainRequest) (chain.UnsignedTx, error) {
	if err := a.refreshCaps(ctx); err != nil {
		return chain.UnsignedTx{}, err
	}
	gen, err := a.genOfShardAddr(ctx, d.PartitionID, d.From)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	toGen, err := a.genOfShardAddr(ctx, d.PartitionID, d.To)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if toGen == gen {
		return chain.UnsignedTx{}, errors.New("btc: a drain pays another generation than its own")
	}
	src, err := a.shardOfGen(d.PartitionID, gen)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	dst, err := a.shardOfGen(d.PartitionID, toGen)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if d.Amount == nil || !d.Amount.IsUint64() || d.Amount.Sign() <= 0 {
		return chain.UnsignedTx{}, fmt.Errorf("btc: drain amount %v out of range", d.Amount)
	}
	rate := a.rawFeeRate(ctx)
	if rate > a.caps().MaxFeeRate {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %s", ErrConsolidateWait, waitAboveCap)
	}
	us, _, err := a.drainInputs(ctx, tx, src, true)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	var picked []utxo
	var sum uint64
	for _, u := range us {
		if u.value > inputVSize*rate {
			picked = append(picked, u)
			sum += u.value
		}
	}
	if sum != d.Amount.Uint64() || len(picked) == 0 {
		return chain.UnsignedTx{}, fmt.Errorf("%w: the shard's spendable outputs add up to %d, the plan said %s", chain.ErrNotEnoughOutputs, sum, d.Amount)
	}
	for _, u := range picked {
		if _, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='reserved', owner_kind=$5, owner_id=$4, updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3`,
			a.cfg.Chain, u.txid, u.vout, d.ID, OwnerKindDrain); err != nil {
			return chain.UnsignedTx{}, err
		}
	}
	fee := vsize(len(picked), dst.script) * rate
	if fee > a.caps().MaxTxFeeSats {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %d sats against the cap %d", ErrFeeTooHigh, fee, a.caps().MaxTxFeeSats)
	}
	if sum < fee+DustLimit(KindP2WPKH)+1 {
		return chain.UnsignedTx{}, fmt.Errorf("btc: %d sats cannot pay a %d sat fee and leave an output above dust", sum, fee)
	}
	p := Payload{Version: PayloadVersion}
	for _, u := range picked {
		p.Inputs = append(p.Inputs, PayloadInput{TxID: u.txid, Vout: u.vout, Value: u.value, Path: src.path, Sequence: SequenceRBF, Gen: src.payloadGen()})
	}
	p.Outputs = []PayloadOutput{{Address: dst.address, Value: sum - fee}}
	built, raw, err := a.record(ctx, tx, OwnerKindDrain, d.ID, "send", p, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, built, raw, d.PartitionID, p), nil
}
