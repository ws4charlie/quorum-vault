package btc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/wire"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// ErrFeeTooHigh: the fee a withdrawal would pay is above the configured cap. It is not retryable.
var ErrFeeTooHigh = errors.New("btc: fee above the cap")

const minRelayRate = 1 // satoshis per virtual byte

func (a *Adapter) shardOf(partitionID string) (shard, error) {
	for _, s := range a.shards {
		if s.partition == partitionID {
			return s, nil
		}
	}
	return shard{}, fmt.Errorf("btc: partition %q has no hot shard", partitionID)
}

// feeRate is the fee rate for a withdrawal in satoshis per virtual byte: the node's estimate for confirmation in a couple of blocks, the
// configured fallback when it has none, never above the configured ceiling (which is below the signing zone's) and never below the relay minimum.
func (a *Adapter) feeRate(ctx context.Context) uint64 {
	return min(a.rawFeeRate(ctx), a.cfg.MaxFeeRate)
}

// rawFeeRate is the market rate before the ceiling: the node's estimate, else the fallback, never below the relay minimum. A sweep compares it
// with its own ceilings (sweepRate) instead of paying less than the market asks.
func (a *Adapter) rawFeeRate(ctx context.Context) uint64 {
	rate := a.cfg.FallbackFeeRate
	var est struct {
		FeeRate float64  `json:"feerate"` // BTC per kvB
		Errors  []string `json:"errors"`
	}
	if err := a.rpc.Call(ctx, &est, "estimatesmartfee", 2); err == nil && est.FeeRate > 0 && len(est.Errors) == 0 {
		rate = uint64(math.Ceil(est.FeeRate * 1e5)) // BTC/kvB -> sat/vB
	}
	return max(rate, minRelayRate)
}

// vsize is the virtual size of a transaction with nIn P2WPKH inputs and the given outputs, once witnessed.
func vsize(nIn int, scripts ...[]byte) uint64 {
	tx := wire.NewMsgTx(PayloadVersion)
	for i := 0; i < nIn; i++ {
		tx.AddTxIn(&wire.TxIn{})
	}
	for _, s := range scripts {
		tx.AddTxOut(wire.NewTxOut(1, s))
	}
	return uint64(EstimateVSize(tx))
}

type utxo struct {
	txid  string
	vout  uint32
	value uint64
}

// BuildWithdrawal builds the transaction of a withdrawal inside the caller's transaction: it selects the partition's own available outputs, oldest
// first, one at a time with FOR UPDATE SKIP LOCKED, reserving each at once, so two builds never pick one output and a rolled-back build reserves
// nothing. The payment is the first output, change (when it is above dust) the second, to the shard's own address. A change at or under the dust limit
// goes to the fee. If the available outputs cannot pay the amount and the fee, it returns chain.ErrNotEnoughOutputs: the withdrawal waits.
func (a *Adapter) BuildWithdrawal(ctx context.Context, tx pgx.Tx, w chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	kind := w.OwnerKind
	if kind == "" {
		kind = "withdrawal"
	}
	if kind != "withdrawal" && kind != "to-cold" { // a hot-to-cold move is built like a withdrawal: the shard's inputs, change back to the shard
		return chain.UnsignedTx{}, errLater
	}
	sh, err := a.shardOf(w.PartitionID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	dest, err := DecodeAddress(w.To, a.cfg.params)
	if err != nil {
		return chain.UnsignedTx{}, fmt.Errorf("btc: destination: %w", err)
	}
	destScript, err := OutputScript(w.To, a.cfg.params)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if w.Amount == nil || !w.Amount.IsUint64() {
		return chain.UnsignedTx{}, fmt.Errorf("btc: amount %v out of range", w.Amount)
	}
	amount := w.Amount.Uint64()
	if amount < DustLimit(dest.Kind) {
		return chain.UnsignedTx{}, fmt.Errorf("btc: amount %d is below the dust limit %d of %s", amount, DustLimit(dest.Kind), dest.Kind)
	}
	rate := a.feeRate(ctx)
	feeFor := func(n int, scripts ...[]byte) uint64 { return vsize(n, scripts...) * rate }
	changeDust := DustLimit(KindP2WPKH)

	var picked []utxo
	var sum uint64
	for {
		// Enough for the payment alone (no change)?
		if len(picked) > 0 && sum >= amount+feeFor(len(picked), destScript) {
			break
		}
		if len(picked) >= a.cfg.MaxInputs {
			return chain.UnsignedTx{}, fmt.Errorf("%w: %d inputs of at most %d cover %d of %d sats plus fee", chain.ErrNotEnoughOutputs, len(picked), a.cfg.MaxInputs, sum, amount)
		}
		var u utxo
		var v int64
		err := tx.QueryRow(ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit
			ORDER BY created_at, txid, vout LIMIT 1 FOR UPDATE SKIP LOCKED`, a.cfg.Chain, w.PartitionID).Scan(&u.txid, &u.vout, &v)
		if errors.Is(err, pgx.ErrNoRows) {
			return chain.UnsignedTx{}, fmt.Errorf("%w: %d sats available in %s, %d needed plus fee", chain.ErrNotEnoughOutputs, sum, w.PartitionID, amount)
		}
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		u.value = uint64(v)
		if _, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='reserved', owner_kind=$5, owner_id=$4, updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3`,
			a.cfg.Chain, u.txid, u.vout, w.ID, kind); err != nil {
			return chain.UnsignedTx{}, err
		}
		picked = append(picked, u)
		sum += u.value
	}

	p := Payload{Version: PayloadVersion}
	for _, u := range picked {
		p.Inputs = append(p.Inputs, PayloadInput{TxID: u.txid, Vout: u.vout, Value: u.value, Path: sh.path, Sequence: SequenceRBF})
	}
	p.Outputs = []PayloadOutput{{Address: dest.Canonical, Value: amount}}
	fee := sum - amount // no change: everything left is fee
	if change := int64(sum) - int64(amount) - int64(feeFor(len(picked), destScript, sh.script)); change >= int64(changeDust) {
		p.Outputs = append(p.Outputs, PayloadOutput{Address: sh.address, Value: uint64(change)})
		fee = sum - amount - uint64(change)
	}
	if fee > a.cfg.MaxTxFeeSats {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %d sats against the cap %d", ErrFeeTooHigh, fee, a.cfg.MaxTxFeeSats)
	}
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO btc_attempts (chain, txid, owner_kind, owner_id, kind, payload, fee) VALUES ($1,$2,$6,$3,'send',$4::jsonb,$5)`,
		a.cfg.Chain, built.TxID, w.ID, string(raw), int64(fee), kind); err != nil {
		return chain.UnsignedTx{}, fmt.Errorf("btc: record attempt: %w", err)
	}
	ref := chain.KeyRef{PartitionID: w.PartitionID, Path: PathString(sh.path)}
	u := chain.UnsignedTx{Chain: a.cfg.Chain, Digest: built.Digests[0], Payload: raw, KeyRef: ref}
	for _, d := range built.Digests[1:] {
		u.More = append(u.More, chain.SigInput{Digest: d, KeyRef: ref})
	}
	return u, nil
}
