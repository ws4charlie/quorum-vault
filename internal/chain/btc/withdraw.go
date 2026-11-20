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

// feeRate is the fee rate for a withdrawal in satoshis per virtual byte: the node's estimate for confirmation in a couple of blocks, the
// configured fallback when it has none, never above the configured ceiling (which is below the signing zone's) and never below the relay minimum.
func (a *Adapter) feeRate(ctx context.Context) uint64 {
	return min(a.rawFeeRate(ctx), a.caps().MaxFeeRate)
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

// oldestCannotCarry reports whether the oldest max_inputs available outputs of the partition cannot pay the amount, the fee and the fee-bump reserve (no prefix of them
// does) while the partition holds more outputs than that, so that taking the largest ones is the only way to pay. Nothing is locked or reserved.
func (a *Adapter) oldestCannotCarry(ctx context.Context, tx pgx.Tx, partitionID string, amount uint64, destScript, changeScript []byte, rate uint64) (bool, error) {
	sh, err := a.shardOf(ctx, partitionID)
	if err != nil {
		return false, err
	}
	rows, err := tx.Query(ctx, `SELECT value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit AND path=$4
		ORDER BY created_at, txid, vout LIMIT $3`, a.cfg.Chain, partitionID, a.cfg.MaxInputs+1, sh.keyPath())
	if err != nil {
		return false, err
	}
	defer rows.Close()
	n, sum := 0, uint64(0)
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return false, err
		}
		n++
		if n > a.cfg.MaxInputs {
			return true, rows.Err() // more outputs than one transaction takes, and no prefix of the oldest ones covered the payment
		}
		sum += uint64(v)
		if vs := vsize(n, destScript, changeScript); sum >= ReserveNeed(amount, vs*rate, vs, a.caps().MaxTxFeeSats, a.caps().MaxFeeRate) {
			return false, nil
		}
	}
	return false, rows.Err() // fewer outputs than the cap: the order does not matter, all of them are taken
}

// BuildWithdrawal builds the transaction of a withdrawal inside the caller's transaction: it selects the partition's own available outputs, oldest
// first (or, when the oldest max_inputs cannot carry the payment, the largest first), one at a time with FOR UPDATE SKIP LOCKED, reserving each at once, so two builds never pick one output and a rolled-back build reserves
// nothing. The payment is the first output, change the second, to the shard's own address.
//
// It keeps the fee-bump reserve (reserve.go): the inputs must hold the payment, the fee cap for the final size and one dust change, so the
// transaction can be bumped to the cap with its own inputs. It keeps adding inputs until that holds. If the available outputs cannot, it returns
// chain.ErrNotEnoughOutputs (also wrapping chain.ErrFeeReserve when the payment and today's fee alone would have been covered, with how much more
// releases it): the withdrawal waits and nothing stays reserved.
func (a *Adapter) BuildWithdrawal(ctx context.Context, tx pgx.Tx, w chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	if err := a.refreshCaps(ctx); err != nil {
		return chain.UnsignedTx{}, err
	}
	kind := w.OwnerKind
	if kind == "" {
		kind = "withdrawal"
	}
	if kind != "withdrawal" && kind != "to-cold" { // a hot-to-cold move is built like a withdrawal: the shard's inputs, change back to the shard
		return chain.UnsignedTx{}, errLater
	}
	sh, err := a.shardOf(ctx, w.PartitionID)
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

	// The order is decided before anything is reserved. A withdrawal takes the oldest outputs; when the oldest max_inputs of them cannot carry it but
	// the shard holds more, it takes the largest instead (a shard fed by many small outputs stays spendable). A hot-to-cold move keeps eating the oldest.
	order := "created_at, txid, vout"
	if kind == "withdrawal" {
		largest, err := a.oldestCannotCarry(ctx, tx, w.PartitionID, amount, destScript, sh.script, rate)
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		if largest {
			order = "value DESC, created_at, txid, vout"
		}
	}

	var picked []utxo
	var sum uint64
	need := func(n int) (uint64, uint64) { // what n inputs must hold, and the size it was computed for
		vs := vsize(n, destScript, sh.script)
		return ReserveNeed(amount, feeFor(n, destScript, sh.script), vs, a.caps().MaxTxFeeSats, a.caps().MaxFeeRate), vs
	}
	// short builds the error of a build that cannot go on with n inputs holding sum: the reserve when the payment and today's fee alone are covered.
	short := func(n int, sum uint64, why string) error {
		want, vs := need(n)
		if n == 0 || sum < amount+feeFor(n, destScript) {
			return fmt.Errorf("%w: %s", chain.ErrNotEnoughOutputs, why)
		}
		// The payment and today's fee are covered, the reserve is not. What releases it: one more output, which also adds its own input to the size.
		release := fmt.Sprintf("the %d inputs of at most are all taken: larger outputs are needed", n)
		if n < a.cfg.MaxInputs {
			next, _ := need(n + 1)
			release = fmt.Sprintf("one more output of at least %d sats releases it", next-sum)
		}
		return fmt.Errorf("%w: %w: %s holds %d sats in %d inputs for a payment of %d plus fee %d, and the reserve to bump it up to the fee cap (%d sats for %d vbytes, plus %d dust change) needs %d in all: %s",
			chain.ErrNotEnoughOutputs, chain.ErrFeeReserve, w.PartitionID, sum, n, amount, feeFor(n, destScript, sh.script),
			FeeCap(a.caps().MaxTxFeeSats, a.caps().MaxFeeRate, vs), vs, changeDust, want, release)
	}
	for {
		// Enough for the payment, today's fee, and the reserve in change?
		if len(picked) > 0 {
			if want, _ := need(len(picked)); sum >= want {
				break
			}
		}
		if len(picked) >= a.cfg.MaxInputs {
			return chain.UnsignedTx{}, short(len(picked), sum, fmt.Sprintf("%d inputs of at most %d cover %d of %d sats plus fee", len(picked), a.cfg.MaxInputs, sum, amount))
		}
		var u utxo
		var v int64
		err := tx.QueryRow(ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit AND path=$3
			ORDER BY `+order+` LIMIT 1 FOR UPDATE SKIP LOCKED`, a.cfg.Chain, w.PartitionID, sh.keyPath()).Scan(&u.txid, &u.vout, &v)
		if errors.Is(err, pgx.ErrNoRows) {
			return chain.UnsignedTx{}, short(len(picked), sum, fmt.Sprintf("%d sats available in %s, %d needed plus fee", sum, w.PartitionID, amount))
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
		p.Inputs = append(p.Inputs, PayloadInput{TxID: u.txid, Vout: u.vout, Value: u.value, Path: sh.path, Sequence: SequenceRBF, Gen: sh.payloadGen()})
	}
	p.Outputs = []PayloadOutput{{Address: dest.Canonical, Value: amount}}
	// The selection guarantees change of at least the dust limit above today's fee: a withdrawal always has a change output to bump from.
	fee := feeFor(len(picked), destScript, sh.script)
	change := sum - amount - fee
	p.Outputs = append(p.Outputs, PayloadOutput{Address: sh.address, Value: change})
	if fee > a.caps().MaxTxFeeSats {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %d sats against the cap %d", ErrFeeTooHigh, fee, a.caps().MaxTxFeeSats)
	}
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	p.FeeCapsSeq = a.capsSeq()
	raw, err := json.Marshal(p)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO btc_attempts (chain, txid, owner_kind, owner_id, kind, payload, fee) VALUES ($1,$2,$6,$3,'send',$4::jsonb,$5)`,
		a.cfg.Chain, built.TxID, w.ID, string(raw), int64(fee), kind); err != nil {
		return chain.UnsignedTx{}, fmt.Errorf("btc: record attempt: %w", err)
	}
	ref := chain.KeyRef{PartitionID: w.PartitionID, Path: sh.keyPath()}
	u := chain.UnsignedTx{Chain: a.cfg.Chain, Digest: built.Digests[0], Payload: raw, KeyRef: ref}
	for _, d := range built.Digests[1:] {
		u.More = append(u.More, chain.SigInput{Digest: d, KeyRef: ref})
	}
	return u, nil
}
