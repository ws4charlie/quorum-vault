package btc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// inputVSize is what one more P2WPKH input adds to a transaction, in virtual bytes (41 bytes of outpoint, script length and sequence, and 108 witness
// bytes at a quarter weight).
const inputVSize = 68

// sinkShard is where a sweep pays: the first hot shard, which is the cell's sweep sink (custody's SinkShard is 0 for this family).
func (a *Adapter) sinkShard() shard { return a.shards[0] }

// sinkPartition is the sink shard's partition, or "" for a deposit-only cell (no hot shards configured): its deposit outputs are recorded all the
// same, and a sweep names its partition itself when hot shards exist.
func (a *Adapter) sinkPartition() string {
	if len(a.shards) == 0 {
		return ""
	}
	return a.shards[0].partition
}

// vout reads the output index out of a deposit's dedup key, chain:txid:vout.
func voutOf(dedupKey string) (uint32, error) {
	i := strings.LastIndex(dedupKey, ":")
	if i < 0 {
		return 0, fmt.Errorf("btc: dedup key %q has no output index", dedupKey)
	}
	n, err := strconv.ParseUint(dedupKey[i+1:], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("btc: dedup key %q: %w", dedupKey, err)
	}
	return uint32(n), nil
}

// The two reasons a sweep waits for the fee rate; stable strings, so a change in the numbers alone is not logged again.
const (
	waitAboveCap     = "the fee rate is above max_fee_rate: no sweep goes, urgent or not"
	waitAboveCeiling = "the fee rate is above sweep_max_fee_rate: routine sweeps wait, sweeps of at least sweep_urgent_value go"
)

// urgent reports whether a sweep of amount sats goes regardless of the routine ceiling.
func (a *Adapter) urgent(amount uint64) bool {
	return a.cfg.SweepUrgentValue > 0 && amount >= a.cfg.SweepUrgentValue
}

// sweepRate is the fee rate a sweep of amount pays now, or why it waits: above max_fee_rate nothing goes; above sweep_max_fee_rate only an urgent
// sweep does (and pays up to max_fee_rate). The node's estimate decides, the configured fallback when it has none.
func (a *Adapter) sweepRate(ctx context.Context, amount uint64) (rate uint64, wait string) {
	raw := a.rawFeeRate(ctx)
	switch {
	case raw > a.cfg.MaxFeeRate:
		return 0, waitAboveCap
	case raw > a.cfg.SweepMaxFeeRate && !a.urgent(amount):
		return 0, waitAboveCeiling
	}
	return raw, ""
}

// noteSweepWait logs a change in why sweeps wait, once per change (an ALERT-free warning: nothing is wrong, the fee is high).
func (a *Adapter) noteSweepWait(why string) {
	a.waitMu.Lock()
	defer a.waitMu.Unlock()
	if why == a.sweepWhy {
		return
	}
	a.sweepWhy = why
	if why == "" {
		slog.Info("btc sweeps resume: the fee rate allows them again")
		return
	}
	slog.Warn("btc sweeps wait", "why", why)
}

// RecordDeposit stores a credited deposit output (the caller calls it in the scan transaction that credits it): the output of a deposit address, with the
// path that spends it and the partition of the shard a sweep pays. It is marked as a deposit output, which hot selection never sees.
func (a *Adapter) RecordDeposit(ctx context.Context, tx pgx.Tx, d chain.ObservedDeposit) error {
	vout, err := voutOf(d.DedupKey)
	if err != nil {
		return err
	}
	if !d.Amount.IsInt64() || d.Amount.Sign() <= 0 {
		return fmt.Errorf("btc: deposit %s amount %v out of range", d.DedupKey, d.Amount)
	}
	var idx int64
	if err := tx.QueryRow(ctx, `SELECT derivation_index FROM deposit_addresses WHERE chain=$1 AND address=$2`, a.cfg.Chain, d.Address).Scan(&idx); err != nil {
		return fmt.Errorf("btc: deposit address %s: %w", d.Address, err)
	}
	path := PathString([]uint32{BranchDeposit, uint32(idx)})
	_, err = tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path, deposit, address) VALUES ($1,$2,$3,$4,$5,$6,true,$7) ON CONFLICT DO NOTHING`,
		a.cfg.Chain, d.TxHash, int64(vout), d.Amount.Int64(), a.sinkPartition(), path, d.Address)
	return err
}

// SweepCandidates lists, per deposit address, what a sweep would take now: the address's available outputs, oldest first, up to the input cap,
// leaving out every output that costs at least its value to spend at the current rate (it would only lose money). The rest of an address waits for
// the next round. An address with nothing left to take is not listed.
func (a *Adapter) SweepCandidates(ctx context.Context) ([]chain.SweepCandidate, error) {
	rate := a.feeRate(ctx)
	rows, err := a.pool.Query(ctx, `SELECT address, value FROM btc_utxos WHERE chain=$1 AND deposit AND status='available' ORDER BY address, created_at, txid, vout`, a.cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []chain.SweepCandidate
	var cur *chain.SweepCandidate
	n := 0
	for rows.Next() {
		var addr string
		var v int64
		if err := rows.Scan(&addr, &v); err != nil {
			return nil, err
		}
		if cur == nil || cur.Address != addr {
			out = append(out, chain.SweepCandidate{Address: addr, Asset: Native, Amount: new(big.Int)})
			cur = &out[len(out)-1]
			n = 0
		}
		if uint64(v) <= inputVSize*rate || n >= a.cfg.MaxInputs {
			continue
		}
		cur.Amount.Add(cur.Amount, big.NewInt(v))
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	kept := out[:0]
	why := ""
	for _, c := range out {
		if c.Amount.Sign() == 0 {
			continue
		}
		if _, wait := a.sweepRate(ctx, c.Amount.Uint64()); wait != "" {
			why = wait
			continue
		}
		kept = append(kept, c)
	}
	a.noteSweepWait(why)
	return kept, nil
}

// EstimateSweepFee is the fee of the sweep that would take the amount from the address: the current rate times the size of that many inputs and one
// output. The number of inputs is that of the outputs SweepCandidates would take.
func (a *Adapter) EstimateSweepFee(ctx context.Context, s chain.SweepIntent) (*big.Int, error) {
	rate := a.feeRate(ctx)
	rows, err := a.pool.Query(ctx, `SELECT value FROM btc_utxos WHERE chain=$1 AND deposit AND address=$2 AND status='available' ORDER BY created_at, txid, vout`, a.cfg.Chain, s.From)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := 0
	sum := new(big.Int)
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if uint64(v) <= inputVSize*rate || n >= a.cfg.MaxInputs {
			continue
		}
		sum.Add(sum, big.NewInt(v))
		n++
		if s.Amount != nil && sum.Cmp(s.Amount) >= 0 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: no spendable output at %s", chain.ErrNotEnoughOutputs, s.From)
	}
	return new(big.Int).SetUint64(vsize(n, a.sinkShard().script) * rate), nil
}

// BuildSweep builds the sweep of a deposit address inside the caller's transaction: it reserves the address's oldest available outputs, one at a time
// with FOR UPDATE SKIP LOCKED (and, as in the plan, leaving out an output that costs more to spend than it carries), until they add up to exactly the intent's amount (the signing zone requires the intent's amount to be the sum of the
// inputs). The one output pays the sink shard the sum minus the fee. If the outputs do not add up to the amount (the set changed since the plan), it
// returns chain.ErrNotEnoughOutputs and reserves nothing: the sweep ends and the planner plans it again.
func (a *Adapter) BuildSweep(ctx context.Context, tx pgx.Tx, s chain.SweepIntent) (chain.UnsignedTx, error) {
	sh, err := a.shardOf(s.ToPartition)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if s.Amount == nil || !s.Amount.IsUint64() || s.Amount.Sign() <= 0 {
		return chain.UnsignedTx{}, fmt.Errorf("btc: sweep amount %v out of range", s.Amount)
	}
	want := s.Amount.Uint64()
	rate, wait := a.sweepRate(ctx, want)
	if wait != "" {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %s", chain.ErrSweepFeePolicy, wait)
	}
	rate = min(rate, a.cfg.MaxFeeRate)
	var picked []utxo
	var paths []string
	var sum uint64
	for sum < want {
		if len(picked) >= a.cfg.MaxInputs {
			return chain.UnsignedTx{}, fmt.Errorf("%w: %d inputs of at most %d do not add up to %d", chain.ErrNotEnoughOutputs, len(picked), a.cfg.MaxInputs, want)
		}
		var u utxo
		var v int64
		var path string
		err := tx.QueryRow(ctx, `SELECT txid, vout, value, path FROM btc_utxos WHERE chain=$1 AND deposit AND address=$2 AND status='available' AND value > $3
			ORDER BY created_at, txid, vout LIMIT 1 FOR UPDATE SKIP LOCKED`, a.cfg.Chain, s.From, int64(inputVSize*rate)).Scan(&u.txid, &u.vout, &v, &path)
		if errors.Is(err, pgx.ErrNoRows) {
			return chain.UnsignedTx{}, fmt.Errorf("%w: %d of %d sats at %s", chain.ErrNotEnoughOutputs, sum, want, s.From)
		}
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		u.value = uint64(v)
		if _, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='reserved', owner_kind='sweep', owner_id=$4, updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3`,
			a.cfg.Chain, u.txid, u.vout, s.ID); err != nil {
			return chain.UnsignedTx{}, err
		}
		picked = append(picked, u)
		paths = append(paths, path)
		sum += u.value
	}
	if sum != want {
		return chain.UnsignedTx{}, fmt.Errorf("%w: the oldest outputs add up to %d, not %d", chain.ErrNotEnoughOutputs, sum, want)
	}
	fee := vsize(len(picked), sh.script) * rate
	if fee > a.cfg.MaxTxFeeSats {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %d sats against the cap %d", ErrFeeTooHigh, fee, a.cfg.MaxTxFeeSats)
	}
	if sum < fee+DustLimit(KindP2WPKH) {
		return chain.UnsignedTx{}, fmt.Errorf("btc: %d sats cannot pay a %d sat fee and leave an output", sum, fee)
	}
	p := Payload{Version: PayloadVersion}
	for i, u := range picked {
		path, err := ParsePath(paths[i])
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		p.Inputs = append(p.Inputs, PayloadInput{TxID: u.txid, Vout: u.vout, Value: u.value, Path: path, Sequence: SequenceRBF})
	}
	p.Outputs = []PayloadOutput{{Address: sh.address, Value: sum - fee}}
	built, raw, err := a.record(ctx, tx, "sweep", s.ID, "send", p, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, built, raw, sh.partition, p), nil
}

// MovedAssets is what a sweep took out of its deposit address, from the attempt's payload: the sum of its inputs, which is also what the signing
// zone approved as the sweep's amount. One entry for the one address and the one asset.
func (a *Adapter) MovedAssets(ctx context.Context, txid string) ([]chain.MovedAsset, error) {
	var raw []byte
	err := a.pool.QueryRow(ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND txid=$2`, a.cfg.Chain, txid).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("btc: no attempt %s", txid)
	}
	if err != nil {
		return nil, err
	}
	p, err := DecodePayload(raw)
	if err != nil {
		return nil, err
	}
	var addr string
	sum := new(big.Int)
	for _, in := range p.Inputs {
		ad, err := a.acct.Address(in.Path)
		if err != nil {
			return nil, err
		}
		if addr != "" && ad != addr {
			return nil, fmt.Errorf("btc: attempt %s spends more than one address", txid)
		}
		addr = ad
		sum.Add(sum, new(big.Int).SetUint64(in.Value))
	}
	if addr == "" {
		return nil, nil
	}
	return []chain.MovedAsset{{Address: addr, Asset: Native, Amount: sum}}, nil
}

var (
	_ chain.DepositRecorder = (*Adapter)(nil)
	_ chain.SweepSource     = (*Adapter)(nil)
)
