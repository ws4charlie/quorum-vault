package btc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Replacement rule. A replacement spends the same inputs and pays the same payment from less change, and Bitcoin Core accepts it (BIP125) only if
// it signals replaceability (every input does), pays an absolute fee at least the old one's plus the relay cost of its own size at the incremental
// relay fee (1 sat/vB), and a higher fee rate. This cell pays the largest of:
//
//	old fee + 15 percent                      (a step worth taking, like EVM's bump)
//	old fee + vsize x 1 sat/vB                (BIP125 rules 3 and 4)
//	the current fee rate x vsize              (what the node would ask for now)
//
// where "old fee" is the higher of the last accepted attempt's and the highest fee the node refused as too low (escalate), so that every attempt
// pays strictly more than any refused one. It refuses (chain.ErrCannotBump) when that is above the fee cap or the fee rate ceiling, or leaves the
// change at or under dust, or when the attempt has no change output to pay it from.
const (
	bumpPercent     = 15
	incrementalRate = 1 // sat/vB, the incremental relay fee
)

// nextFee is the fee of a replacement of an attempt that paid oldFee, for a transaction of vs virtual bytes.
func (a *Adapter) nextFee(ctx context.Context, oldFee, vs uint64) uint64 {
	step := (oldFee*(100+bumpPercent) + 99) / 100
	return max(step, oldFee+vs*incrementalRate, a.feeRate(ctx)*vs)
}

// feeCap is the most a transaction of vs virtual bytes may pay: the fee cap and the fee rate ceiling, whichever is lower.
func (a *Adapter) feeCap(vs uint64) uint64 { return min(a.cfg.MaxTxFeeSats, a.cfg.MaxFeeRate*vs) }

func (a *Adapter) checkFee(fee, vs uint64) error {
	if fee > a.feeCap(vs) {
		return fmt.Errorf("%w: %d sats over %d vbytes would be above the fee cap %d sats or %d sat/vB", chain.ErrCannotBump, fee, vs, a.cfg.MaxTxFeeSats, a.cfg.MaxFeeRate)
	}
	return nil
}

// lastSend is the owner's newest send attempt (broadcast or not), locked.
func (a *Adapter) lastSend(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (Payload, uint64, error) {
	var raw []byte
	var fee int64
	err := tx.QueryRow(ctx, `SELECT payload, fee FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND kind='send' ORDER BY created_at DESC, txid LIMIT 1 FOR UPDATE`,
		a.cfg.Chain, ownerKind, ownerID).Scan(&raw, &fee)
	if errors.Is(err, pgx.ErrNoRows) {
		return Payload{}, 0, fmt.Errorf("btc: %s %s has no attempt", ownerKind, ownerID)
	}
	if err != nil {
		return Payload{}, 0, err
	}
	p, err := DecodePayload(raw)
	return p, uint64(fee), err
}

func (a *Adapter) record(ctx context.Context, tx pgx.Tx, ownerKind, ownerID, kind string, p Payload, fee uint64) (*Unsigned, []byte, error) {
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO btc_attempts (chain, txid, owner_kind, owner_id, kind, payload, fee) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)`,
		a.cfg.Chain, built.TxID, ownerKind, ownerID, kind, string(raw), int64(fee)); err != nil {
		return nil, nil, fmt.Errorf("btc: record attempt: %w", err)
	}
	return built, raw, nil
}

// unsignedOf wraps a built transaction: one signature request per input, each under the key of that input's own path (the shard's for a withdrawal,
// the deposit address's for a sweep).
func unsignedOf(chainName string, built *Unsigned, raw []byte, partition string, p Payload) chain.UnsignedTx {
	ref := func(i int) chain.KeyRef {
		return chain.KeyRef{PartitionID: partition, Path: PathString(p.Inputs[i].Path)}
	}
	u := chain.UnsignedTx{Chain: chainName, Digest: built.Digests[0], Payload: raw, KeyRef: ref(0)}
	for i, d := range built.Digests[1:] {
		u.More = append(u.More, chain.SigInput{Digest: d, KeyRef: ref(i + 1)})
	}
	return u
}

// BuildReplacement builds the fee bump of the owner's newest attempt: the same inputs and the same payment, less change, a higher fee (see the rule
// above). Without a change output, or when the change would fall to dust, it returns chain.ErrCannotBump: the attempt cannot be bumped.
func (a *Adapter) BuildReplacement(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (chain.UnsignedTx, error) {
	if ownerKind == "sweep" {
		return a.buildSweepReplacement(ctx, tx, ownerID)
	}
	if ownerKind == OwnerKindConsolidate {
		return a.buildConsolidateReplacement(ctx, tx, ownerID)
	}
	if ownerKind != "withdrawal" && ownerKind != "to-cold" {
		return chain.UnsignedTx{}, errLater
	}
	p, oldFee, err := a.lastSend(ctx, tx, ownerKind, ownerID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	sh, ok := a.byAddr[p.Outputs[len(p.Outputs)-1].Address]
	if len(p.Outputs) < 2 || !ok {
		return chain.UnsignedTx{}, fmt.Errorf("%w: the transaction has no change output to pay a higher fee from", chain.ErrCannotBump)
	}
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	vs := uint64(EstimateVSize(built.Tx))
	fee, err := a.escalate(ctx, tx, ownerKind, ownerID, oldFee, vs, a.feeCap(vs), func(fee uint64) error { return a.checkFee(fee, vs) })
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	change := &p.Outputs[len(p.Outputs)-1]
	delta := fee - oldFee
	if change.Value < delta || change.Value-delta < DustLimit(KindP2WPKH) {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %d sats of change cannot pay %d more", chain.ErrCannotBump, change.Value, delta)
	}
	change.Value -= delta
	b2, raw, err := a.record(ctx, tx, ownerKind, ownerID, "send", p, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, b2, raw, sh.partition, p), nil
}

// BuildCancel builds the cancel of the owner's attempts: a transaction that spends exactly the inputs of the attempt (the signing zone's strict rule)
// back to the partition's own shard, one output, for a fee above the highest fee any attempt of the owner paid (so it replaces whichever is pending).
// Once it confirms, no other transaction can spend those inputs, so a half-signed one can never confirm. It returns chain.ErrNotSupported when
// nothing was built, and chain.ErrCannotBump when the inputs cannot pay for it.
func (a *Adapter) BuildCancel(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (chain.UnsignedTx, error) {
	if ownerKind != "withdrawal" && ownerKind != "sweep" && ownerKind != "to-cold" && ownerKind != OwnerKindConsolidate {
		return chain.UnsignedTx{}, errLater
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND kind='send'`, a.cfg.Chain, ownerKind, ownerID).Scan(&n); err != nil {
		return chain.UnsignedTx{}, err
	}
	if n == 0 {
		return chain.UnsignedTx{}, errLater
	}
	p, _, err := a.lastSend(ctx, tx, ownerKind, ownerID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	var top int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(fee),0) FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3`, a.cfg.Chain, ownerKind, ownerID).Scan(&top); err != nil {
		return chain.UnsignedTx{}, err
	}
	var part string
	if err := tx.QueryRow(ctx, `SELECT partition_id FROM btc_utxos WHERE chain=$1 AND txid=$2 AND vout=$3`, a.cfg.Chain, p.Inputs[0].TxID, p.Inputs[0].Vout).Scan(&part); err != nil {
		return chain.UnsignedTx{}, fmt.Errorf("btc: partition of the attempt's inputs: %w", err)
	}
	sh, err := a.shardOf(part)
	if err != nil && ownerKind == "sweep" && len(a.shards) > 0 {
		sh, err = a.sinkShard(), nil // a deposit-only cell recorded the output without a partition: the sweep pays the sink shard
	}
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	var sum uint64
	for _, in := range p.Inputs {
		sum += in.Value
	}
	vs := vsize(len(p.Inputs), sh.script)
	fee := a.nextFee(ctx, uint64(top), vs) // a cancel replaces what the node holds, so only accepted attempts count: refused fees do not raise it
	if err := a.checkFee(fee, vs); err != nil {
		return chain.UnsignedTx{}, err
	}
	if sum < fee+DustLimit(KindP2WPKH) {
		return chain.UnsignedTx{}, fmt.Errorf("%w: the inputs hold %d sats, a cancel needs %d fee and an output", chain.ErrCannotBump, sum, fee)
	}
	c := Payload{Version: PayloadVersion, Inputs: p.Inputs, Outputs: []PayloadOutput{{Address: sh.address, Value: sum - fee}}}
	built, raw, err := a.record(ctx, tx, ownerKind, ownerID, "cancel", c, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, built, raw, sh.partition, c), nil
}

// buildSweepReplacement bumps a sweep: the same inputs and the one output lower by the extra fee (a sweep has no change, so the output pays). The new
// fee follows the replacement rule; it must also stay under the sweep ceiling (or, for a sweep of at least sweep_urgent_value, the fee rate cap),
// under the fee cap, and the sweep must still be worth it at that fee (value >= max(min_sweep, k x fee)) and leave an output above dust. If not it
// returns chain.ErrCannotBump: an ALERT, the sweep keeps waiting, nothing is voided.
func (a *Adapter) buildSweepReplacement(ctx context.Context, tx pgx.Tx, ownerID string) (chain.UnsignedTx, error) {
	p, oldFee, err := a.lastSend(ctx, tx, "sweep", ownerID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	sh, ok := a.byAddr[p.Outputs[0].Address]
	if len(p.Outputs) != 1 || !ok {
		return chain.UnsignedTx{}, fmt.Errorf("%w: a sweep has one output to a shard", chain.ErrCannotBump)
	}
	var sum uint64
	for _, in := range p.Inputs {
		sum += in.Value
	}
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	vs := uint64(EstimateVSize(built.Tx))
	sweepCap := a.feeCap(vs)
	if !a.urgent(sum) {
		sweepCap = min(sweepCap, a.cfg.SweepMaxFeeRate*vs)
	}
	fee, err := a.escalate(ctx, tx, "sweep", ownerID, oldFee, vs, sweepCap, func(fee uint64) error {
		if err := a.checkFee(fee, vs); err != nil {
			return err
		}
		if !a.urgent(sum) && fee > a.cfg.SweepMaxFeeRate*vs {
			return fmt.Errorf("%w: %d sats over %d vbytes is above the sweep ceiling of %d sat/vB", chain.ErrCannotBump, fee, vs, a.cfg.SweepMaxFeeRate)
		}
		if need := max(a.cfg.MinSweep, a.cfg.SweepK*fee); sum < need {
			return fmt.Errorf("%w: at a fee of %d the sweep of %d sats would break the sweep rule (it needs %d)", chain.ErrCannotBump, fee, sum, need)
		}
		if sum < fee+DustLimit(KindP2WPKH) {
			return fmt.Errorf("%w: %d sats cannot pay a fee of %d and leave an output", chain.ErrCannotBump, sum, fee)
		}
		return nil
	})
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	p.Outputs[0].Value = sum - fee
	b2, raw, err := a.record(ctx, tx, "sweep", ownerID, "send", p, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, b2, raw, sh.partition, p), nil
}

// buildConsolidateReplacement bumps a consolidation: the same inputs and the one output to the shard lower by the extra fee (a consolidation has no
// change, so the output pays). The new fee follows the replacement rule and must stay under the fee caps and consolidate_max_fee_rate, and the output
// must stay above dust. If not it returns chain.ErrCannotBump: an ALERT, the consolidation keeps waiting, nothing is voided.
func (a *Adapter) buildConsolidateReplacement(ctx context.Context, tx pgx.Tx, ownerID string) (chain.UnsignedTx, error) {
	p, oldFee, err := a.lastSend(ctx, tx, OwnerKindConsolidate, ownerID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	sh, ok := a.byAddr[p.Outputs[0].Address]
	if len(p.Outputs) != 1 || !ok {
		return chain.UnsignedTx{}, fmt.Errorf("%w: a consolidation has one output to a shard", chain.ErrCannotBump)
	}
	var sum uint64
	for _, in := range p.Inputs {
		sum += in.Value
	}
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	vs := uint64(EstimateVSize(built.Tx))
	fee, err := a.escalate(ctx, tx, OwnerKindConsolidate, ownerID, oldFee, vs, min(a.feeCap(vs), a.cfg.ConsolidateMaxFeeRate*vs), func(fee uint64) error {
		if err := a.checkFee(fee, vs); err != nil {
			return err
		}
		if fee > a.cfg.ConsolidateMaxFeeRate*vs {
			return fmt.Errorf("%w: %d sats over %d vbytes is above the consolidation ceiling of %d sat/vB", chain.ErrCannotBump, fee, vs, a.cfg.ConsolidateMaxFeeRate)
		}
		if sum < fee+DustLimit(KindP2WPKH)+1 {
			return fmt.Errorf("%w: %d sats cannot pay a fee of %d and leave an output above dust", chain.ErrCannotBump, sum, fee)
		}
		return nil
	})
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	p.Outputs[0].Value = sum - fee
	b2, raw, err := a.record(ctx, tx, OwnerKindConsolidate, ownerID, "send", p, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, b2, raw, sh.partition, p), nil
}
