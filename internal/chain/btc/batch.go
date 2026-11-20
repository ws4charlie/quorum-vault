package btc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// OwnerKindBatch owns the outputs a batch reserves and the attempts it builds (btc_attempts.owner_kind, btc_utxos.owner_kind); its id is the batch's.
const OwnerKindBatch = "batch"

// BatchMember and BatchBuild are the chain package's (chain.BatchBuilder).
type (
	BatchMember = chain.BatchMember
	BatchBuild  = chain.BatchBuild
)

var _ chain.BatchBuilder = (*Adapter)(nil)

// BuildBatch builds one transaction for the longest FIFO prefix of members that the partition's available outputs can fund, inside the caller's
// transaction, reserving the outputs it takes for the batch (owner kind OwnerKindBatch, owner id batchID) and recording the attempt. Nothing is
// skipped: it never pays member 3 while member 2 cannot be funded; if the head itself cannot be funded it returns chain.ErrNotEnoughOutputs (also
// wrapping chain.ErrFeeReserve when the payment and today's fee alone would have been covered) and reserves nothing, and the batch waits.
//
// It selects like BuildWithdrawal (oldest outputs first; the largest first when the oldest max_inputs cannot carry the payments and the shard holds
// more) and keeps the same fee-bump reserve for the whole batch: sum(inputs) >= sum(payments) + feeCap(vsize of the batch) + dust, so the batch can
// be bumped to the cap with its own inputs (reserve.go). Outputs another transaction holds locked are not taken, so the prefix is what is free now.
// A member whose destination or amount cannot be paid at all (an invalid address, below dust) is an error naming it, not a skip.
func (a *Adapter) BuildBatch(ctx context.Context, tx pgx.Tx, batchID, partitionID string, members []BatchMember) (BatchBuild, error) {
	if err := a.refreshCaps(ctx); err != nil {
		return BatchBuild{}, err
	}
	if batchID == "" || len(members) == 0 {
		return BatchBuild{}, errors.New("btc: a batch needs an id and at least one member")
	}
	sh, err := a.shardOf(ctx, partitionID)
	if err != nil {
		return BatchBuild{}, err
	}
	scripts := make([][]byte, len(members))
	canon := make([]string, len(members))
	seen := map[string]bool{}
	for i, m := range members {
		if m.ID == "" || seen[m.ID] {
			return BatchBuild{}, fmt.Errorf("btc: batch member %d has an empty or repeated id %q", i, m.ID)
		}
		seen[m.ID] = true
		d, err := DecodeAddress(m.To, a.cfg.params)
		if err != nil {
			return BatchBuild{}, &chain.BatchMemberError{ID: m.ID, Err: fmt.Errorf("destination: %w", err)}
		}
		if m.Amount < DustLimit(d.Kind) {
			return BatchBuild{}, &chain.BatchMemberError{ID: m.ID, Err: fmt.Errorf("amount %d is below the dust limit %d of %s", m.Amount, DustLimit(d.Kind), d.Kind)}
		}
		if scripts[i], err = OutputScript(m.To, a.cfg.params); err != nil {
			return BatchBuild{}, err
		}
		canon[i] = d.Canonical
	}
	rate := a.feeRate(ctx)
	changeDust := DustLimit(KindP2WPKH)

	// The candidates, locked for this transaction (not yet reserved): the oldest max_inputs+1 and the largest max_inputs of the partition's available
	// outputs. Everything below is decided in memory from these two lists, then the chosen outputs are reserved.
	oldest, err := a.lockCandidates(ctx, tx, partitionID, "created_at, txid, vout", a.cfg.MaxInputs+1)
	if err != nil {
		return BatchBuild{}, err
	}
	largest, err := a.lockCandidates(ctx, tx, partitionID, "value DESC, created_at, txid, vout", a.cfg.MaxInputs)
	if err != nil {
		return BatchBuild{}, err
	}

	// need is what n inputs must hold to pay members[:k]: the payments, the larger of today's fee and the fee cap for the final size, and a dust change.
	// The outputs held for members that were in a cancelled batch (HoldForResend), by that batch. A prefix that pays such a member spends the held
	// output, and it never ends inside such a group: the rest would be left with no way to be paid.
	held := map[string][]utxo{}
	for _, m := range members {
		if m.ResendOf == "" {
			continue
		}
		if _, ok := held[m.ResendOf]; !ok {
			us, err := a.lockHeld(ctx, tx, m.ResendOf)
			if err != nil {
				return BatchBuild{}, err
			}
			held[m.ResendOf] = us
		}
	}
	// limit is how many leading members can be paid at all: up to the first one whose held output is missing.
	limit := len(members)
	for i, m := range members {
		if m.ResendOf != "" && len(held[m.ResendOf]) == 0 {
			limit = i
			break
		}
	}
	// splits reports whether a prefix of k members ends inside a group of members that share one cancelled batch.
	splits := func(k int) bool {
		in := map[string]bool{}
		for _, m := range members[:k] {
			if m.ResendOf != "" {
				in[m.ResendOf] = true
			}
		}
		for _, m := range members[k:] {
			if in[m.ResendOf] {
				return true
			}
		}
		return false
	}
	// forced is what the prefix must spend: the held outputs of the groups it pays.
	forced := func(k int) []utxo {
		var out []utxo
		seen := map[string]bool{}
		for _, m := range members[:k] {
			if m.ResendOf != "" && !seen[m.ResendOf] {
				seen[m.ResendOf] = true
				out = append(out, held[m.ResendOf]...)
			}
		}
		return out
	}
	need := func(k, n int) (want, vs uint64) {
		outs := append(append([][]byte{}, scripts[:k]...), sh.script)
		vs = vsize(n, outs...)
		var pay uint64
		for _, m := range members[:k] {
			pay += m.Amount
		}
		return ReserveNeed(pay, vs*rate, vs, a.caps().MaxTxFeeSats, a.caps().MaxFeeRate), vs
	}
	// take walks a list in order and returns the shortest prefix of it that holds need(k, n), at most max_inputs long.
	take := func(list []utxo, k int) []utxo {
		first := forced(k)
		var sum uint64
		for _, u := range first {
			sum += u.value
		}
		if len(first) > a.cfg.MaxInputs {
			return nil
		}
		if len(first) > 0 {
			if want, _ := need(k, len(first)); sum >= want {
				return first
			}
		}
		for n, u := range list {
			if len(first)+n >= a.cfg.MaxInputs {
				break
			}
			sum += u.value
			if want, _ := need(k, len(first)+n+1); sum >= want {
				return append(append([]utxo{}, first...), list[:n+1]...)
			}
		}
		return nil
	}
	// pick is the selection of BuildWithdrawal for k payments: the oldest outputs, or the largest when the oldest max_inputs cannot carry them and the
	// shard holds more than that.
	pick := func(k int) []utxo {
		if got := take(oldest, k); got != nil {
			return got
		}
		if len(oldest) > a.cfg.MaxInputs {
			return take(largest, k)
		}
		return nil
	}
	funded, picked := 0, []utxo(nil)
	for k := limit; k >= 1; k-- { // the longest prefix that can be paid
		if splits(k) {
			continue
		}
		if got := pick(k); got != nil {
			funded, picked = k, got
			break
		}
	}
	if funded == 0 {
		return BatchBuild{}, a.batchShort(members[0], oldest, need, changeDust, rate, sh.partition, scripts[0], sh.script)
	}

	var sum, pay uint64
	p := Payload{Version: PayloadVersion}
	for _, u := range picked {
		if _, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='reserved', owner_kind=$5, owner_id=$4, updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3`,
			a.cfg.Chain, u.txid, u.vout, batchID, OwnerKindBatch); err != nil { // an output held for a resend is reserved already: it changes owner
			return BatchBuild{}, err
		}
		sum += u.value
		p.Inputs = append(p.Inputs, PayloadInput{TxID: u.txid, Vout: u.vout, Value: u.value, Path: sh.path, Sequence: SequenceRBF, Gen: sh.payloadGen()})
	}
	for i, m := range members[:funded] {
		p.Outputs = append(p.Outputs, PayloadOutput{Address: canon[i], Value: m.Amount})
		pay += m.Amount
	}
	outs := append(append([][]byte{}, scripts[:funded]...), sh.script)
	vs := vsize(len(picked), outs...)
	fee := vs * rate
	if fee > a.caps().MaxTxFeeSats {
		return BatchBuild{}, fmt.Errorf("%w: %d sats against the cap %d", ErrFeeTooHigh, fee, a.caps().MaxTxFeeSats)
	}
	change := sum - pay - fee // the selection keeps at least the fee cap's room and a dust change above the payments
	p.Outputs = append(p.Outputs, PayloadOutput{Address: sh.address, Value: change})
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return BatchBuild{}, err
	}
	p.FeeCapsSeq = a.capsSeq()
	raw, err := json.Marshal(p)
	if err != nil {
		return BatchBuild{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO btc_attempts (chain, txid, owner_kind, owner_id, kind, payload, fee) VALUES ($1,$2,$6,$3,'send',$4::jsonb,$5)`,
		a.cfg.Chain, built.TxID, batchID, string(raw), int64(fee), OwnerKindBatch); err != nil {
		return BatchBuild{}, fmt.Errorf("btc: record batch attempt: %w", err)
	}
	ref := chain.KeyRef{PartitionID: partitionID, Path: sh.keyPath()}
	u := chain.UnsignedTx{Chain: a.cfg.Chain, Digest: built.Digests[0], Payload: raw, KeyRef: ref}
	for _, d := range built.Digests[1:] {
		u.More = append(u.More, chain.SigInput{Digest: d, KeyRef: ref})
	}
	return BatchBuild{Tx: u, Funded: funded, FeeShares: FeeShares(fee, scripts[:funded], vs), Fee: fee, VSize: vs, Change: change}, nil
}

// lockCandidates reads up to limit of the partition's available hot outputs in the given order and locks them for the caller's transaction, skipping
// the ones another transaction holds.
func (a *Adapter) lockCandidates(ctx context.Context, tx pgx.Tx, partitionID, order string, limit int) ([]utxo, error) {
	sh, err := a.shardOf(ctx, partitionID)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit AND path='`+sh.keyPath()+`'
		ORDER BY `+order+` LIMIT $3 FOR UPDATE SKIP LOCKED`, a.cfg.Chain, partitionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []utxo
	for rows.Next() {
		var u utxo
		var v int64
		if err := rows.Scan(&u.txid, &u.vout, &v); err != nil {
			return nil, err
		}
		u.value = uint64(v)
		out = append(out, u)
	}
	return out, rows.Err()
}

// batchShort explains why the head of a batch cannot be funded: the same two reasons as a single withdrawal.
func (a *Adapter) batchShort(head BatchMember, oldest []utxo, need func(k, n int) (uint64, uint64), changeDust, rate uint64, partitionID string, headScript, changeScript []byte) error {
	var sum uint64
	n := min(len(oldest), a.cfg.MaxInputs)
	for _, u := range oldest[:n] {
		sum += u.value
	}
	if n == 0 || sum < head.Amount+vsize(n, headScript, changeScript)*rate { // the payment and today's fee are not covered either
		return fmt.Errorf("%w: %s: the head of the batch (%s, %d sats) cannot be paid from %d sats in %d available outputs", chain.ErrNotEnoughOutputs, partitionID, head.ID, head.Amount, sum, n)
	}
	want, vs := need(1, n)
	return fmt.Errorf("%w: %w: %s holds %d sats in %d outputs for the head of the batch (%s, %d sats) and the reserve to bump it to the fee cap (%d sats for %d vbytes, plus %d dust change) needs %d in all",
		chain.ErrNotEnoughOutputs, chain.ErrFeeReserve, partitionID, sum, n, head.ID, head.Amount, FeeCap(a.caps().MaxTxFeeSats, a.caps().MaxFeeRate, vs), vs, changeDust, want)
}

// FeeShares splits a batch's fee between its members, in satoshis, deterministically: a member's weight is the size of its own output plus an equal
// share of everything the members have in common (the inputs, the overhead and the change output), so the weights are out_i*N + common for N members,
// scaled by N to stay whole. Each share is the rounded-down fraction of the fee; the satoshis left over go to the first (earliest) member. The shares
// always sum to fee exactly. vs is the virtual size of the whole transaction and scripts are the members' output scripts, in order.
func FeeShares(fee uint64, scripts [][]byte, vs uint64) []uint64 {
	n := uint64(len(scripts))
	if n == 0 {
		return nil
	}
	sizes := make([]uint64, n)
	var outs uint64
	for i, s := range scripts {
		sizes[i] = 8 + compactSize(len(s)) + uint64(len(s)) // value, script length, script
		outs += sizes[i]
	}
	common := uint64(0)
	if vs > outs {
		common = vs - outs
	}
	total := new(big.Int).Mul(new(big.Int).SetUint64(n), new(big.Int).SetUint64(outs+common)) // sum of the weights
	shares := make([]uint64, n)
	var paid uint64
	for i := range shares {
		w := new(big.Int).SetUint64(sizes[i]*n + common)
		w.Mul(w, new(big.Int).SetUint64(fee))
		shares[i] = w.Div(w, total).Uint64()
		paid += shares[i]
	}
	shares[0] += fee - paid
	return shares
}

func compactSize(n int) uint64 {
	switch {
	case n < 0xfd:
		return 1
	case n <= 0xffff:
		return 3
	}
	return 5
}

// lockHeld reads, and locks for the caller's transaction, the outputs held for the members of a cancelled batch.
func (a *Adapter) lockHeld(ctx context.Context, tx pgx.Tx, oldBatchID string) ([]utxo, error) {
	rows, err := tx.Query(ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved'
		ORDER BY txid, vout FOR UPDATE`, a.cfg.Chain, ownerKindResend, oldBatchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []utxo
	for rows.Next() {
		var u utxo
		var v int64
		if err := rows.Scan(&u.txid, &u.vout, &v); err != nil {
			return nil, err
		}
		u.value = uint64(v)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ownerKindResend owns the output of a cancel while it waits for the members of the cancelled batch to be paid again; its owner id is that batch.
const ownerKindResend = "resend"

// HoldForResend sets the output of a confirmed cancel of a batch aside for the batch's members (chain.BatchBuilder). It runs in the transaction that
// settles the cancel, after Settle has recorded the output as available, so no build can take it in between.
func (a *Adapter) HoldForResend(ctx context.Context, tx pgx.Tx, cancelTxID, oldBatchID string) error {
	tag, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='reserved', owner_kind=$4, owner_id=$3, updated_at=now()
		WHERE chain=$1 AND txid=$2 AND vout=0 AND status IN ('available', 'reserved') AND (status = 'available' OR owner_kind = $4)`, a.cfg.Chain, cancelTxID, oldBatchID, ownerKindResend)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("btc: the output of cancel %s is not an available output of the cell: nothing to hold for batch %s", cancelTxID, oldBatchID)
	}
	return nil
}

// ReleaseResend gives the held output of a cancelled batch back to the shard (no member needs it any more).
func (a *Adapter) ReleaseResend(ctx context.Context, tx pgx.Tx, oldBatchID string) error {
	_, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='available', owner_kind=NULL, owner_id=NULL, updated_at=now() WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved'`,
		a.cfg.Chain, ownerKindResend, oldBatchID)
	return err
}

// BatchShares splits the fee a confirmed attempt of a batch paid between its first n payments (chain.BatchBuilder). The sizes come from the attempt's own
// payload, so a fee-bumped attempt that confirmed is split by the same rule as the first one.
func (a *Adapter) BatchShares(ctx context.Context, q chain.Querier, batchID, txid string, n int, fee uint64) ([]uint64, error) {
	var raw []byte
	if err := q.QueryRow(ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND txid=$2 AND owner_kind=$3 AND owner_id=$4`, a.cfg.Chain, txid, OwnerKindBatch, batchID).Scan(&raw); err != nil {
		return nil, fmt.Errorf("btc: batch %s has no attempt %s: %w", batchID, txid, err)
	}
	p, err := DecodePayload(raw)
	if err != nil {
		return nil, err
	}
	if n < 1 || n >= len(p.Outputs)+1 {
		return nil, fmt.Errorf("btc: batch %s attempt %s has %d outputs, not %d payments", batchID, txid, len(p.Outputs), n)
	}
	scripts := make([][]byte, n)
	for i := 0; i < n; i++ {
		if scripts[i], err = OutputScript(p.Outputs[i].Address, a.cfg.params); err != nil {
			return nil, err
		}
	}
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return nil, err
	}
	return FeeShares(fee, scripts, uint64(EstimateVSize(built.Tx))), nil
}
