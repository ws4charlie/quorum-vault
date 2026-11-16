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

// BatchMember is one withdrawal of a batch to build: its id, destination and amount in satoshis. The order of the list is the order of the
// payments (first approved, first paid) and of the transaction's outputs.
type BatchMember struct {
	ID     string
	To     string
	Amount uint64
}

// BatchBuild is a batch built from the head of a member list.
type BatchBuild struct {
	// Tx is the unsigned transaction (every input, then the payments in member order, then the change), as BuildWithdrawal returns one.
	Tx chain.UnsignedTx
	// Funded is how many leading members the transaction pays: the longest prefix of the list that the partition's available outputs can fund
	// within max_inputs with the fee-bump reserve. Member i of the prefix is output i.
	Funded int
	// FeeShares has one entry per funded member: its share of Fee, in satoshis, deterministic, summing to Fee exactly.
	FeeShares []uint64
	Fee       uint64
	VSize     uint64
	Change    uint64
}

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
	if batchID == "" || len(members) == 0 {
		return BatchBuild{}, errors.New("btc: a batch needs an id and at least one member")
	}
	sh, err := a.shardOf(partitionID)
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
			return BatchBuild{}, fmt.Errorf("btc: batch member %s: destination: %w", m.ID, err)
		}
		if m.Amount < DustLimit(d.Kind) {
			return BatchBuild{}, fmt.Errorf("btc: batch member %s: amount %d is below the dust limit %d of %s", m.ID, m.Amount, DustLimit(d.Kind), d.Kind)
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
	need := func(k, n int) (want, vs uint64) {
		outs := append(append([][]byte{}, scripts[:k]...), sh.script)
		vs = vsize(n, outs...)
		var pay uint64
		for _, m := range members[:k] {
			pay += m.Amount
		}
		return ReserveNeed(pay, vs*rate, vs, a.cfg.MaxTxFeeSats, a.cfg.MaxFeeRate), vs
	}
	// take walks a list in order and returns the shortest prefix of it that holds need(k, n), at most max_inputs long.
	take := func(list []utxo, k int) []utxo {
		var sum uint64
		for n, u := range list {
			if n >= a.cfg.MaxInputs {
				break
			}
			sum += u.value
			if want, _ := need(k, n+1); sum >= want {
				return list[:n+1]
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
	for k := len(members); k >= 1; k-- { // the longest prefix that can be paid
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
			a.cfg.Chain, u.txid, u.vout, batchID, OwnerKindBatch); err != nil {
			return BatchBuild{}, err
		}
		sum += u.value
		p.Inputs = append(p.Inputs, PayloadInput{TxID: u.txid, Vout: u.vout, Value: u.value, Path: sh.path, Sequence: SequenceRBF})
	}
	for i, m := range members[:funded] {
		p.Outputs = append(p.Outputs, PayloadOutput{Address: canon[i], Value: m.Amount})
		pay += m.Amount
	}
	outs := append(append([][]byte{}, scripts[:funded]...), sh.script)
	vs := vsize(len(picked), outs...)
	fee := vs * rate
	if fee > a.cfg.MaxTxFeeSats {
		return BatchBuild{}, fmt.Errorf("%w: %d sats against the cap %d", ErrFeeTooHigh, fee, a.cfg.MaxTxFeeSats)
	}
	change := sum - pay - fee // the selection keeps at least the fee cap's room and a dust change above the payments
	p.Outputs = append(p.Outputs, PayloadOutput{Address: sh.address, Value: change})
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return BatchBuild{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return BatchBuild{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO btc_attempts (chain, txid, owner_kind, owner_id, kind, payload, fee) VALUES ($1,$2,$6,$3,'send',$4::jsonb,$5)`,
		a.cfg.Chain, built.TxID, batchID, string(raw), int64(fee), OwnerKindBatch); err != nil {
		return BatchBuild{}, fmt.Errorf("btc: record batch attempt: %w", err)
	}
	ref := chain.KeyRef{PartitionID: partitionID, Path: PathString(sh.path)}
	u := chain.UnsignedTx{Chain: a.cfg.Chain, Digest: built.Digests[0], Payload: raw, KeyRef: ref}
	for _, d := range built.Digests[1:] {
		u.More = append(u.More, chain.SigInput{Digest: d, KeyRef: ref})
	}
	return BatchBuild{Tx: u, Funded: funded, FeeShares: FeeShares(fee, scripts[:funded], vs), Fee: fee, VSize: vs, Change: change}, nil
}

// lockCandidates reads up to limit of the partition's available hot outputs in the given order and locks them for the caller's transaction, skipping
// the ones another transaction holds.
func (a *Adapter) lockCandidates(ctx context.Context, tx pgx.Tx, partitionID, order string, limit int) ([]utxo, error) {
	rows, err := tx.Query(ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit
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
		chain.ErrNotEnoughOutputs, chain.ErrFeeReserve, partitionID, sum, n, head.ID, head.Amount, FeeCap(a.cfg.MaxTxFeeSats, a.cfg.MaxFeeRate, vs), vs, changeDust, want)
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
