package btc

import (
	"math/big"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// BatchPayment is one payment of a verified batch as the transaction itself says it: the canonical destination and the satoshis.
type BatchPayment struct {
	Destination string
	Amount      uint64
}

// DefaultBatchOutputs is the zone ceiling on the payments of one batch that the docs and the example configs recommend. The zone has no default:
// a config that does not set max_batch_outputs does not sign batches at all.
const DefaultBatchOutputs = 50

// BatchesEnabled reports whether this zone signs batches at all: its own output ceiling is set (SigningConfig.MaxBatchOutputs).
func (v *Verifier) BatchesEnabled() bool { return v.cfg.MaxBatchOutputs > 0 }

// VerifyBatch checks that the job's digest is the sighash of one input of the payload under that input's derived key, and that the transaction pays
// exactly the members of the batch and nothing else: the payments are the members' own withdrawals, in the batch's order, then at most one change
// output, to the partition's own shard, last. The zone's own ceilings (its output limit, its value limit), its fee caps for this size and the
// destination rules of every member are what the core cannot move. It returns the payments as the transaction says them, for the gateway's policy.
//
// Every member must be valid on its own the way a single withdrawal's intent is (chain, partition, asset, a positive amount, an id), the ids must
// all differ, and no two members may be the same withdrawal twice. What the batch shares with a single send is judged by Parse (inputs, caps) and,
// for a first send, CheckFirstSend (the fee-bump reserve).
func (v *Verifier) VerifyBatch(u chain.UnsignedTx, b signjob.Batch) ([]BatchPayment, error) {
	if !v.BatchesEnabled() {
		return nil, reject("this zone does not sign batches (max_batch_outputs is not set)")
	}
	if b.Kind != signjob.KindBatch {
		return nil, reject("batch kind %q", b.Kind)
	}
	if b.Chain != v.cfg.Chain {
		return nil, reject("batch chain %q, want %q", b.Chain, v.cfg.Chain)
	}
	if b.Asset != Native {
		return nil, reject("batch asset %q, want %s", b.Asset, Native)
	}
	n := len(b.Members)
	if n == 0 {
		return nil, reject("a batch has at least one member")
	}
	if n > v.cfg.MaxBatchOutputs {
		return nil, reject("batch has %d payments, the zone's ceiling is %d", n, v.cfg.MaxBatchOutputs)
	}
	pr, err := v.Parse(u)
	if err != nil {
		return nil, err
	}
	p := pr.Payload
	if u.KeyRef.PartitionID != b.PartitionID {
		return nil, reject("key partition %q, batch partition %q", u.KeyRef.PartitionID, b.PartitionID)
	}
	own, ok := v.shard[b.PartitionID]
	if !ok {
		return nil, reject("partition %q has no pinned hot shard", b.PartitionID)
	}
	for i, in := range p.Inputs {
		if PathString(in.Path) != PathString(own.path) {
			return nil, reject("batch: input %d is at path %s, not the partition's own shard %s", i, PathString(in.Path), PathString(own.path))
		}
	}
	if len(p.Outputs) != n && len(p.Outputs) != n+1 {
		return nil, reject("batch of %d members has %d outputs, want the %d payments and at most one change", n, len(p.Outputs), n)
	}
	ownA, err := v.shardAt(own, pr.Gen)
	if err != nil {
		return nil, reject("%v", err)
	}
	if len(p.Outputs) == n+1 && pr.outs[n].Canonical != ownA {
		return nil, reject("change goes to %s, not the partition's own shard %s", pr.outs[n].Canonical, ownA)
	}
	ids := map[string]bool{}
	pairs := map[string]bool{}
	var total uint64
	pay := make([]BatchPayment, 0, n)
	for i, m := range b.Members {
		in := m.Intent
		switch {
		case in.Kind != "withdrawal":
			return nil, reject("member %d: kind %q, a batch pays withdrawals", i, in.Kind)
		case in.ID == "":
			return nil, reject("member %d has no id", i)
		case in.Chain != v.cfg.Chain || in.PartitionID != b.PartitionID || in.Asset != b.Asset:
			return nil, reject("member %d (%s): chain %q partition %q asset %q differ from the batch's", i, in.ID, in.Chain, in.PartitionID, in.Asset)
		case in.ID == b.ID:
			return nil, reject("member %d has the batch's own id %q", i, in.ID)
		case ids[in.ID]:
			return nil, reject("withdrawal %s appears twice in the batch", in.ID)
		}
		ids[in.ID] = true
		amount, ok := new(big.Int).SetString(in.Amount, 10)
		if !ok || amount.Sign() <= 0 || !amount.IsUint64() || amount.String() != in.Amount {
			return nil, reject("member %d (%s): amount %q", i, in.ID, in.Amount)
		}
		to, err := DecodeAddress(in.To, v.params)
		if err != nil {
			return nil, reject("member %d (%s): destination: %v", i, in.ID, err)
		}
		// The pair guard: one withdrawal id never pays the same destination and amount twice within the batch (the id check above already makes ids
		// unique, so this is the second line of defence if that ever changed); distinct ids may pay the same pair.
		pair := in.ID + "\x00" + to.Canonical + "\x00" + in.Amount
		if pairs[pair] {
			return nil, reject("withdrawal %s pays %s %s twice in the batch", in.ID, to.Canonical, in.Amount)
		}
		pairs[pair] = true
		if pr.outs[i].Canonical != to.Canonical || p.Outputs[i].Value != amount.Uint64() {
			return nil, reject("output %d pays %d to %s, member %d (%s) is %s to %s", i, p.Outputs[i].Value, pr.outs[i].Canonical, i, in.ID, in.Amount, to.Canonical)
		}
		total += amount.Uint64()
		if total < amount.Uint64() {
			return nil, reject("the batch total overflows")
		}
		pay = append(pay, BatchPayment{Destination: to.Canonical, Amount: amount.Uint64()})
	}
	if total > v.cfg.MaxBatchValue {
		return nil, reject("batch pays %d sats in all, the zone's ceiling is %d", total, v.cfg.MaxBatchValue)
	}
	return pay, nil
}
