package btc

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// CPFP (child pays for parent). When a send cannot be bumped any more (its replacements are used up, or the node refuses them for a reason a higher
// fee does not cure), a child can still pull it in: it spends the send's own change, back to the same hot shard, and pays enough that the pair mines.
//
//	child: one input, the parent's change; one output, the same shard.
//	fee:   parent fee + child fee <= feeCap(parent vsize + child vsize), and the child alone under feeCap(child vsize)
//
// The child's fee is the cost of the parent's owner, like a bump. It must also raise the package fee rate above the parent's own, or it helps nothing:
// when the parent already pays the cap rate there is no room (both are bounded by max_fee_rate), and the builder says so with chain.ErrCannotBump.
//
// One child per parent: while it is unconfirmed the child may be replaced by a higher-fee child of the same input (BIP125), and the parent is no
// longer replaced (that would orphan the child): BuildReplacement refuses, a cancel is still allowed and evicts the child. A child never has a child
// (the 25-ancestor chain limit stays far off): its input is a send's change, nothing else.

// cpfpKind is the owner kind under which the refusals of an owner's child are kept: what the node refused about a child says nothing about the send.
func cpfpKind(ownerKind string) string { return "cpfp:" + ownerKind }

// cpfpOwner reports whether a send of this owner kind has a change output a child can spend.
func cpfpOwner(ownerKind string) bool {
	return ownerKind == "withdrawal" || ownerKind == "to-cold" || ownerKind == OwnerKindBatch
}

// childOf is the owner's newest CPFP child of the parent txid, locked: its payload and fee. ok is false when there is none.
func (a *Adapter) childOf(ctx context.Context, tx pgx.Tx, ownerKind, ownerID, parentTxid string) (p Payload, fee uint64, ok bool, err error) {
	var raw []byte
	var f int64
	err = tx.QueryRow(ctx, `SELECT payload, fee FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND kind='cpfp' AND payload->'inputs'->0->>'txid' = $4
		ORDER BY created_at DESC, txid LIMIT 1 FOR UPDATE`, a.cfg.Chain, ownerKind, ownerID, parentTxid).Scan(&raw, &f)
	if errors.Is(err, pgx.ErrNoRows) {
		return Payload{}, 0, false, nil
	}
	if err != nil {
		return Payload{}, 0, false, err
	}
	p, err = DecodePayload(raw)
	return p, uint64(f), err == nil, err
}

// hasBroadcastChild reports whether a CPFP child of the parent txid was ever handed to the node.
func (a *Adapter) hasBroadcastChild(ctx context.Context, q chain.Querier, ownerKind, ownerID, parentTxid string) (bool, error) {
	var yes bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND kind='cpfp' AND broadcast_at IS NOT NULL
		AND payload->'inputs'->0->>'txid' = $4)`, a.cfg.Chain, ownerKind, ownerID, parentTxid).Scan(&yes)
	return yes, err
}

// parentAttempt is the owner's newest send that was handed to the node: the transaction a child pulls in.
func (a *Adapter) parentAttempt(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (p Payload, built *Unsigned, fee uint64, err error) {
	var raw []byte
	var f int64
	err = tx.QueryRow(ctx, `SELECT payload, fee FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND kind='send' AND broadcast_at IS NOT NULL
		ORDER BY created_at DESC, txid LIMIT 1 FOR UPDATE`, a.cfg.Chain, ownerKind, ownerID).Scan(&raw, &f)
	if errors.Is(err, pgx.ErrNoRows) {
		return Payload{}, nil, 0, fmt.Errorf("%w: %s %s has no transaction in the node to pull in", chain.ErrCannotBump, ownerKind, ownerID)
	}
	if err != nil {
		return Payload{}, nil, 0, err
	}
	if p, err = DecodePayload(raw); err != nil {
		return Payload{}, nil, 0, err
	}
	built, err = BuildUnsigned(p, a.acct)
	return p, built, uint64(f), err
}

// CPFPRoom is the most a child of vc virtual bytes may pay for a parent of vp virtual bytes that paid pf: the package under the fee cap, and the child
// alone under it. The signing zone computes the same from its own caps and its own record of the parent.
func CPFPRoom(maxTxFeeSats, maxFeeRate, pf, vp, vc uint64) uint64 {
	pkg := FeeCap(maxTxFeeSats, maxFeeRate, vp+vc)
	if pkg <= pf {
		return 0
	}
	return min(pkg-pf, FeeCap(maxTxFeeSats, maxFeeRate, vc))
}

// BuildCPFP builds the owner's child, or the next bump of the child it has. See the rule above. It implements chain.CPFPBuilder.
func (a *Adapter) BuildCPFP(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (chain.UnsignedTx, error) {
	if err := a.refreshCaps(ctx); err != nil {
		return chain.UnsignedTx{}, err
	}
	if !cpfpOwner(ownerKind) {
		return chain.UnsignedTx{}, chain.ErrNotSupported
	}
	if cancelling, err := a.isCancelling(ctx, tx, ownerKind, ownerID); err != nil {
		return chain.UnsignedTx{}, err
	} else if cancelling {
		return chain.UnsignedTx{}, fmt.Errorf("%w: %s %s is being cancelled", chain.ErrCannotBump, ownerKind, ownerID)
	}
	pp, pb, pf, err := a.parentAttempt(ctx, tx, ownerKind, ownerID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	n := len(pp.Outputs)
	sh, ok := a.byAddr[pp.Outputs[n-1].Address]
	if n < 2 || !ok {
		return chain.UnsignedTx{}, fmt.Errorf("%w: the transaction has no change output to spend", chain.ErrCannotBump)
	}
	change := pp.Outputs[n-1].Value
	vp := uint64(EstimateVSize(pb.Tx))
	vc := vsize(1, sh.script)
	room := CPFPRoom(a.caps().MaxTxFeeSats, a.caps().MaxFeeRate, pf, vp, vc)
	if dust := DustLimit(KindP2WPKH); change > dust {
		room = min(room, change-dust)
	} else {
		room = 0
	}
	// useful: the package rate must rise above the parent's own, and the child must pay the relay minimum.
	useful := func(fee uint64) error {
		if fee > room {
			return fmt.Errorf("%w: a child would pay %d sats, the room under the fee caps is %d (the parent pays %d over %d vbytes)", chain.ErrCannotBump, fee, room, pf, vp)
		}
		if fee < vc*incrementalRate || fee*vp <= pf*vc {
			return fmt.Errorf("%w: a child paying %d sats does not raise the package fee rate above the parent's %d sats over %d vbytes", chain.ErrCannotBump, fee, pf, vp)
		}
		return nil
	}

	in := PayloadInput{TxID: pb.TxID, Vout: uint32(n - 1), Value: change, Path: sh.path, Sequence: SequenceRBF}
	c := Payload{Version: PayloadVersion, Inputs: []PayloadInput{in}}
	var fee uint64
	if prev, old, have, err := a.childOf(ctx, tx, ownerKind, ownerID, pb.TxID); err != nil {
		return chain.UnsignedTx{}, err
	} else if have {
		// The next bump of the child: the replacement rule over its own fee, above any fee the node refused for a child, within the room.
		if len(prev.Inputs) != 1 || prev.Inputs[0].TxID != pb.TxID {
			return chain.UnsignedTx{}, fmt.Errorf("%w: the child is not the one-input child of %s", chain.ErrCannotBump, pb.TxID)
		}
		fee, err = a.escalate(ctx, tx, cpfpKind(ownerKind), ownerID, old, vc, room, useful)
		if err != nil {
			return chain.UnsignedTx{}, err
		}
	} else {
		// The first child: pay the market rate over the whole package, at least what makes the package rate beat the parent's.
		want := a.feeRate(ctx) * (vp + vc)
		fee = max(want, pf) - pf
		fee = max(fee, vc*incrementalRate, (pf*vc)/vp+1)
		if r, err := a.refusalsOf(ctx, tx, cpfpKind(ownerKind), ownerID); err != nil {
			return chain.UnsignedTx{}, err
		} else if r.Fee > 0 { // a first child the node refused as too cheap: the next pays more than it
			fee = max(fee, a.nextFee(ctx, r.Fee, vc))
		}
		fee = min(fee, room)
		if err := useful(fee); err != nil {
			return chain.UnsignedTx{}, err
		}
	}
	c.Outputs = []PayloadOutput{{Address: sh.address, Value: change - fee}}
	built, raw, err := a.record(ctx, tx, ownerKind, ownerID, "cpfp", c, fee)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return unsignedOf(a.cfg.Chain, built, raw, sh.partition, c), nil
}

var _ chain.CPFPBuilder = (*Adapter)(nil)

// childAtt is a CPFP child as the attempts table holds it.
type childAtt struct {
	txid string
	fee  uint64
	p    Payload
}

type rowsQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// confirmedChild is the CPFP child of the parent txid that confirmed at the spend depth, or nil. At most one can: children of one parent conflict.
func (a *Adapter) confirmedChild(ctx context.Context, q rowsQuerier, parentTxid string) (*childAtt, error) {
	rows, err := q.Query(ctx, `SELECT txid, fee, payload FROM btc_attempts WHERE chain=$1 AND kind='cpfp' AND broadcast_at IS NOT NULL AND payload->'inputs'->0->>'txid' = $2 ORDER BY created_at, txid`,
		a.cfg.Chain, parentTxid)
	if err != nil {
		return nil, err
	}
	var all []childAtt
	for rows.Next() {
		var c childAtt
		var fee int64
		var raw []byte
		if err := rows.Scan(&c.txid, &fee, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		c.fee = uint64(fee)
		if c.p, err = DecodePayload(raw); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range all {
		n, err := a.confirmations(ctx, all[i].txid)
		if err != nil {
			return nil, err
		}
		if n >= int64(a.cfg.SpendConfirmations) {
			return &all[i], nil
		}
	}
	return nil, nil
}
