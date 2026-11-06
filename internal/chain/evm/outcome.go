package evm

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Outcome implements chain.Adapter: it looks at every transaction ever
// broadcast at the owner's nonce (the original, its replacements and any
// cancel). Any of them may be the one that mined, so every decision looks at
// all of them.
func (a *Adapter) Outcome(ctx context.Context, ownerKind, ownerID string) (chain.Outcome, error) {
	rows, err := a.pool.Query(ctx, `SELECT at.tx_hash, at.kind FROM evm_tx_attempts at
		JOIN evm_nonce_allocations al ON al.chain=at.chain AND al.address=at.address AND al.nonce=at.nonce
		WHERE al.chain=$1 AND al.owner_kind=$2 AND al.owner_id=$3 ORDER BY at.created_at`, a.cfg.Chain, ownerKind, ownerID)
	if err != nil {
		return chain.Outcome{}, err
	}
	type attempt struct{ hash, kind string }
	var atts []attempt
	for rows.Next() {
		var t attempt
		if err := rows.Scan(&t.hash, &t.kind); err != nil {
			rows.Close()
			return chain.Outcome{}, err
		}
		atts = append(atts, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return chain.Outcome{}, err
	}
	out := chain.Outcome{State: chain.OutcomeOpen, Attempts: len(atts)}
	if len(atts) == 0 {
		return out, nil
	}
	kindOf := func(k string) string {
		if k == "cancel" {
			return chain.AttemptCancel
		}
		return chain.AttemptSend
	}
	dropped := 0
	for _, t := range atts {
		st, err := a.Status(ctx, t.hash)
		if err != nil {
			return chain.Outcome{}, err
		}
		switch st {
		case chain.TxConfirmed:
			return chain.Outcome{State: chain.OutcomeConfirmed, Hash: t.hash, Kind: kindOf(t.kind), Attempts: len(atts)}, nil
		case chain.TxFailed:
			// A cancel that reverts still used the nonce: the nonce is free either way.
			return chain.Outcome{State: chain.OutcomeConfirmed, Hash: t.hash, Kind: kindOf(t.kind), Failed: t.kind != "cancel", Attempts: len(atts)}, nil
		case chain.TxDropped:
			dropped++
		}
	}
	if dropped == len(atts) {
		// Status reports dropped only when the sender's nonce has already passed
		// the attempt's and the attempt has no receipt: a transaction we did not
		// make used our nonce. A merely forgotten transaction stays pending.
		out.State = chain.OutcomeConsumed
		out.Detail = a.nonceDetail(ctx, a.pool, ownerKind, ownerID)
	}
	return out, nil
}

// Reservation implements chain.Adapter: the owner's nonce allocation, open
// while it is allocated or broadcast and so may still be used by a signature
// somebody holds.
func (a *Adapter) Reservation(ctx context.Context, q chain.Querier, ownerKind, ownerID string) (chain.Reservation, error) {
	var addr string
	var nonce int64
	var open bool
	err := q.QueryRow(ctx, `SELECT address, nonce, status IN ('allocated','broadcast') FROM evm_nonce_allocations
		WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 ORDER BY (status IN ('allocated','broadcast')) DESC, nonce DESC LIMIT 1`,
		a.cfg.Chain, ownerKind, ownerID).Scan(&addr, &nonce, &open)
	if errors.Is(err, pgx.ErrNoRows) {
		return chain.Reservation{}, nil
	}
	if err != nil {
		return chain.Reservation{}, err
	}
	return chain.Reservation{Open: open, Account: addr, Detail: fmt.Sprintf("address %s nonce %d", addr, nonce)}, nil
}

func (a *Adapter) nonceDetail(ctx context.Context, q chain.Querier, ownerKind, ownerID string) string {
	r, err := a.Reservation(ctx, q, ownerKind, ownerID)
	if err != nil {
		return ""
	}
	return r.Detail
}
