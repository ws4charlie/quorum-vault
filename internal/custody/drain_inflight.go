package custody

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Work in flight at the moment a generation is marked compromised (docs/runbooks/stolen-hot-key.md, "Work in flight").
//
// A compromised generation signs nothing but its drain, and that includes the cancel that normally frees the nonce of a refused transaction. So a
// withdrawal or a sweep that the zone refuses after the mark would keep its EVM nonce "allocated" for ever: no signature exists, nothing can be
// cancelled, and the drain waits for the nonce. The rule that ends this, for each state an in-flight transaction can be in:
//
//	built, or queued for signing   the zone has not decided: its next decision refuses it. The core rejects the queued job itself at once, so nothing is
//	                               signed after the mark; the owner ends (a withdrawal is voided and its hold released, a sweep fails and is not planned
//	                               again while the destination is compromised)
//	being signed                   waits for the zone's answer: refused -> as above; signed -> the next row
//	refused, no signature          no transaction can ever exist for the nonce. It becomes a "hole": its owner ends, and the next drain move of the
//	                               shard uses the nonce for its own transfer, so the lane of the old address stays gapless
//	signed, not yet broadcast      real: the worker broadcasts it; the drain waits for it to be broadcast and final
//	broadcast, not confirmed       real: the drain waits for it, and says which transaction it waits for. The old key cannot sign a fee bump (the zone
//	                               refuses), so it can only confirm at the fee it has. The driver's stall limit bounds the wait; the runbook says
//	                               what an operator does then
//
// A hole is an allocation owned by OwnerKindHole, whose owner ID names the owner it came from.

// OwnerKindHole is the owner kind of a nonce that was allocated for a transaction the zone refused, with no signature, at an address that signs only drains.
const OwnerKindHole = "hole"

func (s *Service) evmFamily() bool { return s.Cfg.Family == FamilyEVM || s.Cfg.Family == "" }

// addressCompromised reports whether addr is the address of a generation marked compromised.
func addressCompromised(ctx context.Context, q chain.Querier, addr string) (bool, error) {
	var yes bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM keysets WHERE state='compromised' AND lower(address)=lower($1))`, addr).Scan(&yes)
	return yes, err
}

// handOverUnsigned turns the open nonce of owner o into a hole when the owner's transaction can never be signed: the address is a compromised
// generation's, the allocation is still only "allocated", and no job of the owner is being signed, done or failed (so no signature may exist). Jobs still
// waiting in the queue are rejected in the same transaction, so no gateway claims one afterwards. It reports whether it did.
func (s *Service) handOverUnsigned(ctx context.Context, tx pgx.Tx, o Owner) (bool, error) {
	if !s.evmFamily() || o.Kind == OwnerKindHole {
		return false, nil
	}
	var addr string
	var nonce int64
	err := tx.QueryRow(ctx, `SELECT address, nonce FROM evm_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='allocated'
		ORDER BY nonce DESC LIMIT 1 FOR UPDATE`, s.Cfg.Chain, o.Kind, o.ID).Scan(&addr, &nonce)
	if isNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	bad, err := addressCompromised(ctx, tx, addr)
	if err != nil || !bad {
		return false, err
	}
	pending, may, err := jobStates(ctx, tx, o)
	if err != nil || may {
		return false, err
	}
	for _, id := range pending {
		if _, err := tx.Exec(ctx, `UPDATE sign_jobs SET status='rejected', reject_reason='keyset_state: the generation of this address was marked compromised: it signs nothing but its drain', updated_at=now()
			WHERE id=$1 AND status='pending'`, id); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE evm_nonce_allocations SET owner_kind=$4, owner_id=$5, updated_at=now() WHERE chain=$1 AND address=$2 AND nonce=$3`,
		s.Cfg.Chain, addr, nonce, OwnerKindHole, o.Kind+":"+o.ID); err != nil {
		return false, err
	}
	return true, nil
}

// handedOverBefore reports whether the owner's nonce was handed over earlier (by the planner or an earlier try of the same activity) and a drain move may
// have used it since: the owner holds no open nonce AND no job of it can have produced a signature (every one is rejected). Both are needed. A job
// that is being signed, done or failed may have a signature on chain, and then the cancel must be built as before, whatever the allocation says.
func (s *Service) handedOverBefore(ctx context.Context, tx pgx.Tx, o Owner) (bool, error) {
	var open bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM evm_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status IN ('allocated','broadcast'))`,
		s.Cfg.Chain, o.Kind, o.ID).Scan(&open); err != nil || open {
		return false, err
	}
	var jobs, notRejected int
	if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status <> 'rejected') FROM sign_jobs WHERE starts_with(id, $1)`,
		string(OwnerTrack(o))+":").Scan(&jobs, &notRejected); err != nil {
		return false, err
	}
	return jobs > 0 && notRejected == 0, nil
}

// inflightItem is one open allocation of the old address that is not a drain move's.
type inflightItem struct {
	Kind, ID string
	Nonce    int64
	Status   string
	Jobs     string // the states of the owner's sign jobs
}

func (i inflightItem) String() string {
	return fmt.Sprintf("%s %s at nonce %d is %s (sign jobs: %s)", i.Kind, i.ID, i.Nonce, i.Status, i.Jobs)
}

// drainInflight counts what stops a drain from starting at the old address: transactions that may still reach the chain. A compromised generation's
// transactions that can no longer be signed are handed over first (holes are not in flight). It returns the real ones, in nonce order.
func (s *Service) drainInflight(ctx context.Context, from KeysetInfo) ([]inflightItem, error) {
	compromised := from.State == "compromised"
	rows, err := s.Pool.Query(ctx, `SELECT owner_kind, owner_id, nonce, status FROM evm_nonce_allocations
		WHERE chain=$1 AND lower(address)=lower($2) AND status IN ('allocated','broadcast') AND owner_kind NOT IN ($3,$4) ORDER BY nonce`,
		s.Cfg.Chain, from.Address, OwnerKindDrain, OwnerKindHole)
	if err != nil {
		return nil, err
	}
	var items []inflightItem
	for rows.Next() {
		var it inflightItem
		if err := rows.Scan(&it.Kind, &it.ID, &it.Nonce, &it.Status); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var real []inflightItem
	for _, it := range items {
		o := Owner{Kind: it.Kind, ID: it.ID}
		if compromised && it.Status == "allocated" {
			handed := false
			if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
				var err error
				handed, err = s.handOverUnsigned(ctx, tx, o)
				return err
			}); err != nil {
				return nil, err
			}
			if handed {
				continue
			}
		}
		var jobs string
		if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(string_agg(id || '=' || status, ', ' ORDER BY id), 'none') FROM sign_jobs WHERE starts_with(id, $1)`,
			string(OwnerTrack(o))+":").Scan(&jobs); err != nil {
			return nil, err
		}
		it.Jobs = jobs
		real = append(real, it)
	}
	return real, nil
}

// inflightReason is the line the planner records on the generation and the driver prints: how many, and which ones.
func inflightReason(items []inflightItem) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d transactions built from the old address are still in flight; the drain starts when they are final: ", len(items))
	for i, it := range items {
		if i == 3 {
			fmt.Fprintf(&b, "; and %d more", len(items)-3)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(it.String())
	}
	return b.String()
}

// adoptHole gives the lowest hole of the old address to the drain move that is being built, so the move's transfer fills the gap in the nonce lane.
func (s *Service) adoptHole(ctx context.Context, tx pgx.Tx, m DrainMove) error {
	if !s.evmFamily() {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE evm_nonce_allocations SET owner_kind=$3, owner_id=$4, updated_at=now()
		WHERE (chain, address, nonce) = (SELECT chain, address, nonce FROM evm_nonce_allocations WHERE chain=$1 AND lower(address)=lower($2)
			AND owner_kind=$5 AND status='allocated' ORDER BY nonce LIMIT 1 FOR UPDATE)`,
		s.Cfg.Chain, m.From, OwnerKindDrain, m.ID, OwnerKindHole)
	return err
}
