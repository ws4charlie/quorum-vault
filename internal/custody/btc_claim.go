package custody

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Bitcoin, coins claimed by a refused payment under a compromised generation (docs/runbooks/stolen-hot-key.md, "Work in flight").
//
// The signing gateway claims every coin a payment spends before the parties sign. When a cosigner that already has the mark refuses the payment
// ("signer_refused"), no signature exists but the gateway's claim stays, and a compromised generation signs nothing but its sweeps, its drain and (since
// this change) the strict cancel of exactly such a payment. So for such an owner:
//
//	the coins are NOT released to available (a drain move that spends one is refused for ever, replay_nonce_taken);
//	the cancel is built and signed like any cancel (spends the coins back to the same generation's shard); when it confirms the payment ends as cancelled
//	and the cancel's output is an ordinary coin, which the next drain move takes;
//	meanwhile the drain moves the generation's other coins at once: the held ones are reserved, so no move contains them.

// btcOwnerGenner is what the Bitcoin cell offers to tell the generation of an owner's coins.
type btcOwnerGenner interface {
	OwnerGen(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (int, error)
}

// btcClaimHeld reports whether the owner's attempt was refused by a cosigner after the gateway reserved it ("signer_refused"), with no job that may have a
// signature, and the owner's coins are those of a generation this core marks compromised: the zone then holds a claim for them and only a cancel frees it.
// The job rows are locked first and read from the locked rows, as handOverUnsigned does for EVM.
func (s *Service) btcClaimHeld(ctx context.Context, tx pgx.Tx, o Owner) (bool, error) {
	if s.Cfg.Family != FamilyBTC {
		return false, nil
	}
	g, ok := s.Chain.(btcOwnerGenner)
	if !ok {
		return false, nil
	}
	rows, err := tx.Query(ctx, `SELECT status, COALESCE(reject_reason, '') FROM sign_jobs WHERE starts_with(id, $1) OR starts_with(id, $2) ORDER BY id FOR UPDATE`,
		string(OwnerTrack(o))+":", string(CancelTrack(o))+":")
	if err != nil {
		return false, err
	}
	refused, byMark := false, false
	for rows.Next() {
		var st, why string
		if err := rows.Scan(&st, &why); err != nil {
			rows.Close()
			return false, err
		}
		switch {
		case st == signjob.StatusRejected && strings.HasPrefix(why, "signer_refused"):
			refused = true
			// The cosigner's own words: it refused because the generation is marked compromised there. The core's mirror may not have the mark yet (the
			// operator applies it to the zone first), so this alone is enough.
			byMark = byMark || strings.Contains(why, "is compromised")
		case st == signjob.StatusRejected, st == signjob.StatusPending:
		default:
			rows.Close()
			return false, nil // a signature may exist: the ordinary cancel rule
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || !refused {
		return false, err
	}
	if byMark {
		return true, nil
	}
	gen, err := g.OwnerGen(ctx, tx, o.Kind, o.ID)
	if err != nil {
		if isNoRows(err) || strings.Contains(err.Error(), "has no attempt") {
			return false, nil
		}
		return false, err
	}
	tree, err := s.Cfg.depositTreeID()
	if err != nil {
		return false, nil
	}
	ks, err := shardKeysets(ctx, tx, tree)
	if err != nil {
		return false, err
	}
	for _, k := range ks {
		if k.Generation == gen && k.State == partition.StateCompromised {
			return true, nil
		}
	}
	return false, nil
}

// btcHeldNote says what the reserved coins of the shard under the generation are, for the drain's state text: the ones held by a refused payment, and where their
// cancel is.
func (s *Service) btcHeldNote(ctx context.Context, d btcDrainer, part string, gen int) string {
	lister, ok := d.(interface {
		ReservedOwnersUnder(ctx context.Context, partitionID string, gen int) ([]btc.ReservedOwner, error)
	})
	if !ok {
		return ""
	}
	owners, err := lister.ReservedOwnersUnder(ctx, part, gen)
	if err != nil || len(owners) == 0 {
		return ""
	}
	var pending, signed, unknown, other int
	for _, o := range owners {
		if o.Kind == btc.OwnerKindClaimed {
			unknown += o.Coins
			continue
		}
		var n, done int
		_ = s.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status='done') FROM sign_jobs WHERE starts_with(id, $1)`, string(CancelTrack(Owner{Kind: o.Kind, ID: o.ID}))+":").Scan(&n, &done)
		switch {
		case n == 0:
			other += o.Coins // not on a cancel track: a payment in flight, or one that was refused by a rule
		case done > 0:
			signed += o.Coins
		default:
			pending += o.Coins
		}
	}
	var parts []string
	if pending > 0 {
		parts = append(parts, fmt.Sprintf("%d coins held by a refused payment: cancel pending", pending))
	}
	if signed > 0 {
		parts = append(parts, fmt.Sprintf("%d coins held by a refused payment: cancel signed, waiting for confirmation", signed))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d coins held by a payment the zone says it claimed (drain refused replay_nonce_taken): an operator must cancel it", unknown))
	}
	if other > 0 {
		parts = append(parts, fmt.Sprintf("%d coins reserved by payments in flight", other))
	}
	return strings.Join(parts, "; ")
}

var claimedCoin = regexp.MustCompile(`replay_nonce_taken: ([0-9a-f]{64}:[0-9]+) of \S+ already signed for intent (\S+)`)

// holdClaimedCoins reads a drain refusal "replay_nonce_taken: <txid>:<vout> of <sender> already signed for intent <id>" and takes that coin out of the drain
// moves: it is reserved under owner kind "claimed". Without it the planner would build the same move again and the zone would refuse it again. It reports how
// many coins it held (0: not that refusal, or the coin is not one of ours that is available).
func (s *Service) holdClaimedCoins(ctx context.Context, tx pgx.Tx, reason string) (int, error) {
	if s.Cfg.Family != FamilyBTC {
		return 0, nil
	}
	h, ok := s.Chain.(interface {
		HoldClaimed(ctx context.Context, tx pgx.Tx, outpoints []string, intentID string) (int, error)
	})
	if !ok {
		return 0, nil
	}
	m := claimedCoin.FindStringSubmatch(reason)
	if m == nil {
		return 0, nil
	}
	return h.HoldClaimed(ctx, tx, []string{m[1]}, m[2])
}
