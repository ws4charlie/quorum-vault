package gateway

import (
	"bytes"
	"context"
	"math/big"
	"slices"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// memberFacts is what the audit trail says about one withdrawal of a batch: ids, amounts, destinations and the names of its approvers.
type memberFacts struct {
	ID        string   `json:"id"`
	To        string   `json:"to"`
	Amount    string   `json:"amount"`
	Approvers []string `json:"approvers"`
}

// decideBatch is Decide for a batch job: one transaction that pays several withdrawals. It runs the same five steps as a single withdrawal, with the
// work per member:
//
//  1. The intent is the batch (its own id, the members in payment order); the job carries no approvals of its own.
//  2. The chain codec checks that the transaction pays exactly the members, in order, plus at most one change to the shard, within the zone's own
//     output and value ceilings and fee caps (BatchCodec).
//  3. Every member carries its own approvals over its own intent hash, exactly as a single withdrawal does. Every approval must be valid, and every
//     member must reach the number its amount needs. There is no approval of the batch.
//  4. Every member passes the destination rule, the per-transaction cap and the approval tiers; the members count one by one towards the hourly rate
//     and the daily cap, and each member's not_after is judged like a single withdrawal's.
//  5. The replay guard records the batch under its own id (claims, digests) and each member under its own, so a withdrawal id is signed once, in one
//     batch: the same id in another batch, or alone, is refused. The same batch again, with the same members, is a replacement under the usual rules
//     (same inputs, higher fee); a cancel of the batch is the existing cancel of its claims.
func (d *Decider) decideBatch(ctx context.Context, job signjob.Job, key SignerKey, arec *auditRecord) (*Verdict, error) {
	// 1. Intent.
	b, err := signjob.DecodeBatch(job.Intent)
	if err != nil {
		return nil, reject(ReasonIntent, "%v", err)
	}
	switch {
	case b.ID == "":
		return nil, reject(ReasonIntent, "batch has no id")
	case b.Chain != job.Chain:
		return nil, reject(ReasonIntent, "batch chain %q, job chain %q", b.Chain, job.Chain)
	case b.PartitionID != job.PartitionID:
		return nil, reject(ReasonIntent, "batch partition %q, job partition %q", b.PartitionID, job.PartitionID)
	case len(job.Approvals) != 0:
		return nil, reject(ReasonApprovals, "a batch job carries no approvals of its own: every withdrawal carries its own")
	}
	cc, codec := d.cfg.Chains[b.Chain], d.codecs[b.Chain]
	if cc == nil || codec == nil {
		return nil, reject(ReasonIntent, "chain %q is not configured", b.Chain)
	}
	bc, ok := codec.(BatchCodec)
	if !ok {
		return nil, reject(ReasonIntent, "chain %q does not sign batches", b.Chain)
	}
	pol, ok := cc.Assets[b.Asset]
	if !ok {
		return nil, reject(ReasonPolicyAsset, "no policy for %s on %s", b.Asset, cc.Name)
	}

	// 2. Transaction matches the members.
	u := chain.UnsignedTx{Chain: job.Chain, Digest: job.Digest, Payload: job.Payload,
		KeyRef: chain.KeyRef{PartitionID: job.PartitionID, Path: job.KeyRef}}
	pays, err := bc.VerifyBatch(u, b)
	if err != nil {
		return nil, reject(ReasonTx, "%v", err)
	}
	info, err := codec.Decode(u)
	if err != nil {
		return nil, reject(ReasonTx, "%v", err)
	}
	guardKey := job.Digest
	if gk, ok := codec.(GuardKeyCodec); ok {
		guardKey = gk.GuardKey(u, info)
	}

	// 3 and 4 (the part that needs no guard). Each member as a single withdrawal is judged.
	hash := b.Hash()
	total := new(big.Int)
	for _, p := range pays {
		total.Add(total, p.Amount)
	}
	arec.intent = &intentFacts{ID: b.ID, Kind: signjob.KindBatch, Asset: b.Asset, Amount: total.String(), Sender: info.Sender, Claims: info.Claims, IntentHash: hash[:]}
	members := make([]MemberRelease, len(b.Members))
	for i, m := range b.Members {
		if m.Intent.Kind != "withdrawal" {
			return nil, reject(ReasonIntent, "batch member %s is a %q intent: members are withdrawals", m.Intent.ID, m.Intent.Kind)
		}
		if err := checkRequesterField(m.Intent); err != nil {
			return nil, err
		}
		mh := m.Intent.Hash()
		approvers := d.validApprovers(mh[:], m.Approvals)
		if err := d.checkRequester(m.Intent, approvers); err != nil {
			return nil, err
		}
		arec.members = append(arec.members, memberFacts{ID: m.Intent.ID, To: pays[i].Destination, Amount: pays[i].Amount.String(), Approvers: approvers})
		switch {
		case len(approvers) == 0:
			return nil, reject(ReasonApprovals, "withdrawal %s: no valid approval from a configured, enabled approver", m.Intent.ID)
		case len(approvers) != len(m.Approvals):
			return nil, reject(ReasonApprovals, "withdrawal %s carries %d approvals and only %d are valid (every approval of a batch member must be)", m.Intent.ID, len(m.Approvals), len(approvers))
		}
		dest, derr := codec.Canonical(pays[i].Destination)
		if derr != nil || !pol.AllowsDestination(dest) {
			return nil, reject(ReasonDestination, "withdrawal %s: %s is not a configured %s withdrawal destination on %s", m.Intent.ID, pays[i].Destination, b.Asset, cc.Name)
		}
		if pays[i].Amount.Cmp(pol.PerTxCap) > 0 {
			return nil, reject(ReasonPerTxCap, "withdrawal %s: amount %s exceeds the per-transaction cap %s", m.Intent.ID, pays[i].Amount, pol.PerTxCap)
		}
		if need := pol.RequiredApprovals(pays[i].Amount); len(approvers) < need {
			return nil, reject(ReasonTier, "withdrawal %s: amount %s needs %d distinct approvals, have %d", m.Intent.ID, pays[i].Amount, need, len(approvers))
		}
		members[i] = MemberRelease{ID: m.Intent.ID, Hash: mh[:], Amount: pays[i].Amount}
	}

	// The batch as the replay guard knows it: one intent under the batch's id, for the sum of its payments.
	intent := signjob.Intent{Kind: signjob.KindBatch, ID: b.ID, PartitionID: b.PartitionID, Chain: b.Chain, Asset: b.Asset, Amount: total.String()}
	v := &Verdict{Intent: intent, Info: info, GuardKey: guardKey}
	err = d.guard.Do(ctx, b.Chain, func(gt *GuardTx) error {
		now := d.now()
		rec, err := gt.Intent(ctx, b.ID)
		if err != nil {
			return err
		}
		if rec != nil && rec.Kind != signjob.KindBatch {
			return reject(ReasonMemberReused, "%s is a withdrawal id the zone signed; a batch never shares an id with one", b.ID)
		}
		known := rec != nil && bytes.Equal(rec.Hash, hash[:])
		if rec == nil {
			// A new batch: the fee-bump reserve of its first send, and no member the zone has signed before, alone or in another batch. A
			// replacement or a repeat of this very batch (known) has its members recorded already.
			if fc, ok := codec.(FirstSendChecker); ok {
				if err := fc.CheckFirstSend(u, intent); err != nil {
					return reject(ReasonTx, "%v", err)
				}
			}
			// A member the zone signed before may come back only in a batch that spends an output of a cancel the zone signed for the member's
			// latest batch: that output exists only if the cancel is in the chain, and the cancel conflicts with its batch on every input, so
			// at most one of the two batches ever pays the member. Anything else (alone, in another batch, in a batch that does not spend the
			// cancel's output) could pay twice.
			cancels := map[string][]string{}
			for i := range members {
				m := &members[i]
				prev, err := gt.Intent(ctx, m.ID)
				if err != nil {
					return err
				}
				if prev == nil {
					continue
				}
				if prev.Kind != "withdrawal" || prev.BatchID == "" {
					return reject(ReasonMemberReused, "withdrawal %s was already signed alone: an id is used once", m.ID)
				}
				if !bytes.Equal(prev.Hash, m.Hash) {
					return reject(ReasonIntentChanged, "withdrawal %s was signed with a different intent hash", m.ID)
				}
				outs, ok := cancels[prev.BatchID]
				if !ok {
					if outs, err = gt.CancelOutputs(ctx, prev.BatchID); err != nil {
						return err
					}
					cancels[prev.BatchID] = outs
				}
				if !slices.ContainsFunc(outs, func(o string) bool { return slices.Contains(info.Claims, o) }) {
					return reject(ReasonMemberReused, "withdrawal %s was already signed in batch %s: only a batch that spends an output of the cancel signed for %s may sign it again (cancels signed: %v)",
						m.ID, prev.BatchID, prev.BatchID, outs)
				}
				m.Resend = true
			}
		}

		if !known { // a known batch may be replaced after its members' approvals lapsed
			nowU := now.Unix()
			for _, m := range b.Members {
				switch na := m.Intent.NotAfter; {
				case na == 0:
					return reject(ReasonExpired, "withdrawal %s has no not_after", m.Intent.ID)
				case na <= nowU:
					return reject(ReasonExpired, "withdrawal %s expired at %d, now %d", m.Intent.ID, na, nowU)
				case na > nowU+int64(d.cfg.MaxIntentAge/time.Second):
					return reject(ReasonExpired, "withdrawal %s: not_after %d is more than %s ahead", m.Intent.ID, na, d.cfg.MaxIntentAge)
				}
			}
			fresh, freshTotal := 0, new(big.Int) // a member sent again was counted when it was first signed
			for _, m := range members {
				if !m.Resend {
					fresh++
					freshTotal.Add(freshTotal, m.Amount)
				}
			}
			n, err := gt.CountSince(ctx, "withdrawal", now.Add(-time.Hour))
			if err != nil {
				return err
			}
			if n+fresh > cc.WithdrawalsPerHour {
				return reject(ReasonWithdrawRate, "%d withdrawals in the last hour plus the %d of this batch exceed the limit %d", n, fresh, cc.WithdrawalsPerHour)
			}
			sum, err := gt.WithdrawnSince(ctx, b.Asset, now.Add(-24*time.Hour))
			if err != nil {
				return err
			}
			if all := new(big.Int).Add(sum, freshTotal); all.Cmp(pol.DailyCap) > 0 {
				return reject(ReasonDailyCap, "%s already withdrawn in 24h plus the batch's %s exceeds the cap %s", sum, freshTotal, pol.DailyCap)
			}
		}

		rel := Release{IntentID: b.ID, IntentHash: hash[:], Kind: signjob.KindBatch, Asset: b.Asset, Amount: total, Sender: info.Sender, PartitionID: b.PartitionID,
			Claims: info.Claims, Pins: info.Pins, Identity: info.Identity, Digest: guardKey, Fees: info.Fees, PayloadHash: payloadHash(job.Payload), At: now, Members: members}
		return d.admit(ctx, gt, codec, job, intent, rec, &rel, info, key, v, arec, now)
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}
