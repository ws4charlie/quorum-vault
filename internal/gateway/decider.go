package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Mode says who is deciding.
type Mode int

const (
	// ModeGateway: the gateway signs and stores the signature (Guard.Finish) afterwards. A fresh reservation of a digest
	// that has no signature yet means another worker is signing it.
	ModeGateway Mode = iota
	// ModeCosigner: the cosigner next to party B only authorizes; the signature goes to party A and B never stores it.
	// A repeat of an already reserved digest is allowed (a retry of the same signing), anything else follows the same
	// replay rules.
	ModeCosigner
)

// Decider is the decision component shared by the gateway and the cosigner: steps 1 to 5 (intent, transaction
// verification, approvals, policy, replay guard) and the reservation of the digest. It trusts only its Config and its
// own Guard.
type Decider struct {
	cfg    *Config
	codecs map[string]ChainCodec
	guard  *Guard
	mode   Mode
	now    func() time.Time
}

// NewDecider builds a Decider. now may be nil (time.Now).
func NewDecider(cfg *Config, codecs map[string]ChainCodec, guard *Guard, mode Mode, now func() time.Time) *Decider {
	if now == nil {
		now = time.Now
	}
	return &Decider{cfg: cfg, codecs: codecs, guard: guard, mode: mode, now: now}
}

// NewCodecs builds the per-chain codecs of a config.
func NewCodecs(cfg *Config) (map[string]ChainCodec, error) {
	codecs := map[string]ChainCodec{}
	for name, cc := range cfg.Chains {
		c, err := NewEVMCodec(cc.EVM)
		if err != nil {
			return nil, err
		}
		codecs[name] = c
	}
	return codecs, nil
}

// Verdict is the result of a positive decision.
type Verdict struct {
	Signature []byte // set when the digest was signed before (gateway mode): return it, never sign again
	Replayed  bool
	NeedSign  bool // the digest is reserved: the caller may sign it now
	Intent    signjob.Intent
	Info      TxInfo
}

// ErrSigner marks an operational signer problem (not a policy refusal).
var ErrSigner = errSigner

// IsRejection reports whether err is a policy refusal and returns its "<code>: <detail>" text.
func IsRejection(err error) (string, bool) {
	var rj *rejection
	if errors.As(err, &rj) {
		return rj.Error(), true
	}
	return "", false
}

// Decide runs steps 1 to 5 for job and, if everything passes, reserves its digest. signerPub is the public key that
// would sign (nil: no signer). A policy refusal is returned as a rejection (see IsRejection).
func (d *Decider) Decide(ctx context.Context, job signjob.Job, signerPub *ecdsa.PublicKey) (*Verdict, error) {
	arec := &auditRecord{mode: d.mode, job: job}
	v, err := d.decide(ctx, job, signerPub, arec)
	if err != nil {
		// A refusal is recorded before it is reported. If the record cannot be written, that is an outage, not a refusal:
		// the caller retries, and nothing is answered without a record.
		if rj, ok := IsRejection(err); ok {
			arec.reason = rj
			if aerr := d.guard.auditAlone(ctx, *arec, EventSignRefused); aerr != nil {
				return nil, aerr
			}
		}
		return nil, err
	}
	return v, nil
}

func (d *Decider) decide(ctx context.Context, job signjob.Job, signerPub *ecdsa.PublicKey, arec *auditRecord) (*Verdict, error) {
	// 1. Intent.
	intent, err := parseIntent(job)
	if err != nil {
		return nil, err
	}
	cc := d.cfg.Chains[intent.Chain]
	codec := d.codecs[intent.Chain]
	if cc == nil || codec == nil {
		return nil, reject(ReasonIntent, "chain %q is not configured", intent.Chain)
	}

	// 2. Transaction matches intent.
	u := chain.UnsignedTx{Chain: job.Chain, Digest: job.Digest, Payload: job.Payload,
		KeyRef: chain.KeyRef{PartitionID: job.PartitionID, Path: job.KeyRef}}
	if err := codec.Verify(u, intent); err != nil {
		return nil, reject(ReasonTx, "%v", err)
	}
	info, err := codec.Decode(job.Payload)
	if err != nil {
		return nil, reject(ReasonTx, "%v", err)
	}
	amount, ok := new(big.Int).SetString(intent.Amount, 10)
	if !ok {
		return nil, reject(ReasonTx, "amount %q", intent.Amount)
	}

	// 3. Approvals, from configured keys only.
	hash := intent.Hash()
	approvers := d.validApprovers(hash[:], job.Approvals)
	valid := len(approvers)
	arec.intent = &intentFacts{ID: intent.ID, Kind: intent.Kind, Asset: intent.Asset, Amount: amount.String(), Sender: info.Sender,
		Nonce: info.Nonce, IntentHash: hash[:]}
	arec.approvers = approvers
	if intent.Kind == "withdrawal" && valid == 0 {
		return nil, reject(ReasonApprovals, "no valid approval from a configured, enabled approver")
	}

	// Phase 1, reserve. Steps 4 and 5 run under the replay guard's chain lock,
	// so a second instance sees our records before it decides. The transaction
	// ends with the digest reserved (caps and nonce taken) and no signature
	// yet: the lock is never held while anything signs.
	v := &Verdict{Intent: intent, Info: info}
	err = d.guard.Do(ctx, intent.Chain, func(gt *GuardTx) error {
		now := d.now()
		rec, err := gt.Intent(ctx, intent.ID)
		if err != nil {
			return err
		}
		known := rec != nil && bytes.Equal(rec.Hash, hash[:])

		// 4. Policy. Caps and rates are admitted once per intent; a known
		// intent (resubmission, replacement) is not counted again.
		if err := d.policy(ctx, gt, cc, intent, codec, info, amount, valid, known, now); err != nil {
			return err
		}

		// 5. Replay guard.
		rel := Release{IntentID: intent.ID, IntentHash: hash[:], Kind: intent.Kind, Asset: intent.Asset, Amount: amount,
			Sender: info.Sender, Nonce: info.Nonce, Digest: job.Digest, Tip: info.Tip, FeeCap: info.FeeCap, At: now}
		prior, err := d.replay(ctx, gt, intent, rec, &rel)
		if err != nil {
			return err
		}
		if prior != nil {
			if prior.Signature != nil {
				v.Signature, v.Replayed = prior.Signature, true // signed before: return it, never sign again
				return gt.audit(ctx, *arec, EventSignReplayed)
			}
			if d.mode == ModeGateway && now.Sub(prior.Reserved) < d.cfg.SignTimeout {
				return errInProgress // another worker is signing this digest
			}
			v.NeedSign = true // a stale reservation (gateway) or a retry of the same digest (cosigner)
			if err := gt.Touch(ctx, job.Digest, now); err != nil {
				return err
			}
			return gt.audit(ctx, *arec, EventSignAllowed)
		}

		// 6a. Reserve.
		if signerPub == nil {
			return fmt.Errorf("%w: no signer for partition %q", errSigner, job.PartitionID)
		}
		if err := codec.CheckSigner(info, signerPub); err != nil {
			return fmt.Errorf("%w: %v", errSigner, err)
		}
		v.NeedSign = true
		if err := gt.Record(ctx, rel); err != nil {
			return err
		}
		return gt.audit(ctx, *arec, EventSignAllowed)
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

var errInProgress = errors.New("another worker is signing this digest")

func parseIntent(job signjob.Job) (signjob.Intent, error) {
	var i signjob.Intent
	dec := json.NewDecoder(bytes.NewReader(job.Intent))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&i); err != nil {
		return i, reject(ReasonIntent, "parse intent: %v", err)
	}
	if dec.More() {
		return i, reject(ReasonIntent, "trailing data after intent")
	}
	if i.ID == "" {
		return i, reject(ReasonIntent, "intent has no id")
	}
	switch i.Kind {
	case "withdrawal", "sweep", "cancel", "to-cold", "rebalance":
	default:
		return i, reject(ReasonIntent, "intent kind %q", i.Kind)
	}
	if i.Chain != job.Chain {
		return i, reject(ReasonIntent, "intent chain %q, job chain %q", i.Chain, job.Chain)
	}
	if i.PartitionID != job.PartitionID {
		return i, reject(ReasonIntent, "intent partition %q, job partition %q", i.PartitionID, job.PartitionID)
	}
	return i, nil
}

// countApprovals counts distinct enabled, configured actors whose Ed25519
// signature over hash verifies. Unknown or disabled actors, bad signatures and
// repeats of one actor count for nothing.
func (d *Decider) countApprovals(hash []byte, approvals []signjob.Approval) int {
	return len(d.validApprovers(hash, approvals))
}

// validApprovers names the distinct approvers counted by countApprovals, in the order they were given.
func (d *Decider) validApprovers(hash []byte, approvals []signjob.Approval) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, a := range approvals {
		ap, ok := d.cfg.Approvers[a.Actor]
		if !ok || !ap.Enabled || seen[a.Actor] {
			continue
		}
		if len(a.Signature) == ed25519.SignatureSize && ed25519.Verify(ap.Key, hash, a.Signature) {
			seen[a.Actor] = true
			out = append(out, a.Actor)
		}
	}
	return out
}

func (d *Decider) policy(ctx context.Context, gt *GuardTx, cc *ChainConfig, i signjob.Intent, codec ChainCodec,
	info TxInfo, amount *big.Int, valid int, known bool, now time.Time) error {
	switch i.Kind {
	case "withdrawal":
		if !known { // a known intent may be replaced after it expired
			now := now.Unix()
			switch {
			case i.NotAfter == 0:
				return reject(ReasonExpired, "intent has no not_after")
			case i.NotAfter <= now:
				return reject(ReasonExpired, "intent expired at %d, now %d", i.NotAfter, now)
			case i.NotAfter > now+int64(d.cfg.MaxIntentAge/time.Second):
				return reject(ReasonExpired, "not_after %d is more than %s ahead", i.NotAfter, d.cfg.MaxIntentAge)
			}
		}
		p, ok := cc.Assets[i.Asset]
		if !ok {
			return reject(ReasonPolicyAsset, "no policy for %s on %s", i.Asset, cc.Name)
		}
		// Where the money goes is read from the transaction, not from the intent: the intent is what the business zone claims.
		dest := common.HexToAddress(info.Destination)
		if !common.IsHexAddress(info.Destination) || !p.AllowsDestination(dest) {
			return reject(ReasonDestination, "%s is not a configured %s withdrawal destination on %s", info.Destination, i.Asset, cc.Name)
		}
		if amount.Cmp(p.PerTxCap) > 0 {
			return reject(ReasonPerTxCap, "amount %s exceeds the per-transaction cap %s", amount, p.PerTxCap)
		}
		if need := p.RequiredApprovals(amount); valid < need {
			return reject(ReasonTier, "amount %s needs %d distinct approvals, have %d", amount, need, valid)
		}
		if !known {
			n, err := gt.CountSince(ctx, "withdrawal", now.Add(-time.Hour))
			if err != nil {
				return err
			}
			if n >= cc.WithdrawalsPerHour {
				return reject(ReasonWithdrawRate, "%d withdrawals in the last hour, limit %d", n, cc.WithdrawalsPerHour)
			}
			sum, err := gt.WithdrawnSince(ctx, i.Asset, now.Add(-24*time.Hour))
			if err != nil {
				return err
			}
			if total := new(big.Int).Add(sum, amount); total.Cmp(p.DailyCap) > 0 {
				return reject(ReasonDailyCap, "%s already withdrawn in 24h plus %s exceeds the cap %s", sum, amount, p.DailyCap)
			}
		}
	case "sweep":
		if !known {
			n, err := gt.CountSince(ctx, "sweep", now.Add(-time.Hour))
			if err != nil {
				return err
			}
			if n >= cc.SweepsPerHour {
				return reject(ReasonSweepRate, "%d sweeps in the last hour, limit %d", n, cc.SweepsPerHour)
			}
		}
	case "to-cold":
		// Needs no approval: the destination is pinned in this zone's config (the chain verifier refused anything else), so a
		// move can only make funds safer. Any approvals attached are ignored, not counted towards or against anything: the
		// rate and the daily cap below apply no matter what the intent carries, so an approved intent cannot be used to
		// push more than the cap through this path.
		p, ok := cc.Assets[i.Asset]
		if !ok {
			return reject(ReasonPolicyAsset, "no policy for %s on %s", i.Asset, cc.Name)
		}
		if !codec.OwnsSender(info.Sender) {
			return reject(ReasonCancelTarget, "%s is not a hot address of this gateway", info.Sender)
		}
		if !known {
			n, err := gt.CountSince(ctx, "to-cold", now.Add(-time.Hour))
			if err != nil {
				return err
			}
			if n >= cc.ToColdPerHour {
				return reject(ReasonToColdRate, "%d hot-to-cold moves in the last hour, limit %d", n, cc.ToColdPerHour)
			}
			sum, err := gt.AmountSince(ctx, "to-cold", i.Asset, now.Add(-24*time.Hour))
			if err != nil {
				return err
			}
			if total := new(big.Int).Add(sum, amount); total.Cmp(p.ToColdDailyCap) > 0 {
				return reject(ReasonToColdCap, "%s already moved to cold in 24h plus %s exceeds the cap %s", sum, amount, p.ToColdDailyCap)
			}
		}
	case "rebalance":
		// Needs no approval, like a move to cold: the destination is another hot shard of this zone's own config (the chain
		// verifier refused anything else), so the funds stay in wallets the operator already runs. Approvals are ignored. The rate
		// and the daily cap come from this zone's own guard store and apply to whatever the intent carries.
		p, ok := cc.Assets[i.Asset]
		if !ok {
			return reject(ReasonPolicyAsset, "no policy for %s on %s", i.Asset, cc.Name)
		}
		if !codec.OwnsSender(info.Sender) {
			return reject(ReasonCancelTarget, "%s is not a hot address of this gateway", info.Sender)
		}
		if !known {
			n, err := gt.CountSince(ctx, "rebalance", now.Add(-time.Hour))
			if err != nil {
				return err
			}
			if n >= cc.RebalancePerHour {
				return reject(ReasonRebalanceRate, "%d hot-shard rebalances in the last hour, limit %d", n, cc.RebalancePerHour)
			}
			sum, err := gt.AmountSince(ctx, "rebalance", i.Asset, now.Add(-24*time.Hour))
			if err != nil {
				return err
			}
			if total := new(big.Int).Add(sum, amount); total.Cmp(p.RebalanceDailyCap) > 0 {
				return reject(ReasonRebalanceCap, "%s already rebalanced in 24h plus %s exceeds the cap %s", sum, amount, p.RebalanceDailyCap)
			}
		}
	case "cancel":
		if !codec.OwnsSender(info.Sender) {
			return reject(ReasonCancelTarget, "%s is not a hot address of this gateway", info.Sender)
		}
		if !known {
			n, err := gt.CountSince(ctx, "cancel", now.Add(-time.Hour))
			if err != nil {
				return err
			}
			if n >= cc.CancelsPerHour {
				return reject(ReasonCancelRate, "%d cancels in the last hour, limit %d", n, cc.CancelsPerHour)
			}
		}
	}
	return nil
}

// replay applies the replay-guard rules. It returns the stored signature when
// the record of a digest already reserved or signed for this intent (the
// caller returns its signature, waits, or signs it again if the reservation is
// stale), or nil with rel's NewIntent/TakeNonce set when a new digest may be reserved.
func (d *Decider) replay(ctx context.Context, gt *GuardTx, i signjob.Intent, rec *IntentRecord, rel *Release) (*SigRecord, error) {
	claim, err := gt.NonceClaim(ctx, rel.Sender, rel.Nonce)
	if err != nil {
		return nil, err
	}
	if rec != nil {
		if !bytes.Equal(rec.Hash, rel.IntentHash) {
			return nil, reject(ReasonIntentChanged, "intent %s was signed with a different intent hash", i.ID)
		}
		prior, err := gt.Digest(ctx, rel.Digest)
		if err != nil {
			return nil, err
		}
		if prior != nil && prior.IntentID != i.ID {
			return nil, reject(ReasonIntentChanged, "digest was signed for intent %s", prior.IntentID)
		}
		if prior == nil && (rec.Nonce != rel.Nonce || rec.Sender != rel.Sender) {
			// A new digest for a known intent is only a replacement at the same nonce.
			return nil, reject(ReasonNonceChanged, "intent %s was signed at nonce %d of %s, not nonce %d", i.ID, rec.Nonce, rec.Sender, rel.Nonce)
		}
		if claim == nil || claim.IntentID != i.ID {
			// The intent's nonce is gone: a cancel (or another intent) owns it.
			return nil, reject(ReasonNonceCancel, "nonce %d of %s no longer belongs to intent %s", rel.Nonce, rel.Sender, i.ID)
		}
		if prior != nil {
			return prior, nil
		}
		last, err := gt.LatestSig(ctx, i.ID)
		if err != nil {
			return nil, err
		}
		if last != nil && !feesHigher(rel, last) {
			return nil, reject(ReasonFeeNotHigher, "fees tip %s cap %s do not exceed the signed tip %s cap %s", rel.Tip, rel.FeeCap, last.Tip, last.FeeCap)
		}
		return nil, nil
	}
	if prior, err := gt.Digest(ctx, rel.Digest); err != nil {
		return nil, err
	} else if prior != nil {
		return nil, reject(ReasonIntentChanged, "digest was signed for intent %s", prior.IntentID)
	}
	rel.NewIntent = true
	if claim == nil {
		return nil, nil
	}
	switch {
	case claim.Kind == "cancel":
		return nil, reject(ReasonNonceCancel, "nonce %d of %s was consumed by cancel %s", rel.Nonce, rel.Sender, claim.IntentID)
	case i.Kind == "cancel":
		rel.TakeNonce = true // a cancel may replace what is pending at the nonce
		return nil, nil
	default:
		return nil, reject(ReasonNonceTaken, "nonce %d of %s already signed for intent %s", rel.Nonce, rel.Sender, claim.IntentID)
	}
}

// feesHigher: neither fee drops and at least one rises.
func feesHigher(r *Release, last *SigRecord) bool {
	a, b := r.Tip.Cmp(last.Tip), r.FeeCap.Cmp(last.FeeCap)
	return a >= 0 && b >= 0 && (a > 0 || b > 0)
}
