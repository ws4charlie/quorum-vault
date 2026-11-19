package gateway

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
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
	bindFeeCaps(cfg, codecs, guard)
	return &Decider{cfg: cfg, codecs: codecs, guard: guard, mode: mode, now: now}
}

// NewCodecs builds the per-chain codecs of a config, through NewCodec.
func NewCodecs(cfg *Config) (map[string]ChainCodec, error) {
	codecs := map[string]ChainCodec{}
	for name, cc := range cfg.Chains {
		c, err := NewCodec(cc)
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
	// GuardKey is what the replay guard recorded this job under: the job's digest, or what the chain's codec says (GuardKeyCodec). Finish stores the
	// signature under it.
	GuardKey []byte
}

// SignerKey is the public key that would sign a job: a secp256k1 key or an Ed25519 key. The zero value is "no signer".
type SignerKey struct {
	ECDSA   *ecdsa.PublicKey
	Ed25519 ed25519.PublicKey
}

func (k SignerKey) none() bool { return k.ECDSA == nil && len(k.Ed25519) == 0 }

// checkSigner asks the codec whether the key is the one this job needs.
func checkSigner(codec ChainCodec, info TxInfo, k SignerKey) error {
	if len(k.Ed25519) > 0 {
		ec, ok := codec.(EdSignerCodec)
		if !ok {
			return errors.New("this chain does not use Ed25519 keys")
		}
		return ec.CheckEd25519Signer(info, k.Ed25519)
	}
	return codec.CheckSigner(info, k.ECDSA)
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
	return d.DecideKey(ctx, job, SignerKey{ECDSA: signerPub})
}

// DecideKey is Decide for either kind of signer key.
func (d *Decider) DecideKey(ctx context.Context, job signjob.Job, key SignerKey) (*Verdict, error) {
	arec := &auditRecord{mode: d.mode, job: job}
	v, err := d.decide(ctx, job, key, arec)
	if err != nil {
		// A refusal is recorded before it is reported. If the record cannot be written, that is an outage, not a refusal:
		// the caller retries, and nothing is answered without a record.
		if rj, ok := IsRejection(err); ok {
			if lag := d.lagRetry(*arec, err); lag != nil {
				return nil, lag
			}
			arec.reason = rj
			if aerr := d.guard.auditAlone(ctx, *arec, EventSignRefused); aerr != nil {
				return nil, aerr
			}
		}
		return nil, err
	}
	return v, nil
}

// approverSet is the set of approvers in force for the decision about to be made: read from the guard database at every decision, so a signed change
// applies to the next one without a restart.
func (d *Decider) approverSet(ctx context.Context) (*ApproverSet, error) {
	return d.guard.EffectiveApprovers(ctx, d.cfg)
}

// lagRetry turns a refusal that may come only from an approver list that is behind into a retry: the refusal is about approvals (none valid, or too few
// for the amount), and an approval names an approver this zone does not count yet (ApproverSet.lagging), and the job has not expired. The job waits
// and is decided again; once its not_after has passed the refusal stands. Only a zone with an operators section has a list that can be behind.
// nil: not such a refusal.
func (d *Decider) lagRetry(arec auditRecord, err error) error {
	var rj *rejection
	if d.cfg.Operators == nil || !errors.As(err, &rj) || (rj.code != ReasonApprovals && rj.code != ReasonTier) || arec.lagUntil <= d.now().Unix() {
		return nil
	}
	slog.Error("ALERT approver registry: a job waits because an approval names an approver this zone does not count yet; apply the same signed approver changes to the gateway and every cosigner (docs/runbooks/approvers.md)",
		"job", arec.job.ID, "mode", d.mode.actor(), "refusal", rj.Error())
	return fmt.Errorf("%w: %s: %s", ErrApproverLag, ApproverLagNote, rj.Error())
}

func (d *Decider) decide(ctx context.Context, job signjob.Job, key SignerKey, arec *auditRecord) (*Verdict, error) {
	if signjob.IsBatch(job.Intent) {
		return d.decideBatch(ctx, job, key, arec)
	}
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

	set, err := d.approverSet(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.refreshFeeCaps(ctx, intent.Chain, codec, set); err != nil {
		return nil, err
	}

	// 2. Transaction matches intent.
	u := chain.UnsignedTx{Chain: job.Chain, Digest: job.Digest, Payload: job.Payload,
		KeyRef: chain.KeyRef{PartitionID: job.PartitionID, Path: job.KeyRef}}
	if err := codec.Verify(u, intent); err != nil {
		return nil, reject(ReasonTx, "%v", err)
	}
	var info TxInfo
	if idc, ok := codec.(IntentDecoder); ok {
		info, err = idc.DecodeFor(u, intent)
	} else {
		info, err = codec.Decode(u)
	}
	if err != nil {
		return nil, reject(ReasonTx, "%v", err)
	}
	guardKey := job.Digest
	if gk, ok := codec.(GuardKeyCodec); ok {
		guardKey = gk.GuardKey(u, info)
	}
	amount, ok := new(big.Int).SetString(intent.Amount, 10)
	if !ok {
		return nil, reject(ReasonTx, "amount %q", intent.Amount)
	}

	// 3. Approvals, from the effective approver set only: the config's approvers with the signed changes of this zone's own log applied.
	hash := intent.Hash()
	approvers := set.validApprovers(hash[:], job.Approvals)
	if set.lagging(job.Approvals) {
		arec.lagUntil = intent.NotAfter
	}
	valid := len(approvers)
	arec.intent = &intentFacts{ID: intent.ID, Kind: intent.Kind, Asset: intent.Asset, Amount: amount.String(), Sender: info.Sender,
		Claims: info.Claims, IntentHash: hash[:]}
	arec.approvers = approvers
	if err := checkRequesterField(intent); err != nil {
		return nil, err
	}
	if err := d.checkRequester(set, intent, approvers); err != nil {
		return nil, err
	}
	if intent.Kind == "withdrawal" && valid == 0 {
		return nil, reject(ReasonApprovals, "no valid approval from a configured, enabled approver")
	}

	// Phase 1, reserve. Steps 4 and 5 run under the replay guard's chain lock,
	// so a second instance sees our records before it decides. The transaction
	// ends with the digest reserved (caps and nonce taken) and no signature
	// yet: the lock is never held while anything signs.
	v := &Verdict{Intent: intent, Info: info, GuardKey: guardKey}
	err = d.guard.Do(ctx, intent.Chain, func(gt *GuardTx) error {
		now := d.now()
		rec, err := gt.Intent(ctx, intent.ID)
		if err != nil {
			return err
		}
		if rec != nil && (rec.BatchID != "" || rec.Kind == signjob.KindBatch) {
			// An id the zone signed inside a batch (or a batch's own id) is never a single withdrawal's.
			return reject(ReasonMemberReused, "%s was signed as part of batch %s: a withdrawal id is used once, in one batch", intent.ID, cmp.Or(rec.BatchID, rec.ID))
		}
		known := rec != nil && bytes.Equal(rec.Hash, hash[:])
		if rec == nil {
			if fc, ok := codec.(FirstSendChecker); ok {
				if err := fc.CheckFirstSend(u, intent); err != nil {
					return reject(ReasonTx, "%v", err)
				}
			}
		}
		if intent.Kind == "cpfp" {
			// A child is judged against what this zone itself signed, at every attempt (a bump of the child is judged again against the same parent).
			if err := d.checkCPFP(ctx, gt, codec, u, intent, info); err != nil {
				return err
			}
		}

		// 4. Policy. Caps and rates are admitted once per intent; a known
		// intent (resubmission, replacement) is not counted again.
		if err := d.policy(ctx, gt, cc, intent, codec, info, amount, valid, known, now); err != nil {
			return err
		}

		// 5. Replay guard.
		rel := Release{IntentID: intent.ID, IntentHash: hash[:], Kind: intent.Kind, Asset: intent.Asset, Amount: amount,
			Sender: info.Sender, PartitionID: intent.PartitionID, Claims: info.Claims, Pins: info.Pins, Identity: info.Identity, Digest: guardKey, Fees: info.Fees, PayloadHash: payloadHash(job.Payload), At: now}
		if intent.Kind == "withdrawal" || intent.Kind == "to-cold" {
			rel.Parent = info.Parent // kinds that keep a change: a child may pull them in later
		}
		return d.admit(ctx, gt, codec, job, intent, rec, &rel, info, key, v, arec, now)
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

// checkCPFP is the rule of a child that pulls a stuck send in: the codec judges it against the guard's records of the transactions the zone signed,
// by the identity of each transaction the child spends.
func (d *Decider) checkCPFP(ctx context.Context, gt *GuardTx, codec ChainCodec, u chain.UnsignedTx, i signjob.Intent, info TxInfo) error {
	cc, ok := codec.(CPFPCodec)
	if !ok {
		return reject(ReasonIntent, "chain %q does not sign cpfp children", i.Chain)
	}
	parents := map[string]ParentRecord{}
	for _, claim := range info.Claims {
		txid, _, _ := strings.Cut(claim, ":")
		if _, seen := parents[txid]; seen {
			continue
		}
		rec, err := gt.Parent(ctx, txid)
		if err != nil {
			return err
		}
		if rec != nil {
			parents[txid] = *rec
		}
	}
	if err := cc.CheckCPFP(u, i, parents); err != nil {
		return reject(ReasonCPFP, "%v", err)
	}
	return nil
}

// admit is step 5 and 6a for one job, inside the guard transaction: the replay rules against what the guard has recorded, then either the stored
// signature (or a retry of a reservation) or the reservation of the digest. A single intent and a batch take the same path.
func (d *Decider) admit(ctx context.Context, gt *GuardTx, codec ChainCodec, job signjob.Job, intent signjob.Intent, rec *IntentRecord, rel *Release,
	info TxInfo, key SignerKey, v *Verdict, arec *auditRecord, now time.Time) error {
	guardKey := rel.Digest
	prior, err := d.replay(ctx, gt, intent, rec, codec, rel)
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
		if err := gt.Touch(ctx, guardKey, now); err != nil {
			return err
		}
		return gt.audit(ctx, *arec, EventSignAllowed)
	}

	// 6a. Reserve.
	if key.none() {
		return fmt.Errorf("%w: no signer for partition %q", errSigner, job.PartitionID)
	}
	if err := checkSigner(codec, info, key); err != nil {
		return fmt.Errorf("%w: %v", errSigner, err)
	}
	v.NeedSign = true
	if err := gt.Record(ctx, *rel); err != nil {
		return err
	}
	return gt.audit(ctx, *arec, EventSignAllowed)
}

// payloadHash identifies the transaction a job belongs to: the jobs of one transaction (one per signature) share it.
func payloadHash(payload []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, payload); err != nil {
		buf.Reset()
		buf.Write(payload)
	}
	h := sha256.Sum256(buf.Bytes())
	return h[:]
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
	case "withdrawal", "sweep", "cancel", "to-cold", "rebalance", "consolidate", "cpfp", sol.KindNonceSetup, sol.KindNonceClose:
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

// checkRequesterField is the shape rule of requested_by: a withdrawal (alone or as a batch member) names the person who asked for it; every other
// kind is started by the system or by an operator's own approval and carries none, so a requester there is a sign of a confused or forged intent.
// An intent written before v2 has no requester: it is refused here with that reason, and its approvals (over the v1 hash) would not verify anyway.
func checkRequesterField(i signjob.Intent) error {
	if i.Kind == "withdrawal" {
		if i.RequestedBy == "" {
			return reject(ReasonRequester, "withdrawal %s has no requested_by (an intent from before intent v2: see docs/runbooks/intent-v2-upgrade.md)", i.ID)
		}
		return nil
	}
	if i.RequestedBy != "" {
		return reject(ReasonRequester, "a %s intent has no requester, but requested_by is %q", i.Kind, i.RequestedBy)
	}
	return nil
}

// checkRequester refuses a job one of whose counted approvers is the person who requested it. The comparison is on identity (the person), not on
// the key's name, so a person with two keys cannot approve through the second.
func (d *Decider) checkRequester(set *ApproverSet, i signjob.Intent, approvers []string) error {
	if i.RequestedBy == "" {
		return nil
	}
	for _, a := range approvers {
		if set.identity(a) == i.RequestedBy {
			return reject(ReasonRequester, "%s: approver %q is the requester %q: a requester cannot approve their own withdrawal", i.ID, a, i.RequestedBy)
		}
	}
	return nil
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
		dest, derr := codec.Canonical(info.Destination)
		if derr != nil || !p.AllowsDestination(dest) {
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
	case "consolidate":
		// Needs no approval: the chain verifier refused anything but the partition's own shard spending its own outputs back to itself, so the money
		// stays where it is and only the fee can be lost, at most the hourly limit times max_tx_fee_sats. Approvals are ignored. A new attempt of a
		// known intent (a fee bump) is not counted again.
		if !codec.OwnsSender(info.Sender) {
			return reject(ReasonCancelTarget, "%s is not a hot address of this gateway", info.Sender)
		}
		if !known {
			n, err := gt.CountSince(ctx, "consolidate", now.Add(-time.Hour))
			if err != nil {
				return err
			}
			if n >= cc.ConsolidationsPerHour {
				return reject(ReasonConsolidateRate, "%d consolidations in the last hour, limit %d", n, cc.ConsolidationsPerHour)
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
	case sol.KindNonceSetup:
		// An operator creates nonce accounts on a hot shard: at least one approval of a configured approver, and the shard must be ours. The
		// shape (the pool's own addresses, the rent the config names) is the chain verifier's; what an approval cannot widen is the pool size.
		if valid == 0 {
			return reject(ReasonApprovals, "a nonce setup needs an operator approval")
		}
		if !codec.OwnsSender(info.Sender) {
			return reject(ReasonCancelTarget, "%s is not a hot address of this gateway", info.Sender)
		}
	case sol.KindNonceClose:
		// An operator closes a retired nonce account of a hot shard, the rent going back to the shard: an approval is needed, and the shape (the
		// pool's own account, the shard as destination and authority) is the chain verifier's.
		if valid == 0 {
			return reject(ReasonApprovals, "a nonce close needs an operator approval")
		}
		if !codec.OwnsSender(info.Sender) {
			return reject(ReasonCancelTarget, "%s is not a hot address of this gateway", info.Sender)
		}
	case "cpfp":
		// Needs no approval: the chain verifier refused anything but a child that spends the shard's own coins back to the shard, and checkCPFP that one of them
		// is the change of a send this zone signed and that the pair stays within the fee caps. The money stays where it is; at most the room under the
		// caps is paid in fee, once per parent (the change is claimed by one intent). Approvals are ignored.
		if !codec.OwnsSender(info.Sender) {
			return reject(ReasonCancelTarget, "%s is not a hot address of this gateway", info.Sender)
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
// stale), or nil with rel's NewIntent/NewClaims/TakeClaims set when a new digest may be reserved.
//
// The rules are the same on every chain; the codec decides what a claim is and what raising the fees means.
// A claim is held by one intent. A known intent may add another digest of the same transaction (another input to
// sign), or one of a replacement that has the same claims and higher fees.
func (d *Decider) replay(ctx context.Context, gt *GuardTx, i signjob.Intent, rec *IntentRecord, codec ChainCodec, rel *Release) (*SigRecord, error) {
	if len(rel.Pins) != 0 && len(rel.Pins) != len(rel.Claims) {
		return nil, reject(ReasonPinChanged, "the codec gave %d pins for %d claims", len(rel.Pins), len(rel.Claims))
	}
	claims := map[string]*Claim{}
	for _, c := range rel.Claims {
		cl, err := gt.Claim(ctx, c)
		if err != nil {
			return nil, err
		}
		claims[c] = cl
		// A claim that exists keeps its pin, for every intent and in every path: another pin means another view of what the claim is
		// worth (the segwit v0 fee attack signs one input under a payload that understates another).
		if cl != nil && cl.Pin != rel.pinOf(c) {
			return nil, reject(ReasonPinChanged, "%s of %s is already claimed with pin %q, not %q", c, rel.Sender, cl.Pin, rel.pinOf(c))
		}
	}
	// One transaction identity has one payload: a second payload with the same identity is not a replacement (a replacement is a
	// new transaction) but the same transaction described differently.
	if rel.Identity != "" {
		other, err := gt.IdentityConflict(ctx, rel.Identity, rel.PayloadHash)
		if err != nil {
			return nil, err
		}
		if other != "" {
			return nil, reject(ReasonIdentity, "transaction %s was already signed for intent %s under a different payload", rel.Identity, other)
		}
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
		if prior == nil && (!sameSet(rec.Claims, rel.Claims) || rec.Sender != rel.Sender) {
			// A new digest for a known intent is only a replacement that consumes the same things.
			return nil, reject(ReasonNonceChanged, "intent %s was signed against %v of %s, not %v", i.ID, rec.Claims, rec.Sender, rel.Claims)
		}
		for _, c := range rel.Claims {
			if cl := claims[c]; cl == nil || cl.IntentID != i.ID {
				// What the intent consumed is gone: a cancel (or another intent) owns it.
				return nil, reject(ReasonNonceCancel, "%s of %s no longer belongs to intent %s", c, rel.Sender, i.ID)
			}
		}
		if prior != nil {
			return prior, nil
		}
		if same, err := gt.SameTx(ctx, i.ID, rel.PayloadHash); err != nil {
			return nil, err
		} else if same != nil {
			return nil, nil // another signature of a transaction already being signed: no replacement, no fee check
		}
		last, err := gt.LatestSig(ctx, i.ID)
		if err != nil {
			return nil, err
		}
		if last != nil && !codec.FeesRaised(last.Fees, rel.Fees) {
			return nil, reject(ReasonFeeNotHigher, "fees %v do not exceed the signed fees %v", rel.Fees, last.Fees)
		}
		return nil, nil
	}
	if prior, err := gt.Digest(ctx, rel.Digest); err != nil {
		return nil, err
	} else if prior != nil {
		return nil, reject(ReasonIntentChanged, "digest was signed for intent %s", prior.IntentID)
	}
	rel.NewIntent = true
	if i.Kind == "cancel" {
		if sc, ok := codec.(StrictCancelCodec); ok && sc.StrictCancel() {
			if err := d.strictCancel(ctx, gt, i, rel, claims); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range rel.Claims {
		cl := claims[c]
		switch {
		case cl == nil:
			rel.NewClaims = append(rel.NewClaims, c)
		case cl.Kind == "cancel":
			return nil, reject(ReasonNonceCancel, "%s of %s was consumed by cancel %s", c, rel.Sender, cl.IntentID)
		case i.Kind == "cancel":
			rel.TakeClaims = append(rel.TakeClaims, c) // a cancel may replace what is pending at the claim
		default:
			return nil, reject(ReasonNonceTaken, "%s of %s already signed for intent %s", c, rel.Sender, cl.IntentID)
		}
	}
	return nil, nil
}

// sameSet reports whether a and b hold the same strings.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

// strictCancel is the rule of a cancel on a chain where it can only free what was claimed. The guard has no chain to ask, so it is
// decided here from its own records: every claim of the cancel exists (with its pin: replay checked that), all under one signed intent,
// of the cancel's own partition, and together they are all of that intent's claims. Otherwise a cancel, which needs no approval, could spend
// any input, a deposit output included, under no intent at all.
func (d *Decider) strictCancel(ctx context.Context, gt *GuardTx, i signjob.Intent, rel *Release, claims map[string]*Claim) error {
	owner := ""
	for _, c := range rel.Claims {
		cl := claims[c]
		if cl == nil {
			return reject(ReasonCancelClaims, "%s is not claimed by any signed intent: a cancel only spends what an attempt claimed", c)
		}
		if owner == "" {
			owner = cl.IntentID
		} else if owner != cl.IntentID {
			return reject(ReasonCancelClaims, "the inputs of a cancel are claimed by two intents, %s and %s", owner, cl.IntentID)
		}
	}
	orec, err := gt.Intent(ctx, owner)
	if err != nil {
		return err
	}
	if orec == nil {
		return reject(ReasonCancelClaims, "the intent %s that holds the claims is not recorded", owner)
	}
	if orec.PartitionID != i.PartitionID {
		return reject(ReasonCancelClaims, "the claims belong to intent %s of partition %q, the cancel is for partition %q", owner, orec.PartitionID, i.PartitionID)
	}
	if !sameSet(orec.Claims, rel.Claims) {
		return reject(ReasonCancelClaims, "the cancel spends %d inputs, intent %s claimed %d: a cancel spends exactly the inputs of the attempt it frees", len(rel.Claims), owner, len(orec.Claims))
	}
	return nil
}
