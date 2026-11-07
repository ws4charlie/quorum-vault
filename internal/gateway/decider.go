package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

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
	info, err := codec.Decode(u)
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
		Claims: info.Claims, IntentHash: hash[:]}
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
			Sender: info.Sender, PartitionID: intent.PartitionID, Claims: info.Claims, Pins: info.Pins, Identity: info.Identity, Digest: job.Digest, Fees: info.Fees, PayloadHash: payloadHash(job.Payload), At: now}
		prior, err := d.replay(ctx, gt, intent, rec, codec, &rel)
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
	case "withdrawal", "sweep", "cancel", "to-cold", "rebalance", "consolidate":
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
