package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Rejection codes, one per check, in decision order. A job's reject_reason is
// "<code>: <detail>".
const (
	ReasonIntent        = "intent_invalid"         // 1 unparseable intent, or chain/partition differ from the job's
	ReasonExpired       = "intent_expired"         // 4 first-time withdrawal with not_after zero, past, or too far ahead
	ReasonTx            = "tx_mismatch"            // 2 TxVerifier refused the transaction
	ReasonApprovals     = "approval_invalid"       // 3 no valid approval from a configured, enabled approver
	ReasonPolicyAsset   = "policy_unknown_asset"   // 4 no policy for the chain or asset
	ReasonPerTxCap      = "policy_per_tx_cap"      // 4
	ReasonDailyCap      = "policy_daily_cap"       // 4
	ReasonTier          = "policy_approvals"       // 4 fewer distinct approvers than the amount requires
	ReasonSweepRate     = "policy_sweep_rate"      // 4
	ReasonCancelRate    = "policy_cancel_rate"     // 4
	ReasonCancelTarget  = "policy_cancel_target"   // 4 sender is not a hot address the gateway owns
	ReasonIntentChanged = "replay_intent_conflict" // 5 same intent ID, different intent hash
	ReasonNonceChanged  = "replay_nonce_changed"   // 5 same intent, new digest, different nonce
	ReasonFeeNotHigher  = "replay_fee_not_higher"  // 5 same intent, new digest, fees not higher
	ReasonNonceTaken    = "replay_nonce_taken"     // 5 another intent already signed at this nonce
	ReasonNonceCancel   = "replay_nonce_cancelled" // 5 a cancel consumed this nonce
)

// Outcomes of processing one job.
const (
	OutcomeSigned   = "signed"   // new signature released
	OutcomeReplayed = "replayed" // stored signature returned, nothing signed
	OutcomeRejected = "rejected"
	OutcomeFailed   = "failed" // operational error (signer); job marked failed
	OutcomeRetry    = "retry"  // transient error; job left to its lease
	OutcomeLost     = "lost"   // finished but the job was no longer held
)

// Decision is the result of processing one job.
type Decision struct {
	JobID   string
	Outcome string
	Reason  string // rejection code and detail, or error text
	Sig     []byte // 64 bytes r||s, for signed and replayed
}

// rejection is a policy refusal; anything else returned from a step is operational.
type rejection struct{ code, detail string }

func (r *rejection) Error() string { return r.code + ": " + r.detail }

func reject(code, format string, args ...any) error {
	return &rejection{code: code, detail: fmt.Sprintf(format, args...)}
}

// Options configures a Gateway.
type Options struct {
	WorkerID string
	Lease    time.Duration // how long a claimed job stays ours before others may reclaim it
	Logger   *slog.Logger
	Now      func() time.Time // default time.Now
}

// Gateway claims sign jobs and signs the ones it independently approves.
type Gateway struct {
	cfg     *Config
	codecs  map[string]ChainCodec
	signers map[string]signer.Signer // partition ID -> signer
	guard   *Guard
	jobs    *pgxpool.Pool // business database, role qv_gateway
	opt     Options

	inflight sync.WaitGroup // signer calls still running, abandoned ones included
}

// New builds a Gateway. codecs has one entry per configured chain; New builds
// the EVM codecs from cfg when codecs is nil.
func New(cfg *Config, codecs map[string]ChainCodec, signers map[string]signer.Signer, guard *Guard, jobs *pgxpool.Pool, opt Options) (*Gateway, error) {
	if codecs == nil {
		codecs = map[string]ChainCodec{}
		for name, cc := range cfg.Chains {
			c, err := NewEVMCodec(cc.EVM)
			if err != nil {
				return nil, err
			}
			codecs[name] = c
		}
	}
	for name := range cfg.Chains {
		if codecs[name] == nil {
			return nil, fmt.Errorf("gateway: no codec for chain %q", name)
		}
	}
	if opt.WorkerID == "" {
		return nil, errors.New("gateway: worker id is required")
	}
	if opt.Lease <= 0 {
		opt.Lease = 2 * time.Minute
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewJSONHandler(discard{}, nil))
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Gateway{cfg: cfg, codecs: codecs, signers: signers, guard: guard, jobs: jobs, opt: opt}, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// RunOnce claims one job and processes it. ok is false when the queue is empty.
func (g *Gateway) RunOnce(ctx context.Context) (d Decision, ok bool, err error) {
	job, err := signjob.Claim(ctx, g.jobs, g.opt.WorkerID, g.opt.Lease)
	if errors.Is(err, signjob.ErrNoJob) {
		return Decision{}, false, nil
	}
	if err != nil {
		return Decision{}, false, err
	}
	return g.Process(ctx, job), true, nil
}

// Run polls until ctx is cancelled, draining the queue between sleeps.
func (g *Gateway) Run(ctx context.Context, interval time.Duration) error {
	for {
		for {
			_, ok, err := g.RunOnce(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				g.opt.Logger.Error("claim failed", "error", err.Error())
				break
			}
			if !ok {
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// Process decides on a claimed job and records the outcome on the job row.
func (g *Gateway) Process(ctx context.Context, job signjob.Job) Decision {
	d := g.decide(ctx, job)
	var err error
	switch d.Outcome {
	case OutcomeSigned, OutcomeReplayed:
		err = signjob.Complete(ctx, g.jobs, job.ID, g.opt.WorkerID, d.Sig)
	case OutcomeRejected:
		err = signjob.Reject(ctx, g.jobs, job.ID, g.opt.WorkerID, d.Reason)
	case OutcomeFailed:
		err = signjob.Fail(ctx, g.jobs, job.ID, g.opt.WorkerID, d.Reason)
	}
	if errors.Is(err, signjob.ErrNotHeld) {
		d.Outcome = OutcomeLost
	} else if err != nil {
		d.Outcome, d.Reason = OutcomeRetry, "store result: "+err.Error()
	}
	attrs := []any{"job", job.ID, "partition", job.PartitionID, "chain", job.Chain, "outcome", d.Outcome}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	g.opt.Logger.Info("decision", attrs...)
	return d
}

// decide runs the decision steps in order. It never touches the job row.
func (g *Gateway) decide(ctx context.Context, job signjob.Job) Decision {
	d := Decision{JobID: job.ID}
	sig, replayed, err := g.evaluate(ctx, job)
	var rj *rejection
	switch {
	case errors.As(err, &rj):
		d.Outcome, d.Reason = OutcomeRejected, rj.Error()
	case errors.Is(err, errSigner):
		d.Outcome, d.Reason = OutcomeFailed, err.Error()
	case err != nil:
		d.Outcome, d.Reason = OutcomeRetry, err.Error()
	case replayed:
		d.Outcome, d.Sig = OutcomeReplayed, sig
	default:
		d.Outcome, d.Sig = OutcomeSigned, sig
	}
	return d
}

var errSigner = errors.New("signer failed")

func (g *Gateway) evaluate(ctx context.Context, job signjob.Job) (sig []byte, replayed bool, err error) {
	// 1. Intent.
	intent, err := parseIntent(job)
	if err != nil {
		return nil, false, err
	}
	cc := g.cfg.Chains[intent.Chain]
	codec := g.codecs[intent.Chain]
	if cc == nil || codec == nil {
		return nil, false, reject(ReasonIntent, "chain %q is not configured", intent.Chain)
	}

	// 2. Transaction matches intent.
	u := chain.UnsignedTx{Chain: job.Chain, Digest: job.Digest, Payload: job.Payload,
		KeyRef: chain.KeyRef{PartitionID: job.PartitionID, Path: job.KeyRef}}
	if err := codec.Verify(u, intent); err != nil {
		return nil, false, reject(ReasonTx, "%v", err)
	}
	info, err := codec.Decode(job.Payload)
	if err != nil {
		return nil, false, reject(ReasonTx, "%v", err)
	}
	amount, ok := new(big.Int).SetString(intent.Amount, 10)
	if !ok {
		return nil, false, reject(ReasonTx, "amount %q", intent.Amount)
	}

	// 3. Approvals, from configured keys only.
	hash := intent.Hash()
	valid := g.countApprovals(hash[:], job.Approvals)
	if intent.Kind == "withdrawal" && valid == 0 {
		return nil, false, reject(ReasonApprovals, "no valid approval from a configured, enabled approver")
	}

	// Phase 1, reserve. Steps 4 and 5 run under the replay guard's chain lock,
	// so a second gateway instance sees our records before it decides. The
	// transaction ends with the digest reserved (caps and nonce taken) and no
	// signature yet: the lock is never held while the signer runs.
	s := g.signers[job.PartitionID]
	needSign := false
	err = g.guard.Do(ctx, intent.Chain, func(gt *GuardTx) error {
		now := g.opt.Now()
		rec, err := gt.Intent(ctx, intent.ID)
		if err != nil {
			return err
		}
		known := rec != nil && bytes.Equal(rec.Hash, hash[:])

		// 4. Policy. Caps and rates are admitted once per intent; a known
		// intent (resubmission, replacement) is not counted again.
		if err := g.policy(ctx, gt, cc, intent, codec, info, amount, valid, known, now); err != nil {
			return err
		}

		// 5. Replay guard.
		rel := Release{IntentID: intent.ID, IntentHash: hash[:], Kind: intent.Kind, Asset: intent.Asset, Amount: amount,
			Sender: info.Sender, Nonce: info.Nonce, Digest: job.Digest, Tip: info.Tip, FeeCap: info.FeeCap, At: now}
		prior, err := g.replay(ctx, gt, intent, rec, &rel)
		if err != nil {
			return err
		}
		if prior != nil {
			if prior.Signature != nil {
				sig, replayed = prior.Signature, true // signed before: return it, never sign again
				return nil
			}
			if now.Sub(prior.Reserved) < g.cfg.SignTimeout {
				return errInProgress // another worker is signing this digest
			}
			needSign = true // a stale reservation: sign the same digest again
			return gt.Touch(ctx, job.Digest, now)
		}

		// 6a. Reserve.
		if s == nil {
			return fmt.Errorf("%w: no signer for partition %q", errSigner, job.PartitionID)
		}
		if err := codec.CheckSigner(info, s.PublicKey()); err != nil {
			return fmt.Errorf("%w: %v", errSigner, err)
		}
		needSign = true
		return gt.Record(ctx, rel)
	})
	if err != nil || !needSign {
		return sig, replayed, err
	}

	// Phase 2, sign, outside any lock or transaction, within sign_timeout.
	if s == nil {
		return nil, false, fmt.Errorf("%w: no signer for partition %q", errSigner, job.PartitionID)
	}
	raw, err := g.sign(ctx, s, job.Digest)
	if err != nil {
		return nil, false, err
	}

	// Phase 3, finish. The first stored signature wins; release only the stored value.
	stored, err := g.guard.Finish(ctx, job.Digest, raw, g.opt.Now())
	return stored, false, err
}

var errInProgress = errors.New("another worker is signing this digest")

// Wait blocks until no signer call is running, or d passes, and reports whether
// they all finished. Call it before closing the signers: a call abandoned after
// sign_timeout may still be inside the HSM library, and finalizing the library
// under it crashes the process.
func (g *Gateway) Wait(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		g.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// sign calls the signer with a timeout and verifies the signature locally. A
// signer that ignores the context is abandoned; its late result is dropped.
func (g *Gateway) sign(ctx context.Context, s signer.Signer, digest []byte) ([]byte, error) {
	var dg [32]byte
	copy(dg[:], digest)
	sctx, cancel := context.WithTimeout(ctx, g.cfg.SignTimeout)
	defer cancel()
	type result struct {
		res signer.Result
		err error
	}
	ch := make(chan result, 1)
	g.inflight.Add(1)
	go func() {
		defer g.inflight.Done()
		res, err := s.SignDigest(sctx, dg, signer.SignOptions{})
		ch <- result{res, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("%w: %v", errSigner, r.err)
		}
		if !signer.Verify(s.PublicKey(), dg, r.res.Sig) {
			return nil, fmt.Errorf("%w: signature does not verify", errSigner)
		}
		raw := make([]byte, 64)
		r.res.Sig.R.FillBytes(raw[:32])
		r.res.Sig.S.FillBytes(raw[32:])
		return raw, nil
	case <-sctx.Done():
		return nil, fmt.Errorf("%w: sign timed out after %s", errSigner, g.cfg.SignTimeout)
	}
}

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
	case "withdrawal", "sweep", "cancel":
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
func (g *Gateway) countApprovals(hash []byte, approvals []signjob.Approval) int {
	seen := map[string]bool{}
	for _, a := range approvals {
		ap, ok := g.cfg.Approvers[a.Actor]
		if !ok || !ap.Enabled || seen[a.Actor] {
			continue
		}
		if len(a.Signature) == ed25519.SignatureSize && ed25519.Verify(ap.Key, hash, a.Signature) {
			seen[a.Actor] = true
		}
	}
	return len(seen)
}

func (g *Gateway) policy(ctx context.Context, gt *GuardTx, cc *ChainConfig, i signjob.Intent, codec ChainCodec,
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
			case i.NotAfter > now+int64(g.cfg.MaxIntentAge/time.Second):
				return reject(ReasonExpired, "not_after %d is more than %s ahead", i.NotAfter, g.cfg.MaxIntentAge)
			}
		}
		p, ok := cc.Assets[i.Asset]
		if !ok {
			return reject(ReasonPolicyAsset, "no policy for %s on %s", i.Asset, cc.Name)
		}
		if amount.Cmp(p.PerTxCap) > 0 {
			return reject(ReasonPerTxCap, "amount %s exceeds the per-transaction cap %s", amount, p.PerTxCap)
		}
		if need := p.RequiredApprovals(amount); valid < need {
			return reject(ReasonTier, "amount %s needs %d distinct approvals, have %d", amount, need, valid)
		}
		if !known {
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
func (g *Gateway) replay(ctx context.Context, gt *GuardTx, i signjob.Intent, rec *IntentRecord, rel *Release) (*SigRecord, error) {
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
