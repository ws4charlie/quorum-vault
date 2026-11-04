package gateway

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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
	dec     *Decider
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
	dec := NewDecider(cfg, codecs, guard, ModeGateway, opt.Now)
	return &Gateway{cfg: cfg, codecs: codecs, signers: signers, guard: guard, dec: dec, jobs: jobs, opt: opt}, nil
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
	var pub *ecdsa.PublicKey
	s := g.signers[job.PartitionID]
	if s != nil {
		pub = s.PublicKey()
	}
	v, err := g.dec.Decide(ctx, job, pub)
	if err != nil {
		return nil, false, err
	}
	if !v.NeedSign {
		return v.Signature, v.Replayed, nil
	}

	// Phase 2, sign, outside any lock or transaction, within sign_timeout.
	pkg, err := EncodePackage(job)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", errSigner, err)
	}
	raw, err := g.signWith(ctx, s, job.Digest, signer.SignOptions{JobID: job.ID, IntentPackage: pkg})
	if err != nil {
		return nil, false, err
	}

	// Phase 3, finish. The first stored signature wins; release only the stored value.
	stored, err := g.guard.Finish(ctx, job.Digest, raw, g.opt.Now())
	return stored, false, err
}

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
	return g.signWith(ctx, s, digest, signer.SignOptions{})
}

func (g *Gateway) signWith(ctx context.Context, s signer.Signer, digest []byte, opts signer.SignOptions) ([]byte, error) {
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
		res, err := s.SignDigest(sctx, dg, opts)
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
