package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	ReasonIntent          = "intent_invalid"          // 1 unparseable intent, or chain/partition differ from the job's
	ReasonExpired         = "intent_expired"          // 4 first-time withdrawal with not_after zero, past, or too far ahead
	ReasonTx              = "tx_mismatch"             // 2 TxVerifier refused the transaction
	ReasonApprovals       = "approval_invalid"        // 3 no valid approval from a configured, enabled approver
	ReasonPolicyAsset     = "policy_unknown_asset"    // 4 no policy for the chain or asset
	ReasonPerTxCap        = "policy_per_tx_cap"       // 4
	ReasonDailyCap        = "policy_daily_cap"        // 4
	ReasonTier            = "policy_approvals"        // 4 fewer distinct approvers than the amount requires
	ReasonDestination     = "policy_destination"      // 4 withdrawal pays an address that is not on the asset's list
	ReasonWithdrawRate    = "policy_withdrawal_rate"  // 4 too many withdrawals in the last hour
	ReasonSweepRate       = "policy_sweep_rate"       // 4
	ReasonCancelRate      = "policy_cancel_rate"      // 4
	ReasonCancelTarget    = "policy_cancel_target"    // 4 sender is not a hot address the gateway owns
	ReasonToColdRate      = "policy_to_cold_rate"     // 4 too many hot-to-cold moves in the last hour
	ReasonToColdCap       = "policy_to_cold_cap"      // 4 hot-to-cold moves of this asset would exceed the daily cap
	ReasonConsolidateRate = "policy_consolidate_rate" // 4 too many consolidations in the last hour (zero allowed: none)
	ReasonRebalanceRate   = "policy_rebalance_rate"   // 4 too many hot-shard rebalances in the last hour
	ReasonRebalanceCap    = "policy_rebalance_cap"    // 4 rebalances of this asset would exceed the daily cap
	ReasonIntentChanged   = "replay_intent_conflict"  // 5 same intent ID, different intent hash
	ReasonNonceChanged    = "replay_nonce_changed"    // 5 same intent, new digest, different nonce
	ReasonFeeNotHigher    = "replay_fee_not_higher"   // 5 same intent, new digest, fees not higher
	ReasonNonceTaken      = "replay_nonce_taken"      // 5 another intent already signed at this nonce
	ReasonNonceCancel     = "replay_nonce_cancelled"  // 5 a cancel consumed this nonce
	ReasonPinChanged      = "replay_pin_changed"      // 5 a claim that exists is named again with another pin (Bitcoin: another input value)
	ReasonCancelClaims    = "replay_cancel_claims"    // 5 a cancel on a chain that requires it names inputs that are not exactly the claims of one signed intent of its partition
	ReasonIdentity        = "replay_identity_reused"  // 5 the transaction identity was signed under another payload (Bitcoin: same txid, other values)
	ReasonSignerRefused   = "signer_refused"          // 6 the signer's other party (cb-mpc party B) refused; nothing was signed
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
	// MessageSigners and DepositSigners are the Ed25519 signers of the chains whose codec is a MessageCodec (Solana): per partition, the hot shard's
	// signer and the signer of the deposit key tree. ECDSA chains use the signers argument of New.
	MessageSigners map[string]signer.MessageSigner
	DepositSigners map[string]signer.MessageDeriver
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

	outageMu sync.Mutex
	outages  map[string]bool // chain -> an outage has been reported and signing has not resumed
}

// New builds a Gateway. codecs has one entry per configured chain; New builds
// them from cfg (NewCodecs) when codecs is nil.
func New(cfg *Config, codecs map[string]ChainCodec, signers map[string]signer.Signer, guard *Guard, jobs *pgxpool.Pool, opt Options) (*Gateway, error) {
	if codecs == nil {
		var err error
		if codecs, err = NewCodecs(cfg); err != nil {
			return nil, err
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

// errUnavailable marks an availability failure of the signer: the outcome is a retry, never a failed job.
var errUnavailable = errors.New("signer unavailable")

func (g *Gateway) evaluate(ctx context.Context, job signjob.Job) (sig []byte, replayed bool, err error) {
	if mc, ok := g.codecs[job.Chain].(MessageCodec); ok {
		return g.evaluateMessage(ctx, job, mc)
	}
	var pub *ecdsa.PublicKey
	s := g.signers[job.PartitionID]
	if d, ok := s.(signer.Deriver); ok {
		// A signer for a key tree: the job names its key by path, and that key is the one that would sign.
		kp, ok := g.codecs[job.Chain].(KeyPathCodec)
		if !ok {
			return nil, false, fmt.Errorf("%w: chain %q has no key paths but partition %q has a key tree", errSigner, job.Chain, job.PartitionID)
		}
		path, err := kp.KeyPath(job.KeyRef)
		if err != nil {
			return nil, false, reject(ReasonTx, "key reference: %v", err)
		}
		ks, err := d.At(ctx, path)
		if err != nil {
			var un interface{ SignerUnavailable() bool }
			if errors.As(err, &un) && un.SignerUnavailable() {
				return nil, false, fmt.Errorf("%w: derive %v: %v", errUnavailable, path, err)
			}
			return nil, false, fmt.Errorf("%w: derive %v: %v", errSigner, path, err)
		}
		s = ks
	}
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
		if errors.Is(err, errUnavailable) {
			g.outage(job.Chain, err)
		}
		return nil, false, err
	}
	g.resumed(job.Chain)

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
			return nil, g.signerError(r.err)
		}
		if !signer.Verify(s.PublicKey(), dg, r.res.Sig) {
			return nil, fmt.Errorf("%w: signature does not verify", errSigner)
		}
		raw := make([]byte, 64)
		r.res.Sig.R.FillBytes(raw[:32])
		r.res.Sig.S.FillBytes(raw[32:])
		return raw, nil
	case <-sctx.Done():
		if rt, ok := s.(interface{ RetryOnTimeout() bool }); ok && rt.RetryOnTimeout() {
			return nil, fmt.Errorf("%w: sign timed out after %s", errUnavailable, g.cfg.SignTimeout)
		}
		return nil, fmt.Errorf("%w: sign timed out after %s", errSigner, g.cfg.SignTimeout)
	}
}

// signerError maps a failure of a signer to the gateway's outcomes: an availability failure never finishes the job (a retry: nothing was signed or
// refused; the job stays "signing" and is reclaimed when its lease ends), a refusal by the other party (cb-mpc: a cosigner) is a rejection, and
// anything else is a signer failure, with an ALERT when an operator must look.
func (g *Gateway) signerError(err error) error {
	var un interface{ SignerUnavailable() bool }
	if errors.As(err, &un) && un.SignerUnavailable() {
		return fmt.Errorf("%w: %v", errUnavailable, err)
	}
	var ref interface{ SignerRefusal() (string, bool) }
	if errors.As(err, &ref) {
		if why, ok := ref.SignerRefusal(); ok {
			return reject(ReasonSignerRefused, "%s", why)
		}
	}
	var al interface{ SignerAlert() bool }
	if errors.As(err, &al) && al.SignerAlert() {
		g.opt.Logger.Error("ALERT signer failure: an operator must look (keyset may be frozen)", "error", err.Error())
	}
	return fmt.Errorf("%w: %v", errSigner, err)
}

// evaluateMessage is evaluate for a chain whose jobs are signed with Ed25519 over the whole message (Solana): the same steps, with the key picked
// by the job's key reference (the partition's hot signer, or a deposit key below the deposit tree) and a signature checked by crypto/ed25519.
func (g *Gateway) evaluateMessage(ctx context.Context, job signjob.Job, mc MessageCodec) (sig []byte, replayed bool, err error) {
	deposit, path, err := mc.SignerFor(job.KeyRef)
	if err != nil {
		return nil, false, reject(ReasonTx, "key reference: %v", err)
	}
	var s signer.MessageSigner
	if !deposit {
		s = g.opt.MessageSigners[job.PartitionID]
	} else if d := g.opt.DepositSigners[job.PartitionID]; d != nil {
		ks, err := d.At(ctx, path)
		if err != nil {
			var un interface{ SignerUnavailable() bool }
			if errors.As(err, &un) && un.SignerUnavailable() {
				return nil, false, fmt.Errorf("%w: derive %v: %v", errUnavailable, path, err)
			}
			return nil, false, fmt.Errorf("%w: derive %v: %v", errSigner, path, err)
		}
		s = ks
	}
	var key SignerKey
	if s != nil {
		key.Ed25519 = s.PublicKey()
	}
	v, err := g.dec.DecideKey(ctx, job, key)
	if err != nil {
		return nil, false, err
	}
	if !v.NeedSign {
		return v.Signature, v.Replayed, nil
	}
	pkg, err := EncodePackage(job)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", errSigner, err)
	}
	raw, err := g.signMessage(ctx, s, job.Digest, signer.SignOptions{JobID: job.ID, IntentPackage: pkg})
	if err != nil {
		if errors.Is(err, errUnavailable) {
			g.outage(job.Chain, err)
		}
		return nil, false, err
	}
	g.resumed(job.Chain)
	stored, err := g.guard.Finish(ctx, v.GuardKey, raw, g.opt.Now())
	return stored, false, err
}

// signMessage is signWith for a MessageSigner.
func (g *Gateway) signMessage(ctx context.Context, s signer.MessageSigner, msg []byte, opts signer.SignOptions) ([]byte, error) {
	sctx, cancel := context.WithTimeout(ctx, g.cfg.SignTimeout)
	defer cancel()
	type result struct {
		res signer.MessageResult
		err error
	}
	ch := make(chan result, 1)
	g.inflight.Add(1)
	go func() {
		defer g.inflight.Done()
		res, err := s.SignMessage(sctx, msg, opts)
		ch <- result{res, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, g.signerError(r.err)
		}
		if len(r.res.Signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(s.PublicKey()), msg, r.res.Signature) {
			return nil, fmt.Errorf("%w: signature does not verify", errSigner)
		}
		return r.res.Signature, nil
	case <-sctx.Done():
		if rt, ok := s.(interface{ RetryOnTimeout() bool }); ok && rt.RetryOnTimeout() {
			return nil, fmt.Errorf("%w: sign timed out after %s", errUnavailable, g.cfg.SignTimeout)
		}
		return nil, fmt.Errorf("%w: sign timed out after %s", errSigner, g.cfg.SignTimeout)
	}
}

// outage logs ONE alert per chain per outage (not one per job).
func (g *Gateway) outage(chain string, err error) {
	g.outageMu.Lock()
	if g.outages == nil {
		g.outages = map[string]bool{}
	}
	first := !g.outages[chain]
	g.outages[chain] = true
	g.outageMu.Unlock()
	if first {
		g.opt.Logger.Error("ALERT signer unavailable: jobs wait and are retried, nothing was signed or refused", "chain", chain, "error", err.Error())
	}
}

// resumed logs once when signing works again after an outage.
func (g *Gateway) resumed(chain string) {
	g.outageMu.Lock()
	was := g.outages[chain]
	delete(g.outages, chain)
	g.outageMu.Unlock()
	if was {
		g.opt.Logger.Info("signer available again: signing resumed", "chain", chain)
	}
}
