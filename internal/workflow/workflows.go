package workflow

import (
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Signals of the withdrawal workflow.
const (
	SignalApproval = "approval" // an approval was added to the row; re-read it
	SignalReject   = "reject"   // a human rejected; payload is the reason
)

// Timings the workflows use that are not business configuration.
type Timings struct {
	ApprovalTimeout time.Duration
	ApprovalPoll    time.Duration // re-read approvals this often even without a signal
	SignTimeout     time.Duration // the gateway's sign_timeout: wait this long before retrying a failed job
	StuckAfter      time.Duration
	HotWait         time.Duration
	HotPoll         time.Duration
	MaxReplacements int
	ScanInterval    time.Duration
	PlanInterval    time.Duration
}

// DefaultTimings derives timings from the business config.
func DefaultTimings(c *custody.Config) Timings {
	return Timings{ApprovalTimeout: c.ApprovalTimeout, ApprovalPoll: 15 * time.Second, SignTimeout: c.SignTimeout, StuckAfter: c.StuckAfter,
		HotWait: c.HotWait, HotPoll: 10 * time.Second, MaxReplacements: c.MaxReplacements, ScanInterval: c.ScanInterval, PlanInterval: c.PlanInterval}
}

// Input of the workflows that need timings. The worker passes them at start;
// they are part of the recorded history, so replays see the same values.
type Input struct {
	ID string
	T  Timings
}

var a *Activities // only used to name activities

func opts(ctx workflow.Context) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second},
	})
}

// planOpts gives the planner room: one pass asks the node about each candidate.
func planOpts(ctx workflow.Context) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second},
	})
}

// buildOpts bounds the retries of a build: an estimate that keeps failing (the
// chain refuses the call) is not going to start working, and nothing was
// allocated, because the build and the nonce share one transaction.
func buildOpts(ctx workflow.Context) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second, MaximumAttempts: 10},
	})
}

// longOpts is for polling activities that heartbeat.
func longOpts(ctx workflow.Context, wait time.Duration) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: wait + 20*time.Second,
		HeartbeatTimeout:    8 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second},
	})
}

// ScanWorkflow reads one chain forever: each pass credits new deposits and
// advances the cursor in one database transaction. It continues as new after a
// while so its history stays small.
func ScanWorkflow(ctx workflow.Context, in Input) error {
	for i := 0; i < 300; i++ {
		var r ScanResult
		if err := workflow.ExecuteActivity(opts(ctx), a.ScanOnce).Get(ctx, &r); err != nil {
			return err
		}
		if err := workflow.Sleep(ctx, in.T.ScanInterval); err != nil {
			return err
		}
	}
	return workflow.NewContinueAsNewError(ctx, ScanWorkflow, in)
}

// SweepPlannerWorkflow decides what to sweep and makes sure each open sweep has
// a workflow. A frozen factory just means nothing is planned this round.
func SweepPlannerWorkflow(ctx workflow.Context, in Input) error {
	for i := 0; i < 300; i++ {
		var frozen bool
		if err := workflow.ExecuteActivity(planOpts(ctx), a.PlanSweeps).Get(ctx, &frozen); err != nil {
			return err
		}
		var n int
		if err := workflow.ExecuteActivity(opts(ctx), a.StartOpenSweeps).Get(ctx, &n); err != nil {
			return err
		}
		if err := workflow.Sleep(ctx, in.T.PlanInterval); err != nil {
			return err
		}
	}
	return workflow.NewContinueAsNewError(ctx, SweepPlannerWorkflow, in)
}

// WithdrawalReconcilerWorkflow starts a workflow for every open withdrawal that
// has none, which repairs a crash between the API's commit and its start call.
func WithdrawalReconcilerWorkflow(ctx workflow.Context, in Input) error {
	for i := 0; i < 300; i++ {
		var n int
		if err := workflow.ExecuteActivity(opts(ctx), a.StartOpenWithdrawals).Get(ctx, &n); err != nil {
			return err
		}
		if err := workflow.Sleep(ctx, in.T.PlanInterval); err != nil {
			return err
		}
	}
	return workflow.NewContinueAsNewError(ctx, WithdrawalReconcilerWorkflow, in)
}

// ---- shared: from an enqueued job to a final transaction ----

type txKind string

const (
	txMined     txKind = "mined"     // the owner's own transaction mined and succeeded
	txReverted  txKind = "reverted"  // ... and reverted
	txCancelled txKind = "cancelled" // a cancel mined; the owner's transaction never will
	txRefused   txKind = "refused"   // the gateway refused (or failed twice); nothing was broadcast
)

type txResult struct {
	Kind   txKind
	Hash   string
	Reason string
}

// waitJob polls the job until the gateway is done with it.
func waitJob(ctx workflow.Context, jobID string) (JobResult, error) {
	const slice = 20 * time.Second
	for {
		var r JobResult
		if err := workflow.ExecuteActivity(longOpts(ctx, slice), a.WaitJob, jobID, slice).Get(ctx, &r); err != nil {
			return r, err
		}
		if r.Status != custody.JobPending {
			return r, nil
		}
	}
}

// driveTx takes an enqueued first job through signing, broadcast and
// confirmation, replacing it with a higher fee if it sticks. It looks at every
// attempt at the nonce, because any of them may be the one that mines.
//
//	done     -> broadcast, wait
//	rejected -> txRefused
//	failed   -> wait sign_timeout, enqueue the same digest again once; a second
//	            failure -> txRefused
//
// record is called with each broadcast hash (the withdrawal or sweep row).
func driveTx(ctx workflow.Context, t Timings, o OwnerArg, track custody.Track, firstJob string, record bool) (txResult, error) {
	jobID := firstJob
	for attempt := 1; ; attempt++ {
		r, err := waitJob(ctx, jobID)
		if err != nil {
			return txResult{}, err
		}
		if r.Status == custody.JobDone {
			break
		}
		if r.Status == custody.JobRejected {
			return txResult{Kind: txRefused, Reason: r.Reason}, nil
		}
		// failed: the gateway keeps its reservation; retry after sign_timeout.
		if attempt >= 2 {
			return txResult{Kind: txRefused, Reason: "signing failed twice: " + r.Reason}, nil
		}
		if err := workflow.Sleep(ctx, t.SignTimeout); err != nil {
			return txResult{}, err
		}
		next := track.Retry()
		if err := workflow.ExecuteActivity(opts(ctx), a.RequeueJob, jobID, next).Get(ctx, nil); err != nil {
			return txResult{}, err
		}
		jobID = next
	}

	broadcast := func(job string) error {
		var hash string
		if err := workflow.ExecuteActivity(opts(ctx), a.BroadcastJob, job).Get(ctx, &hash); err != nil {
			return err
		}
		if record {
			return workflow.ExecuteActivity(opts(ctx), a.RecordBroadcast, o, hash).Get(ctx, nil)
		}
		return nil
	}
	if err := broadcast(jobID); err != nil {
		return txResult{}, err
	}

	stuckAt := workflow.Now(ctx).Add(t.StuckAfter)
	replacements := 0
	const slice = 10 * time.Second
	for {
		var n NonceResult
		if err := workflow.ExecuteActivity(longOpts(ctx, slice), a.WaitNonce, o, slice).Get(ctx, &n); err != nil {
			return txResult{}, err
		}
		switch n.State {
		case custody.NonceMined:
			return txResult{Kind: txMined, Hash: n.Hash}, nil
		case custody.NonceReverted:
			return txResult{Kind: txReverted, Hash: n.Hash}, nil
		case custody.NonceCancelled:
			return txResult{Kind: txCancelled, Hash: n.Hash}, nil
		case custody.NonceDropped:
			// The node forgot every attempt: send the stored signed transaction again.
			var h string
			if err := workflow.ExecuteActivity(opts(ctx), a.Rebroadcast, o).Get(ctx, &h); err != nil {
				return txResult{}, err
			}
		}
		if !workflow.Now(ctx).Before(stuckAt) && replacements < t.MaxReplacements {
			replacements++
			var rj string
			if err := workflow.ExecuteActivity(opts(ctx), a.EnqueueReplacement, o, string(track), replacements).Get(ctx, &rj); err != nil {
				return txResult{}, err
			}
			rr, err := waitJob(ctx, rj)
			if err != nil {
				return txResult{}, err
			}
			if rr.Status == custody.JobDone {
				if err := broadcast(rj); err != nil {
					return txResult{}, err
				}
			} // refused or failed: the original may still mine; try again at the next deadline
			stuckAt = workflow.Now(ctx).Add(t.StuckAfter)
		}
	}
}

// cancelNonce frees the owner's nonce with a cancel transaction and returns
// what finally mined at it: the cancel (txCancelled), or the owner's own
// transaction after all (txMined / txReverted). Only then may money be released.
func cancelNonce(ctx workflow.Context, t Timings, o OwnerArg) (txResult, error) {
	var cj string
	if err := workflow.ExecuteActivity(opts(ctx), a.EnqueueCancel, o).Get(ctx, &cj); err != nil {
		return txResult{}, err
	}
	ow := custody.Owner{Kind: o.Kind, ID: o.ID, PartitionID: o.Part}
	r, err := driveTx(ctx, t, o, custody.CancelTrack(ow), cj, false)
	if err != nil {
		return r, err
	}
	if r.Kind == txRefused {
		// A refused cancel leaves a live nonce; never release the money. Park for an operator.
		workflow.GetLogger(ctx).Error("ALERT: the gateway refused to cancel a nonce; manual intervention needed", "owner", o.ID, "reason", r.Reason)
		return r, temporal.NewApplicationError("cancel refused: "+r.Reason, "cancel_refused")
	}
	return r, nil
}

// ---- withdrawal ----

// WithdrawalWorkflow is one withdrawal, from request to settlement or void.
// Its workflow ID is the withdrawal ID. The API already committed the row,
// the hold and the outbox event.
func WithdrawalWorkflow(ctx workflow.Context, in Input) error {
	id, t := in.ID, in.T
	var st WdState
	if err := workflow.ExecuteActivity(opts(ctx), a.LoadWithdrawal, id).Get(ctx, &st); err != nil {
		return err
	}
	if st.Status == custody.WdConfirmed || st.Status == custody.WdFailed {
		return nil
	}
	o := OwnerArg{Kind: "withdrawal", ID: id, Part: st.Part}
	void := func(reason, feeTx string) error {
		return workflow.ExecuteActivity(opts(ctx), a.VoidWithdrawal, id, reason, feeTx).Get(ctx, nil)
	}

	// 2. Approvals. Skipped when the job already exists (a restarted workflow).
	if st.Status == custody.WdRequested {
		if st.Auto {
			if err := workflow.ExecuteActivity(opts(ctx), a.AutoApprove, id).Get(ctx, nil); err != nil {
				return err
			}
		}
		approved, reason, err := awaitApprovals(ctx, t, id, st)
		if err != nil {
			return err
		}
		if !approved {
			return void(reason, "")
		}
		if err := workflow.ExecuteActivity(opts(ctx), a.MarkApproved, id).Get(ctx, nil); err != nil {
			return err
		}
	}

	// 3. Hot liquidity. The shard is part of the signed intent, so it was chosen
	// at request time; wait here until it can pay.
	if st.Status == custody.WdRequested || st.Status == custody.WdApproved {
		deadline := workflow.Now(ctx).Add(t.HotWait)
		for {
			var ok bool
			if err := workflow.ExecuteActivity(opts(ctx), a.ReserveHot, id).Get(ctx, &ok); err != nil {
				return err
			}
			if ok {
				break
			}
			if !workflow.Now(ctx).Before(deadline) {
				return void("no hot wallet could cover the amount in time", "")
			}
			if err := workflow.Sleep(ctx, t.HotPoll); err != nil {
				return err
			}
		}

		// 4. Build and enqueue, in one transaction.
		var job string
		if err := workflow.ExecuteActivity(buildOpts(ctx), a.BuildWithdrawalJob, id).Get(ctx, &job); err != nil {
			if isType(err, errExpired) {
				return void("approval window passed before signing", "")
			}
			// Nothing was allocated (the build rolled back), so the hold can go.
			workflow.GetLogger(ctx).Error("ALERT: could not build the withdrawal transaction; voiding", "withdrawal", id, "error", err.Error())
			return void("could not build the transaction: "+err.Error(), "")
		}
	}

	// 5-8. Sign, broadcast, confirm (replacing if stuck).
	ow := custody.Owner{Kind: "withdrawal", ID: id, PartitionID: st.Part}
	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true)
	if err != nil {
		return err
	}
	if r.Kind == txRefused {
		// The nonce was allocated and may hold a signature the gateway reserved.
		// Cancel it; only when a transaction at that nonce has confirmed may the hold go.
		reason := "gateway refused: " + r.Reason
		cr, err := cancelNonce(ctx, t, o)
		if err != nil {
			return err
		}
		if cr.Kind == txCancelled {
			return void(reason, cr.Hash)
		}
		r = cr // the withdrawal itself mined after all: settle or void by what it did
	}
	switch r.Kind {
	case txMined:
		return workflow.ExecuteActivity(opts(ctx), a.SettleWithdrawal, id, r.Hash).Get(ctx, nil)
	case txReverted:
		return void("transaction reverted", r.Hash)
	case txCancelled:
		return void("cancelled", r.Hash)
	}
	return fmt.Errorf("unexpected outcome %q", r.Kind)
}

// awaitApprovals waits for enough approvals, a rejection, or the timeout. It
// re-reads the database on a timer as well as on a signal, so a lost signal only
// delays. Duplicate signals do nothing: the row is the state.
func awaitApprovals(ctx workflow.Context, t Timings, id string, st WdState) (approved bool, reason string, err error) {
	deadline := workflow.Now(ctx).Add(t.ApprovalTimeout)
	approvals := workflow.GetSignalChannel(ctx, SignalApproval)
	rejects := workflow.GetSignalChannel(ctx, SignalReject)
	for {
		var have int
		if err := workflow.ExecuteActivity(opts(ctx), a.ApprovalsHave, id).Get(ctx, &have); err != nil {
			return false, "", err
		}
		if have >= st.Required {
			return true, "", nil
		}
		left := deadline.Sub(workflow.Now(ctx))
		if left <= 0 {
			return false, "approval timeout", nil
		}
		wait := min(left, t.ApprovalPoll)
		timer := workflow.NewTimer(ctx, wait)
		sel := workflow.NewSelector(ctx)
		rejected, rejReason := false, ""
		sel.AddReceive(approvals, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil) })
		sel.AddReceive(rejects, func(c workflow.ReceiveChannel, _ bool) {
			c.Receive(ctx, &rejReason)
			rejected = true
		})
		sel.AddFuture(timer, func(workflow.Future) {})
		sel.Select(ctx)
		if rejected {
			return false, "rejected: " + rejReason, nil
		}
	}
}

// ---- sweep ----

// SweepWorkflow is one sweep of one address and asset. Its workflow ID is the
// sweep ID: build and enqueue, wait for the gateway, assemble and broadcast,
// wait, then account for what actually moved.
func SweepWorkflow(ctx workflow.Context, in Input) error {
	id, t := in.ID, in.T
	var st SweepState
	if err := workflow.ExecuteActivity(opts(ctx), a.LoadSweep, id).Get(ctx, &st); err != nil {
		return err
	}
	if st.Status == "confirmed" || st.Status == "failed" {
		return nil
	}
	o := OwnerArg{Kind: "sweep", ID: id, Part: st.Part}
	ow := custody.Owner{Kind: "sweep", ID: id, PartitionID: st.Part}

	var job string
	if err := workflow.ExecuteActivity(buildOpts(ctx), a.BuildSweepJob, id).Get(ctx, &job); err != nil {
		if isType(err, errFrozen) {
			return nil // marked failed; the planner plans it again after unfreezing
		}
		workflow.GetLogger(ctx).Warn("could not build the sweep; it will be planned again", "sweep", id, "error", err.Error())
		return workflow.ExecuteActivity(opts(ctx), a.FailSweep, id, "could not build: "+err.Error()).Get(ctx, nil)
	}
	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true)
	if err != nil {
		return err
	}
	if r.Kind == txRefused {
		cr, err := cancelNonce(ctx, t, o)
		if err != nil {
			return err
		}
		if cr.Kind == txCancelled {
			return workflow.ExecuteActivity(opts(ctx), a.FailSweep, id, "gateway refused: "+r.Reason).Get(ctx, nil)
		}
		r = cr
	}
	switch r.Kind {
	case txMined, txReverted:
		if err := workflow.ExecuteActivity(opts(ctx), a.SettleSweep, id, r.Hash, r.Kind == txReverted).Get(ctx, nil); err != nil {
			return err
		}
	case txCancelled:
		return workflow.ExecuteActivity(opts(ctx), a.FailSweep, id, "cancelled").Get(ctx, nil)
	}
	// Excess that no deposit explains goes to suspense once the scan is past it.
	for i := 0; i < 600; i++ {
		var done bool
		if err := workflow.ExecuteActivity(opts(ctx), a.TrueUp, id).Get(ctx, &done); err != nil {
			return err
		}
		if done {
			return nil
		}
		if err := workflow.Sleep(ctx, 3*time.Second); err != nil {
			return err
		}
	}
	return errors.New("true-up did not finish: the deposit scan is not advancing")
}
