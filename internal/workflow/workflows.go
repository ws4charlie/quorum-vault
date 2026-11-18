package workflow

import (
	"errors"
	"fmt"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Signals of the withdrawal workflow.
const (
	SignalApproval = "approval" // an approval was added to the row; re-read it
	SignalReject   = "reject"   // a human rejected; payload is the reason
	// SignalCPFPNow is sent to the workflow that drives a Bitcoin send (a withdrawal's, or its batch's: the workflow ID is the owner's ID) when an operator
	// asks for the CPFP child now. The API has already built and enqueued the child's first job; the signal makes the stuck-send step sign and broadcast it.
	SignalCPFPNow = "cpfp-now"
)

// Timings the workflows use that are not business configuration.
type Timings struct {
	ApprovalTimeout  time.Duration
	ApprovalPoll     time.Duration // re-read approvals this often even without a signal
	SignTimeout      time.Duration // the gateway's sign_timeout: wait this long before retrying a failed job
	StuckAfter       time.Duration
	CPFPAfter        time.Duration // Bitcoin: how long a send that cannot be raised any more waits before a CPFP child pulls it in; 0: never
	HotWait          time.Duration
	HotPoll          time.Duration
	MaxReplacements  int
	ScanInterval     time.Duration
	PlanInterval     time.Duration
	ColdInterval     time.Duration // how often the cold planner looks at the hot wallets
	RefillPoll       time.Duration // how often a refill workflow looks for the imported signed file
	RefillStuckAfter time.Duration // a broadcast refill that has not confirmed after this raises an ALERT
	// ActivityTimeout, when set, replaces the fixed activity timeouts below (20 s to run, 30 s for a build, 20 s in the queue, 8 s
	// without a heartbeat): that is how long the engine waits before it notices an activity died with its worker. Zero keeps the
	// production values. It exists so tests that kill the worker do not wait 20 to 30 seconds per crash.
	ActivityTimeout time.Duration
}

// DefaultTimings derives timings from the business config.
func DefaultTimings(c *custody.Config) Timings {
	return Timings{ApprovalTimeout: c.ApprovalTimeout, ApprovalPoll: 15 * time.Second, SignTimeout: c.SignTimeout, StuckAfter: c.StuckAfter, CPFPAfter: c.CPFPAfter,
		HotWait: c.HotWait, HotPoll: 10 * time.Second, MaxReplacements: c.MaxReplacements, ScanInterval: c.ScanInterval, PlanInterval: c.PlanInterval, ColdInterval: c.ColdPlanInterval, RefillPoll: c.RefillPoll, RefillStuckAfter: c.RefillStuckAfter, ActivityTimeout: c.ActivityTimeout}
}

// Input of the workflows that need timings. The worker passes them at start;
// they are part of the recorded history, so replays see the same values.
type Input struct {
	ID string
	T  Timings
}

var a *Activities // only used to name activities

// call runs an activity and waits for it. A task that was dispatched to a worker
// that died (so no worker ever starts it) times out in the queue after
// ScheduleToStart; call schedules it again, so a crash costs seconds, not the
// server's poll timeout. Other errors (including the retry policy's) are returned.
func call(ctx, optx workflow.Context, res any, act any, args ...any) error {
	for {
		err := workflow.ExecuteActivity(optx, act, args...).Get(ctx, res)
		var te *temporal.TimeoutError
		if errors.As(err, &te) && te.TimeoutType() == enumspb.TIMEOUT_TYPE_SCHEDULE_TO_START {
			continue
		}
		return err
	}
}

const queueTimeout = 20 * time.Second

type timingsKey struct{}

// withTimings makes the workflow's Timings available to the option helpers below. Every workflow calls it first.
func withTimings(ctx workflow.Context, t Timings) workflow.Context {
	return workflow.WithValue(ctx, timingsKey{}, t)
}

// act returns the timeouts to use: the production ones, or the shorter ones Timings.ActivityTimeout asks for.
func act(ctx workflow.Context) (run, build, queue, beat time.Duration, short bool) {
	if t, ok := ctx.Value(timingsKey{}).(Timings); ok && t.ActivityTimeout > 0 {
		d := t.ActivityTimeout
		return d, d, d, max(d/2, 2*time.Second), true
	}
	return 20 * time.Second, 30 * time.Second, queueTimeout, 8 * time.Second, false
}

func opts(ctx workflow.Context) workflow.Context {
	run, _, queue, _, _ := act(ctx)
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout:    run,
		ScheduleToStartTimeout: queue,
		RetryPolicy:            &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second},
	})
}

// planOpts gives the planner room: one pass asks the node about each candidate.
//
// A planning pass can take a while, so StartToClose is long; but if the worker running it dies, the server would wait the whole
// StartToClose before trying again, and the planner would stand still for two minutes (the "no sweep within 90 s" failure in the
// crash tests). The pass heartbeats (see heartbeating), so a dead worker is noticed after HeartbeatTimeout.
func planOpts(ctx workflow.Context) workflow.Context {
	_, _, queue, _, short := act(ctx)
	beat := 15 * time.Second
	if short {
		beat = 5 * time.Second
	}
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout:    2 * time.Minute,
		HeartbeatTimeout:       beat,
		ScheduleToStartTimeout: queue,
		RetryPolicy:            &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second},
	})
}

// buildOpts bounds the retries of a build: an estimate that keeps failing (the
// chain refuses the call) is not going to start working, and nothing was
// allocated, because the build and the nonce share one transaction.
func buildOpts(ctx workflow.Context) workflow.Context {
	_, build, queue, _, _ := act(ctx)
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout:    build,
		ScheduleToStartTimeout: queue,
		RetryPolicy:            &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second, MaximumAttempts: 10},
	})
}

// longOpts is for polling activities that heartbeat.
func longOpts(ctx workflow.Context, wait time.Duration) workflow.Context {
	run, _, queue, beat, _ := act(ctx)
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout:    wait + run,
		ScheduleToStartTimeout: queue,
		HeartbeatTimeout:       beat,
		RetryPolicy:            &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 1.5, MaximumInterval: 10 * time.Second},
	})
}

// ScanWorkflow reads one chain forever: each pass credits new deposits and
// advances the cursor in one database transaction. It continues as new after a
// while so its history stays small.
func ScanWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	for i := 0; i < 300; i++ {
		var r ScanResult
		if err := call(ctx, opts(ctx), &r, a.ScanOnce); err != nil {
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
	ctx = withTimings(ctx, in.T)
	for i := 0; i < 300; i++ {
		var frozen bool
		if err := call(ctx, planOpts(ctx), &frozen, a.PlanSweeps); err != nil {
			return err
		}
		var n int
		if err := call(ctx, opts(ctx), &n, a.StartOpenSweeps); err != nil {
			return err
		}
		if err := workflow.Sleep(ctx, in.T.PlanInterval); err != nil {
			return err
		}
	}
	return workflow.NewContinueAsNewError(ctx, SweepPlannerWorkflow, in)
}

// ColdPlannerWorkflow decides which hot partitions hold more than their high-water mark and makes sure each open cold move
// has a workflow.
func ColdPlannerWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	for i := 0; i < 300; i++ {
		var n int
		// Rebalance first, then the move to cold: the cold planner then sees a rebalance that is on its way to a shard (see
		// custody/rebalance.go for the rules that keep the two from undoing each other).
		if err := call(ctx, planOpts(ctx), &n, a.PlanRebalances); err != nil {
			return err
		}
		if err := call(ctx, planOpts(ctx), &n, a.PlanColdMoves); err != nil {
			return err
		}
		if err := call(ctx, opts(ctx), &n, a.StartOpenRebalances); err != nil {
			return err
		}
		if err := call(ctx, opts(ctx), &n, a.StartOpenColdMoves); err != nil {
			return err
		}
		// A shard fed by many small outputs is merged (Bitcoin; a no-op elsewhere, and where consolidate_above is 0). A loop that started before this
		// existed keeps the calls it recorded: it replays without them, and the next run (after ContinueAsNew) has them.
		if workflow.GetVersion(ctx, "consolidation", workflow.DefaultVersion, 1) >= 1 {
			if err := call(ctx, planOpts(ctx), &n, a.PlanConsolidations); err != nil {
				return err
			}
			if err := call(ctx, opts(ctx), &n, a.StartOpenConsolidations); err != nil {
				return err
			}
		}
		if err := workflow.Sleep(ctx, in.T.ColdInterval); err != nil {
			return err
		}
	}
	return workflow.NewContinueAsNewError(ctx, ColdPlannerWorkflow, in)
}

// WithdrawalReconcilerWorkflow starts a workflow for every open withdrawal that
// has none, which repairs a crash between the API's commit and its start call.
func WithdrawalReconcilerWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	for i := 0; i < 300; i++ {
		var n int
		if err := call(ctx, opts(ctx), &n, a.StartOpenWithdrawals); err != nil {
			return err
		}
		// Bitcoin batching: seal the batches that are due and start the ones sealed. A loop that began before this existed replays without the calls.
		if workflow.GetVersion(ctx, "batching", workflow.DefaultVersion, 1) >= 1 {
			if err := call(ctx, planOpts(ctx), &n, a.PlanBatches); err != nil {
				return err
			}
			if err := call(ctx, opts(ctx), &n, a.StartOpenBatches); err != nil {
				return err
			}
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
	// txCancelRequested: an operator asked to cancel the whole batch while it was waiting to confirm (batches only).
	txCancelRequested txKind = "cancel_requested"
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
		if err := call(ctx, longOpts(ctx, slice), &r, a.WaitJob, jobID, slice); err != nil {
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
func driveTx(ctx workflow.Context, t Timings, o OwnerArg, track custody.Track, firstJob string, record, watchCancel bool) (txResult, error) {
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
		if err := call(ctx, opts(ctx), nil, a.RequeueJob, jobID, next); err != nil {
			return txResult{}, err
		}
		jobID = next
	}

	broadcast := func(job string) error {
		var hash string
		if err := call(ctx, opts(ctx), &hash, a.BroadcastJob, o, job); err != nil {
			return err
		}
		if hash == "" {
			return nil // the nonce was already decided; the wait loop below reports how
		}
		if record {
			return call(ctx, opts(ctx), nil, a.RecordBroadcast, o, hash)
		}
		return nil
	}
	if err := broadcast(jobID); err != nil {
		return txResult{}, err
	}

	stuckAt := workflow.Now(ctx).Add(t.StuckAfter)
	replacements := 0
	alerted := false
	alert := func(why string) {
		if !alerted {
			alerted = true
			workflow.GetLogger(ctx).Error("ALERT: transaction is stuck and cannot be replaced; still waiting, never voiding while it may mine",
				"owner", o.Kind+" "+o.ID, "why", why)
		}
	}
	slice := 10 * time.Second
	if _, _, _, _, short := act(ctx); short {
		slice = 2 * time.Second // tests: look at the transaction (and at "stuck") more often
	}
	refused0 := -1 // replacements the node had refused as too cheap when this run began to look
	// CPFP (Bitcoin, off unless cpfp_after is set): when the owner's own send cannot be raised any more it is pulled in by a child that spends its
	// change. Only the owner's own track has a child (a cancel does not). exhaustedAt is when RBF first had nothing more to give.
	cpfpCan := track == custody.OwnerTrack(custody.Owner{Kind: o.Kind, ID: o.ID}) && workflow.GetVersion(ctx, "btc-cpfp", workflow.DefaultVersion, 1) >= 1
	cpfpOn := t.CPFPAfter > 0 && cpfpCan
	// Manual CPFP (an operator's call, which works with cpfp_after off): the child is also raised when it exists, whatever cpfp_after says.
	manual := cpfpCan && workflow.GetVersion(ctx, "btc-cpfp-manual", workflow.DefaultVersion, 1) >= 1
	var cpfpNow workflow.ReceiveChannel
	if manual {
		cpfpNow = workflow.GetSignalChannel(ctx, SignalCPFPNow)
	}
	wantChild := false
	var exhaustedAt time.Time
	cpfpN := 0
	cpfpStep := func() error {
		cpfpN++
		var cj string
		if err := call(ctx, buildOpts(ctx), &cj, a.EnqueueCPFP, o, cpfpN); err != nil {
			cpfpN--
			alert("a CPFP child could not be built: " + err.Error())
			stuckAt = workflow.Now(ctx).Add(t.StuckAfter)
			return nil
		}
		if cj == "" { // the chain has no CPFP
			cpfpN--
			stuckAt = workflow.Now(ctx).Add(t.StuckAfter)
			return nil
		}
		rr, err := waitJob(ctx, cj)
		if err != nil {
			return err
		}
		if rr.Status == custody.JobDone {
			if err := call(ctx, opts(ctx), nil, a.BroadcastCPFP, o, cj); err != nil {
				return err
			}
		} // refused or failed: the send may still mine; try again at the next deadline
		stuckAt = workflow.Now(ctx).Add(t.StuckAfter)
		return nil
	}
	for {
		var n NonceResult
		if err := call(ctx, longOpts(ctx, slice), &n, a.WaitNonce, o, slice); err != nil {
			return txResult{}, err
		}
		if refused0 < 0 {
			refused0 = n.FeeRefusals
		}
		switch n.State {
		case custody.AttemptMined:
			return txResult{Kind: txMined, Hash: n.Hash}, nil
		case custody.AttemptReverted:
			return txResult{Kind: txReverted, Hash: n.Hash}, nil
		case custody.AttemptCancelled:
			return txResult{Kind: txCancelled, Hash: n.Hash}, nil
		case custody.AttemptConsumed:
			// The chain's nonce is past ours and none of our attempts mined: a
			// transaction we did not make used it, so the hot key signed something
			// outside this system. Our transaction can never mine. Keep the hold,
			// alert, park the row so the reconciler leaves it alone, and stop.
			var where string
			_ = call(ctx, opts(ctx), &where, a.ConsumedInfo, o)
			workflow.GetLogger(ctx).Error("ALERT: the hot wallet nonce was used by a transaction this system did not make; possible key compromise",
				"owner", o.Kind+" "+o.ID, "where", where)
			if err := call(ctx, opts(ctx), nil, a.Park, o, "nonce consumed by an unknown transaction ("+where+")"); err != nil {
				return txResult{}, err
			}
			return txResult{}, temporal.NewNonRetryableApplicationError("nonce consumed by an unknown transaction", "nonce_consumed", nil)
		}
		if watchCancel {
			var req bool
			if err := call(ctx, opts(ctx), &req, a.BatchCancelRequested, o.ID); err != nil {
				return txResult{}, err
			}
			if req {
				return txResult{Kind: txCancelRequested}, nil
			}
		}
		if n.Refusal != "" {
			// Not about the fee, so a higher fee does not cure it: the replacement is built again as it was, up to the limit, and an operator looks.
			alert("the node refused a replacement for a reason a higher fee does not cure: " + n.Refusal)
		}
		// A replacement the node refused as too cheap was never in the mempool: it does not use up a replacement. The next one pays more, up to the caps.
		used := replacements - (n.FeeRefusals - refused0)
		stuck := !workflow.Now(ctx).Before(stuckAt)
		if manual {
			var sig string
			for cpfpNow.ReceiveAsync(&sig) {
				wantChild = true
			}
			if wantChild && cpfpN == 0 && !n.Child {
				// An operator asked for the child now. The API built its first job; sign and broadcast it. A repeat while a child exists does nothing.
				wantChild = false
				if err := cpfpStep(); err != nil {
					return txResult{}, err
				}
				continue
			}
			wantChild = false
		}
		if (cpfpOn || manual) && stuck && n.Child {
			// A child already pulls the send in: raise the child's fee. The send is never replaced under it.
			if err := cpfpStep(); err != nil {
				return txResult{}, err
			}
			continue
		}
		if stuck && used >= t.MaxReplacements {
			alert("replacements exhausted")
			if cpfpOn {
				if exhaustedAt.IsZero() {
					exhaustedAt = workflow.Now(ctx)
				}
				if !workflow.Now(ctx).Before(exhaustedAt.Add(t.CPFPAfter)) {
					if err := cpfpStep(); err != nil {
						return txResult{}, err
					}
					continue
				}
			}
		}
		if stuck && used < t.MaxReplacements {
			replacements++
			var rj string
			if err := call(ctx, buildOpts(ctx), &rj, a.EnqueueReplacement, o, string(track), replacements); err != nil {
				// Typically the fee cap: the bumped fee is above what the gateway allows.
				replacements--
				alert("replacement could not be built: " + err.Error())
				if cpfpOn {
					// RBF has nothing more to give. After CPFPAfter a child takes over.
					if exhaustedAt.IsZero() {
						exhaustedAt = workflow.Now(ctx)
					}
					if !workflow.Now(ctx).Before(exhaustedAt.Add(t.CPFPAfter)) {
						if err := cpfpStep(); err != nil {
							return txResult{}, err
						}
						continue
					}
				}
				stuckAt = workflow.Now(ctx).Add(t.StuckAfter)
				continue
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

// cancelNonce frees what the owner reserved (EVM: its nonce) with a cancel transaction and returns
// what finally mined: the cancel (txCancelled), or the owner's own
// transaction after all (txMined / txReverted). Only then may money be released.
// On a chain without cancel there is nothing to free: it returns txCancelled at once, with no hash.
func cancelNonce(ctx workflow.Context, t Timings, o OwnerArg) (txResult, error) {
	var cj string
	if err := call(ctx, opts(ctx), &cj, a.EnqueueCancel, o); err != nil {
		if isType(err, errCannotBump) {
			// The cancel cannot be built (the inputs cannot pay its fee): a signature may exist and nothing can free it. Never release; park.
			workflow.GetLogger(ctx).Error("ALERT: a cancel is needed but cannot be built; manual intervention needed", "owner", o.ID, "error", err.Error())
			if perr := call(ctx, opts(ctx), nil, a.Park, o, "a cancel is needed and cannot be built: "+err.Error()); perr != nil {
				return txResult{}, perr
			}
			return txResult{}, temporal.NewNonRetryableApplicationError("cancel cannot be built: "+err.Error(), "cancel_refused", nil)
		}
		return txResult{}, err
	}
	if cj == "" {
		// The chain has no cancel. A refusal should leave nothing behind, but that is checked, not assumed: only when the
		// chain says no attempt was ever broadcast and no reservation is open may the money be released. (This activity
		// is called only here, which EVM never reaches, so EVM histories do not change.)
		var fr FreeResult
		if err := call(ctx, opts(ctx), &fr, a.NothingToFree, o); err != nil {
			return txResult{}, err
		}
		if !fr.Free {
			workflow.GetLogger(ctx).Error("ALERT: the gateway refused a transaction on a chain without cancel, but something may still confirm; manual intervention needed",
				"owner", o.ID, "why", fr.Why)
			if err := call(ctx, opts(ctx), nil, a.Park, o, "refused, the chain has no cancel and is not clean: "+fr.Why); err != nil {
				return txResult{}, err
			}
			return txResult{}, temporal.NewNonRetryableApplicationError("refused without cancel but not clean: "+fr.Why, "cancel_refused", nil)
		}
		return txResult{Kind: txCancelled}, nil
	}
	ow := custody.Owner{Kind: o.Kind, ID: o.ID, PartitionID: o.Part}
	r, err := driveTx(ctx, t, o, custody.CancelTrack(ow), cj, false, false)
	if err != nil {
		return r, err
	}
	if r.Kind == txRefused {
		// A refused cancel leaves a live nonce; never release the money. Park for an operator.
		workflow.GetLogger(ctx).Error("ALERT: the gateway refused to cancel a nonce; manual intervention needed", "owner", o.ID, "reason", r.Reason)
		if err := call(ctx, opts(ctx), nil, a.Park, o, "the gateway refused to cancel the nonce: "+r.Reason); err != nil {
			return r, err
		}
		return r, temporal.NewNonRetryableApplicationError("cancel refused: "+r.Reason, "cancel_refused", nil)
	}
	return r, nil
}

// ---- withdrawal ----

// WithdrawalWorkflow is one withdrawal, from request to settlement or void.
// Its workflow ID is the withdrawal ID. The API already committed the row,
// the hold and the outbox event.
func WithdrawalWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	id, t := in.ID, in.T
	var st WdState
	if err := call(ctx, opts(ctx), &st, a.LoadWithdrawal, id); err != nil {
		return err
	}
	if st.Status == custody.WdConfirmed || st.Status == custody.WdFailed || st.Parked {
		return nil
	}
	o := OwnerArg{Kind: "withdrawal", ID: id, Part: st.Part}
	void := func(reason, feeTx string) error {
		return call(ctx, opts(ctx), nil, a.VoidWithdrawal, id, reason, feeTx)
	}
	// A withdrawal in the batch queue (Bitcoin batching) is carried by its shard's batches: the workflow only watches it until it is booked or ends.
	if st.Queued {
		return waitBatched(ctx, t, in)
	}

	// 2. Approvals. Skipped when the job already exists (a restarted workflow).
	if st.Status == custody.WdRequested {
		if st.Auto {
			if err := call(ctx, opts(ctx), nil, a.AutoApprove, id); err != nil {
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
		if err := call(ctx, opts(ctx), nil, a.MarkApproved, id); err != nil {
			return err
		}
	}

	// 3. Hot liquidity. The shard is part of the signed intent, so it was chosen
	// at request time; wait here until it can pay.
	if st.Status == custody.WdRequested || st.Status == custody.WdApproved {
		deadline := workflow.Now(ctx).Add(t.HotWait)
		for {
			var ok bool
			if err := call(ctx, opts(ctx), &ok, a.ReserveHot, id); err != nil {
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

		// Bitcoin batching: the withdrawal joins its shard's queue and a batch carries it. A workflow that began before this existed replays without the call.
		if workflow.GetVersion(ctx, "batching", workflow.DefaultVersion, 1) >= 1 {
			var queued bool
			if err := call(ctx, opts(ctx), &queued, a.EnqueueForBatch, id); err != nil {
				return err
			}
			if queued {
				return waitBatched(ctx, t, in)
			}
		}

		// 4. Build and enqueue, in one transaction.
		for {
			var job string
			err := call(ctx, buildOpts(ctx), &job, a.BuildWithdrawalJob, id)
			if err == nil {
				break
			}
			if isType(err, errExpired) {
				return void("approval window passed before signing", "")
			}
			// A chain whose funds are separate outputs (Bitcoin) may have too few available now: they free up or arrive, so wait, as for hot liquidity.
			if isType(err, errNoOutputs) {
				if !workflow.Now(ctx).Before(deadline) {
					return void("not enough available outputs in time: "+err.Error(), "")
				}
				if err := workflow.Sleep(ctx, t.HotPoll); err != nil {
					return err
				}
				continue
			}
			// Nothing was allocated (the build rolled back), so the hold can go.
			workflow.GetLogger(ctx).Error("ALERT: could not build the withdrawal transaction; voiding", "withdrawal", id, "error", err.Error())
			return void("could not build the transaction: "+err.Error(), "")
		}
	}

	// 5-8. Sign, broadcast, confirm (replacing if stuck).
	ow := custody.Owner{Kind: "withdrawal", ID: id, PartitionID: st.Part}
	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true, false)
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
		return call(ctx, opts(ctx), nil, a.SettleWithdrawal, id, r.Hash)
	case txReverted:
		return void("transaction reverted", r.Hash)
	case txCancelled:
		return void("cancelled", r.Hash)
	}
	return fmt.Errorf("unexpected outcome %q", r.Kind)
}

// waitBatched watches a withdrawal that a batch carries until it is booked, voided or parked. Everything that happens to it (sealing, signing,
// broadcast, bumps, booking, a cancel) is done by the batch's own workflow and by the cancel API; this loop only voids it when its approval is about to
// lapse while it still waits in the queue (QueueTick), and starts again (continue as new) now and then so that a long wait leaves a short history.
func waitBatched(ctx workflow.Context, t Timings, in Input) error {
	for i := 0; i < 200; i++ {
		var qs custody.QueueState
		if err := call(ctx, opts(ctx), &qs, a.QueueTick, in.ID); err != nil {
			return err
		}
		if qs.Status == custody.WdConfirmed || qs.Status == custody.WdFailed || qs.Parked {
			return nil
		}
		if err := workflow.Sleep(ctx, t.HotPoll); err != nil {
			return err
		}
	}
	return workflow.NewContinueAsNewError(ctx, WithdrawalWorkflow, in)
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
		if err := call(ctx, opts(ctx), &have, a.ApprovalsHave, id); err != nil {
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
	ctx = withTimings(ctx, in.T)
	id, t := in.ID, in.T
	var st SweepState
	if err := call(ctx, opts(ctx), &st, a.LoadSweep, id); err != nil {
		return err
	}
	if st.Status == "confirmed" || st.Status == "failed" || st.Parked {
		return nil
	}
	o := OwnerArg{Kind: "sweep", ID: id, Part: st.Part}
	ow := custody.Owner{Kind: "sweep", ID: id, PartitionID: st.Part}

	var job string
	if err := call(ctx, buildOpts(ctx), &job, a.BuildSweepJob, id); err != nil {
		if isType(err, errFrozen) {
			return nil // marked failed; the planner plans it again after unfreezing
		}
		workflow.GetLogger(ctx).Warn("could not build the sweep; it will be planned again", "sweep", id, "error", err.Error())
		return call(ctx, opts(ctx), nil, a.FailSweep, id, "could not build: "+err.Error(), "")
	}
	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true, false)
	if err != nil {
		return err
	}
	if r.Kind == txRefused {
		cr, err := cancelNonce(ctx, t, o)
		if err != nil {
			return err
		}
		if cr.Kind == txCancelled && !(st.SettlesCancel && cr.Hash != "") {
			return call(ctx, opts(ctx), nil, a.FailSweep, id, "gateway refused: "+r.Reason, cr.Hash)
		}
		r = cr
	}
	switch r.Kind {
	case txMined, txReverted:
		if err := call(ctx, opts(ctx), nil, a.SettleSweep, id, r.Hash, r.Kind == txReverted); err != nil {
			return err
		}
	case txCancelled:
		if !(st.SettlesCancel && r.Hash != "") {
			return call(ctx, opts(ctx), nil, a.FailSweep, id, "cancelled", r.Hash)
		}
		// Bitcoin: the cancel spent the same inputs to the same shard, so the coins reached the hot shard anyway. It settles as the sweep would
		// have, with the cancel's own fee.
		if err := call(ctx, opts(ctx), nil, a.SettleSweep, id, r.Hash, false); err != nil {
			return err
		}
	}
	// Excess that no deposit explains goes to suspense once the scan is past it.
	for i := 0; i < 600; i++ {
		var done bool
		if err := call(ctx, opts(ctx), &done, a.TrueUp, id); err != nil {
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

// ---- hot to cold ----

// ColdMoveWorkflow is one hot-to-cold move. Its workflow ID is the move ID: build and enqueue, wait for the gateway (which
// pins the destination and caps the amount itself), broadcast, wait, settle. A move that fails ends cleanly and the planner
// plans another if the partition is still above its mark.
func ColdMoveWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	id, t := in.ID, in.T
	var st ColdState
	if err := call(ctx, opts(ctx), &st, a.LoadColdMove, id); err != nil {
		return err
	}
	if st.Status == "confirmed" || st.Status == "failed" || st.Parked {
		return nil
	}
	o := OwnerArg{Kind: custody.OwnerKindToCold, ID: id, Part: st.Part}
	ow := custody.Owner{Kind: custody.OwnerKindToCold, ID: id, PartitionID: st.Part}

	var job string
	if err := call(ctx, buildOpts(ctx), &job, a.BuildColdMoveJob, id); err != nil {
		workflow.GetLogger(ctx).Warn("could not build the cold move; it will be planned again", "cold_move", id, "error", err.Error())
		return call(ctx, opts(ctx), nil, a.FailColdMove, id, "could not build: "+err.Error(), "")
	}
	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true, false)
	if err != nil {
		return err
	}
	if r.Kind == txRefused {
		cr, err := cancelNonce(ctx, t, o)
		if err != nil {
			return err
		}
		if cr.Kind == txCancelled && !(st.SettlesCancel && cr.Hash != "") {
			return call(ctx, opts(ctx), nil, a.FailColdMove, id, "gateway refused: "+r.Reason, cr.Hash)
		}
		r = cr
	}
	switch r.Kind {
	case txMined, txReverted:
		return call(ctx, opts(ctx), nil, a.SettleColdMove, id, r.Hash, r.Kind == txReverted)
	case txCancelled:
		if st.SettlesCancel && r.Hash != "" {
			return call(ctx, opts(ctx), nil, a.SettleColdMove, id, r.Hash, true) // settled as a failed move, with the cancel's fee
		}
		return call(ctx, opts(ctx), nil, a.FailColdMove, id, "cancelled", r.Hash)
	}
	return fmt.Errorf("unexpected outcome %q", r.Kind)
}

// ConsolidationWorkflow is one consolidation of a hot shard's small outputs. Its workflow ID is the consolidation ID: build and enqueue, wait for the
// gateway (which checks that the transaction spends only the shard's own outputs back to the shard, and caps how many it signs per hour), broadcast,
// wait, settle. One that fails ends cleanly and the planner plans another after a wait if the shard still holds too many outputs. A cancel that
// mines (the same inputs back to the shard) settles it like the consolidation itself.
func ConsolidationWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	id, t := in.ID, in.T
	var st ColdState
	if err := call(ctx, opts(ctx), &st, a.LoadConsolidation, id); err != nil {
		return err
	}
	if st.Status == "confirmed" || st.Status == "failed" || st.Parked {
		return nil
	}
	o := OwnerArg{Kind: custody.OwnerKindConsolidate, ID: id, Part: st.Part}
	ow := custody.Owner{Kind: custody.OwnerKindConsolidate, ID: id, PartitionID: st.Part}

	var job string
	if err := call(ctx, buildOpts(ctx), &job, a.BuildConsolidationJob, id); err != nil {
		workflow.GetLogger(ctx).Warn("could not build the consolidation; it will be planned again", "consolidation", id, "error", err.Error())
		return call(ctx, opts(ctx), nil, a.FailConsolidation, id, "could not build: "+err.Error())
	}
	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true, false)
	if err != nil {
		return err
	}
	if r.Kind == txRefused {
		cr, err := cancelNonce(ctx, t, o)
		if err != nil {
			return err
		}
		if cr.Kind == txCancelled && !(st.SettlesCancel && cr.Hash != "") {
			return call(ctx, opts(ctx), nil, a.FailConsolidation, id, "gateway refused: "+r.Reason)
		}
		r = cr
	}
	switch r.Kind {
	case txMined, txReverted:
		return call(ctx, opts(ctx), nil, a.SettleConsolidation, id, r.Hash)
	case txCancelled:
		if st.SettlesCancel && r.Hash != "" {
			return call(ctx, opts(ctx), nil, a.SettleConsolidation, id, r.Hash) // settled like the consolidation, with the cancel's fee
		}
		return call(ctx, opts(ctx), nil, a.FailConsolidation, id, "cancelled")
	}
	return fmt.Errorf("unexpected outcome %q", r.Kind)
}

// RebalanceWorkflow is one move between hot shards. Its workflow ID is the rebalance ID: build and enqueue, wait for the gateway
// (which pins the destination to its own list of hot shards and caps the amount itself), broadcast, wait, settle. One that fails
// ends cleanly and the planner plans another if the shard is still below its target.
func RebalanceWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	id, t := in.ID, in.T
	var st ColdState
	if err := call(ctx, opts(ctx), &st, a.LoadRebalance, id); err != nil {
		return err
	}
	if st.Status == "confirmed" || st.Status == "failed" || st.Parked {
		return nil
	}
	o := OwnerArg{Kind: custody.OwnerKindRebalance, ID: id, Part: st.Part}
	ow := custody.Owner{Kind: custody.OwnerKindRebalance, ID: id, PartitionID: st.Part}

	var job string
	if err := call(ctx, buildOpts(ctx), &job, a.BuildRebalanceJob, id); err != nil {
		workflow.GetLogger(ctx).Warn("could not build the rebalance; it will be planned again", "rebalance", id, "error", err.Error())
		return call(ctx, opts(ctx), nil, a.FailRebalance, id, "could not build: "+err.Error(), "")
	}
	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true, false)
	if err != nil {
		return err
	}
	if r.Kind == txRefused {
		cr, err := cancelNonce(ctx, t, o)
		if err != nil {
			return err
		}
		if cr.Kind == txCancelled {
			return call(ctx, opts(ctx), nil, a.FailRebalance, id, "gateway refused: "+r.Reason, cr.Hash)
		}
		r = cr
	}
	switch r.Kind {
	case txMined, txReverted:
		return call(ctx, opts(ctx), nil, a.SettleRebalance, id, r.Hash, r.Kind == txReverted)
	case txCancelled:
		return call(ctx, opts(ctx), nil, a.FailRebalance, id, "cancelled", r.Hash)
	}
	return fmt.Errorf("unexpected outcome %q", r.Kind)
}

// ---- refill ----

// RefillWorkflow is one refill from cold to hot. Its workflow ID is the refill ID. It waits for people: the request sits until an
// operator has run the offline ceremony and imported the signed file, which can take days, so it polls cheaply and continues as new
// now and then to keep its history short. Then it broadcasts, follows the transaction to confirmation and books it. A transaction
// that does not confirm raises one ALERT and keeps waiting: a new nonce is a new ceremony, never automatic.
func RefillWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	id, t := in.ID, in.T
	for i := 0; i < 300; i++ {
		var st RefillView
		if err := call(ctx, opts(ctx), &st, a.LoadRefill, id); err != nil {
			return err
		}
		if st.Status == "confirmed" || st.Status == "failed" || st.Parked {
			return nil
		}
		switch st.Status {
		case "requested":
			if st.Expired {
				return call(ctx, opts(ctx), nil, a.ExpireRefill, id)
			}
			if err := workflow.Sleep(ctx, t.RefillPoll); err != nil {
				return err
			}
		case "signed":
			var h string
			if err := call(ctx, opts(ctx), &h, a.BroadcastRefill, id); err != nil {
				return err
			}
		case "broadcast":
			if st.Replacement {
				if err := call(ctx, opts(ctx), nil, a.BroadcastRefillReplacement, id); err != nil {
					return err
				}
			}
			var state string
			if err := call(ctx, longOpts(ctx, 10*time.Second), &state, a.WaitRefillTx, id, 10*time.Second); err != nil {
				return err
			}
			switch state {
			case "confirmed", "reverted":
				return call(ctx, opts(ctx), nil, a.SettleRefill, id, state == "reverted")
			case "consumed":
				return call(ctx, opts(ctx), nil, a.ParkRefillConsumed, id)
			}
			if !st.Stuck && time.Duration(st.AgeSeconds)*time.Second > t.RefillStuckAfter {
				if err := call(ctx, opts(ctx), nil, a.AlertRefillStuck, id); err != nil {
					return err
				}
			}
		}
	}
	return workflow.NewContinueAsNewError(ctx, RefillWorkflow, in)
}

// ---- batch (Bitcoin) ----

// BatchWorkflow is one batch of withdrawals. Its workflow ID is the batch ID. The planner sealed it from the head of a shard's queue; here it is built
// for the longest prefix the shard's coins can fund (waiting, like a single withdrawal, while they cannot), signed by the zone (which checks every
// payment against its own approval), broadcast, bumped as a whole, and booked once, member by member, when it confirms. A refusal of the zone, or an
// operator's cancel, ends it in a discard (nothing was signed: coins released) or in a cancel of the whole batch (the same coins back to the shard); the
// members return to the queue in both.
func BatchWorkflow(ctx workflow.Context, in Input) error {
	ctx = withTimings(ctx, in.T)
	id, t := in.ID, in.T
	var st BatchState
	if err := call(ctx, opts(ctx), &st, a.LoadBatch, id); err != nil {
		return err
	}
	final := func(s BatchState) bool {
		return s.Status == custody.BatchConfirmed || s.Status == custody.BatchCancelled || s.Status == custody.BatchDiscarded || s.Parked
	}
	if final(st) {
		return nil
	}
	o := OwnerArg{Kind: custody.OwnerKindBatch, ID: id, Part: st.Part}
	ow := custody.Owner{Kind: custody.OwnerKindBatch, ID: id, PartitionID: st.Part}
	discard := func(reason string, refused bool) (bool, error) {
		var ok bool
		err := call(ctx, opts(ctx), &ok, a.DiscardBatch, id, reason, refused)
		return ok, err
	}

	if st.Status == custody.BatchSealed {
		deadline := workflow.Now(ctx).Add(t.HotWait)
		for {
			var left int
			if err := call(ctx, opts(ctx), &left, a.PrepareBatch, id); err != nil {
				return err
			}
			if left == 0 {
				return nil // nobody left to pay: the batch was discarded
			}
			if left < 0 {
				break // not sealed any more (a crash after the build): go on from what it is
			}
			var job string
			err := call(ctx, buildOpts(ctx), &job, a.BuildBatchJob, id)
			if err == nil {
				break
			}
			if isType(err, errMemberRemoved) {
				continue // a withdrawal that cannot be paid was parked and taken out: look at the batch again without it
			}
			if isType(err, errNoOutputs) {
				if !workflow.Now(ctx).Before(deadline) {
					_, derr := discard("not enough available outputs in time: "+err.Error(), false)
					return derr
				}
				if err := workflow.Sleep(ctx, t.HotPoll); err != nil {
					return err
				}
				continue
			}
			// Nothing was allocated (the build rolled back): the members go back to the queue.
			workflow.GetLogger(ctx).Error("ALERT: could not build the batch transaction; its withdrawals return to the queue", "batch", id, "error", err.Error())
			_, derr := discard("could not build the transaction: "+err.Error(), false)
			return derr
		}
		// A member's cancel may have discarded the batch while it waited for coins.
		if err := call(ctx, opts(ctx), &st, a.LoadBatch, id); err != nil {
			return err
		}
		if final(st) {
			return nil
		}
	}

	r, err := driveTx(ctx, t, o, custody.OwnerTrack(ow), custody.OwnerTrack(ow).FirstJob(), true, true)
	if err != nil {
		return err
	}
	if r.Kind == txRefused {
		// Nothing signed (or only some inputs): with no signature, discard in one step; otherwise the coins must be freed by a cancel first.
		ok, err := discard("gateway refused: "+r.Reason, true)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if r, err = cancelNonce(ctx, t, o); err != nil {
			return err
		}
	} else if r.Kind == txCancelRequested {
		if r, err = cancelNonce(ctx, t, o); err != nil {
			return err
		}
	}
	switch r.Kind {
	case txMined, txReverted:
		return call(ctx, opts(ctx), nil, a.SettleBatch, id, r.Hash)
	case txCancelled:
		if r.Hash != "" {
			return call(ctx, opts(ctx), nil, a.SettleBatchCancel, id, r.Hash)
		}
		_, err := discard("cancelled", false)
		return err
	}
	return fmt.Errorf("unexpected outcome %q", r.Kind)
}
