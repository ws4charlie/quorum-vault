// Package workflow holds the Temporal workflows of the closed loop and the
// activities they call. Workflow code is deterministic: it reads no clock but
// workflow.Now, draws no random numbers, and touches no database, node or
// network. Everything that does is an activity, and every activity is
// idempotent: it can run twice (after a worker crash or a timeout) and the
// money still moves once.
package workflow

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// DefaultTaskQueue is the task queue of the business zone's worker unless a
// deployment (or a test that shares one Temporal server) names another.
const DefaultTaskQueue = "qv-core"

// Error types the workflows branch on.
const (
	errExpired    = "expired"
	errFrozen     = "sweep_frozen"
	errNonceOpen  = "nonce_open"
	errBadRequest = "bad_request"
)

// Deps are what activities need.
type Deps struct {
	Svc     *custody.Service
	Client  client.Client
	AutoKey ed25519.PrivateKey // the worker's automated approver, lowest tier only
	Log     *slog.Logger
	T       Timings // handed to the workflows this package starts
	Queue   string  // task queue; default DefaultTaskQueue
}

// Activities is the activity set. Register one instance with the worker.
type Activities struct{ D Deps }

func (a *Activities) log() *slog.Logger {
	if a.D.Log != nil {
		return a.D.Log
	}
	return slog.Default()
}

// nonRetry marks errors that retrying cannot fix.
func nonRetry(err error) error {
	if err == nil {
		return nil
	}
	typ := ""
	switch {
	case errors.Is(err, custody.ErrExpired):
		typ = errExpired
	case errors.Is(err, custody.ErrSweepFrozen):
		typ = errFrozen
	case errors.Is(err, custody.ErrNonceOpen):
		typ = errNonceOpen
	case errors.Is(err, custody.ErrInvalid), errors.Is(err, ledger.ErrInsufficientFunds), errors.Is(err, ledger.ErrIdempotencyConflict):
		typ = errBadRequest
	default:
		return err
	}
	return temporal.NewNonRetryableApplicationError(err.Error(), typ, err)
}

// isType reports whether err carries the application error type typ.
func isType(err error, typ string) bool {
	var ae *temporal.ApplicationError
	return errors.As(err, &ae) && ae.Type() == typ
}

// ---- deposits ----

// ScanResult is the outcome of one scan pass.
type ScanResult struct {
	Credited int
	Cursor   uint64
}

// ScanOnce reads the chain from the stored cursor and credits what it finds.
func (a *Activities) ScanOnce(ctx context.Context) (ScanResult, error) {
	n, err := a.D.Svc.ScanOnce(ctx)
	if errors.Is(err, custody.ErrCursorMoved) {
		return ScanResult{}, err // retried: re-reads the cursor
	}
	if err != nil {
		return ScanResult{}, err
	}
	cur, err := a.D.Svc.Cursor(ctx)
	return ScanResult{Credited: n, Cursor: cur}, err
}

// heartbeating reports the activity alive every few seconds until the returned function is called, so the server notices a dead
// worker after the activity's HeartbeatTimeout instead of after its whole StartToCloseTimeout.
func heartbeating(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				activity.RecordHeartbeat(ctx)
			}
		}
	}()
	return func() { close(done) }
}

// ---- starting workflows (reconcilers) ----

func (a *Activities) start(ctx context.Context, id string, wf any, arg any) error {
	_, err := a.D.Client.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: id, TaskQueue: a.D.queue(),
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
		WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
	}, wf, arg)
	return err
}

// PlanSweeps creates sweep rows for addresses worth sweeping. Returns whether
// sweeping is frozen (nothing is planned then, and that is not an error).
func (a *Activities) PlanSweeps(ctx context.Context) (frozen bool, err error) {
	stop := heartbeating(ctx)
	defer stop()
	_, err = a.D.Svc.PlanSweeps(ctx, a.log())
	if errors.Is(err, custody.ErrSweepFrozen) {
		a.log().Info("sweeping is frozen; planning again later")
		return true, nil
	}
	return false, err
}

// StartOpenSweeps starts a Sweep workflow for every unfinished sweep row that has none running.
func (a *Activities) StartOpenSweeps(ctx context.Context) (int, error) {
	open, err := a.D.Svc.OpenSweeps(ctx)
	if err != nil {
		return 0, err
	}
	for _, sw := range open {
		if err := a.start(ctx, sw.ID, SweepWorkflow, Input{ID: sw.ID, T: a.D.T}); err != nil {
			return 0, fmt.Errorf("start sweep %s: %w", sw.ID, err)
		}
	}
	return len(open), nil
}

// StartOpenWithdrawals is the reconciler: it starts a Withdrawal workflow for
// every unfinished withdrawal row that has none running, so a crash between the
// API's commit and its workflow start loses nothing.
func (a *Activities) StartOpenWithdrawals(ctx context.Context) (int, error) {
	open, err := a.D.Svc.OpenWithdrawals(ctx)
	if err != nil {
		return 0, err
	}
	for _, w := range open {
		if err := a.start(ctx, w.ID, WithdrawalWorkflow, Input{ID: w.ID, T: a.D.T}); err != nil {
			return 0, fmt.Errorf("start withdrawal %s: %w", w.ID, err)
		}
	}
	return len(open), nil
}

// ---- withdrawal steps ----

// WdState is a withdrawal as the workflow needs it.
type WdState struct {
	Status   string
	Asset    string
	Amount   string
	Required int
	Auto     bool
	Have     int
	Expired  bool
	NotAfter int64
	Part     string
	Parked   bool
}

// LoadWithdrawal reads the withdrawal.
func (a *Activities) LoadWithdrawal(ctx context.Context, id string) (WdState, error) {
	w, err := a.D.Svc.GetWithdrawal(ctx, id)
	if err != nil {
		return WdState{}, err
	}
	st, err := a.D.Svc.Approvals(ctx, id)
	if err != nil {
		return WdState{}, err
	}
	return WdState{Status: w.Status, Asset: w.Asset, Amount: w.Amount.String(), Required: st.Required, Auto: st.Auto, Have: st.Have,
		Expired: st.Expired, NotAfter: w.NotAfter, Part: w.PartitionID, Parked: w.Parked()}, nil
}

// AutoApprove adds the worker's automated approval if the amount is in the lowest tier.
func (a *Activities) AutoApprove(ctx context.Context, id string) error {
	return nonRetry(a.D.Svc.AutoApprove(ctx, a.D.AutoKey, id))
}

// ApprovalsHave returns the current approval count.
func (a *Activities) ApprovalsHave(ctx context.Context, id string) (int, error) {
	st, err := a.D.Svc.Approvals(ctx, id)
	return st.Have, err
}

// MarkApproved moves the withdrawal to approved.
func (a *Activities) MarkApproved(ctx context.Context, id string) error {
	return a.D.Svc.MarkApproved(ctx, id)
}

// ReserveHot sets hot liquidity aside; false means no liquidity yet.
func (a *Activities) ReserveHot(ctx context.Context, id string) (bool, error) {
	ok, err := a.D.Svc.ReserveHot(ctx, id)
	if err == nil && !ok {
		a.log().Warn("ALERT: hot wallet cannot cover a withdrawal yet; waiting", "withdrawal", id)
	}
	return ok, err
}

// BuildWithdrawalJob builds the transaction and enqueues the sign job in one transaction.
func (a *Activities) BuildWithdrawalJob(ctx context.Context, id string) (string, error) {
	job, err := a.D.Svc.BuildWithdrawalJob(ctx, id)
	if err != nil {
		return "", nonRetry(err)
	}
	Hit("withdrawal", "after_build")
	return job, nil
}

// VoidWithdrawal releases the hold. It refuses while the nonce is live.
func (a *Activities) VoidWithdrawal(ctx context.Context, id, reason, feeTx string) error {
	return nonRetry(a.D.Svc.VoidWithdrawal(ctx, id, reason, feeTx))
}

// SettleWithdrawal books a confirmed withdrawal.
func (a *Activities) SettleWithdrawal(ctx context.Context, id, txHash string) error {
	if err := a.D.Svc.SettleWithdrawal(ctx, id, txHash); err != nil {
		return nonRetry(err)
	}
	Hit("withdrawal", "after_settle")
	return nil
}

// ---- sweep steps ----

// SweepState is a sweep as the workflow needs it.
type SweepState struct {
	Status string
	Part   string
	Parked bool
}

// LoadSweep reads the sweep.
func (a *Activities) LoadSweep(ctx context.Context, id string) (SweepState, error) {
	sw, err := a.D.Svc.GetSweep(ctx, id)
	return SweepState{Status: sw.Status, Part: sw.PartitionID, Parked: sw.Parked()}, err
}

// BuildSweepJob builds the sweep and enqueues its sign job in one transaction.
func (a *Activities) BuildSweepJob(ctx context.Context, id string) (string, error) {
	job, err := a.D.Svc.BuildSweepJob(ctx, id)
	if err != nil {
		return "", nonRetry(err)
	}
	Hit("sweep", "after_build")
	return job, nil
}

// SettleSweep books a mined sweep from what the chain says moved.
func (a *Activities) SettleSweep(ctx context.Context, id, txHash string, reverted bool) error {
	st := chain.TxConfirmed
	if reverted {
		st = chain.TxFailed
	}
	if err := a.D.Svc.SettleSweep(ctx, id, txHash, st); err != nil {
		return nonRetry(err)
	}
	Hit("sweep", "after_settle")
	return nil
}

// TrueUp sends unexplained excess to suspense once the scan is past the sweep. Returns done.
func (a *Activities) TrueUp(ctx context.Context, id string) (bool, error) {
	return a.D.Svc.TrueUp(ctx, id)
}

// FailSweep ends a sweep that never broadcast, once its nonce is freed.
func (a *Activities) FailSweep(ctx context.Context, id, reason string) error {
	return nonRetry(a.D.Svc.FailSweepBeforeBroadcast(ctx, id, reason))
}

// ---- hot-to-cold move steps ----

// PlanColdMoves creates a move for every hot partition above its high-water mark and logs the low-water ALERT (once per
// outage). It returns how many it created.
func (a *Activities) PlanColdMoves(ctx context.Context) (int, error) {
	stop := heartbeating(ctx)
	defer stop()
	mv, err := a.D.Svc.PlanColdMoves(ctx, a.log())
	return len(mv), err
}

// StartOpenColdMoves starts a ColdMove workflow for every unfinished move that has none running.
func (a *Activities) StartOpenColdMoves(ctx context.Context) (int, error) {
	open, err := a.D.Svc.OpenColdMoves(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range open {
		if err := a.start(ctx, m.ID, ColdMoveWorkflow, Input{ID: m.ID, T: a.D.T}); err != nil {
			return 0, fmt.Errorf("start cold move %s: %w", m.ID, err)
		}
	}
	refills, err := a.D.Svc.OpenRefills(ctx)
	if err != nil {
		return 0, err
	}
	for _, r := range refills {
		if err := a.start(ctx, r.ID, RefillWorkflow, Input{ID: r.ID, T: a.D.T}); err != nil {
			return 0, fmt.Errorf("start refill %s: %w", r.ID, err)
		}
	}
	return len(open) + len(refills), nil
}

// ---- refill steps (cold to hot, after an offline ceremony) ----

// RefillView is a refill as the workflow needs it.
type RefillView struct {
	Status     string
	Parked     bool
	Stuck      bool
	AgeSeconds int64 // since the row last changed (for a broadcast refill: since it was broadcast)
}

// LoadRefill reads the refill.
func (a *Activities) LoadRefill(ctx context.Context, id string) (RefillView, error) {
	r, err := a.D.Svc.GetRefill(ctx, id)
	if err != nil {
		return RefillView{}, err
	}
	var age int64
	if err := a.D.Svc.Pool.QueryRow(ctx, `SELECT extract(epoch from now() - updated_at)::bigint FROM refills WHERE id=$1`, id).Scan(&age); err != nil {
		return RefillView{}, err
	}
	return RefillView{Status: r.Status, Parked: r.Parked(), Stuck: r.Stuck, AgeSeconds: age}, nil
}

// BroadcastRefill sends the imported, signed transaction and books it as on its way. A nonce that another transaction used
// parks the refill: it is never retried with a new nonce (that needs a new ceremony).
func (a *Activities) BroadcastRefill(ctx context.Context, id string) (string, error) {
	h, err := a.D.Svc.BroadcastRefill(ctx, id, func() { Hit("refill", "after_send") })
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "nonce too low") {
			a.log().Error("ALERT: the cold address's nonce was used by another transaction; the signed refill can never mine. Needs an operator", "refill", id, "error", err.Error())
			_ = a.D.Svc.ParkRefill(ctx, id, "the nonce was used by another transaction: "+err.Error())
			return "", temporal.NewNonRetryableApplicationError("cold nonce consumed", "nonce_consumed", err)
		}
		return "", err
	}
	Hit("refill", "after_record")
	return h, nil
}

// WaitRefillTx polls the transaction for up to wait and returns "pending", "confirmed" or "reverted".
func (a *Activities) WaitRefillTx(ctx context.Context, id string, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for {
		st, err := a.D.Svc.RefillTxState(ctx, id)
		if err != nil {
			return "", err
		}
		if st != "pending" {
			Hit("refill", "after_confirm")
			return string(st), nil
		}
		activity.RecordHeartbeat(ctx)
		if time.Now().After(deadline) {
			return "pending", nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// SettleRefill books a mined refill.
func (a *Activities) SettleRefill(ctx context.Context, id string, reverted bool) error {
	if err := a.D.Svc.SettleRefill(ctx, id, reverted); err != nil {
		return nonRetry(err)
	}
	Hit("refill", "after_settle")
	return nil
}

// AlertRefillStuck logs the ALERT for a refill that was broadcast and has not confirmed, once.
func (a *Activities) AlertRefillStuck(ctx context.Context, id string) error {
	first, err := a.D.Svc.MarkRefillStuck(ctx, id)
	if err == nil && first {
		a.log().Error("ALERT: a cold refill was broadcast and has not confirmed. It is never retried with a new nonce: look at the transaction, "+
			"and if it was dropped, re-export and run a new ceremony only after the old one can no longer mine", "refill", id)
	}
	return err
}

// ColdState is a cold move as the workflow needs it.
type ColdState struct {
	Status string
	Part   string
	Parked bool
}

// LoadColdMove reads the move.
func (a *Activities) LoadColdMove(ctx context.Context, id string) (ColdState, error) {
	m, err := a.D.Svc.GetColdMove(ctx, id)
	return ColdState{Status: m.Status, Part: m.PartitionID, Parked: m.Parked()}, err
}

// BuildColdMoveJob builds the move and enqueues its sign job in one transaction.
func (a *Activities) BuildColdMoveJob(ctx context.Context, id string) (string, error) {
	job, err := a.D.Svc.BuildColdMoveJob(ctx, id)
	if err != nil {
		return "", nonRetry(err)
	}
	Hit(custody.OwnerKindToCold, "after_build")
	return job, nil
}

// SettleColdMove books a mined move.
func (a *Activities) SettleColdMove(ctx context.Context, id, txHash string, reverted bool) error {
	st := chain.TxConfirmed
	if reverted {
		st = chain.TxFailed
	}
	if err := a.D.Svc.SettleColdMove(ctx, id, txHash, st); err != nil {
		return nonRetry(err)
	}
	Hit(custody.OwnerKindToCold, "after_settle")
	return nil
}

// FailColdMove ends a move that never broadcast, once its nonce is freed.
func (a *Activities) FailColdMove(ctx context.Context, id, reason string) error {
	return nonRetry(a.D.Svc.FailColdMoveBeforeBroadcast(ctx, id, reason))
}

// ---- hot-shard rebalance steps ----

// PlanRebalances creates a rebalance for every hot shard below its target that a fuller shard can feed. It returns how many it created.
func (a *Activities) PlanRebalances(ctx context.Context) (int, error) {
	stop := heartbeating(ctx)
	defer stop()
	mv, err := a.D.Svc.PlanRebalances(ctx, a.log())
	return len(mv), err
}

// StartOpenRebalances starts a Rebalance workflow for every unfinished rebalance that has none running.
func (a *Activities) StartOpenRebalances(ctx context.Context) (int, error) {
	open, err := a.D.Svc.OpenRebalances(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range open {
		if err := a.start(ctx, m.ID, RebalanceWorkflow, Input{ID: m.ID, T: a.D.T}); err != nil {
			return 0, fmt.Errorf("start rebalance %s: %w", m.ID, err)
		}
	}
	return len(open), nil
}

// LoadRebalance reads the rebalance (the same view as a cold move).
func (a *Activities) LoadRebalance(ctx context.Context, id string) (ColdState, error) {
	m, err := a.D.Svc.GetRebalance(ctx, id)
	return ColdState{Status: m.Status, Part: m.PartitionID, Parked: m.Parked()}, err
}

// BuildRebalanceJob builds the rebalance and enqueues its sign job in one transaction.
func (a *Activities) BuildRebalanceJob(ctx context.Context, id string) (string, error) {
	job, err := a.D.Svc.BuildRebalanceJob(ctx, id)
	if err != nil {
		return "", nonRetry(err)
	}
	Hit(custody.OwnerKindRebalance, "after_build")
	return job, nil
}

// SettleRebalance books a mined rebalance.
func (a *Activities) SettleRebalance(ctx context.Context, id, txHash string, reverted bool) error {
	st := chain.TxConfirmed
	if reverted {
		st = chain.TxFailed
	}
	if err := a.D.Svc.SettleRebalance(ctx, id, txHash, st); err != nil {
		return nonRetry(err)
	}
	Hit(custody.OwnerKindRebalance, "after_settle")
	return nil
}

// FailRebalance ends a rebalance that never broadcast, once its nonce is freed.
func (a *Activities) FailRebalance(ctx context.Context, id, reason string) error {
	return nonRetry(a.D.Svc.FailRebalanceBeforeBroadcast(ctx, id, reason))
}

// ---- shared transaction steps (withdrawals and sweeps) ----

// OwnerArg identifies a transaction owner and its tracks in activity arguments.
type OwnerArg struct {
	Kind, ID, Part string
}

func (o OwnerArg) owner() custody.Owner {
	return custody.Owner{Kind: o.Kind, ID: o.ID, PartitionID: o.Part}
}

// JobResult is a sign job's state.
type JobResult struct {
	Status string // pending | done | rejected | failed
	Reason string
}

// WaitJob polls the job for up to wait and returns its state. It heartbeats,
// so a dead worker is noticed within the heartbeat timeout.
func (a *Activities) WaitJob(ctx context.Context, jobID string, wait time.Duration) (JobResult, error) {
	st, reason, err := a.D.Svc.WaitJob(ctx, jobID, wait, func() { activity.RecordHeartbeat(ctx) })
	if err != nil {
		return JobResult{}, err
	}
	if st == custody.JobDone {
		k, id := killKind(jobID)
		Hit(k, "after_job")
		_ = id
	}
	return JobResult{Status: st, Reason: reason}, nil
}

// killKind derives the failpoint kind from a job ID prefix.
func killKind(jobID string) (string, string) {
	switch {
	case len(jobID) > 3 && jobID[:3] == "wd:":
		return "withdrawal", jobID
	case len(jobID) > 6 && jobID[:6] == "sweep:":
		return "sweep", jobID
	case len(jobID) > 7 && jobID[:7] == "tocold:":
		return custody.OwnerKindToCold, jobID
	case len(jobID) > 6 && jobID[:6] == "rebal:":
		return custody.OwnerKindRebalance, jobID
	}
	return "cancel", jobID
}

// RequeueJob enqueues the retry of a failed job: same digest, so the gateway returns the same signature.
func (a *Activities) RequeueJob(ctx context.Context, failedID, newID string) error {
	return a.D.Svc.RequeueJob(ctx, failedID, newID)
}

// BroadcastJob assembles the signed job and sends it. Safe to repeat.
func (a *Activities) BroadcastJob(ctx context.Context, o OwnerArg, jobID string) (string, error) {
	h, err := a.D.Svc.SubmitJob(ctx, jobID, o.owner())
	if err != nil {
		return "", err
	}
	if h != "" {
		k, _ := killKind(jobID)
		Hit(k, "after_broadcast")
	}
	return h, nil
}

// RecordBroadcast stores the hash on the business row (withdrawal or sweep).
func (a *Activities) RecordBroadcast(ctx context.Context, o OwnerArg, txHash string) error {
	switch o.Kind {
	case "withdrawal":
		return a.D.Svc.RecordWithdrawalBroadcast(ctx, o.ID, txHash)
	case "sweep":
		return a.D.Svc.RecordSweepBroadcast(ctx, o.ID, txHash)
	case custody.OwnerKindToCold:
		return a.D.Svc.RecordColdMoveBroadcast(ctx, o.ID, txHash)
	case custody.OwnerKindRebalance:
		return a.D.Svc.RecordRebalanceBroadcast(ctx, o.ID, txHash)
	}
	return fmt.Errorf("unknown owner kind %q", o.Kind)
}

// NonceResult is the combined state of every attempt at the owner's nonce.
type NonceResult struct {
	State string
	Hash  string
	Kind  string
}

// WaitNonce polls every attempt at the owner's nonce for up to wait and returns
// as soon as one is final. "Final" includes the withdrawal itself reverting,
// and a cancel mining.
func (a *Activities) WaitNonce(ctx context.Context, o OwnerArg, wait time.Duration) (NonceResult, error) {
	deadline := time.Now().Add(wait)
	for {
		n, err := a.D.Svc.NonceState(ctx, o.owner())
		if err != nil {
			return NonceResult{}, err
		}
		switch n.State {
		case custody.NonceMined, custody.NonceReverted, custody.NonceCancelled:
			Hit(o.Kind, "after_confirm")
			return NonceResult{State: n.State, Hash: n.Hash, Kind: n.Kind}, nil
		case custody.NonceConsumed:
			return NonceResult{State: n.State}, nil
		}
		if time.Now().After(deadline) {
			return NonceResult{State: n.State}, nil
		}
		activity.RecordHeartbeat(ctx)
		select {
		case <-ctx.Done():
			return NonceResult{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Park records that a withdrawal or sweep needs an operator and logs the ALERT.
func (a *Activities) Park(ctx context.Context, o OwnerArg, reason string) error {
	a.log().Error("ALERT: parked for an operator", "owner", o.Kind+" "+o.ID, "reason", reason)
	switch o.Kind {
	case "withdrawal":
		return a.D.Svc.ParkWithdrawal(ctx, o.ID, reason)
	case custody.OwnerKindToCold:
		return a.D.Svc.ParkColdMove(ctx, o.ID, reason)
	case custody.OwnerKindRebalance:
		return a.D.Svc.ParkRebalance(ctx, o.ID, reason)
	}
	return a.D.Svc.ParkSweep(ctx, o.ID, reason)
}

// ConsumedInfo describes a nonce someone else used, for the alert.
func (a *Activities) ConsumedInfo(ctx context.Context, o OwnerArg) (string, error) {
	var addr string
	var nonce int64
	err := a.D.Svc.Pool.QueryRow(ctx, `SELECT address, nonce FROM evm_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 ORDER BY nonce DESC LIMIT 1`,
		a.D.Svc.Cfg.Chain, o.Kind, o.ID).Scan(&addr, &nonce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("address %s nonce %d", addr, nonce), nil
}

// EnqueueReplacement builds and enqueues the n-th fee-bumped replacement on a track.
func (a *Activities) EnqueueReplacement(ctx context.Context, o OwnerArg, track string, n int) (string, error) {
	return a.D.Svc.EnqueueReplacement(ctx, o.owner(), custody.Track(track), n)
}

// EnqueueCancel builds and enqueues the cancel that frees the owner's nonce.
func (a *Activities) EnqueueCancel(ctx context.Context, o OwnerArg) (string, error) {
	return a.D.Svc.EnqueueCancel(ctx, o.owner())
}

var _ = big.NewInt

func (d Deps) queue() string {
	if d.Queue == "" {
		return DefaultTaskQueue
	}
	return d.Queue
}
