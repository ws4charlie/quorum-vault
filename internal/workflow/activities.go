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
	"sync/atomic"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// DefaultTaskQueue is the task queue of the business zone's worker when no chain is
// named (tests that build a Deps without one). A running worker uses QueueFor.
const DefaultTaskQueue = "qv-core"

// QueueFor is the task queue of the worker of one chain cell. It carries the chain name, so two
// workers for two chains on one Temporal server never pick up each other's workflows. (The long-running loop
// workflows already carry it in their IDs, see ScanID; the IDs of withdrawal and sweep workflows are the row IDs, which
// are unique in the business database the cells share.)
func QueueFor(chain string) string { return DefaultTaskQueue + "-" + chain }

// Error types the workflows branch on.
const (
	errExpired    = "expired"
	errFrozen     = "sweep_frozen"
	errNonceOpen  = "nonce_open"
	errBadRequest = "bad_request"
	errCannotBump = "cannot_bump" // no replacement or cancel can be built
	errSweepFee   = "sweep_fee"   // the fee rate does not allow this sweep now
	errNoOutputs  = "no_outputs"  // too few available outputs: retryable by waiting
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
type Activities struct {
	D Deps
	// haltAlerted: the "scan halted" ALERT was given by this process (one per process, not one per scan pass).
	haltAlerted atomic.Bool
}

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
	case errors.Is(err, custody.ErrReservationOpen):
		typ = errNonceOpen
	case errors.Is(err, chain.ErrCannotBump):
		typ = errCannotBump
	case errors.Is(err, chain.ErrSweepFeePolicy):
		typ = errSweepFee
	case errors.Is(err, chain.ErrNotEnoughOutputs):
		typ = errNoOutputs
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
	if errors.Is(err, custody.ErrScanHalted) {
		// Stopped on purpose (the chain was rewritten below the safe depth): credits stay, nothing is retried or reversed, and
		// the loop idles until an operator clears the halt.
		if !a.haltAlerted.Swap(true) {
			a.log().Error("ALERT: scanning is halted and credits are kept; an operator must look (see docs/learn/p7-2-btc-deposits.md)", "error", err.Error())
		}
		cur, cerr := a.D.Svc.Cursor(ctx)
		return ScanResult{Cursor: cur}, cerr
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
	// SettlesCancel: a confirmed cancel of this sweep moved its coins like the sweep would have (Bitcoin: its output is the sweep's), so it settles
	// as the sweep. False for chains where a cancel moves nothing (EVM); absent in histories recorded before, which is false.
	SettlesCancel bool
}

// LoadSweep reads the sweep.
func (a *Activities) LoadSweep(ctx context.Context, id string) (SweepState, error) {
	sw, err := a.D.Svc.GetSweep(ctx, id)
	_, settles := a.D.Svc.Chain.(chain.Settler)
	return SweepState{Status: sw.Status, Part: sw.PartitionID, Parked: sw.Parked(), SettlesCancel: settles}, err
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
func (a *Activities) FailSweep(ctx context.Context, id, reason, feeTx string) error {
	return nonRetry(a.D.Svc.FailSweepBeforeBroadcast(ctx, id, reason, feeTx))
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
	// Expired: a Bitcoin refill request that was not imported within its time. Absent (false) in histories recorded before.
	Expired bool
	// Replacement: a signed replacement of a Bitcoin refill is waiting to be broadcast. Absent (false) in histories recorded before.
	Replacement bool
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
	exp := a.D.Svc.Cfg.Family == custody.FamilyBTC && r.Status == custody.RefillRequested && time.Duration(age)*time.Second > a.D.Svc.Cfg.RefillRequestTTL
	repl := false
	if r.Status == custody.RefillBroadcast {
		repl, _ = a.D.Svc.HasUnsentReplacement(ctx, id)
	}
	return RefillView{Status: r.Status, Parked: r.Parked(), Stuck: r.Stuck, AgeSeconds: age, Expired: exp, Replacement: repl}, nil
}

// BroadcastRefill sends the imported, signed transaction and books it as on its way. A nonce that another transaction used
// parks the refill: it is never retried with a new nonce (that needs a new ceremony).
func (a *Activities) BroadcastRefill(ctx context.Context, id string) (string, error) {
	h, err := a.D.Svc.BroadcastRefill(ctx, id, func() { Hit("refill", "after_send") })
	if err != nil && (errors.Is(err, chain.ErrInputsSpent) || errors.Is(err, chain.ErrBroadcastStuck)) {
		// Bitcoin: an input is gone (spent by something else), or the node will not take it at this fee. Either needs a person (a new ceremony, 6b-3).
		a.log().Error("ALERT: the signed refill cannot be broadcast; the signed transaction is kept and its inputs stay reserved. Needs an operator", "refill", id, "error", err.Error())
		_ = a.D.Svc.ParkRefill(ctx, id, "the signed transaction cannot be broadcast: "+err.Error())
		return "", temporal.NewNonRetryableApplicationError("refill cannot be broadcast", "refill_unbroadcastable", err)
	}
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

// BroadcastRefillReplacement sends an imported replacement of a Bitcoin refill. A replacement the node refuses is forgotten with an ALERT; the refill
// goes on waiting for whichever attempt confirms.
func (a *Activities) BroadcastRefillReplacement(ctx context.Context, id string) error {
	_, err := a.D.Svc.BroadcastRefillReplacement(ctx, id)
	if errors.Is(err, chain.ErrBroadcastStuck) || errors.Is(err, chain.ErrInputsSpent) {
		a.log().Error("ALERT: the node did not take the fee-bumped replacement of a cold refill; it is forgotten and the earlier attempt may still confirm. Export again with a higher fee",
			"refill", id, "error", err.Error())
		return nil
	}
	return err
}

// ExpireRefill ends a Bitcoin refill request that was never imported in time.
func (a *Activities) ExpireRefill(ctx context.Context, id string) error {
	a.log().Warn("a refill request was not imported in time; it ends and nothing moved", "refill", id)
	return a.D.Svc.ExpireRefill(ctx, id)
}

// ParkRefillConsumed parks a Bitcoin refill whose cold inputs were spent by something that is not our transaction.
func (a *Activities) ParkRefillConsumed(ctx context.Context, id string) error {
	a.log().Error("ALERT: an input of a signed cold refill was spent by a transaction this system did not make; the cold key may be compromised. Needs an operator", "refill", id)
	return a.D.Svc.ParkRefill(ctx, id, "an input of the refill was spent by a transaction this system did not make")
}

// AlertRefillStuck logs the ALERT for a refill that was broadcast and has not confirmed, once.
func (a *Activities) AlertRefillStuck(ctx context.Context, id string) error {
	first, err := a.D.Svc.MarkRefillStuck(ctx, id)
	if err == nil && first && a.D.Svc.Cfg.Family == custody.FamilyBTC {
		a.log().Error("ALERT: a cold refill was broadcast and has not confirmed. "+a.D.Svc.StuckHint(ctx, id), "refill", id)
		return nil
	}
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
	// SettlesCancel: a confirmed cancel of the move spent its inputs and made an output of its own (Bitcoin), so it is settled (as a failed move)
	// instead of just ended. False for chains where a cancel moves nothing, and in histories recorded before.
	SettlesCancel bool
}

// LoadColdMove reads the move.
func (a *Activities) LoadColdMove(ctx context.Context, id string) (ColdState, error) {
	m, err := a.D.Svc.GetColdMove(ctx, id)
	_, settles := a.D.Svc.Chain.(chain.Settler)
	return ColdState{Status: m.Status, Part: m.PartitionID, Parked: m.Parked(), SettlesCancel: settles}, err
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
func (a *Activities) FailColdMove(ctx context.Context, id, reason, feeTx string) error {
	return nonRetry(a.D.Svc.FailColdMoveBeforeBroadcast(ctx, id, reason, feeTx))
}

// ---- consolidation steps (Bitcoin) ----

// PlanConsolidations creates a consolidation for every hot shard that holds more small outputs than its threshold and may go now. It returns how many
// it created.
func (a *Activities) PlanConsolidations(ctx context.Context) (int, error) {
	stop := heartbeating(ctx)
	defer stop()
	mv, err := a.D.Svc.PlanConsolidations(ctx, a.log())
	return len(mv), err
}

// StartOpenConsolidations starts a Consolidation workflow for every unfinished consolidation that has none running.
func (a *Activities) StartOpenConsolidations(ctx context.Context) (int, error) {
	open, err := a.D.Svc.OpenConsolidations(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range open {
		if err := a.start(ctx, m.ID, ConsolidationWorkflow, Input{ID: m.ID, T: a.D.T}); err != nil {
			return 0, fmt.Errorf("start consolidation %s: %w", m.ID, err)
		}
	}
	return len(open), nil
}

// LoadConsolidation reads the consolidation.
func (a *Activities) LoadConsolidation(ctx context.Context, id string) (ColdState, error) {
	m, err := a.D.Svc.GetConsolidation(ctx, id)
	_, settles := a.D.Svc.Chain.(chain.Settler)
	return ColdState{Status: m.Status, Part: m.PartitionID, Parked: m.Parked(), SettlesCancel: settles}, err
}

// BuildConsolidationJob builds the consolidation and enqueues its sign job in one transaction.
func (a *Activities) BuildConsolidationJob(ctx context.Context, id string) (string, error) {
	job, err := a.D.Svc.BuildConsolidationJob(ctx, id)
	if err != nil {
		return "", nonRetry(err)
	}
	Hit(custody.OwnerKindConsolidate, "after_build")
	return job, nil
}

// SettleConsolidation books a mined consolidation, or a confirmed cancel of it.
func (a *Activities) SettleConsolidation(ctx context.Context, id, txHash string) error {
	if err := a.D.Svc.SettleConsolidation(ctx, id, txHash); err != nil {
		return nonRetry(err)
	}
	Hit(custody.OwnerKindConsolidate, "after_settle")
	return nil
}

// FailConsolidation ends a consolidation that never broadcast, once its outputs are released.
func (a *Activities) FailConsolidation(ctx context.Context, id, reason string) error {
	return nonRetry(a.D.Svc.FailConsolidationBeforeBroadcast(ctx, id, reason))
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
func (a *Activities) FailRebalance(ctx context.Context, id, reason, feeTx string) error {
	return nonRetry(a.D.Svc.FailRebalanceBeforeBroadcast(ctx, id, reason, feeTx))
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
	case len(jobID) > 7 && jobID[:7] == "consol:":
		return custody.OwnerKindConsolidate, jobID
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
	case custody.OwnerKindConsolidate:
		return a.D.Svc.RecordConsolidationBroadcast(ctx, o.ID, txHash)
	}
	return fmt.Errorf("unknown owner kind %q", o.Kind)
}

// NonceResult is the combined state of every attempt at the owner's nonce.
type NonceResult struct {
	State string
	Hash  string
	Kind  string
	// FeeRefusals and Refusal: what the node refused of the owner's replacements (Bitcoin). A replacement refused as too cheap was never in the
	// mempool and does not count against the limit on replacements; any other refusal is an ALERT. Absent in older histories: zero.
	FeeRefusals int
	Refusal     string
}

// WaitNonce polls every attempt of the owner for up to wait and returns
// as soon as one is final. "Final" includes the withdrawal itself reverting,
// and a cancel mining.
func (a *Activities) WaitNonce(ctx context.Context, o OwnerArg, wait time.Duration) (NonceResult, error) {
	deadline := time.Now().Add(wait)
	for {
		n, err := a.D.Svc.AttemptState(ctx, o.owner())
		if err != nil {
			return NonceResult{}, err
		}
		switch n.State {
		case custody.AttemptMined, custody.AttemptReverted, custody.AttemptCancelled:
			Hit(o.Kind, "after_confirm")
			return NonceResult{State: n.State, Hash: n.Hash, Kind: n.Kind}, nil
		case custody.AttemptConsumed:
			return NonceResult{State: n.State}, nil
		}
		if time.Now().After(deadline) {
			return NonceResult{State: n.State, FeeRefusals: n.FeeRefusals, Refusal: n.Refusal}, nil
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
	case custody.OwnerKindConsolidate:
		return a.D.Svc.ParkConsolidation(ctx, o.ID, reason)
	}
	return a.D.Svc.ParkSweep(ctx, o.ID, reason)
}

// FreeResult is the answer of NothingToFree.
type FreeResult struct {
	Free bool
	Why  string
}

// NothingToFree asks the chain, for an owner whose refused attempt has no cancel, whether anything could still confirm:
// an attempt that was ever broadcast, or a reservation that is still open. Free is true only when neither holds; Why says
// what does otherwise. The workflow never releases money on a chain without cancel unless Free.
func (a *Activities) NothingToFree(ctx context.Context, o OwnerArg) (FreeResult, error) {
	// A refusal that left no signature: give back what the attempt reserved (Bitcoin's outputs). If a signature may exist this does nothing and the
	// reservation below keeps the row parked.
	if _, err := a.D.Svc.ReleaseIfUnsigned(ctx, o.owner()); err != nil {
		return FreeResult{}, err
	}
	oc, err := a.D.Svc.Chain.Outcome(ctx, o.Kind, o.ID)
	if err != nil {
		return FreeResult{}, err
	}
	if oc.Attempts > 0 || oc.State != chain.OutcomeOpen {
		return FreeResult{Why: fmt.Sprintf("%d attempt(s) were broadcast (state %s)", oc.Attempts, oc.State)}, nil
	}
	r, err := a.D.Svc.Chain.Reservation(ctx, a.D.Svc.Pool, o.Kind, o.ID)
	if err != nil {
		return FreeResult{}, err
	}
	if r.Open {
		return FreeResult{Why: "a reservation is still open: " + r.Detail}, nil
	}
	return FreeResult{Free: true}, nil
}

// ConsumedInfo describes what someone else used (EVM: a nonce), for the alert.
func (a *Activities) ConsumedInfo(ctx context.Context, o OwnerArg) (string, error) {
	r, err := a.D.Svc.Chain.Reservation(ctx, a.D.Svc.Pool, o.Kind, o.ID)
	if err != nil {
		return "", err
	}
	return r.Detail, nil
}

// EnqueueReplacement builds and enqueues the n-th fee-bumped replacement on a track.
func (a *Activities) EnqueueReplacement(ctx context.Context, o OwnerArg, track string, n int) (string, error) {
	id, err := a.D.Svc.EnqueueReplacement(ctx, o.owner(), custody.Track(track), n)
	return id, nonRetry(err)
}

// EnqueueCancel builds and enqueues the cancel that frees what the owner reserved (EVM: its nonce). It returns "" on a
// chain without cancel: there is nothing to free. (The activity names WaitNonce and EnqueueCancel are kept for
// workflow histories already recorded.)
func (a *Activities) EnqueueCancel(ctx context.Context, o OwnerArg) (string, error) {
	id, err := a.D.Svc.EnqueueCancel(ctx, o.owner())
	return id, nonRetry(err)
}

var _ = big.NewInt

func (d Deps) queue() string {
	if d.Queue == "" {
		return DefaultTaskQueue
	}
	return d.Queue
}
