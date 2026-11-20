package workflow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Names of the long-running workflows (their workflow IDs).
func ScanID(chain string) string         { return "scan:" + chain }
func PlannerID(chain string) string      { return "sweep-planner:" + chain }
func ReconcilerID(chain string) string   { return "withdrawal-reconciler:" + chain }
func ColdPlannerID(chain string) string  { return "cold-planner:" + chain }
func DrainPlannerID(chain string) string { return "drain-planner:" + chain }

// RegisterNamespace creates the Temporal namespace if it does not exist (the
// dev server starts without one). Idempotent.
func RegisterNamespace(ctx context.Context, addr, namespace string, conn ...client.ConnectionOptions) error {
	opts := client.Options{HostPort: addr}
	if len(conn) > 0 {
		opts.ConnectionOptions = conn[0]
	}
	ns, err := client.NewNamespaceClient(opts)
	if err != nil {
		return err
	}
	defer ns.Close()
	err = ns.Register(ctx, &workflowservice.RegisterNamespaceRequest{
		Namespace:                        namespace,
		WorkflowExecutionRetentionPeriod: durationpb.New(7 * 24 * 3600 * 1e9),
	})
	var exists *serviceerror.NamespaceAlreadyExists
	if err != nil && !errors.As(err, &exists) {
		return fmt.Errorf("register namespace: %w", err)
	}
	return nil
}

// DefaultStopTimeout is how long a stopping worker lets running activities finish. The normal activities take seconds (the build
// and sign-wait activities are bounded by 30 s and one 20 s slice); a planning pass has a two-minute limit but ends in seconds.
// 40 s covers them all and leaves 20 s of the chart's 60 s grace period for the exit. See deploy/images/README.md.
const DefaultStopTimeout = 40 * time.Second

// NewWorker registers every workflow and the activities on a worker. On Stop the worker polls no more, waits up to d.StopTimeout
// (DefaultStopTimeout when zero) for running activities, then cancels their context. Long waits end earlier: they watch the stop
// channel (see stopping).
func NewWorker(c client.Client, d Deps) worker.Worker {
	st := d.StopTimeout
	if st <= 0 {
		st = DefaultStopTimeout
	}
	w := worker.New(c, d.queue(), worker.Options{WorkerStopTimeout: st})
	w.RegisterWorkflow(ScanWorkflow)
	w.RegisterWorkflow(SweepPlannerWorkflow)
	w.RegisterWorkflow(WithdrawalReconcilerWorkflow)
	w.RegisterWorkflow(ColdPlannerWorkflow)
	w.RegisterWorkflow(ColdMoveWorkflow)
	w.RegisterWorkflow(ConsolidationWorkflow)
	w.RegisterWorkflow(RebalanceWorkflow)
	w.RegisterWorkflow(DrainWorkflow)
	w.RegisterWorkflow(DrainPlannerWorkflow)
	w.RegisterWorkflow(BatchWorkflow)
	w.RegisterWorkflow(RefillWorkflow)
	w.RegisterWorkflow(SweepWorkflow)
	w.RegisterWorkflow(WithdrawalWorkflow)
	w.RegisterActivity(&Activities{D: d})
	return w
}

// loopSpec is one long-running per-chain loop.
type loopSpec struct {
	id string
	wf any
}

// loopSpecs are the loops of an evm chain cell. A family that does not sweep or withdraw yet runs only the scan (loopSpecsFor).
func loopSpecs(chain string) []loopSpec { return loopSpecsFor(custody.FamilyEVM, chain) }

func loopSpecsFor(family, chain string) []loopSpec {
	if family == custody.FamilySOL { // deposits, sweeps, withdrawals and the cold tier
		return []loopSpec{{ScanID(chain), ScanWorkflow}, {PlannerID(chain), SweepPlannerWorkflow}, {ReconcilerID(chain), WithdrawalReconcilerWorkflow}, {ColdPlannerID(chain), ColdPlannerWorkflow}}
	}
	if family == custody.FamilyBTC {
		return []loopSpec{{ScanID(chain), ScanWorkflow}, {PlannerID(chain), SweepPlannerWorkflow}, {ReconcilerID(chain), WithdrawalReconcilerWorkflow}, {ColdPlannerID(chain), ColdPlannerWorkflow}, {DrainPlannerID(chain), DrainPlannerWorkflow}}
	}
	return []loopSpec{{ScanID(chain), ScanWorkflow}, {PlannerID(chain), SweepPlannerWorkflow}, {ReconcilerID(chain), WithdrawalReconcilerWorkflow}, {ColdPlannerID(chain), ColdPlannerWorkflow}, {DrainPlannerID(chain), DrainPlannerWorkflow}}
}

func startLoop(ctx context.Context, c client.Client, queue string, t Timings, l loopSpec) error {
	_, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: l.id, TaskQueue: queue,
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
		WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
	}, l.wf, Input{ID: l.id, T: t})
	if err != nil {
		return fmt.Errorf("start %s: %w", l.id, err)
	}
	return nil
}

// EnsureLoops starts the per-chain loops if they are not running.
func EnsureLoops(ctx context.Context, c client.Client, queue string, cfg *custody.Config, log *slog.Logger) error {
	if queue == "" {
		queue = DefaultTaskQueue
	}
	t := DefaultTimings(cfg)
	for _, l := range loopSpecsFor(cfg.Family, cfg.Chain) {
		if err := startLoop(ctx, c, queue, t, l); err != nil {
			return err
		}
		log.Info("loop running", "workflow", l.id)
	}
	return nil
}

// Orch implements custody.Orchestrator on a Temporal client.
type Orch struct {
	C     client.Client
	T     Timings
	Queue string // default DefaultTaskQueue
}

var _ custody.Orchestrator = Orch{}

func (o Orch) opts(id string) client.StartWorkflowOptions {
	q := o.Queue
	if q == "" {
		q = DefaultTaskQueue
	}
	return client.StartWorkflowOptions{ID: id, TaskQueue: q,
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
		WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE}
}

// StartWithdrawal starts the withdrawal's workflow, or finds it running.
func (o Orch) StartWithdrawal(ctx context.Context, id string) error {
	_, err := o.C.ExecuteWorkflow(ctx, o.opts(id), WithdrawalWorkflow, Input{ID: id, T: o.T})
	return err
}

// SignalWithdrawal wakes the workflow after an approval. Signal-with-start
// means a signal sent before the workflow started is not lost.
func (o Orch) SignalWithdrawal(ctx context.Context, id string) error {
	_, err := o.C.SignalWithStartWorkflow(ctx, id, SignalApproval, nil, o.opts(id), WithdrawalWorkflow, Input{ID: id, T: o.T})
	return err
}

// RejectWithdrawal tells the workflow a human rejected the withdrawal.
func (o Orch) RejectWithdrawal(ctx context.Context, id, reason string) error {
	_, err := o.C.SignalWithStartWorkflow(ctx, id, SignalReject, reason, o.opts(id), WithdrawalWorkflow, Input{ID: id, T: o.T})
	return err
}

// CPFPNow tells the workflow that drives a Bitcoin send (its workflow ID is the owner's ID: the withdrawal's, or its batch's) to sign and broadcast the
// CPFP child whose first job the API has just enqueued. It does not start a workflow: a send that is broadcast and unconfirmed has one running.
func (o Orch) CPFPNow(ctx context.Context, ownerID string) error {
	return o.C.SignalWorkflow(ctx, ownerID, "", SignalCPFPNow, nil)
}
