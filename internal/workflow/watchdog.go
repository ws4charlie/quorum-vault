package workflow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// The watchdog exists for one failure seen once in the crash tests: a workflow task handed to a worker that died at that
// moment is not delivered again until the server's task timeout, and in the meantime nothing happens. A healthy workflow
// writes history all the time (every poll, every timer, every activity), so "no new history event for a long time" is a
// reliable sign of a stall.
//
//   - A long-running loop (scan, sweep planner, withdrawal reconciler) that shows no progress for StallAfter, or is not
//     running at all: ALERT, terminate that run, start a new one. Loops are safe to restart because every pass is idempotent
//     (they only read the database and chain and start the per-owner workflows).
//   - A withdrawal or sweep workflow with no progress for StallAfter: ALERT only. Restarting money movement automatically
//     is not this watchdog's job; the reconciler already restarts workflows that do not exist.

// Progress is what the watchdog sees of one workflow execution.
type Progress struct {
	Exists  bool
	Running bool
	RunID   string
	Events  int64 // length of the history: grows with every task, timer and activity
}

// Engine is the part of Temporal the watchdog needs.
type Engine interface {
	Describe(ctx context.Context, id string) (Progress, error)
	Terminate(ctx context.Context, id, runID, reason string) error
	StartLoop(ctx context.Context, id string) error
}

type watchState struct {
	run     string
	events  int64
	since   time.Time
	alerted bool
}

// Watchdog checks the loops and the open owners now and then.
type Watchdog struct {
	Engine     Engine
	Chain      string
	OpenOwners func(ctx context.Context) ([]string, error) // ids of unfinished withdrawals and sweeps
	Interval   time.Duration                               // how often to look; default 15 s
	StallAfter time.Duration                               // no progress for this long is a stall; default 2 min
	Log        *slog.Logger
	Now        func() time.Time // tests

	state map[string]*watchState
}

func (w *Watchdog) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

func (w *Watchdog) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Run checks until ctx ends.
func (w *Watchdog) Run(ctx context.Context) {
	iv := w.Interval
	if iv <= 0 {
		iv = 15 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Check(ctx)
		}
	}
}

// stalled returns true when id has shown no progress for StallAfter (and reports a new run or new history as progress).
func (w *Watchdog) stalled(id string, p Progress) (stalled, firstTime bool) {
	if w.state == nil {
		w.state = map[string]*watchState{}
	}
	after := w.StallAfter
	if after <= 0 {
		after = 2 * time.Minute
	}
	st := w.state[id]
	if st == nil || st.run != p.RunID || st.events != p.Events {
		w.state[id] = &watchState{run: p.RunID, events: p.Events, since: w.now()}
		return false, false
	}
	if w.now().Sub(st.since) < after {
		return false, false
	}
	first := !st.alerted
	st.alerted = true
	return true, first
}

// Check is one pass.
func (w *Watchdog) Check(ctx context.Context) {
	for _, l := range loopSpecs(w.Chain) {
		p, err := w.Engine.Describe(ctx, l.id)
		if err != nil {
			w.log().Warn("watchdog: cannot describe loop", "workflow", l.id, "err", err)
			continue
		}
		if !p.Exists || !p.Running {
			w.log().Error("ALERT: loop workflow is not running; starting it", "workflow", l.id)
			if err := w.Engine.StartLoop(ctx, l.id); err != nil {
				w.log().Error("watchdog: start loop failed", "workflow", l.id, "err", err)
			}
			delete(w.state, l.id)
			continue
		}
		if stalled, _ := w.stalled(l.id, p); stalled {
			w.log().Error("ALERT: loop workflow made no progress; terminating this run and starting a new one",
				"workflow", l.id, "run", p.RunID, "events", p.Events, "stalled_for", w.StallAfter.String())
			if err := w.Engine.Terminate(ctx, l.id, p.RunID, "watchdog: no progress"); err != nil {
				w.log().Error("watchdog: terminate failed", "workflow", l.id, "err", err)
				continue
			}
			if err := w.Engine.StartLoop(ctx, l.id); err != nil {
				w.log().Error("watchdog: start loop failed", "workflow", l.id, "err", err)
			}
			delete(w.state, l.id)
		}
	}
	if w.OpenOwners == nil {
		return
	}
	ids, err := w.OpenOwners(ctx)
	if err != nil {
		w.log().Warn("watchdog: cannot list open withdrawals and sweeps", "err", err)
		return
	}
	for _, id := range ids {
		p, err := w.Engine.Describe(ctx, id)
		if err != nil || !p.Exists || !p.Running {
			continue // no workflow: the reconciler's job; a finished one has nothing to stall
		}
		if stalled, first := w.stalled(id, p); stalled && first {
			w.log().Error("ALERT: withdrawal or sweep workflow made no progress; not restarted automatically",
				"workflow", id, "run", p.RunID, "events", p.Events, "stalled_for", w.StallAfter.String())
		}
	}
}

// ---- Temporal-backed engine ----

type temporalEngine struct {
	c     client.Client
	queue string
	t     Timings
	chain string
}

// NewEngine is the Engine on a Temporal client.
func NewEngine(c client.Client, queue string, cfg *custody.Config) Engine {
	if queue == "" {
		queue = DefaultTaskQueue
	}
	return &temporalEngine{c: c, queue: queue, t: DefaultTimings(cfg), chain: cfg.Chain}
}

func (e *temporalEngine) Describe(ctx context.Context, id string) (Progress, error) {
	d, err := e.c.DescribeWorkflowExecution(ctx, id, "")
	var nf *serviceerror.NotFound
	if errors.As(err, &nf) {
		return Progress{}, nil
	}
	if err != nil {
		return Progress{}, err
	}
	info := d.WorkflowExecutionInfo
	return Progress{Exists: true, Running: info.Status == enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING,
		RunID: info.Execution.RunId, Events: info.HistoryLength}, nil
}

func (e *temporalEngine) Terminate(ctx context.Context, id, runID, reason string) error {
	return e.c.TerminateWorkflow(ctx, id, runID, reason)
}

func (e *temporalEngine) StartLoop(ctx context.Context, id string) error {
	for _, l := range loopSpecs(e.chain) {
		if l.id == id {
			return startLoop(ctx, e.c, e.queue, e.t, l)
		}
	}
	return fmt.Errorf("unknown loop %q", id)
}

// OpenOwnerIDs lists the unfinished withdrawals and sweeps of svc, for Watchdog.OpenOwners.
func OpenOwnerIDs(svc *custody.Service) func(ctx context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		ws, err := svc.OpenWithdrawals(ctx)
		if err != nil {
			return nil, err
		}
		ss, err := svc.OpenSweeps(ctx)
		if err != nil {
			return nil, err
		}
		var ids []string
		for _, w := range ws {
			ids = append(ids, w.ID)
		}
		for _, s := range ss {
			ids = append(ids, s.ID)
		}
		return ids, nil
	}
}
