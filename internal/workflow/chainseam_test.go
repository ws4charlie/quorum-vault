package workflow

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// A chain without cancel goes through a refusal without trying to cancel: the activity that builds the cancel says there is
// nothing to free (""), no job is waited for, and the hold is released at once.
func TestRefusalOnAChainWithoutCancelVoidsAtOnce(t *testing.T) {
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	env.RegisterWorkflow(WithdrawalWorkflow)

	var mu sync.Mutex
	var calls []string
	var voided []string
	rec := func(name string) { mu.Lock(); calls = append(calls, name); mu.Unlock() }
	reg := func(name string, fn any) { env.RegisterActivityWithOptions(fn, activity.RegisterOptions{Name: name}) }
	reg("LoadWithdrawal", func(context.Context, string) (WdState, error) {
		rec("LoadWithdrawal")
		return WdState{Status: custody.WdSigning, Part: "p"}, nil
	})
	reg("WaitJob", func(_ context.Context, jobID string, _ time.Duration) (JobResult, error) {
		rec("WaitJob " + jobID)
		return JobResult{Status: custody.JobRejected, Reason: "policy_x: no"}, nil
	})
	reg("EnqueueCancel", func(_ context.Context, o OwnerArg) (string, error) {
		rec("EnqueueCancel")
		return "", nil // chain.ErrNotSupported inside: nothing reserved to free
	})
	reg("VoidWithdrawal", func(_ context.Context, id, reason, feeTx string) error {
		rec("VoidWithdrawal")
		mu.Lock()
		voided = append(voided, id+"|"+reason+"|"+feeTx)
		mu.Unlock()
		return nil
	})
	// Every other activity is unregistered: using one (Park, WaitNonce, BroadcastJob, ...) fails the workflow.

	env.ExecuteWorkflow(WithdrawalWorkflow, Input{ID: "w1", T: Timings{SignTimeout: time.Second, StuckAfter: time.Hour, MaxReplacements: 1}})
	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow: %v (calls %v)", err, calls)
	}
	if len(voided) != 1 || voided[0] != "w1|gateway refused: policy_x: no|" {
		t.Fatalf("voided %v", voided)
	}
	want := []string{"LoadWithdrawal", "WaitJob " + custody.OwnerTrack(custody.Owner{Kind: "withdrawal", ID: "w1"}).FirstJob(), "EnqueueCancel", "VoidWithdrawal"}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("activities %v, want %v", calls, want)
	}
}

// Two workers for two chains on one Temporal server do not cross: each chain's queue is its own, and the IDs of the
// loop workflows differ too. A probe workflow stands in for a real one so no database is needed.
func TestTwoChainsOnOneTemporalDoNotCross(t *testing.T) {
	if QueueFor("a") == QueueFor("b") || QueueFor("a") == DefaultTaskQueue {
		t.Fatalf("queues %q %q", QueueFor("a"), QueueFor("b"))
	}
	ids := map[string]bool{}
	for _, c := range []string{"a", "b"} {
		for _, l := range loopSpecs(c) {
			if ids[l.id] {
				t.Fatalf("loop id %q is shared by two chains", l.id)
			}
			ids[l.id] = true
		}
	}
	if os.Getenv("QV_REQUIRE_INFRA") != "1" {
		t.Skip("QV_REQUIRE_INFRA != 1: the Temporal part needs `make infra-up`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	const addr = "127.0.0.1:7233"
	if err := RegisterNamespace(ctx, addr, "default"); err != nil {
		t.Fatal(err)
	}
	c, err := client.DialContext(ctx, client.Options{HostPort: addr, Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	suffix := fmt.Sprint(time.Now().UnixNano())
	chains := []string{"seam-a-" + suffix, "seam-b-" + suffix}
	for _, ch := range chains {
		ch := ch
		w := worker.New(c, QueueFor(ch), worker.Options{})
		w.RegisterWorkflowWithOptions(func(ctx workflow.Context) (string, error) {
			var who string
			err := workflow.ExecuteActivity(workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: 10 * time.Second}), "WhoAmI").Get(ctx, &who)
			return who, err
		}, workflow.RegisterOptions{Name: "Probe"})
		w.RegisterActivityWithOptions(func(context.Context) (string, error) { return ch, nil }, activity.RegisterOptions{Name: "WhoAmI"})
		if err := w.Start(); err != nil {
			t.Fatal(err)
		}
		defer w.Stop()
	}
	for _, ch := range chains {
		for i := 0; i < 5; i++ { // a worker of the wrong chain would answer some of these
			run, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: fmt.Sprintf("probe:%s:%d", ch, i), TaskQueue: QueueFor(ch)}, "Probe")
			if err != nil {
				t.Fatal(err)
			}
			var who string
			if err := run.Get(ctx, &who); err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if who != ch {
				t.Fatalf("a workflow on %s was run by the worker of %s", QueueFor(ch), who)
			}
		}
	}
}
