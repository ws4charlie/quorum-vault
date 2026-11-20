package custody_test

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	sdkworkflow "go.temporal.io/sdk/workflow"
)

// Graceful stop of qv-worker (SIGTERM). Two tests:
//   - the real binary, restarted while a withdrawal waits for its signature: readiness flips first, the process exits 0 well inside the bound,
//     the next worker carries the withdrawal to one settlement, Reconcile is clean;
//   - the Temporal worker's stop timeout as qv-worker configures it (worker.Options.WorkerStopTimeout, set by workflow.NewWorker): an activity
//     in flight finishes and is not run twice; a stuck one is abandoned at the bound and retried by another worker.

func (s *system) readyz(addr string) int {
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestWorkerRestartDuringWithdrawalSettlesOnce(t *testing.T) {
	s, _ := funded(t, opts{}, "c-gstop", 5)
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("graceful stop")
		}
	})
	// The worker under test, with a health listener and a 30 s bound.
	s.worker.stop()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	w1 := s.spawn("qv-worker", nil, "-config", s.cfgPath, "-dsn", s.bizDSN, "-task-queue", s.queue, "-auto-approver-key-file", s.keyPath,
		"-health-listen", addr, "-stop-timeout", "30s")
	s.worker = w1
	s.waitFor(30*time.Second, "worker started", func() bool { return fileContains(w1.log, "qv-worker started") })
	s.waitFor(10*time.Second, "worker ready", func() bool { return s.readyz(addr) == 200 })

	// The gateway is down, so the withdrawal sits in its sign wait: an activity in flight.
	s.gateway.kill()
	dest := randAddr()
	w := s.withdraw("initiator", "k-gstop", "c-gstop", "ETH", dest, new(big.Int).Div(eth(1), big.NewInt(4)))
	s.waitFor(30*time.Second, "job enqueued", func() bool {
		return s.count(`SELECT count(*) FROM sign_jobs WHERE id LIKE 'wd:%' AND status='pending'`) >= 1
	})
	time.Sleep(scaled(2 * time.Second)) // the sign wait is running

	start := time.Now()
	if err := w1.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	s.waitFor(5*time.Second, "readiness drops first", func() bool { return s.readyz(addr) == 503 || w1.exited() })
	if w1.exited() {
		t.Fatal("the worker exited before it reported not ready")
	}
	code, ok := w1.exitCode(25 * time.Second)
	if !ok || code != 0 {
		t.Fatalf("worker after SIGTERM: exited=%v code=%d (want 0 inside the bound)", ok, code)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("the sign wait did not hand back at the stop: the worker took %s", d)
	}
	if !fileContains(w1.log, "qv-worker stopping") || !fileContains(w1.log, "qv-worker stopped") {
		t.Fatalf("log lacks the stop lines")
	}
	if got := s.getWd(w.ID).Status; got != "signing" {
		t.Fatalf("withdrawal while no worker runs: %s", got)
	}

	// The next worker and the gateway finish it: one settlement.
	s.startGateway()
	s.startWorker("")
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	s.waitIdle(30 * time.Second)
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE id LIKE 'wd:%' AND status='done'`); n != 1 {
		t.Fatalf("signed jobs = %d, want 1", n)
	}
	if got := s.ethBalance(dest); got.Cmp(new(big.Int).Div(eth(1), big.NewInt(4))) != 0 {
		t.Fatalf("destination received %s, want one payment of 0.25 ETH", got)
	}
	s.reconcileClean()
}

// stopProbeWorkflow runs one activity with unlimited retries and a short StartToClose.
func stopProbeWorkflow(ctx sdkworkflow.Context, _ string) (string, error) {
	ctx = sdkworkflow.WithActivityOptions(ctx, sdkworkflow.ActivityOptions{StartToCloseTimeout: 8 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{InitialInterval: 200 * time.Millisecond, BackoffCoefficient: 1}})
	var out string
	err := sdkworkflow.ExecuteActivity(ctx, "StopProbe").Get(ctx, &out)
	return out, err
}

func TestWorkerStopTimeoutFinishesOrAbandons(t *testing.T) {
	s := newSystem(t, opts{})
	newWorker := func(q string, stopTimeout time.Duration, act func(ctx context.Context) (string, error)) worker.Worker {
		w := worker.New(s.tc, q, worker.Options{WorkerStopTimeout: stopTimeout})
		w.RegisterWorkflowWithOptions(stopProbeWorkflow, sdkworkflow.RegisterOptions{Name: "StopProbeWorkflow"})
		w.RegisterActivityWithOptions(act, activity.RegisterOptions{Name: "StopProbe"})
		return w
	}
	run := func(q string) client.WorkflowRun {
		r, err := s.tc.ExecuteWorkflow(s.ctx, client.StartWorkflowOptions{ID: "stopprobe-" + uuid.NewString(), TaskQueue: q}, "StopProbeWorkflow", "x")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("in flight finishes and is not run twice", func(t *testing.T) {
		q := "gstop-" + uuid.NewString()
		var runs atomic.Int32
		started := make(chan struct{}, 1)
		act := func(ctx context.Context) (string, error) {
			runs.Add(1)
			started <- struct{}{}
			time.Sleep(3 * time.Second) // a normal activity: shorter than the bound
			return "done", nil
		}
		w1 := newWorker(q, 20*time.Second, act)
		if err := w1.Start(); err != nil {
			t.Fatal(err)
		}
		r := run(q)
		<-started
		t0 := time.Now()
		w1.Stop() // returns when the activity has finished
		if d := time.Since(t0); d < 2*time.Second || d > 15*time.Second {
			t.Fatalf("Stop took %s: it should wait for the 3 s activity and not for the bound", d)
		}
		w2 := newWorker(q, 20*time.Second, act) // another worker takes the workflow task that records the result
		if err := w2.Start(); err != nil {
			t.Fatal(err)
		}
		defer w2.Stop()
		var got string
		if err := r.Get(s.ctx, &got); err != nil || got != "done" {
			t.Fatalf("result %q err %v", got, err)
		}
		if n := runs.Load(); n != 1 {
			t.Fatalf("the activity ran %d times, want 1", n)
		}
	})

	t.Run("stuck is abandoned at the bound and retried elsewhere", func(t *testing.T) {
		q := "gstop-" + uuid.NewString()
		var runs atomic.Int32
		started := make(chan struct{}, 1)
		act := func(ctx context.Context) (string, error) {
			if runs.Add(1) == 1 {
				started <- struct{}{}
				<-ctx.Done() // stuck: only the cancel at the bound ends it
				return "", ctx.Err()
			}
			return "retried", nil
		}
		w1 := newWorker(q, 2*time.Second, act)
		if err := w1.Start(); err != nil {
			t.Fatal(err)
		}
		r := run(q)
		<-started
		t0 := time.Now()
		w1.Stop()
		if d := time.Since(t0); d < 1500*time.Millisecond || d > 6*time.Second {
			t.Fatalf("Stop took %s, want about the 2 s bound", d)
		}
		w2 := newWorker(q, 2*time.Second, act)
		if err := w2.Start(); err != nil {
			t.Fatal(err)
		}
		defer w2.Stop()
		var got string
		if err := r.Get(s.ctx, &got); err != nil || got != "retried" {
			t.Fatalf("result %q err %v", got, err)
		}
		if n := runs.Load(); n != 2 {
			t.Fatalf("the activity ran %d times, want 2 (abandoned once, retried once)", n)
		}
	})
}
