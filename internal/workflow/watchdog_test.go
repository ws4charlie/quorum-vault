package workflow

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
)

type fakeEngine struct {
	progress   map[string]Progress
	terminated []string
	started    []string
}

func (f *fakeEngine) Describe(_ context.Context, id string) (Progress, error) {
	return f.progress[id], nil
}
func (f *fakeEngine) Terminate(_ context.Context, id, _, _ string) error {
	f.terminated = append(f.terminated, id)
	return nil
}
func (f *fakeEngine) StartLoop(_ context.Context, id string) error {
	f.started = append(f.started, id)
	f.progress[id] = Progress{Exists: true, Running: true, RunID: "new-" + id, Events: 3}
	return nil
}

func newDog(t *testing.T, f *fakeEngine, clock *time.Time) (*Watchdog, *bytes.Buffer) {
	var buf bytes.Buffer
	return &Watchdog{Engine: f, Chain: "c", StallAfter: time.Minute, Now: func() time.Time { return *clock },
		Log:        slog.New(slog.NewTextHandler(&buf, nil)),
		OpenOwners: func(context.Context) ([]string, error) { return []string{"wd-1"}, nil }}, &buf
}

func TestWatchdogRestartsAStalledLoopAndOnlyAlertsForOwners(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fakeEngine{progress: map[string]Progress{
		ScanID("c"):       {Exists: true, Running: true, RunID: "r1", Events: 10},
		PlannerID("c"):    {Exists: true, Running: true, RunID: "r2", Events: 10},
		ReconcilerID("c"): {Exists: true, Running: true, RunID: "r3", Events: 10},
		"wd-1":            {Exists: true, Running: true, RunID: "w1", Events: 7},
	}}
	dog, logs := newDog(t, f, &now)
	dog.Check(context.Background()) // first look: everything is new

	now = now.Add(40 * time.Second)
	p := f.progress[PlannerID("c")]
	p.Events = 14 // the planner keeps writing history
	f.progress[PlannerID("c")] = p
	dog.Check(context.Background())
	if len(f.terminated) != 0 || strings.Contains(logs.String(), "ALERT") {
		t.Fatalf("nothing is stalled yet: terminated %v\n%s", f.terminated, logs)
	}

	now = now.Add(40 * time.Second) // scan, reconciler and wd-1 have been still for 80 s; the planner moved 40 s ago
	dog.Check(context.Background())
	if got := strings.Join(f.terminated, ","); got != ScanID("c")+","+ReconcilerID("c") {
		t.Fatalf("terminated %q, want the scan and the reconciler (not the planner, not the withdrawal)", got)
	}
	if strings.Join(f.started, ",") != strings.Join(f.terminated, ",") {
		t.Fatalf("started %v, terminated %v", f.started, f.terminated)
	}
	if n := strings.Count(logs.String(), "ALERT: loop workflow made no progress"); n != 2 {
		t.Fatalf("%d loop ALERTs, want 2:\n%s", n, logs)
	}
	if n := strings.Count(logs.String(), "ALERT: withdrawal or sweep workflow made no progress"); n != 1 {
		t.Fatalf("%d owner ALERTs, want 1:\n%s", n, logs)
	}

	// The alert for a stuck owner is given once, and the owner is never terminated.
	now = now.Add(time.Minute)
	dog.Check(context.Background())
	if n := strings.Count(logs.String(), "ALERT: withdrawal or sweep workflow made no progress"); n != 1 {
		t.Fatalf("owner alert repeated (%d)", n)
	}
	for _, id := range f.terminated {
		if id == "wd-1" {
			t.Fatal("a withdrawal workflow was terminated")
		}
	}
}

func TestWatchdogStartsALoopThatIsNotRunning(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fakeEngine{progress: map[string]Progress{
		ScanID("c"):       {Exists: true, Running: false, RunID: "r1"},
		PlannerID("c"):    {Exists: true, Running: true, RunID: "r2", Events: 1},
		ReconcilerID("c"): {}, // never existed
	}}
	dog, logs := newDog(t, f, &now)
	dog.OpenOwners = nil
	dog.Check(context.Background())
	if len(f.terminated) != 0 || len(f.started) != 2 {
		t.Fatalf("terminated %v started %v", f.terminated, f.started)
	}
	if !strings.Contains(logs.String(), "ALERT: loop workflow is not running") {
		t.Fatalf("no alert:\n%s", logs)
	}
}

// A loop that really stalls: its workflow task is never picked up (no worker polls the queue), which is what a task lost to
// a dying worker looks like from outside. The watchdog must alert, end that run and start another. Needs the dev Temporal
// server (`make infra-up`).
func TestWatchdogReplacesARealStalledLoop(t *testing.T) {
	if os.Getenv("QV_REQUIRE_INFRA") != "1" {
		t.Skip("QV_REQUIRE_INFRA != 1 (`make infra-up`)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := RegisterNamespace(ctx, "127.0.0.1:7233", "default"); err != nil {
		t.Fatal(err)
	}
	c, err := client.DialContext(ctx, client.Options{HostPort: "127.0.0.1:7233", Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	chain := "wd-test-" + time.Now().Format("150405.000")
	queue := "qv-watchdog-" + chain // nobody polls it
	eng := &temporalEngine{c: c, queue: queue, chain: chain}
	t.Cleanup(func() {
		for _, l := range loopSpecs(chain) {
			_ = c.TerminateWorkflow(context.Background(), l.id, "", "test cleanup")
		}
	})
	for _, l := range loopSpecs(chain) {
		if err := eng.StartLoop(ctx, l.id); err != nil {
			t.Fatal(err)
		}
	}
	before, err := eng.Describe(ctx, ScanID(chain))
	if err != nil || !before.Running {
		t.Fatalf("scan loop: %+v %v", before, err)
	}

	var buf bytes.Buffer
	dog := &Watchdog{Engine: eng, Chain: chain, StallAfter: 3 * time.Second, Log: slog.New(slog.NewTextHandler(&buf, nil))}
	var after Progress
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		dog.Check(ctx)
		after, _ = eng.Describe(ctx, ScanID(chain))
		if after.Running && after.RunID != before.RunID {
			break
		}
		time.Sleep(time.Second)
	}
	if !after.Running || after.RunID == before.RunID {
		t.Fatalf("the stalled loop was not replaced: before %+v after %+v\n%s", before, after, buf.String())
	}
	if !strings.Contains(buf.String(), "ALERT: loop workflow made no progress") {
		t.Fatalf("no ALERT logged:\n%s", buf.String())
	}
	old, _ := c.DescribeWorkflowExecution(ctx, ScanID(chain), before.RunID)
	if old.WorkflowExecutionInfo.Status.String() != "Terminated" {
		t.Fatalf("old run is %s, want Terminated", old.WorkflowExecutionInfo.Status)
	}
}
