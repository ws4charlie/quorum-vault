package workflow

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// feeCapsHoldForTest is the hold of the runs below (0: the production hour).
var feeCapsHoldForTest time.Duration

const feeCapsRefusal = "tx_mismatch: btc: transaction does not match intent: " + btc.FeeCapsSeqNote

// feeCapsRun runs a withdrawal whose first send the zone refuses for another fee-cap change. rebuild is what each call of the RebuildWithdrawalJob
// activity answers; the job is accepted (done) once a rebuild returned true.
func feeCapsRun(t *testing.T, rebuild func(n int) (bool, error)) (calls []string, werr error) {
	t.Helper()
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	env.RegisterWorkflow(WithdrawalWorkflow)
	var mu sync.Mutex
	rec := func(name string) { mu.Lock(); calls = append(calls, name); mu.Unlock() }
	reg := func(name string, fn any) { env.RegisterActivityWithOptions(fn, activity.RegisterOptions{Name: name}) }
	rebuilds, rebuiltOK := 0, false
	reg("LoadWithdrawal", func(context.Context, string) (WdState, error) {
		return WdState{Status: custody.WdSigning, Part: "p"}, nil
	})
	reg("WaitJob", func(_ context.Context, _ string, _ time.Duration) (JobResult, error) {
		rec("WaitJob")
		mu.Lock()
		defer mu.Unlock()
		if rebuiltOK {
			return JobResult{Status: custody.JobDone}, nil
		}
		return JobResult{Status: custody.JobRejected, Reason: feeCapsRefusal}, nil
	})
	reg("RebuildWithdrawalJob", func(context.Context, string) (bool, error) {
		rec("Rebuild")
		mu.Lock()
		defer mu.Unlock()
		rebuilds++
		ok, err := rebuild(rebuilds)
		rebuiltOK = rebuiltOK || (ok && err == nil)
		return ok, err
	})
	reg("Park", func(_ context.Context, o OwnerArg, reason string) error { rec("Park:" + reason); return nil })
	reg("BroadcastJob", func(context.Context, OwnerArg, string) (string, error) { rec("Broadcast"); return "h1", nil })
	reg("RecordBroadcast", func(context.Context, OwnerArg, string) error { rec("RecordBroadcast"); return nil })
	reg("WaitNonce", func(context.Context, OwnerArg, time.Duration) (NonceResult, error) {
		rec("WaitNonce")
		return NonceResult{State: custody.AttemptMined, Hash: "h1"}, nil
	})
	reg("SettleWithdrawal", func(context.Context, string, string) error { rec("Settle"); return nil })
	reg("VoidWithdrawal", func(context.Context, string, string, string) error { rec("Void"); return nil })
	reg("EnqueueCancel", func(context.Context, OwnerArg) (string, error) { rec("EnqueueCancel"); return "", nil })
	reg("NothingToFree", func(context.Context, OwnerArg) (FreeResult, error) {
		rec("NothingToFree")
		return FreeResult{Free: true}, nil
	})
	env.ExecuteWorkflow(WithdrawalWorkflow, Input{ID: "w1", T: Timings{SignTimeout: time.Second, StuckAfter: time.Hour, MaxReplacements: 1, HotPoll: time.Second, FeeCapsHold: feeCapsHoldForTest}})
	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	return calls, env.GetWorkflowError()
}

func count(calls []string, name string) (n int) {
	for _, c := range calls {
		if c == name {
			n++
		}
	}
	return
}

// The zone refused the first send for another fee-cap change; the core rebuilds, the second send is signed and goes out. The withdrawal is settled,
// never voided, and no cancel runs.
func TestFeeCapsRefusalRebuildsAndTheSecondSendGoesOut(t *testing.T) {
	calls, err := feeCapsRun(t, func(int) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("%v (calls %v)", err, calls)
	}
	if count(calls, "Rebuild") != 1 || count(calls, "WaitJob") != 2 || count(calls, "Broadcast") != 1 || count(calls, "Settle") != 1 ||
		count(calls, "Void") != 0 || count(calls, "EnqueueCancel") != 0 || count(calls, "NothingToFree") != 0 {
		t.Fatalf("activities %v", calls)
	}
}

// Too few outputs for the rebuild keeps the withdrawal waiting (nothing voided) until the outputs are there.
func TestFeeCapsRefusalKeepsWaitingWhenOutputsAreShort(t *testing.T) {
	calls, err := feeCapsRun(t, func(n int) (bool, error) {
		if n <= 3 {
			return false, temporal.NewNonRetryableApplicationError("not enough available outputs", errNoOutputs, nil)
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("%v (calls %v)", err, calls)
	}
	if count(calls, "Rebuild") != 4 || count(calls, "Settle") != 1 || count(calls, "Void") != 0 || count(calls, "EnqueueCancel") != 0 {
		t.Fatalf("activities %v", calls)
	}
}

// A rebuild that does nothing (false) or fails for another reason falls through to the old refusal path: cancel, then void.
func TestFeeCapsRefusalThatCannotBeRebuiltTakesTheOldPath(t *testing.T) {
	for name, rebuild := range map[string]func(int) (bool, error){
		"false": func(int) (bool, error) { return false, nil },
		"error": func(int) (bool, error) {
			return false, temporal.NewNonRetryableApplicationError("it broke", "other", errors.New("x"))
		},
	} {
		calls, err := feeCapsRun(t, rebuild)
		if err != nil {
			t.Fatalf("%s: %v (calls %v)", name, err, calls)
		}
		if count(calls, "Rebuild") != 1 || count(calls, "EnqueueCancel") != 1 || count(calls, "Void") != 1 || count(calls, "Settle") != 0 || strings.Contains(strings.Join(calls, ","), "Broadcast") {
			t.Fatalf("%s: activities %v", name, calls)
		}
	}
}

// The zone keeps refusing for fee caps (a forged or stale row in the core): the withdrawal is rebuilt and waits, and after the hold it is PARKED with the zone's
// reason, which is its visible state; nothing was signed, so nothing is voided and no cancel runs. It does not retry for ever.
func TestFeeCapsRefusalThatNeverClearsIsParkedWithTheZonesReason(t *testing.T) {
	feeCapsHoldForTest = 10 * time.Second
	defer func() { feeCapsHoldForTest = 0 }()
	calls, err := feeCapsRun(t, func(int) (bool, error) {
		return false, temporal.NewNonRetryableApplicationError("not enough available outputs", errNoOutputs, nil)
	})
	_ = err
	parked := ""
	for _, c := range calls {
		if strings.HasPrefix(c, "Park:") {
			parked = c
		}
	}
	if parked == "" || !strings.Contains(parked, "core and zone are on different fee-cap changes") {
		t.Fatalf("not parked with the zone's reason (calls %v, err %v)", calls, err)
	}
	if count(calls, "Void") != 0 || count(calls, "EnqueueCancel") != 0 || count(calls, "Broadcast") != 0 {
		t.Fatalf("parked, but also: %v", calls)
	}
}
