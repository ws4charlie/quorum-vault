package custody_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

// Histories recorded from real runs replay against the current workflow code:
// the code is deterministic. With QV_RECORD_HISTORY=<dir> the histories are
// also saved as JSON (internal/workflow/testdata) for the offline replay test.
func TestWorkflowReplayOfRecordedHistories(t *testing.T) {
	s, _ := funded(t, opts{}, "c-replay", 5)
	w := s.withdraw("initiator", "k-replay", "c-replay", "ETH", randAddr(), eth(2)) // two approvals: signals in the history
	s.approve("alice", w.ID)
	s.approve("bob", w.ID)
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	s.waitIdle(30 * time.Second)

	var sweepID string
	if err := s.pool.QueryRow(s.ctx, `SELECT id FROM sweeps ORDER BY created_at LIMIT 1`).Scan(&sweepID); err != nil {
		t.Fatal(err)
	}
	rp := worker.NewWorkflowReplayer()
	rp.RegisterWorkflow(workflow.WithdrawalWorkflow)
	rp.RegisterWorkflow(workflow.SweepWorkflow)
	rp.RegisterWorkflow(workflow.ScanWorkflow)
	rp.RegisterWorkflow(workflow.SweepPlannerWorkflow)
	rp.RegisterWorkflow(workflow.WithdrawalReconcilerWorkflow)

	for name, id := range map[string]string{"withdrawal": w.ID, "sweep": sweepID,
		"scan": workflow.ScanID(s.chainName), "planner": workflow.PlannerID(s.chainName), "reconciler": workflow.ReconcilerID(s.chainName)} {
		hist := historyOf(t, s, id)
		if err := rp.ReplayWorkflowHistory(nil, hist); err != nil {
			t.Fatalf("replay of %s (%s) failed: %v", name, id, err)
		}
		t.Logf("replayed %-10s %s: %d events, deterministic", name, id, len(hist.Events))
		if dir := os.Getenv("QV_RECORD_HISTORY"); dir != "" && (name == "withdrawal" || name == "sweep") {
			b, err := protojson.MarshalOptions{Multiline: true}.Marshal(hist)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func historyOf(t *testing.T, s *system, id string) *historypb.History {
	t.Helper()
	it := s.tc.GetWorkflowHistory(s.ctx, id, "", false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	h := &historypb.History{}
	for it.HasNext() {
		ev, err := it.Next()
		if err != nil {
			t.Fatal(err)
		}
		h.Events = append(h.Events, ev)
	}
	return h
}

var _ client.Client
