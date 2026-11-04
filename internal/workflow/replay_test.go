package workflow

import (
	"os"
	"path/filepath"
	"testing"

	"go.temporal.io/sdk/worker"
)

// Histories recorded from real end-to-end runs (e2e/custody, QV_RECORD_HISTORY)
// must replay against the current workflow code. If this fails after a workflow
// change, the change is not backward compatible with running executions: version
// it (workflow.GetVersion) or re-record the histories deliberately.
func TestRecordedHistoriesReplay(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	if len(files) == 0 {
		t.Skip("no recorded histories in testdata")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			if _, err := os.Stat(f); err != nil {
				t.Skip(err)
			}
			rp := worker.NewWorkflowReplayer()
			rp.RegisterWorkflow(WithdrawalWorkflow)
			rp.RegisterWorkflow(SweepWorkflow)
			if err := rp.ReplayWorkflowHistoryFromJSONFile(nil, f); err != nil {
				t.Fatalf("replay %s: %v", f, err)
			}
		})
	}
}
