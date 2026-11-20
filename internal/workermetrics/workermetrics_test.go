package workermetrics

import (
	"bytes"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegistryWritesSDKMetricsAndState(t *testing.T) {
	r := New(40 * time.Second)
	h := r.WithTags(map[string]string{"namespace": "default", "task_queue": "qv-core-eth"})
	h.WithTags(map[string]string{"workflow_type": "SweepWorkflow"}).Counter("temporal_workflow_failed").Inc(1)
	h.WithTags(map[string]string{"workflow_type": "SweepWorkflow"}).Counter("temporal_workflow_failed").Inc(2)
	h.Gauge("temporal_num_pollers").Update(5)
	h.Timer("temporal_workflow_task_schedule_to_start_latency").Record(2 * time.Second)
	h.Timer("temporal_workflow_task_schedule_to_start_latency").Record(90 * time.Second)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`qv_worker_workflow_failed_total{namespace="default",task_queue="qv-core-eth",workflow_type="SweepWorkflow"} 3`,
		`qv_worker_num_pollers{namespace="default",task_queue="qv-core-eth"} 5`,
		`qv_worker_workflow_task_schedule_to_start_latency_seconds_bucket{namespace="default",task_queue="qv-core-eth",le="5"} 1`,
		`qv_worker_workflow_task_schedule_to_start_latency_seconds_bucket{namespace="default",task_queue="qv-core-eth",le="+Inf"} 2`,
		`qv_worker_workflow_task_schedule_to_start_latency_seconds_count{namespace="default",task_queue="qv-core-eth"} 2`,
		"qv_worker_ready 0\n", "qv_worker_stopping 0\n", "qv_worker_stop_timeout_seconds 40\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	r.SetReady(true)
	r.SetStopping()
	var b bytes.Buffer
	r.Write(&b)
	if !strings.Contains(b.String(), "qv_worker_ready 1\n") || !strings.Contains(b.String(), "qv_worker_stopping 1\n") {
		t.Errorf("state not published:\n%s", b.String())
	}
}

func kindOf(published string) string {
	switch {
	case strings.HasSuffix(published, "_total"):
		return "counter"
	case strings.HasSuffix(published, "_seconds"):
		return "histogram"
	}
	return "gauge"
}

func TestRuleMetricsArePublishedNames(t *testing.T) {
	for pub, sdk := range RuleMetrics {
		if got := promName(sdk, kindOf(pub)); got != pub {
			t.Errorf("%s is published as %s", sdk, got)
		}
	}
}

// Every SDK name a rule relies on must be one the SDK defines: a renamed metric after an SDK upgrade fails here, not silently in production.
func TestRuleMetricsExistInSDK(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "go.temporal.io/sdk").Output()
	dir := strings.TrimSpace(string(out))
	if err != nil || dir == "" {
		t.Fatalf("cannot find the Temporal SDK source: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "internal", "common", "metrics", "constants.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sdk := range RuleMetrics {
		if !strings.Contains(string(b), `TemporalMetricsPrefix + "`+strings.TrimPrefix(sdk, "temporal_")+`"`) {
			t.Errorf("the SDK defines no metric %s", sdk)
		}
	}
}
