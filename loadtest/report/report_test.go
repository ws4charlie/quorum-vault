package report

import (
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/loadtest/gen"
)

func TestRender(t *testing.T) {
	res := &gen.Result{RunID: "r1", Scenario: &gen.Scenario{Name: "demo", Mode: "open", RampS: 5, StepS: 10, Steps: []float64{1, 2}}, Pass: false,
		Checks:  []gen.CheckResult{{Name: "reconcile_clean", OK: false, Detail: "not clean <b>"}},
		Total:   map[string]*gen.OpSummary{"withdraw:auto": {Offered: 3, OK: 2, Errors: map[string]int{"timeout": 1}, Latency: map[string]gen.Quantiles{"total": {N: 2, P50: 10, P95: 20}}}},
		Series:  []gen.SeriesPoint{{T: 1, Offered: map[string]int64{"withdraw:auto": 1}, Done: map[string]int64{}, Inflight: map[string]int64{"withdraw:auto": 1}}, {T: 2, Offered: map[string]int64{"withdraw:auto": 3}, Done: map[string]int64{"withdraw:auto": 1}, Inflight: map[string]int64{"withdraw:auto": 2}}},
		Windows: map[string][]gen.Window{"withdraw:auto": {{T: 2.5, N: 1, P50: 10, P95: 20}}}}
	st := &StackSeries{IntervalS: 1, T: []float64{1, 2}, Series: map[string][]float64{"cpu:qv-core-1": {10, 20}, "queue:x": {1, 2}}}
	h := Render(res, st)
	for _, want := range []string{"Load run r1", "FAILED", "not clean &lt;b&gt;", "withdraw:auto", "<svg", "CPU per process", "timeout 1"} {
		if !strings.Contains(h, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(h, "<script") || strings.Contains(h, "http://") || strings.Contains(h, "https://") {
		t.Error("the report must need nothing from outside")
	}
}
