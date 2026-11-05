package gateway

import (
	"os"
	"sort"
	"testing"
	"time"
)

// TestMeasureCostPerSignedJob prints how long one signed job takes through the gateway (claim, decide, reserve, sign with the
// HSM, store, complete). Run it with QV_MEASURE=1 before and after a change to the decision path and compare:
//
//	QV_MEASURE=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -run TestMeasureCostPerSignedJob -v ./internal/gateway/
func TestMeasureCostPerSignedJob(t *testing.T) {
	if os.Getenv("QV_MEASURE") != "1" {
		t.Skip("QV_MEASURE != 1")
	}
	h := newHarness(t)
	const n = 300
	d := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		j := h.withdrawal("m"+string(rune('a'+i/26/26%26))+string(rune('a'+i/26%26))+string(rune('a'+i%26)), addrUser, 1, uint64(i), "alice")
		h.put(j)
		start := time.Now()
		dec, ok, err := h.gw.RunOnce(t.Context())
		if err != nil || !ok || dec.Outcome != OutcomeSigned {
			t.Fatalf("job %d: ok=%v err=%v outcome=%s %s", i, ok, err, dec.Outcome, dec.Reason)
		}
		d = append(d, time.Since(start))
	}
	sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	t.Logf("signed jobs: %d  mean %.2f ms  median %.2f ms  p95 %.2f ms", n, float64(sum/n)/1e6, float64(d[n/2])/1e6, float64(d[n*95/100])/1e6)
}
