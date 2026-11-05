package gateway

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

// TestMeasureCostPerSignedJob prints, for 1, 8 and 32 workers, how many signed jobs per second the gateway completes and how long
// one job takes (claim, decide, reserve, HSM sign, store, complete). Run it before and after a change to the decision path:
//
//	QV_MEASURE=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -run TestMeasureCostPerSignedJob -v ./internal/gateway/
func TestMeasureCostPerSignedJob(t *testing.T) {
	if os.Getenv("QV_MEASURE") != "1" {
		t.Skip("QV_MEASURE != 1")
	}
	for _, workers := range []int{1, 8, 32} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			h := newHarness(t)
			const n = 320
			for i := 0; i < n; i++ {
				h.put(h.withdrawal(fmt.Sprintf("m%04d", i), addrUser, 1, uint64(i), "alice"))
			}
			var mu sync.Mutex
			d := make([]time.Duration, 0, n)
			var wg sync.WaitGroup
			start := time.Now()
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						t0 := time.Now()
						dec, ok, err := h.gw.RunOnce(t.Context())
						if err != nil {
							t.Error(err)
							return
						}
						if !ok {
							return
						}
						if dec.Outcome != OutcomeSigned {
							t.Errorf("outcome %s %s", dec.Outcome, dec.Reason)
							return
						}
						mu.Lock()
						d = append(d, time.Since(t0))
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			total := time.Since(start)
			if len(d) != n {
				t.Fatalf("%d of %d jobs signed", len(d), n)
			}
			sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
			t.Logf("workers %2d: %d jobs  %.0f jobs/s  median %.1f ms  p95 %.1f ms", workers, n, float64(n)/total.Seconds(),
				float64(d[n/2])/1e6, float64(d[n*95/100])/1e6)
		})
	}
}
