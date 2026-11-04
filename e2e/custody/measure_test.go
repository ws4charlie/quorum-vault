package custody_test

import (
	"fmt"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"
)

func pct(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

// TestMeasureClosedLoop prints the numbers for docs/measurements/closed-loop.md:
// time per step and end-to-end latency on a local anvil (instant blocks), with
// SoftHSM signing. Not a capacity figure.
func TestMeasureClosedLoop(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("c-measure")

	// Deposit -> credit -> swept.
	t0 := time.Now()
	s.sendETH(addr, eth(40))
	var credited, swept time.Duration
	s.waitFor(60*time.Second, "credited", func() bool {
		a, _, _ := s.balance("c-measure", "ETH")
		return a.Sign() > 0
	})
	credited = time.Since(t0)
	s.waitFor(90*time.Second, "swept", func() bool { return s.sweepsConfirmed() >= 1 && s.openWork() == 0 })
	swept = time.Since(t0)

	// One withdrawal, step by step (polling the row every 5 ms).
	type stamp struct {
		status string
		at     time.Duration
	}
	one := func(key string) (total time.Duration, steps []stamp) {
		start := time.Now()
		w := s.withdraw("initiator", key, "c-measure", "ETH", randAddr(), new(big.Int).Div(eth(1), big.NewInt(100)))
		if w.Code != 201 {
			t.Fatalf("%d %v", w.Code, w.Raw)
		}
		last := "requested"
		steps = append(steps, stamp{last, time.Since(start)})
		for {
			var st string
			if err := s.pool.QueryRow(s.ctx, `SELECT status FROM withdrawals WHERE id=$1`, w.ID).Scan(&st); err != nil {
				t.Fatal(err)
			}
			if st != last {
				steps = append(steps, stamp{st, time.Since(start)})
				last = st
			}
			if st == "confirmed" || st == "failed" {
				if st == "failed" {
					t.Fatalf("withdrawal failed")
				}
				return time.Since(start), steps
			}
			if time.Since(start) > 60*time.Second {
				t.Fatal("withdrawal did not finish")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	_, first := one("m-0") // warm
	var totals []time.Duration
	byStatus := map[string][]time.Duration{}
	for i := 1; i <= 15; i++ {
		tot, steps := one(fmt.Sprintf("m-%d", i))
		totals = append(totals, tot)
		for _, st := range steps {
			byStatus[st.status] = append(byStatus[st.status], st.at)
		}
	}
	t.Logf("deposit sent -> credited:       %v", credited.Round(10*time.Millisecond))
	t.Logf("deposit sent -> sweep confirmed: %v", swept.Round(10*time.Millisecond))
	t.Logf("first (cold) withdrawal steps: %v", first)
	for _, st := range []string{"requested", "approved", "signing", "broadcast", "confirmed"} {
		if v := byStatus[st]; len(v) > 0 {
			t.Logf("withdrawal reaches %-9s median %v  p95 %v", st, pct(v, 0.5).Round(time.Millisecond), pct(v, 0.95).Round(time.Millisecond))
		}
	}
	t.Logf("withdrawal end-to-end (15 sequential): median %v  p95 %v  max %v", pct(totals, 0.5).Round(time.Millisecond), pct(totals, 0.95).Round(time.Millisecond), pct(totals, 1).Round(time.Millisecond))

	// 20 at once.
	var wg sync.WaitGroup
	ids := make([]string, 20)
	start := time.Now()
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i] = s.withdraw("initiator", fmt.Sprintf("p-%d", i), "c-measure", "ETH", randAddr(), new(big.Int).Div(eth(1), big.NewInt(100))).ID
		}()
	}
	wg.Wait()
	for _, id := range ids {
		s.waitWd(id, "confirmed", 120*time.Second)
	}
	conc := time.Since(start)
	t.Logf("20 concurrent withdrawals: all confirmed after %v (%.1f/s)", conc.Round(10*time.Millisecond), 20/conc.Seconds())
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}
