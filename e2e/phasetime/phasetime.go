// Package phasetime is the per-test timing log of the end-to-end harnesses (EVM and Bitcoin): how long a test spent in each start-up
// phase, in its body, and in teardown. Always on and cheap: one clock read per phase and one log line per test,
//
//	qv-timing test=TestX db=0.31 dkg=1.70 chain=0.42 spawn=2.10 body=12.40 cleanup=0.30 total=17.2
//
// (keys in the order the phases ran; seconds). When $QV_E2E_TIMING_FILE is set, one JSON line per test is appended to it as well, with the
// condition waits of half a second or more and what they waited on. The tables in docs/measurements/e2e-timing.md are made from it.
package phasetime

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type Timer struct {
	mu      sync.Mutex
	name    string
	mode    string
	t0      time.Time
	last    time.Time
	phases  []Phase
	ready   time.Time
	bodyEnd time.Time
	waits   []Wait
}

type Phase struct {
	Name string  `json:"name"`
	Sec  float64 `json:"sec"`
}

type Wait struct {
	What string  `json:"what"`
	Sec  float64 `json:"sec"`
}

// Start begins timing the test. Call it first in the harness's constructor: its cleanup is registered first, so it runs last, after
// everything else has been torn down. mode is a free label for the JSON line (the EVM signer mode, or the chain).
func Start(t *testing.T, mode string) *Timer {
	now := time.Now()
	tm := &Timer{name: t.Name(), mode: mode, t0: now, last: now}
	t.Cleanup(func() { tm.finish(t) })
	return tm
}

// Phase closes the current start-up phase under key (a short word: db, dkg, chain, spawn, ...). A key used twice adds up.
func (tm *Timer) Phase(key string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	now := time.Now()
	tm.phases = append(tm.phases, Phase{key, now.Sub(tm.last).Seconds()})
	tm.last = now
}

// Ready marks the end of start-up: the test body begins. It also registers the end of the body, the first cleanup to run.
func (tm *Timer) Ready(t *testing.T) {
	tm.mu.Lock()
	tm.ready = time.Now()
	tm.mu.Unlock()
	t.Cleanup(func() {
		tm.mu.Lock()
		tm.bodyEnd = time.Now()
		tm.mu.Unlock()
	})
}

// Wait records one condition wait; those under half a second are not worth a line.
func (tm *Timer) Wait(what string, d time.Duration) {
	if tm == nil || d < 500*time.Millisecond {
		return
	}
	tm.mu.Lock()
	tm.waits = append(tm.waits, Wait{what, d.Seconds()})
	tm.mu.Unlock()
}

func (tm *Timer) finish(t *testing.T) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	end := time.Now()
	ready, bodyEnd := tm.ready, tm.bodyEnd
	if ready.IsZero() { // the test failed or returned before start-up was over
		ready, bodyEnd = end, end
	}
	if bodyEnd.IsZero() {
		bodyEnd = end
	}
	startup, body, cleanup, total := ready.Sub(tm.t0).Seconds(), bodyEnd.Sub(ready).Seconds(), end.Sub(bodyEnd).Seconds(), end.Sub(tm.t0).Seconds()
	var sb strings.Builder
	fmt.Fprintf(&sb, "qv-timing test=%s", tm.name)
	sum := map[string]float64{}
	var order []string
	for _, p := range tm.phases {
		if _, ok := sum[p.Name]; !ok {
			order = append(order, p.Name)
		}
		sum[p.Name] += p.Sec
	}
	for _, k := range order {
		fmt.Fprintf(&sb, " %s=%.2f", k, sum[k])
	}
	fmt.Fprintf(&sb, " body=%.2f cleanup=%.2f total=%.2f", body, cleanup, total)
	if t.Failed() {
		sb.WriteString(" failed=true")
	}
	t.Log(sb.String())
	if p := os.Getenv("QV_E2E_TIMING_FILE"); p != "" {
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			b, _ := json.Marshal(map[string]any{"test": tm.name, "mode": tm.mode, "total": total, "startup": startup, "body": body, "teardown": cleanup,
				"phases": tm.phases, "waits": tm.waits, "failed": t.Failed()})
			fmt.Fprintln(f, string(b))
			f.Close()
		}
	}
}
