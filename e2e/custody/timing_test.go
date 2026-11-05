package custody_test

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// A small timing log for the harness: per test, how long start-up took (split in phases), how long the test body took with the
// slowest waits and what they waited on, and how long teardown took. Printed with the test's log, and appended as one JSON
// line per test to $QV_E2E_TIMING_FILE when that is set (docs/measurements/e2e-timing.md is made from it).

type timing struct {
	mu       sync.Mutex
	name     string
	t0       time.Time
	last     time.Time
	phases   []phase
	ready    time.Time
	bodyEnd  time.Time
	waits    []waitRec
	sleeping time.Duration
}

type phase struct {
	Name string  `json:"name"`
	Sec  float64 `json:"sec"`
}

type waitRec struct {
	What string  `json:"what"`
	Sec  float64 `json:"sec"`
}

func newTiming(t *testing.T) *timing {
	now := time.Now()
	return &timing{name: t.Name(), t0: now, last: now}
}

// phase closes the current start-up phase under name.
func (tm *timing) phase(name string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	now := time.Now()
	tm.phases = append(tm.phases, phase{name, now.Sub(tm.last).Seconds()})
	tm.last = now
}

func (tm *timing) markReady() {
	tm.mu.Lock()
	tm.ready = time.Now()
	tm.mu.Unlock()
}

func (tm *timing) markBodyEnd() {
	tm.mu.Lock()
	tm.bodyEnd = time.Now()
	tm.mu.Unlock()
}

// wait records one condition wait of at least half a second.
func (tm *timing) wait(what string, d time.Duration) {
	if tm == nil || d < 500*time.Millisecond {
		return
	}
	tm.mu.Lock()
	tm.waits = append(tm.waits, waitRec{what, d.Seconds()})
	tm.mu.Unlock()
}

// finish runs when the test has completely torn down.
func (tm *timing) finish(t *testing.T) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	end := time.Now()
	rec := map[string]any{
		"test": tm.name, "mode": os.Getenv("QV_CUSTODY_SIGNER"), "total": end.Sub(tm.t0).Seconds(),
		"startup": tm.ready.Sub(tm.t0).Seconds(), "body": tm.bodyEnd.Sub(tm.ready).Seconds(), "teardown": end.Sub(tm.bodyEnd).Seconds(),
		"phases": tm.phases, "waits": tm.waits, "failed": t.Failed(),
	}
	t.Logf("TIMING %s: total %.1fs = start-up %.1fs + test %.1fs + teardown %.1fs", tm.name, rec["total"], rec["startup"], rec["body"], rec["teardown"])
	if p := os.Getenv("QV_E2E_TIMING_FILE"); p != "" {
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			b, _ := json.Marshal(rec)
			fmt.Fprintln(f, string(b))
			f.Close()
		}
	}
}
