package cbmpc

import (
	"runtime"
	"testing"
	"time"
)

type counts struct{ goroutines int }

func threadsAndGoroutines() counts { return counts{runtime.NumGoroutine()} }

func waitGoroutines(t *testing.T, max int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > max && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > max {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("goroutines did not drain: %d > %d\n%s", n, max, buf)
	}
}
