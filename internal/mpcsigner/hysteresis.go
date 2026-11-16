package mpcsigner

import (
	"fmt"
	"time"
)

// Thresholds are the health rules of the signing route. A party or link is routed away from after FailCount failed checks within Window,
// and routed back only after RecoverCount consecutive good checks. One failed check, or one failed signature, never moves a route.
type Thresholds struct {
	FailCount    int           // N: failed checks within Window that make something unhealthy
	Window       time.Duration // T
	RecoverCount int           // M: consecutive good checks that make it healthy again
}

// DefaultThresholds: three failures in 30 s (probes every 5 s), six good checks in a row (30 s) to come back.
func DefaultThresholds() Thresholds {
	return Thresholds{FailCount: 3, Window: 30 * time.Second, RecoverCount: 6}
}

// Validate fills nothing in: a zero field is an error, so a config typo cannot silently turn the hysteresis off.
func (t Thresholds) Validate(interval time.Duration) error {
	switch {
	case t.FailCount < 1:
		return fmt.Errorf("fail_count must be at least 1")
	case t.RecoverCount < 1:
		return fmt.Errorf("recover_count must be at least 1")
	case t.Window <= 0:
		return fmt.Errorf("fail_window must be positive")
	case interval <= 0:
		return fmt.Errorf("probe_interval must be positive")
	case time.Duration(t.FailCount-1)*interval >= t.Window:
		// N failures cannot fit in T at this probe rate: the party could never be marked unhealthy.
		return fmt.Errorf("fail_count %d at a probe interval of %s needs a fail_window longer than %s (got %s): a party could never be routed away from",
			t.FailCount, interval, time.Duration(t.FailCount-1)*interval, t.Window)
	}
	return nil
}

// tracker is the hysteresis state of one thing (a party, or a link between two parties). It starts healthy: a gateway that has just started
// signs on the preferred pair until checks say otherwise.
type tracker struct {
	th      Thresholds
	healthy bool
	fails   []time.Time // failed checks inside the window, oldest first
	good    int         // consecutive good checks since the last failure (counted while unhealthy)
}

func newTracker(th Thresholds) *tracker { return &tracker{th: th, healthy: true} }

// observe records one check and reports whether the state changed.
func (t *tracker) observe(ok bool, now time.Time) (changed bool) {
	cut := now.Add(-t.th.Window)
	i := 0
	for i < len(t.fails) && !t.fails[i].After(cut) {
		i++
	}
	t.fails = t.fails[i:]
	if t.healthy {
		if ok {
			return false // old failures age out of the window by themselves
		}
		t.fails = append(t.fails, now)
		t.good = 0
		if len(t.fails) >= t.th.FailCount {
			t.healthy = false
			return true
		}
		return false
	}
	if !ok {
		t.good = 0
		return false
	}
	t.good++
	if t.good >= t.th.RecoverCount {
		t.healthy, t.fails, t.good = true, nil, 0
		return true
	}
	return false
}
