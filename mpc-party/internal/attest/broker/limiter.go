package broker

import (
	"sync"
	"time"
)

// limiter is a token bucket per party: burst tokens, refilled at perMinute per minute.
type limiter struct {
	mu        sync.Mutex
	perMinute float64
	burst     float64
	b         map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(perMinute, burst int) *limiter {
	return &limiter{perMinute: float64(perMinute), burst: float64(burst), b: map[string]*bucket{}}
}

func (l *limiter) allow(party string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.b[party]
	if !ok {
		b = &bucket{tokens: l.burst, at: now}
		l.b[party] = b
	}
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(l.burst, b.tokens+d.Minutes()*l.perMinute)
		b.at = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
