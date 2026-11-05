package server

import (
	"errors"
	"sync"
	"time"
)

// ErrLimit marks a refusal caused by a configured limit. Nothing ran.
var ErrLimit = errors.New("limit exceeded")

// rateLimiter: token bucket per key, rate tokens/s with burst = max(1, rate).
type rateLimiter struct {
	mu    sync.Mutex
	rate  float64
	b     map[string]*bucket
	now   func() time.Time
	sweep time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newRateLimiter(rate float64) *rateLimiter {
	return &rateLimiter{rate: rate, b: map[string]*bucket{}, now: time.Now}
}

func (r *rateLimiter) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	burst := r.rate
	if burst < 1 {
		burst = 1
	}
	b := r.b[key]
	if b == nil {
		b = &bucket{tokens: burst, at: now}
		r.b[key] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * r.rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.at = now
	if now.Sub(r.sweep) > time.Minute { // drop idle full buckets
		for k, v := range r.b {
			if now.Sub(v.at) > time.Minute {
				delete(r.b, k)
			}
		}
		r.sweep = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// slots limits concurrent sessions without ever blocking: acquire fails at once when full.
type slots struct {
	mu   sync.Mutex
	n, m int
}

func newSlots(max int) *slots { return &slots{m: max} }

func (s *slots) acquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n >= s.m {
		return false
	}
	s.n++
	return true
}

func (s *slots) release() { s.mu.Lock(); s.n--; s.mu.Unlock() }

func (s *slots) active() int { s.mu.Lock(); defer s.mu.Unlock(); return s.n }

// replayCache remembers session ids that were ever accepted; an OPEN for a known id is refused. Bounded FIFO.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]struct{}
	ring []string
	pos  int
}

func newReplayCache(n int) *replayCache {
	return &replayCache{seen: make(map[string]struct{}, n), ring: make([]string, n)}
}

// add returns false if id was already seen.
func (c *replayCache) add(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[id]; ok {
		return false
	}
	if old := c.ring[c.pos]; old != "" {
		delete(c.seen, old)
	}
	c.ring[c.pos] = id
	c.pos = (c.pos + 1) % len(c.ring)
	c.seen[id] = struct{}{}
	return true
}
