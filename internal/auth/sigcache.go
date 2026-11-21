package auth

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// A token is used for hundreds of requests in its life, and an ES256 check costs far more than everything else Verify does, so the
// signature of a token that passed full verification is remembered for a short time. Only the signature check and the key lookup are
// skipped on a hit: every claim check (expiry, not-before, issuer, audience, roles, auth_time and the login-age rules, the client
// rules) runs again on every request.
const (
	// sigCacheTTL is the longest an entry lives. It bounds how long a key the identity provider has removed (or a token it has
	// revoked by rotating the key) is still honoured when no refetch of the key set happens in between: one minute is the clock skew
	// the verifier already allows, and short enough that a rotation after a leak takes effect before anyone could act on it.
	sigCacheTTL = 60 * time.Second
	// sigCacheMax bounds the entries. One entry is a 32-byte digest and an 8-byte expiry in a map (about 100 bytes with the map's
	// own overhead), so 8192 entries are under 1 MB per replica. Only tokens that passed full verification are stored, so a caller
	// without a valid token cannot fill it; it holds as many entries as there are live tokens of this identity provider's users and services.
	sigCacheMax = 8192
	// sigCacheSweep is the least time between two passes that remove dead entries from a full cache.
	sigCacheSweep = time.Second
)

type sigCache struct {
	mu    sync.Mutex
	m     map[[sha256.Size]byte]time.Time // digest of the raw token -> when the entry stops counting
	swept time.Time                       // last pass over a full cache
	gen   uint64                          // advanced whenever the key set changes; a store made under an older value is dropped

	hits, misses atomic.Uint64
}

func newSigCache() *sigCache { return &sigCache{m: map[[sha256.Size]byte]time.Time{}} }

// generation is read before the key lookup that precedes a full verification, and handed back to store.
func (c *sigCache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// has reports whether h was verified and its entry is still alive at now. A dead entry is removed.
func (c *sigCache) has(h [sha256.Size]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[h]
	if !ok {
		c.misses.Add(1)
		return false
	}
	if !now.Before(exp) {
		delete(c.m, h)
		c.misses.Add(1)
		return false
	}
	c.hits.Add(1)
	return true
}

// store remembers h until the earlier of the token's exp and sigCacheTTL from now, unless the key set changed since gen was read or the
// cache is full of live entries (then h is not stored). It takes O(1) time, except for one sweep per sigCacheSweep when full.
func (c *sigCache) store(h [sha256.Size]byte, tokenExp, now time.Time, gen uint64) {
	until := now.Add(sigCacheTTL)
	if tokenExp.Before(until) {
		until = tokenExp
	}
	if !now.Before(until) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if _, ok := c.m[h]; !ok && len(c.m) >= sigCacheMax {
		// Full. Dead entries are swept at most once per sigCacheSweep, so a flood of new tokens costs one pass per interval, not one per
		// token (hits take the same lock). If nothing was freed the token is simply not stored: it costs one signature check per use,
		// which is the price without a cache.
		if now.Before(c.swept) || now.Sub(c.swept) >= sigCacheSweep {
			c.swept = now
			for k, e := range c.m {
				if !now.Before(e) {
					delete(c.m, k)
				}
			}
		}
		if len(c.m) >= sigCacheMax {
			return
		}
	}
	c.m[h] = until
}

// clear forgets everything; called whenever the key set is replaced.
func (c *sigCache) clear() {
	c.mu.Lock()
	c.m = map[[sha256.Size]byte]time.Time{}
	c.swept = time.Time{}
	c.gen++
	c.mu.Unlock()
}

// WriteMetrics writes the signature cache's hit and miss counts in the Prometheus text format. It reports counts only.
func (a *Authenticator) WriteMetrics(w io.Writer) {
	if a == nil || a.sigs == nil {
		return
	}
	fmt.Fprintf(w, "# HELP qv_core_auth_sigcache_hits_total Bearer tokens whose signature was already verified (signature check skipped).\n# TYPE qv_core_auth_sigcache_hits_total counter\nqv_core_auth_sigcache_hits_total %d\n", a.sigs.hits.Load())
	fmt.Fprintf(w, "# HELP qv_core_auth_sigcache_misses_total Bearer tokens whose signature was verified in full.\n# TYPE qv_core_auth_sigcache_misses_total counter\nqv_core_auth_sigcache_misses_total %d\n", a.sigs.misses.Load())
}

// WithMetrics serves h, then the authenticator's metrics.
func WithMetrics(h http.Handler, a *Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		a.WriteMetrics(w)
	})
}
