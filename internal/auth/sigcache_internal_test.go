package auth

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func digest(n int) (h [sha256.Size]byte) {
	binary.BigEndian.PutUint64(h[:], uint64(n))
	return
}

func TestAFullCacheSkipsNewTokensAndSweepsDeadOnesOncePerInterval(t *testing.T) {
	c := newSigCache()
	now := time.Now()
	for i := 0; i < sigCacheMax+500; i++ {
		c.store(digest(i), now.Add(time.Hour), now, 0)
	}
	if len(c.m) != sigCacheMax {
		t.Fatalf("%d entries, bound %d", len(c.m), sigCacheMax)
	}
	if _, ok := c.m[digest(sigCacheMax+1)]; ok {
		t.Fatal("a new token was stored in a full cache")
	}
	if _, ok := c.m[digest(0)]; !ok {
		t.Fatal("a live entry was evicted")
	}
	later := now.Add(sigCacheTTL + time.Second) // everything above is dead now
	c.store(digest(-1), later.Add(time.Hour), later, 0)
	if len(c.m) != 1 {
		t.Fatalf("dead entries were kept: %d", len(c.m))
	}
	// Within one interval of a sweep, a full cache is not scanned again.
	for i := 0; i < sigCacheMax; i++ {
		c.store(digest(i), later.Add(time.Hour), later, 0)
	}
	swept := c.swept
	c.store(digest(-2), later.Add(time.Hour), later.Add(sigCacheSweep/2), 0)
	if !c.swept.Equal(swept) {
		t.Fatal("a full cache was swept twice within one interval")
	}
}

func TestAnEntryNeverOutlivesTheTokenOrTheLimit(t *testing.T) {
	c := newSigCache()
	now := time.Now()
	c.store(digest(1), now.Add(10*time.Second), now, 0)
	c.store(digest(2), now.Add(time.Hour), now, 0)
	c.store(digest(3), now.Add(-time.Second), now, 0) // already expired: not stored
	if got := c.m[digest(1)]; !got.Equal(now.Add(10 * time.Second)) {
		t.Fatal(got)
	}
	if got := c.m[digest(2)]; !got.Equal(now.Add(sigCacheTTL)) {
		t.Fatal(got)
	}
	if _, ok := c.m[digest(3)]; ok {
		t.Fatal("an expired token was stored")
	}
}

func TestAStoreFromBeforeAKeySetChangeIsDropped(t *testing.T) {
	c := newSigCache()
	now := time.Now()
	g := c.generation()
	c.clear()
	c.store(digest(1), now.Add(time.Hour), now, g)
	if len(c.m) != 0 {
		t.Fatal("a token verified against the old key set was stored")
	}
}

func TestCacheRaceUnderLoad(t *testing.T) {
	c := newSigCache()
	now := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				h := digest(g*100000 + i)
				c.store(h, now.Add(time.Hour), now, c.generation())
				c.has(h, now)
				if i%1000 == 0 {
					c.clear()
				}
			}
		}(g)
	}
	wg.Wait()
}

// A flood of new tokens at a full cache must not make hits wait: no store may scan the map while holding the lock a hit needs.
func TestHitsDoNotWaitForStoresAtAFullCache(t *testing.T) {
	c := newSigCache()
	now := time.Now()
	for i := 0; i < sigCacheMax; i++ {
		c.store(digest(i), now.Add(time.Hour), now, 0)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					c.store(digest(1_000_000+g*10_000_000+i), now.Add(time.Hour), now, 0)
				}
			}
		}(g)
	}
	start := time.Now()
	const n = 20000
	for i := 0; i < n; i++ {
		if !c.has(digest(i%sigCacheMax), now) {
			t.Fatal("a stored entry was lost")
		}
	}
	per := time.Since(start) / n
	close(stop)
	wg.Wait()
	if per > 20*time.Microsecond {
		t.Fatalf("a hit took %v while new tokens kept arriving at a full cache", per)
	}
}
