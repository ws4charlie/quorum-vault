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

func TestTheCacheIsBoundedAndPrefersDeadEntries(t *testing.T) {
	c := newSigCache()
	now := time.Now()
	for i := 0; i < sigCacheMax+500; i++ {
		c.store(digest(i), now.Add(time.Hour), now, 0)
	}
	if len(c.m) != sigCacheMax {
		t.Fatalf("%d entries, bound %d", len(c.m), sigCacheMax)
	}
	later := now.Add(sigCacheTTL + time.Second) // everything above is dead now
	c.store(digest(-1), later.Add(time.Hour), later, 0)
	if len(c.m) != 1 {
		t.Fatalf("dead entries were kept: %d", len(c.m))
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
