package broker

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

func TestNonceStoreRules(t *testing.T) {
	now := time.Now()
	s := newNonceStore(time.Minute)
	var p1, p2 [32]byte
	p1[0], p2[0] = 1, 2
	n, _, err := s.issue(p1, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.consume(n, p2, now); err == nil || err.Error() != nonceWrongCaller {
		t.Fatalf("other caller: %v", err)
	}
	if err := s.consume(n, p1, now); err == nil || err.Error() != nonceReused { // burned by the wrong-caller attempt
		t.Fatalf("after a wrong-caller attempt: %v", err)
	}
	n, _, _ = s.issue(p1, now)
	if err := s.consume(n, p1, now); err != nil {
		t.Fatal(err)
	}
	if err := s.consume(n, p1, now); err == nil || err.Error() != nonceReused {
		t.Fatalf("reuse: %v", err)
	}
	n, _, _ = s.issue(p1, now)
	if err := s.consume(n, p1, now.Add(2*time.Minute)); err == nil || err.Error() != nonceExpired {
		t.Fatalf("expiry: %v", err)
	}
	if err := s.consume([]byte("x"), p1, now); err == nil || err.Error() != nonceUnknown {
		t.Fatalf("unknown: %v", err)
	}
	for i := 0; i < maxNoncesPerCaller+5; i++ {
		_, _, err = s.issue(p2, now)
	}
	if err == nil {
		t.Fatal("a caller can hold unlimited open challenges")
	}
}

func TestLimiterRefills(t *testing.T) {
	now := time.Now()
	l := newLimiter(60, 2)
	if !l.allow("A", now) || !l.allow("A", now) || l.allow("A", now) {
		t.Fatal("burst of 2")
	}
	if !l.allow("A", now.Add(time.Second)) { // 60 per minute = 1 per second
		t.Fatal("no refill")
	}
	if !l.allow("B", now) {
		t.Fatal("parties share a bucket")
	}
}

// The production build refuses debug evidence and a test root. (In a simulation build the policy is empty: see TestMockRootIsMarkedTestOnly.)
func TestProductionPolicy(t *testing.T) {
	if Simulation {
		t.Skip("simulation build")
	}
	test := &x509.Certificate{Subject: pkix.Name{CommonName: "QV mock Nitro root (TEST ONLY)"}}
	real := &x509.Certificate{Subject: pkix.Name{CommonName: "AWS_NitroEnclaves_Root-G1"}}
	if err := checkBuildPolicy(Config{}, []*x509.Certificate{real}); err != nil {
		t.Fatal(err)
	}
	if err := checkBuildPolicy(Config{AllowDebug: true}, []*x509.Certificate{real}); err == nil || !strings.Contains(err.Error(), "debug") {
		t.Fatalf("allow_debug: %v", err)
	}
	if err := checkBuildPolicy(Config{}, []*x509.Certificate{real, test}); err == nil || !strings.Contains(err.Error(), "TEST ONLY") {
		t.Fatalf("test root: %v", err)
	}
}

// The defaults: a 50-keyset start (102 calls, one every 50 ms) is not limited; a flood from one party is, and does not touch another party.
func TestDefaultLimitAllowsLargeStartsAndStopsAFlood(t *testing.T) {
	l := newLimiter(DefaultRatePerMinute, DefaultRateBurst)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 2*50+2; i++ {
		if !l.allow("A", now) {
			t.Fatalf("call %d of a 50-keyset start was rate limited", i+1)
		}
		now = now.Add(50 * time.Millisecond)
	}
	flood := 0
	for i := 0; i < 5000; i++ {
		if l.allow("B", now) {
			flood++
		}
	}
	if flood > DefaultRateBurst {
		t.Fatalf("a flood got %d calls through at one instant, burst is %d", flood, DefaultRateBurst)
	}
	if !l.allow("A", now) {
		t.Fatal("party B's flood used party A's tokens")
	}
}
