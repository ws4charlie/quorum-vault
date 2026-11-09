package cbmpc

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Malicious-peer tests for the 2-of-3 Ed25519 calls (P8-1), same rules as tmalicious_test.go: one member corrupts,
// truncates, empties, extends or replays the n-th message it sends on one link. A signature that comes out verifies with
// crypto/ed25519; every honest member that fails fails with Cryptographic or Transport; DKG and Refresh may "succeed"
// on all three and then SelfTest must expose the damage.

// edSignRun runs one pair signing over the given meshes.
func edSignRun(t testing.TB, ks [NumMembers]*TKey, a, b, recv Member, msg []byte, meshes [NumMembers]*LinkMesh) (sig []byte, ea, eb error) {
	ctx := ctx5(t)
	var wg sync.WaitGroup
	wg.Add(2)
	one := func(me, peer Member, e *error) {
		defer wg.Done()
		s, err := ks[me].Sign(ctx, meshes[me], peer, recv, msg)
		if me == recv {
			sig = s
		}
		if *e = err; err != nil {
			meshes[me].Close()
		}
	}
	go one(a, b, &ea)
	go one(b, a, &eb)
	wg.Wait()
	return
}

// Tamper every message of every pair signing, with every mutation, in both directions and with either receiver. Reports,
// per message index, how often damage was NOT detected by the honest receiver (it got a valid signature anyway).
func TestMaliciousPeerEdThresholdSign(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	pub := ks[0].PublicKey()
	msg := edMsg(120, 77)
	res := &outcome{m: map[string]int{}}
	var mu sync.Mutex
	type key struct {
		role string // "receiver-sends" or "sender-sends": who sent the damaged message
		idx  int
		mut  string
	}
	undetected := map[key]int{}
	total := map[key]int{}
	for _, pr := range allPairs {
		a, b := pr[0], pr[1]
		for _, recv := range []Member{a, b} {
			rec := record(func(m [NumMembers]*LinkMesh) { edSignRun(t, ks, a, b, recv, msg, m) })
			old := rec.msgs
			specs := matrix(rec, []Member{a, b}, func(bad Member) []Member {
				if bad == a {
					return []Member{b}
				}
				return []Member{a}
			})
			t.Logf("pair %s-%s receiver %s: messages %s->%s %d, %s->%s %d; %d tampered runs", a, b, recv, a, b, rec.count(link{a, b}), b, a, rec.count(link{b, a}), len(specs))
			parallel(specs, func(s tapSpec) {
				sig, ea, eb := edSignRun(t, ks, a, b, recv, msg, tamperedMesh(s, old[link{s.bad, s.peer}]))
				if sig != nil && !verifyQuiet(Ed25519, pub, msg, sig) {
					t.Errorf("INVALID SIGNATURE RETURNED: pair %s-%s recv %s: %s", a, b, recv, s.name)
				}
				honest := ea
				if s.bad == a {
					honest = eb
				}
				switch {
				case honest == nil:
					res.add("honest-ok")
				case IsTransport(honest):
					res.add("transport")
				case IsCryptographic(honest):
					res.add("cryptographic")
				default:
					res.add("OTHER")
					t.Errorf("pair %s-%s recv %s: %s: honest got %v", a, b, recv, s.name, honest)
				}
				// what matters for custody: the receiver is the one that returns a signature
				if s.bad != recv {
					role := "sender-sends"
					fields := strings.Fields(s.name)
					mut := fields[len(fields)-1]
					k := key{role, s.idx, mut}
					recvErr := ea
					if recv == b {
						recvErr = eb
					}
					mu.Lock()
					total[k]++
					if recvErr == nil {
						undetected[k]++
					}
					mu.Unlock()
				}
			})
		}
	}
	t.Logf("outcomes (honest member, any role): %s", res)
	var lines []string
	for k, n := range undetected {
		lines = append(lines, fmt.Sprintf("message #%d (%s) %s: receiver returned a valid signature in %d of %d runs", k.idx, k.role, k.mut, n, total[k]))
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		t.Logf("every tampering of a message sent TO the receiver was detected by the receiver")
	}
	for _, l := range lines {
		t.Logf("NOT DETECTED: %s", l)
	}
}

// The E23-3 finding for ECDSA (one flipped byte in the middle of message index 2 is ignored about half the time): flip
// one random byte of each message, many times, and count the runs where BOTH members still returned success.
func TestEdThresholdFlippedByteIsDetected(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	msg := edMsg(80, 5)
	const trials = 25
	rec := record(func(m [NumMembers]*LinkMesh) { edSignRun(t, ks, 0, 1, 0, msg, m) })
	for _, dir := range []link{{0, 1}, {1, 0}} {
		for idx := 0; idx < rec.count(dir); idx++ {
			ignored := 0
			var mu sync.Mutex
			var specs []tapSpec
			for i := 0; i < trials; i++ {
				seed := int64(1000*idx + i)
				specs = append(specs, tapSpec{bad: dir.from, peer: dir.to, idx: idx, name: "flip-random", mut: func(_, _ [][]byte, b []byte) []byte {
					if len(b) > 0 {
						b[rand.New(rand.NewSource(seed)).Intn(len(b))] ^= 0x40
					}
					return b
				}})
			}
			parallel(specs, func(s tapSpec) {
				sig, ea, eb := edSignRun(t, ks, 0, 1, 0, msg, tamperedMesh(s, nil))
				if sig != nil && !verifyQuiet(Ed25519, ks[0].PublicKey(), msg, sig) {
					t.Errorf("INVALID SIGNATURE RETURNED (#%d)", idx)
				}
				if ea == nil && eb == nil {
					mu.Lock()
					ignored++
					mu.Unlock()
				}
			})
			t.Logf("%s->%s message #%d (%d bytes): one random byte flipped, %d of %d runs still succeeded", dir.from, dir.to, idx, len(rec.msgs[dir][idx]), ignored, trials)
		}
	}
}

func TestMaliciousPeerEdThresholdDKG(t *testing.T) {
	testMaliciousCeremony(t, "ed-dkg", func() func(context.Context, Member, *LinkMesh) (*TKey, error) {
		return func(ctx context.Context, m Member, mesh *LinkMesh) (*TKey, error) {
			return TDKGAlg(ctx, mesh, m, Ed25519)
		}
	})
}

func TestMaliciousPeerEdThresholdRefresh(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	testMaliciousCeremony(t, "ed-refresh", func() func(context.Context, Member, *LinkMesh) (*TKey, error) {
		return func(ctx context.Context, m Member, mesh *LinkMesh) (*TKey, error) { return ks[m].Refresh(ctx, mesh) }
	})
}

func TestMaliciousPeerEdThresholdSelfTest(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	rec := record(func(m [NumMembers]*LinkMesh) {
		trioOn(ctx5(t), m, func(ctx context.Context, me Member, mesh *LinkMesh) error {
			return ks[me].SelfTest(ctx, mesh, []byte("x"))
		})
	})
	var specs []tapSpec
	for _, c := range []struct{ bad, peer Member }{{0, 1}, {1, 0}, {0, 2}, {2, 0}, {1, 2}, {2, 1}} {
		specs = append(specs, matrix(rec, []Member{c.bad}, func(Member) []Member { return []Member{c.peer} })...)
	}
	parallel(specs, func(s tapSpec) {
		errs := trioOn(ctx5(t), tamperedMesh(s, rec.msgs[link{s.bad, s.peer}]), func(ctx context.Context, me Member, mesh *LinkMesh) error {
			return ks[me].SelfTest(ctx, mesh, []byte("x"))
		})
		for m := Member(0); m < NumMembers; m++ {
			if m != s.bad && errs[m] != nil && !classOK(errs[m]) {
				t.Errorf("%s: honest %s got %v", s.name, m, errs[m])
			}
		}
	})
	t.Logf("%d tampered self-test runs, no unclassified error", len(specs))
}
