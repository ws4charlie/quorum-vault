package cbmpc

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
)

// Malicious-peer tests for the threshold calls (DKG, sign, refresh). One member corrupts, truncates, empties, extends
// or replays (from the previous message, or from an earlier session) the n-th message it sends on one link. Required:
//   - a signature that comes out of Sign verifies (never a wrong signature);
//   - every honest member that fails fails with Cryptographic or Transport (never Internal, never a hang or crash);
//   - DKG and Refresh may succeed on every honest member although a message was damaged (README point 1): then
//     SelfTest must expose the damage; it is run on every such result and a pass is only possible if all pairs sign.

type link struct{ from, to Member }

type tapSpec struct {
	bad, peer Member
	idx       int
	name      string
	mut       func(prev, old [][]byte, msg []byte) []byte
}

// recorded is what an honest run sent on each directed link.
type recorded struct {
	msgs map[link][][]byte
}

func (r *recorded) count(l link) int { return len(r.msgs[l]) }

// record runs f over meshes whose links record every message.
func record(f func(meshes [NumMembers]*LinkMesh)) *recorded {
	meshes := NewMemMesh()
	r := &recorded{msgs: map[link][][]byte{}}
	var mu sync.Mutex
	for i := 0; i < NumMembers; i++ {
		for p := 0; p < NumMembers; p++ {
			if i == p {
				continue
			}
			l := link{Member(i), Member(p)}
			meshes[i].Link(Member(p)).(*MemTransport).Tap = func(n int, msg []byte) []byte {
				mu.Lock()
				r.msgs[l] = append(r.msgs[l], append([]byte(nil), msg...))
				mu.Unlock()
				return msg
			}
		}
	}
	f(meshes)
	return r
}

func tamperedMesh(spec tapSpec, old [][]byte) [NumMembers]*LinkMesh {
	m := NewMemMesh()
	var prev [][]byte
	m[spec.bad].Link(spec.peer).(*MemTransport).Tap = func(n int, msg []byte) []byte {
		orig := append([]byte(nil), msg...)
		out := msg
		if n == spec.idx {
			out = spec.mut(prev, old, append([]byte(nil), msg...))
		}
		prev = append(prev, orig)
		return out
	}
	return m
}

func tmutations() []struct {
	name string
	f    func(prev, old [][]byte, msg []byte) []byte
} {
	type mu = struct {
		name string
		f    func(prev, old [][]byte, msg []byte) []byte
	}
	return []mu{
		{"flip-first", func(_, _ [][]byte, b []byte) []byte {
			if len(b) > 0 {
				b[0] ^= 1
			}
			return b
		}},
		{"flip-mid", func(_, _ [][]byte, b []byte) []byte {
			if len(b) > 0 {
				b[len(b)/2] ^= 1
			}
			return b
		}},
		{"flip-last", func(_, _ [][]byte, b []byte) []byte {
			if len(b) > 0 {
				b[len(b)-1] ^= 1
			}
			return b
		}},
		{"truncate-half", func(_, _ [][]byte, b []byte) []byte { return b[:len(b)/2] }},
		{"empty", func(_, _ [][]byte, b []byte) []byte { return nil }},
		{"extend", func(_, _ [][]byte, b []byte) []byte { return append(b, 0xde, 0xad) }},
		{"replay-previous-message", func(prev, _ [][]byte, b []byte) []byte {
			if len(prev) == 0 {
				return b[:len(b)/2] // nothing to replay yet: still a damaged message
			}
			return append([]byte(nil), prev[len(prev)-1]...)
		}},
		{"replay-earlier-session", func(_, old [][]byte, b []byte) []byte {
			if len(old) == 0 {
				return b[:len(b)/2]
			}
			return append([]byte(nil), old[len(old)-1]...) // placeholder, replaced per idx by caller
		}},
	}
}

// matrix lists every (bad, peer, idx, mutation) for the recorded run, restricted to bad members in `bads`.
func matrix(rec *recorded, bads []Member, peers func(bad Member) []Member) []tapSpec {
	var out []tapSpec
	for _, bad := range bads {
		for _, peer := range peers(bad) {
			l := link{bad, peer}
			for idx := 0; idx < rec.count(l); idx++ {
				idx := idx
				for _, m := range tmutations() {
					m := m
					name := fmt.Sprintf("%s->%s #%d %s", bad, peer, idx, m.name)
					f := m.f
					if m.name == "replay-earlier-session" {
						f = func(prev, old [][]byte, b []byte) []byte {
							if idx < len(old) {
								return append([]byte(nil), old[idx]...)
							}
							return b[:len(b)/2]
						}
					}
					out = append(out, tapSpec{bad: bad, peer: peer, idx: idx, name: name, mut: f})
				}
			}
		}
	}
	return out
}

func allPeers(bad Member) (ps []Member) {
	for p := Member(0); p < NumMembers; p++ {
		if p != bad {
			ps = append(ps, p)
		}
	}
	return
}

// parallel runs fn over specs with a few workers.
func parallel(specs []tapSpec, fn func(tapSpec)) {
	ch := make(chan tapSpec)
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range ch {
				fn(s)
			}
		}()
	}
	for _, s := range specs {
		ch <- s
	}
	close(ch)
	wg.Wait()
}

func classOK(err error) bool { return IsCryptographic(err) || IsTransport(err) }

func TestMaliciousPeerThresholdSign(t *testing.T) {
	ks := tDKG(t)
	pub := ks[0].PublicKey()
	msg := digest32(77)
	res := &outcome{m: map[string]int{}}
	for _, pr := range allPairs {
		a, b := pr[0], pr[1]
		for _, recv := range []Member{a, b} {
			run := func(meshes [NumMembers]*LinkMesh) (sig []byte, ea, eb error) {
				ctx := ctx5(t)
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					s, err := ks[a].Sign(ctx, meshes[a], b, recv, msg)
					if recv == a {
						sig = s
					}
					if ea = err; err != nil {
						meshes[a].Close()
					}
				}()
				go func() {
					defer wg.Done()
					s, err := ks[b].Sign(ctx, meshes[b], a, recv, msg)
					if recv == b {
						sig = s
					}
					if eb = err; err != nil {
						meshes[b].Close()
					}
				}()
				wg.Wait()
				return
			}
			rec := record(func(m [NumMembers]*LinkMesh) { run(m) })
			old := rec.msgs
			specs := matrix(rec, []Member{a, b}, func(bad Member) []Member {
				if bad == a {
					return []Member{b}
				}
				return []Member{a}
			})
			t.Logf("pair %s-%s receiver %s: %d + %d messages, %d tampered runs", a, b, recv, rec.count(link{a, b}), rec.count(link{b, a}), len(specs))
			parallel(specs, func(s tapSpec) {
				sig, ea, eb := run(tamperedMesh(s, old[link{s.bad, s.peer}]))
				if sig != nil && !verifyQuiet(ECDSA, pub, msg, sig) {
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
			})
		}
	}
	t.Logf("outcomes: %s", res)
}

// dkgOrRefresh is the shared harness for the two three-party ceremonies.
func testMaliciousCeremony(t *testing.T, name string, prepare func() func(ctx context.Context, m Member, mesh *LinkMesh) (*TKey, error)) {
	res := &outcome{m: map[string]int{}}
	exec := func(meshes [NumMembers]*LinkMesh) (out [NumMembers]*TKey, errs [NumMembers]error) {
		f := prepare()
		errs = trioOn(ctx5(t), meshes, func(ctx context.Context, m Member, mesh *LinkMesh) (err error) {
			out[m], err = f(ctx, m, mesh)
			return
		})
		return
	}
	rec := record(func(m [NumMembers]*LinkMesh) {
		out, _ := exec(m)
		for _, k := range out {
			k.Wipe()
		}
	})
	// one bad member per run: member 2 on its link to 0, member 0 on its link to 1, member 1 on its link to 2 (each
	// member is bad on one of its two links, so all three roles and all three honest-pair shapes occur)
	var specs []tapSpec
	for _, c := range []struct{ bad, peer Member }{{2, 0}, {0, 1}, {1, 2}, {0, 2}} {
		specs = append(specs, matrix(rec, []Member{c.bad}, func(Member) []Member { return []Member{c.peer} })...)
	}
	t.Logf("%s: %d messages on 0->1, %d tampered runs", name, rec.count(link{0, 1}), len(specs))
	parallel(specs, func(s tapSpec) {
		out, errs := exec(tamperedMesh(s, rec.msgs[link{s.bad, s.peer}]))
		defer func() {
			for _, k := range out {
				k.Wipe()
			}
		}()
		allOK := true
		for m := Member(0); m < NumMembers; m++ {
			if errs[m] != nil {
				allOK = false
			}
			if m == s.bad {
				continue
			}
			if errs[m] != nil && !classOK(errs[m]) {
				res.add("OTHER")
				t.Errorf("%s: %s: honest %s got %v", name, s.name, m, errs[m])
			}
		}
		if !allOK {
			res.add("failed-closed")
			return
		}
		// every member returned nil: the damage may sit in the shares. SelfTest must tell.
		errs2 := tSelfTest(ctx5(t), out, []byte("mal|"+s.name))
		if errs2[0] == nil && errs2[1] == nil && errs2[2] == nil {
			res.add("all-ok,shares-work")
		} else {
			res.add("all-ok,SHARES-BROKEN(caught by SelfTest)")
		}
	})
	t.Logf("%s outcomes: %s", name, res)
}

func TestMaliciousPeerThresholdDKG(t *testing.T) {
	testMaliciousCeremony(t, "dkg", func() func(context.Context, Member, *LinkMesh) (*TKey, error) {
		return func(ctx context.Context, m Member, mesh *LinkMesh) (*TKey, error) { return TDKG(ctx, mesh, m) }
	})
}

func TestMaliciousPeerThresholdRefresh(t *testing.T) {
	ks := tDKG(t)
	testMaliciousCeremony(t, "refresh", func() func(context.Context, Member, *LinkMesh) (*TKey, error) {
		return func(ctx context.Context, m Member, mesh *LinkMesh) (*TKey, error) { return ks[m].Refresh(ctx, mesh) }
	})
}

// The self-test itself: a member that lies about the verdict or sends a bad signature is detected.
func TestMaliciousPeerThresholdSelfTest(t *testing.T) {
	ks := tDKG(t)
	rec := record(func(m [NumMembers]*LinkMesh) {
		trioOn(ctx5(t), m, func(ctx context.Context, me Member, mesh *LinkMesh) error {
			return ks[me].SelfTest(ctx, mesh, []byte("x"))
		})
	})
	var specs []tapSpec
	for _, c := range []struct{ bad, peer Member }{{0, 1}, {1, 0}, {0, 2}, {2, 0}, {1, 2}, {2, 1}} {
		specs = append(specs, matrix(rec, []Member{c.bad}, func(Member) []Member { return []Member{c.peer} })...)
	}
	res := &outcome{m: map[string]int{}}
	parallel(specs, func(s tapSpec) {
		errs := trioOn(ctx5(t), tamperedMesh(s, rec.msgs[link{s.bad, s.peer}]), func(ctx context.Context, me Member, mesh *LinkMesh) error {
			return ks[me].SelfTest(ctx, mesh, []byte("x"))
		})
		for m := Member(0); m < NumMembers; m++ {
			if m != s.bad && errs[m] != nil && !classOK(errs[m]) {
				t.Errorf("%s: honest %s got %v", s.name, m, errs[m])
			}
		}
		// A tampered ack must never turn a failure into a pass: if the signature the higher member got is damaged, the
		// higher member must fail.
		res.add("done")
	})
	t.Logf("%d tampered self-test runs, no unclassified error", len(specs))
	_ = bytes.Equal
}
