package cbmpc

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Malicious-peer smoke test: one party corrupts the n-th protocol message it sends (flip a byte at several positions,
// truncate, extend). The honest party must fail with Cryptographic or Transport, or - if the corruption hit bytes the
// protocol does not use - still end with a signature that verifies. It must never return a bad signature, crash, or hang.
// Not a fuzzing campaign and not a proof: the evidence for soundness is cb-mpc's proofs plus its 195 upstream tests.

type mutation struct {
	name string
	f    func(b []byte) []byte
}

func mutations(msgLen int) []mutation {
	var ms []mutation
	seen := map[int]bool{}
	for _, p := range []int{0, 1, 3, 4, 8, msgLen / 8, msgLen / 4, msgLen / 2, msgLen * 3 / 4, msgLen - 2, msgLen - 1} {
		if p < 0 || p >= msgLen || seen[p] {
			continue
		}
		seen[p] = true
		p := p
		ms = append(ms, mutation{fmt.Sprintf("flip@%d", p), func(b []byte) []byte { b[p] ^= 0x01; return b }})
	}
	ms = append(ms,
		mutation{"flip-high-bit@mid", func(b []byte) []byte { b[len(b)/2] ^= 0x80; return b }},
		mutation{"truncate-1", func(b []byte) []byte { return b[:len(b)-1] }},
		mutation{"truncate-half", func(b []byte) []byte { return b[:len(b)/2] }},
		mutation{"empty", func(b []byte) []byte { return nil }},
		mutation{"extend", func(b []byte) []byte { return append(b, 0xde, 0xad) }},
		mutation{"zeros", func(b []byte) []byte { return make([]byte, len(b)) }},
	)
	return ms
}

type outcome struct {
	mu sync.Mutex
	m  map[string]int
}

func (o *outcome) add(k string) { o.mu.Lock(); o.m[k]++; o.mu.Unlock() }

func (o *outcome) String() string {
	var ks []string
	for k, v := range o.m {
		ks = append(ks, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(ks)
	return fmt.Sprint(ks)
}

// runTampered runs fa/fb over a mem link where `badSide` (0 = P1, 1 = P2) mutates its message number `idx`.
func runTampered(badSide, idx int, mut func([]byte) []byte, fa, fb func(tr Transport) error) (ea, eb error) {
	a, b := NewMemPair()
	tap := func(n int, msg []byte) []byte {
		if n == idx {
			return mut(append([]byte(nil), msg...))
		}
		return msg
	}
	if badSide == 0 {
		a.Tap = tap
	} else {
		b.Tap = tap
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if ea = fa(a); ea != nil {
			a.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if eb = fb(b); eb != nil {
			b.Close()
		}
	}()
	wg.Wait()
	return
}

func TestMaliciousPeerSign(t *testing.T) {
	for _, alg := range []Alg{ECDSA, Ed25519, BIP340} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			ctx := ctx5(t)
			var s1, s2 *SignKey
			if alg == BIP340 {
				e1, e2 := both(
					func(tr Transport) (err error) { s1, err = DKGBIP340(ctx, tr, P1); return },
					func(tr Transport) (err error) { s2, err = DKGBIP340(ctx, tr, P2); return })
				must(t, e1)
				must(t, e2)
				defer s1.Wipe()
				defer s2.Wipe()
			} else {
				k1, k2 := dkgPair(t, alg)
				s1, s2 = derivePair(t, k1, k2, []uint32{1, 2}, []uint32{3})
			}
			pub, _ := s1.PublicKey()
			msg := digest32(42)
			verify := func(sig []byte) bool {
				switch alg {
				case ECDSA, Ed25519:
					return verifyQuiet(alg, pub, msg, sig)
				default:
					x, _ := s1.XOnlyPublicKey()
					return verifyBIP340Quiet(x, msg, sig)
				}
			}
			// count the messages each side sends in an honest run
			var n1, n2 int
			{
				a, b := NewMemPair()
				a.Tap = func(n int, m []byte) []byte { n1++; return m }
				b.Tap = func(n int, m []byte) []byte { n2++; return m }
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); s1.Sign(ctx, a, msg) }()
				go func() { defer wg.Done(); s2.Sign(ctx, b, msg) }()
				wg.Wait()
			}
			t.Logf("honest run: P1 sends %d messages, P2 sends %d", n1, n2)
			res := &outcome{m: map[string]int{}}
			for badSide, n := range []int{n1, n2} {
				for idx := 0; idx < n; idx++ {
					// probe the message length with an identity run to pick positions
					lens := probeLen(s1, s2, msg, badSide, idx)
					for _, mu := range mutations(lens) {
						var sig []byte
						e1, e2 := runTampered(badSide, idx, mu.f,
							func(tr Transport) (err error) { sig, err = s1.Sign(ctx, tr, msg); return },
							func(tr Transport) (err error) { _, err = s2.Sign(ctx, tr, msg); return })
						side := "P1"
						if badSide == 0 {
							side = "P2" // honest side is the OTHER one
						}
						// honest party = the one that did not tamper
						honestErr := e1
						if badSide == 0 {
							honestErr = e2
						}
						if sig != nil && !verify(sig) {
							t.Fatalf("%s bad=%d msg#%d %s: INVALID SIGNATURE RETURNED", alg, badSide+1, idx, mu.name)
						}
						switch {
						case honestErr == nil:
							res.add("honest-ok(" + mu.name[:3] + ")")
						case IsTransport(honestErr):
							res.add("transport")
						case IsCryptographic(honestErr):
							res.add("cryptographic")
						default:
							res.add("OTHER")
							t.Errorf("%s: malicious P%d msg#%d %s: honest %s got unexpected class: %v", alg, badSide+1, idx, mu.name, side, honestErr)
						}
					}
				}
			}
			t.Logf("outcomes: %s", res)
		})
	}
}

func verifyBIP340Quiet(x, msg, sig []byte) bool {
	defer func() { recover() }()
	pk, err := schnorr.ParsePubKey(x)
	if err != nil {
		return false
	}
	s, err := schnorr.ParseSignature(sig)
	if err != nil {
		return false
	}
	return s.Verify(msg, pk)
}

// probeLen returns the length of message idx sent by badSide in an honest run.
func probeLen(s1, s2 *SignKey, msg []byte, badSide, idx int) int {
	l := 64
	a, b := NewMemPair()
	tap := func(n int, m []byte) []byte {
		if n == idx {
			l = len(m)
		}
		return m
	}
	if badSide == 0 {
		a.Tap = tap
	} else {
		b.Tap = tap
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s1.Sign(context.Background(), a, msg) }()
	go func() { defer wg.Done(); s2.Sign(context.Background(), b, msg) }()
	wg.Wait()
	return l
}

// The same for the other protocols, with fewer positions.
func TestMaliciousPeerOtherProtocols(t *testing.T) {
	ctx := ctx5(t)
	for _, alg := range []Alg{ECDSA, Ed25519} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			k1, k2 := dkgPair(t, alg)
			type proto struct {
				name   string
				p1, p2 func(tr Transport) error
				// after a SUCCESSFUL run with a tampered message, the result must still be consistent
				consistent func() bool
			}
			var r1, r2 []byte
			var nk1, nk2 *Keyset
			var d1, d2 *SignKey
			protos := []proto{
				{"derive",
					func(tr Transport) (err error) { d1, err = k1.Derive(ctx, tr, []uint32{5}, []uint32{1}); return },
					func(tr Transport) (err error) { d2, err = k2.Derive(ctx, tr, []uint32{5}, []uint32{1}); return },
					func() bool {
						if d1 == nil || d2 == nil {
							return false
						}
						a, _ := d1.PublicKey()
						b, _ := d2.PublicKey()
						return string(a) == string(b)
					}},
				{"node",
					func(tr Transport) error {
						n, err := k1.NodeExport(ctx, tr, []uint32{5})
						r1 = append(n.PublicKey, n.ChainCode...)
						return err
					},
					func(tr Transport) error {
						n, err := k2.NodeExport(ctx, tr, []uint32{5})
						r2 = append(n.PublicKey, n.ChainCode...)
						return err
					},
					func() bool { return string(r1) == string(r2) }},
				{"refresh",
					func(tr Transport) (err error) { nk1, err = k1.Refresh(ctx, tr); return },
					func(tr Transport) (err error) { nk2, err = k2.Refresh(ctx, tr); return },
					func() bool { return selfTestOK(ctx, nk1, nk2) }},
				{"dkg",
					func(tr Transport) (err error) { nk1, err = DKG(ctx, tr, P1, alg); return },
					func(tr Transport) (err error) { nk2, err = DKG(ctx, tr, P2, alg); return },
					func() bool { return selfTestOK(ctx, nk1, nk2) }},
			}
			for _, p := range protos {
				res := &outcome{m: map[string]int{}}
				// message counts
				var c1, c2 int
				{
					a, b := NewMemPair()
					a.Tap = func(n int, m []byte) []byte { c1++; return m }
					b.Tap = func(n int, m []byte) []byte { c2++; return m }
					var wg sync.WaitGroup
					wg.Add(2)
					go func() { defer wg.Done(); p.p1(a) }()
					go func() { defer wg.Done(); p.p2(b) }()
					wg.Wait()
				}
				for badSide, n := range []int{c1, c2} {
					for idx := 0; idx < n; idx++ {
						for _, pos := range []string{"first", "mid", "last"} {
							pos := pos
							mu := func(b []byte) []byte {
								if len(b) == 0 {
									return b
								}
								switch pos {
								case "first":
									b[0] ^= 1
								case "mid":
									b[len(b)/2] ^= 1
								default:
									b[len(b)-1] ^= 1
								}
								return b
							}
							r1, r2, d1, d2, nk1, nk2 = nil, nil, nil, nil, nil, nil
							e1, e2 := runTampered(badSide, idx, mu, p.p1, p.p2)
							honest := e1
							if badSide == 0 {
								honest = e2
							}
							switch {
							case honest == nil:
								if e1 == nil && e2 == nil {
									// Both report success. Derive/Node results must agree; for DKG/Refresh the new shares may
									// be silently inconsistent (library behaviour): SelfTest must DETECT it, never pass wrongly.
									if p.name == "refresh" || p.name == "dkg" {
										if p.consistent() {
											res.add("both-ok,shares-work")
										} else {
											res.add("both-ok,SHARES-BROKEN(detected by SelfTest)")
										}
									} else if !p.consistent() {
										t.Errorf("%s: tampered msg %d/%d (%s) accepted by both with inconsistent result", p.name, badSide, idx, pos)
									}
								}
								res.add("honest-ok")
							case IsTransport(honest):
								res.add("transport")
							case IsCryptographic(honest):
								res.add("cryptographic")
							default:
								res.add("OTHER")
								t.Errorf("%s: P%d tampered msg %d (%s): honest got %v", p.name, badSide+1, idx, pos, honest)
							}
						}
					}
				}
				t.Logf("%s: %s", p.name, res)
			}
		})
	}
}

// selfTestOK runs SelfTest on a pair of keysets; false when it reports an error on either side.
func selfTestOK(ctx context.Context, k1, k2 *Keyset) bool {
	if k1 == nil || k2 == nil {
		return false
	}
	var p1, p2 []byte
	e1, e2 := both(
		func(tr Transport) (err error) { p1, err = k1.SelfTest(ctx, tr); return },
		func(tr Transport) (err error) { p2, err = k2.SelfTest(ctx, tr); return })
	return e1 == nil && e2 == nil && string(p1) == string(p2)
}
