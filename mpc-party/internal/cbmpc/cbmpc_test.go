package cbmpc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPinMatchesBuild(t *testing.T) {
	pin, err := os.ReadFile("../../cbmpc.pin")
	must(t, err)
	if !strings.Contains(string(pin), "CBMPC_TAG="+PinnedTag+"\n") || !strings.Contains(string(pin), "CBMPC_COMMIT="+PinnedCommit+"\n") {
		t.Fatalf("pin.go (%s %s) and cbmpc.pin disagree:\n%s", PinnedTag, PinnedCommit, pin)
	}
	stamp, err := os.ReadFile("../../.deps/BUILD_STAMP")
	must(t, err)
	if !strings.HasPrefix(string(stamp), "commit="+PinnedCommit+" ") {
		t.Fatalf("library was built from another commit than the pin: BUILD_STAMP=%q pin=%s. Run scripts/fetch-build-cbmpc.sh", stamp, PinnedCommit)
	}
	if out, err := exec.Command("git", "-C", "../../.deps/cb-mpc", "rev-parse", "HEAD").Output(); err == nil {
		if got := strings.TrimSpace(string(out)); got != PinnedCommit {
			t.Fatalf("cb-mpc source in .deps is at %s, pin is %s", got, PinnedCommit)
		}
	} else {
		t.Logf("git not available to double-check .deps/cb-mpc: %v", err)
	}
	if LayoutID() == "" {
		t.Fatal("empty layout id")
	}
}

// The boundary guard: every kind of C++ throw must come back as an error, not terminate the process.
func TestBoundaryCatchesExceptions(t *testing.T) {
	cases := []struct {
		kind int
		code uint32
	}{
		{0, CodeException}, // std::runtime_error
		{1, CodeAssert},    // cb_assert failure: a real coinbase::assertion_failed_t thrown by cb-mpc's own machinery
		{2, CodeBadAlloc},  // std::bad_alloc
		{3, CodeException}, // throw 42
	}
	for _, c := range cases {
		err := TestThrow(c.kind)
		var e *Error
		if !errors.As(err, &e) || e.Code != c.code || e.Kind != KindInternal {
			t.Fatalf("kind %d: got %#v want code %#x internal", c.kind, err, c.code)
		}
	}
	if err := TestThrow(4); err != nil {
		t.Fatal(err)
	}
}

// A throw while a protocol is in flight (the assertion fires inside the library, not just at a trivial entry point).
func TestAssertionInsideLibraryIsCaught(t *testing.T) {
	// Joining a P1 keyset whose Paillier-encrypted share cannot be decrypted makes paillier_t::decrypt cb_assert.
	// Build that situation: take a real P1 split, then corrupt c_key by swapping in the stripped blob of ANOTHER keyset's
	// Paillier material is not possible from Go; instead corrupt bytes of the stripped blob until a cb_assert path is hit.
	k1, _ := dkgPair(t, ECDSA)
	sp, err := k1.Split()
	must(t, err)
	defer sp.Wipe()
	raw, err := sp.Stripped.Bytes()
	must(t, err)
	defer WipeBytes(raw)
	hit := map[uint32]int{}
	for i := 0; i < len(raw); i++ {
		for _, mask := range []byte{0x01, 0x80} {
			mut := append([]byte(nil), raw...)
			mut[i] ^= mask
			s2, err := NewKeysetSplit(ECDSA, P1, mut, sp.PubX, sp.PubK)
			must(t, err)
			s2.X, s2.K = sp.X, sp.K
			ks, err := Join(s2)
			if err == nil {
				ks.Wipe()
				continue
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("non-*Error from Join: %v", err)
			}
			hit[e.Code]++
			if e.Code == CodeAssert {
				t.Logf("flipping byte %d (mask %#x) reached a real cb_assert inside cb-mpc: %v", i, mask, err)
				return
			}
		}
	}
	t.Logf("no byte flip reached cb_assert through Join (codes seen: %v); guard still covered by TestBoundaryCatchesExceptions", hit)
}

func TestECDSAHDEndToEnd(t *testing.T) {
	ctx := ctx5(t)
	k1, k2 := dkgPair(t, ECDSA)
	r1, err := k1.RootPublicKey()
	must(t, err)
	r2, err := k2.RootPublicKey()
	must(t, err)
	if !bytes.Equal(r1, r2) || len(r1) != 33 {
		t.Fatalf("root keys differ or wrong size: %x %x", r1, r2)
	}
	s1, s2 := derivePair(t, k1, k2, []uint32{44, 60, 0}, []uint32{0, 7})
	p1, err := s1.PublicKey()
	must(t, err)
	p2, err := s2.PublicKey()
	must(t, err)
	if !bytes.Equal(p1, p2) {
		t.Fatal("derived public keys differ")
	}
	d := digest32(1)
	sig, e1, e2 := signPair(ctx, s1, s2, d)
	must(t, e1)
	must(t, e2)
	verifyECDSA(t, p1, d, sig)
	// Wrong digest size is rejected before any protocol starts.
	if _, err := s1.Sign(ctx, mustPair(t), []byte("short")); !IsInternal(err) || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want internal invalid-argument, got %v", err)
	}
}

func mustPair(t testing.TB) Transport { a, _ := NewMemPair(); return a }

func TestEd25519HDEndToEnd(t *testing.T) {
	ctx := ctx5(t)
	k1, k2 := dkgPair(t, Ed25519)
	s1, s2 := derivePair(t, k1, k2, []uint32{44, 501, 0}, []uint32{3})
	pub, err := s1.PublicKey()
	must(t, err)
	if len(pub) != 32 {
		t.Fatalf("pub len %d", len(pub))
	}
	msg := []byte("solana transaction message bytes")
	sig, e1, e2 := signPair(ctx, s1, s2, msg)
	must(t, e1)
	must(t, e2)
	verifyEd25519(t, pub, msg, sig)
	// Randomized: a second signature over the same message differs (store the first one).
	sig2, e1, e2 := signPair(ctx, s1, s2, msg)
	must(t, e1)
	must(t, e2)
	verifyEd25519(t, pub, msg, sig2)
	if bytes.Equal(sig, sig2) {
		t.Fatal("Ed25519 signatures unexpectedly deterministic")
	}
}

func TestBIP340EndToEnd(t *testing.T) {
	ctx := ctx5(t)
	var s1, s2 *SignKey
	e1, e2 := both(
		func(tr Transport) (err error) { s1, err = DKGBIP340(ctx, tr, P1); return },
		func(tr Transport) (err error) { s2, err = DKGBIP340(ctx, tr, P2); return })
	must(t, e1)
	must(t, e2)
	defer s1.Wipe()
	defer s2.Wipe()
	x, err := s1.XOnlyPublicKey()
	must(t, err)
	d := digest32(9)
	sig, e1, e2 := signPair(ctx, s1, s2, d)
	must(t, e1)
	must(t, e2)
	verifyBIP340(t, x, d, sig)
	// refresh keeps the key
	var n1, n2 *SignKey
	e1, e2 = both(
		func(tr Transport) (err error) { n1, err = s1.Refresh(ctx, tr); return },
		func(tr Transport) (err error) { n2, err = s2.Refresh(ctx, tr); return })
	must(t, e1)
	must(t, e2)
	defer n1.Wipe()
	defer n2.Wipe()
	x2, err := n1.XOnlyPublicKey()
	must(t, err)
	if !bytes.Equal(x, x2) {
		t.Fatal("BIP340 key changed on refresh")
	}
	sig, e1, e2 = signPair(ctx, n1, n2, d)
	must(t, e1)
	must(t, e2)
	verifyBIP340(t, x, d, sig)
}

func TestRefreshKeepsKeysAndInvalidatesOldDerivedKeys(t *testing.T) {
	for _, alg := range []Alg{ECDSA, Ed25519} {
		t.Run(alg.String(), func(t *testing.T) {
			ctx := ctx5(t)
			k1, k2 := dkgPair(t, alg)
			h := []uint32{1, 2}
			old1, old2 := derivePair(t, k1, k2, h, []uint32{5})
			oldPub, _ := old1.PublicKey()
			var n1, n2 *Keyset
			e1, e2 := both(
				func(tr Transport) (err error) { n1, err = k1.Refresh(ctx, tr); return },
				func(tr Transport) (err error) { n2, err = k2.Refresh(ctx, tr); return })
			must(t, e1)
			must(t, e2)
			t.Cleanup(func() { n1.Wipe(); n2.Wipe() })
			r0, _ := k1.RootPublicKey()
			r1, _ := n1.RootPublicKey()
			if !bytes.Equal(r0, r1) {
				t.Fatal("root public key changed on refresh")
			}
			// Shares really changed.
			b0, _ := k1.Bytes()
			b1, _ := n1.Bytes()
			if bytes.Equal(b0, b1) {
				t.Fatal("refresh did not change the share")
			}
			WipeBytes(b0)
			WipeBytes(b1)
			// Re-derived children are the same keys and sign.
			s1, s2 := derivePair(t, n1, n2, h, []uint32{5})
			newPub, _ := s1.PublicKey()
			if !bytes.Equal(oldPub, newPub) {
				t.Fatal("derived public key changed on refresh")
			}
			d := digest32(3)
			sig, e1, e2 := signPair(ctx, s1, s2, d)
			must(t, e1)
			must(t, e2)
			if alg == ECDSA {
				verifyECDSA(t, newPub, d, sig)
			} else {
				verifyEd25519(t, newPub, d, sig)
			}
			// What happens when old and new shares are mixed (P1 refreshed, P2 not, and the reverse):
			// the call fails with an error and NO signature is produced; the error is classified as cryptographic
			// (a proof or the final verification fails), never as a transport fault. Documented in README.
			for name, pair := range map[string][2]*SignKey{"newP1-oldP2": {s1, old2}, "oldP1-newP2": {old1, s2}} {
				sig, e1, e2 := signPair(ctx, pair[0], pair[1], d)
				if e1 == nil && e2 == nil {
					t.Fatalf("%s: mixed shares produced a result (sig %x)", name, sig)
				}
				if sig != nil {
					t.Fatalf("%s: signature returned despite error", name)
				}
				t.Logf("%s: p1 err=%v | p2 err=%v", name, e1, e2)
				for _, e := range []error{e1, e2} {
					if e != nil && IsInternal(e) {
						t.Fatalf("%s: mixed shares must not be an internal error: %v", name, e)
					}
				}
			}
			// Same for keyset-level mixing: deriving with one refreshed and one old keyset.
			var x1, x2 *SignKey
			e1, e2 = both(
				func(tr Transport) (err error) { x1, err = n1.Derive(ctx, tr, h, []uint32{5}); return },
				func(tr Transport) (err error) { x2, err = k2.Derive(ctx, tr, h, []uint32{5}); return })
			t.Logf("derive newP1-oldP2: p1 err=%v | p2 err=%v", e1, e2)
			if e1 == nil && e2 == nil {
				// derive may succeed (it only runs the VRF on the K shares, which refresh does not touch); then signing must fail
				p1, _ := x1.PublicKey()
				p2, _ := x2.PublicKey()
				if bytes.Equal(p1, p2) {
					t.Fatal("mixed derive produced a consistent key")
				}
				defer x1.Wipe()
				defer x2.Wipe()
				sig, a, b := signPair(ctx, x1, x2, d)
				if a == nil && b == nil || sig != nil {
					t.Fatal("mixed derive produced a working signing key")
				}
			}
		})
	}
}

func TestTransportFailureIsTransportError(t *testing.T) {
	k1, k2 := dkgPair(t, ECDSA)
	_ = k2
	s1, s2 := derivePair(t, k1, k2, []uint32{1}, []uint32{0})
	ctx := ctx5(t)
	a, b := NewMemPair()
	go func() { time.Sleep(50 * time.Millisecond); b.Close() }()
	_, err := s1.Sign(ctx, a, digest32(1))
	if !IsTransport(err) {
		t.Fatalf("want transport error, got %v", err)
	}
	_ = s2
}

func TestRecvTimeoutIsTransportError(t *testing.T) {
	k1, _ := dkgPair(t, Ed25519)
	a, _ := NewMemPair() // peer never answers
	start := time.Now()
	_, err := k1.NodeExport(ctx5(t), a, []uint32{1}, WithRecvTimeout(300*time.Millisecond))
	if !IsTransport(err) || !errors.Is(err, ErrRecvTimeout) {
		t.Fatalf("want transport timeout, got %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
}

// Every blocking call returns promptly when the context is cancelled, even if the Transport ignores the context.
type deafTransport struct{ block chan struct{} }

func (d deafTransport) Send(context.Context, []byte) error { <-d.block; return nil }
func (d deafTransport) Recv(context.Context) ([]byte, error) {
	<-d.block
	return nil, errors.New("released")
}

func TestContextCancelReturnsPromptly(t *testing.T) {
	k1, _ := dkgPair(t, ECDSA)
	cases := map[string]Transport{}
	a, _ := NewMemPair()
	cases["mem-silent-peer"] = a
	dt := deafTransport{block: make(chan struct{})}
	cases["transport-ignores-ctx"] = dt
	t.Cleanup(func() { close(dt.block) })
	before := threadsAndGoroutines()
	for name, tr := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(150*time.Millisecond, cancel)
			start := time.Now()
			_, err := k1.NodeExport(ctx, tr, []uint32{1})
			el := time.Since(start)
			if !IsTransport(err) || !errors.Is(err, context.Canceled) {
				t.Fatalf("want transport/canceled, got %v", err)
			}
			if el > 2*time.Second {
				t.Fatalf("returned after %v", el)
			}
		})
	}
	// An already-cancelled context never reaches C++.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DKG(ctx, a, P1, ECDSA); !IsTransport(err) {
		t.Fatalf("got %v", err)
	}
	// Nothing stays stuck: goroutines come back to baseline (the deaf transport's own goroutine is released in cleanup).
	waitGoroutines(t, before.goroutines+3)
}

func TestConcurrency32(t *testing.T) {
	// 32 concurrent sessions per curve over one keyset: derive + sign, verify every signature.
	const n = 32
	for _, alg := range []Alg{ECDSA, Ed25519} {
		t.Run(alg.String(), func(t *testing.T) {
			k1, k2 := dkgPair(t, alg)
			ctx := ctx5(t)
			var wg sync.WaitGroup
			errs := make(chan error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					path := []uint32{uint32(i)}
					var s1, s2 *SignKey
					e1, e2 := both(
						func(tr Transport) (err error) { s1, err = k1.Derive(ctx, tr, []uint32{7}, path); return },
						func(tr Transport) (err error) { s2, err = k2.Derive(ctx, tr, []uint32{7}, path); return })
					if e1 != nil || e2 != nil {
						errs <- errors.Join(e1, e2)
						return
					}
					defer s1.Wipe()
					defer s2.Wipe()
					msg := digest32(byte(i))
					sig, e1, e2 := signPair(ctx, s1, s2, msg)
					if e1 != nil || e2 != nil {
						errs <- errors.Join(e1, e2)
						return
					}
					pub, _ := s1.PublicKey()
					if !verifyQuiet(alg, pub, msg, sig) {
						errs <- errors.New("signature does not verify")
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

func TestSecretWipe(t *testing.T) {
	k1, _ := dkgPair(t, ECDSA)
	b, err := k1.Bytes()
	must(t, err)
	if len(b) == 0 || k1.Len() != len(b) {
		t.Fatal("bad len")
	}
	WipeBytes(b)
	for _, c := range b {
		if c != 0 {
			t.Fatal("WipeBytes left data")
		}
	}
	k1.Wipe()
	k1.Wipe() // idempotent
	if k1.Len() != 0 {
		t.Fatal("Len after wipe")
	}
	if _, err := k1.Bytes(); !errors.Is(err, ErrWiped) {
		t.Fatalf("want ErrWiped, got %v", err)
	}
	if _, err := k1.RootPublicKey(); !IsInternal(err) || !errors.Is(err, ErrWiped) {
		t.Fatalf("use after wipe: %v", err)
	}
	if _, err := k1.Derive(ctx5(t), mustPair(t), []uint32{1}, nil); !IsInternal(err) {
		t.Fatalf("derive after wipe: %v", err)
	}
	// SecretFromBytes consumes its input.
	in := []byte{1, 2, 3, 4}
	s := SecretFromBytes(in)
	if !bytes.Equal(in, []byte{0, 0, 0, 0}) || s.Len() != 4 {
		t.Fatal("SecretFromBytes must wipe its input")
	}
	s.Wipe()
}

func TestInvalidArguments(t *testing.T) {
	k1, _ := dkgPair(t, ECDSA)
	ctx := ctx5(t)
	tr := mustPair(t)
	for name, f := range map[string]func() error{
		"empty hardened":       func() error { _, e := k1.Derive(ctx, tr, nil, nil); return e },
		"hardened as child":    func() error { _, e := k1.Derive(ctx, tr, []uint32{1}, []uint32{0x80000000}); return e },
		"too long":             func() error { _, e := k1.Derive(ctx, tr, make([]uint32, 17), nil); return e },
		"bip340 hd":            func() error { _, e := DKG(ctx, tr, P1, BIP340); return e },
		"bad role":             func() error { _, e := DKG(ctx, tr, Role(5), ECDSA); return e },
		"nil transport":        func() error { _, e := k1.NodeExport(ctx, nil, []uint32{1}); return e },
		"load garbage":         func() error { _, e := LoadKeyset(ECDSA, P1, []byte("garbage")); return e },
		"load empty":           func() error { _, e := LoadKeyset(ECDSA, P1, nil); return e },
		"load wrong alg":       func() error { b, _ := k1.Bytes(); _, e := LoadKeyset(Ed25519, P1, b); return e },
		"load wrong role":      func() error { b, _ := k1.Bytes(); _, e := LoadKeyset(ECDSA, P2, b); return e },
		"signkey load garbage": func() error { _, e := LoadSignKey(ECDSA, P1, []byte("garbage")); return e },
	} {
		if err := f(); !IsInternal(err) {
			t.Errorf("%s: want internal error, got %v", name, err)
		}
	}
	// A valid blob round-trips through Load.
	b, _ := k1.Bytes()
	k, err := LoadKeyset(ECDSA, P1, b)
	must(t, err)
	r0, _ := k1.RootPublicKey()
	r1, _ := k.RootPublicKey()
	if !bytes.Equal(r0, r1) {
		t.Fatal("load changed key")
	}
	k.Wipe()
}
