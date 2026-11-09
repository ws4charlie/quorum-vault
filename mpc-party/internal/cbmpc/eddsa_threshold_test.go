package cbmpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"
)

// 2-of-3 Ed25519 (P8-1): the same wrapper as the ECDSA threshold calls, signatures checked with crypto/ed25519.

func edMsg(n int, seed byte) []byte {
	m := make([]byte, n)
	for i := range m {
		m[i] = seed + byte(i*7)
	}
	return m
}

func TestEdThresholdDKGSignEveryPair(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	pub := ks[0].PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key is %d bytes", len(pub))
	}
	for i := range ks {
		if ks[i].Alg() != Ed25519 || !bytes.Equal(ks[i].PublicKey(), pub) || ks[i].Self() != Member(i) {
			t.Fatalf("member %d disagrees", i)
		}
		if len(ks[i].SharePoint()) != 32 {
			t.Fatalf("share point is %d bytes", len(ks[i].SharePoint()))
		}
	}
	if bytes.Equal(ks[0].SharePoint(), ks[1].SharePoint()) {
		t.Fatal("two members have the same share point")
	}
	ctx := ctx5(t)
	// message sizes: 1 byte, a digest, a typical Solana message, the largest one a transaction may carry, and the cap
	for _, n := range []int{1, 32, 200, 1232, MaxEdMessage} {
		for _, pr := range allPairs {
			for _, recv := range []Member{pr[0], pr[1]} {
				m := edMsg(n, byte(pr[0]+pr[1]))
				sig, ea, eb := tSign(ctx, ks, pr[0], pr[1], recv, m)
				must(t, ea)
				must(t, eb)
				if len(sig) != 64 {
					t.Fatalf("signature is %d bytes", len(sig))
				}
				verifyEd25519(t, pub, m, sig) // crypto/ed25519, RFC 8032
			}
		}
		if testing.Short() && n >= 200 {
			break
		}
	}
}

// Signatures are randomized: two signatures over the same message differ and both verify (custody stores the first).
func TestEdThresholdSignaturesAreRandomized(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	ctx := ctx5(t)
	m := edMsg(100, 3)
	s1, ea, eb := tSign(ctx, ks, 0, 1, 0, m)
	must(t, ea)
	must(t, eb)
	s2, ea, eb := tSign(ctx, ks, 0, 1, 0, m)
	must(t, ea)
	must(t, eb)
	s3, ea, eb := tSign(ctx, ks, 1, 2, 2, m)
	must(t, ea)
	must(t, eb)
	if bytes.Equal(s1, s2) || bytes.Equal(s1, s3) {
		t.Fatal("two signatures over one message are identical: nonces are not fresh")
	}
	for _, s := range [][]byte{s1, s2, s3} {
		verifyEd25519(t, ks[0].PublicKey(), m, s)
	}
}

func TestEdThresholdSelfTestAfterDKGAndRefresh(t *testing.T) {
	ctx := ctx5(t)
	ks := tDKGAlg(t, Ed25519)
	for i, e := range tSelfTest(ctx, ks, []byte("ks1|g1")) {
		if e != nil {
			t.Fatalf("self-test after DKG, member %d: %v", i, e)
		}
	}
	nk := tRefresh(t, ks)
	if !bytes.Equal(nk[0].PublicKey(), ks[0].PublicKey()) {
		t.Fatal("refresh moved the public key")
	}
	if nk[0].Alg() != Ed25519 {
		t.Fatal("refresh changed the scheme")
	}
	if bytes.Equal(tBlob(t, nk[0]), tBlob(t, ks[0])) || bytes.Equal(nk[1].SharePoint(), ks[1].SharePoint()) {
		t.Fatal("refresh did not change the shares")
	}
	for i, e := range tSelfTest(ctx, nk, []byte("ks1|g2")) {
		if e != nil {
			t.Fatalf("self-test after refresh, member %d: %v", i, e)
		}
	}
	for _, pr := range allPairs {
		m := edMsg(64, byte(pr[1]))
		sig, ea, eb := tSign(ctx, nk, pr[0], pr[1], pr[0], m)
		must(t, ea)
		must(t, eb)
		verifyEd25519(t, nk[0].PublicKey(), m, sig)
	}
	sig, ea, eb := tSign(ctx, ks, 0, 1, 1, edMsg(10, 1)) // the old generation works until wiped
	must(t, ea)
	must(t, eb)
	verifyEd25519(t, ks[0].PublicKey(), edMsg(10, 1), sig)
}

// Old and new shares never mix: no signature comes out, the receiver fails with Cryptographic or Transport.
func TestEdThresholdOldAndNewSharesDoNotMix(t *testing.T) {
	ctx := ctx5(t)
	ks := tDKGAlg(t, Ed25519)
	nk := tRefresh(t, ks)
	for _, pr := range allPairs {
		for _, oldIsFirst := range []bool{true, false} {
			mixed := nk
			if oldIsFirst {
				mixed[pr[0]] = ks[pr[0]]
			} else {
				mixed[pr[1]] = ks[pr[1]]
			}
			for _, recv := range []Member{pr[0], pr[1]} {
				sig, ea, eb := tSign(ctx, mixed, pr[0], pr[1], recv, edMsg(32, 5))
				if sig != nil {
					t.Fatalf("pair %v old-first=%v: a signature came out of mixed generations", pr, oldIsFirst)
				}
				re := ea
				if recv == pr[1] {
					re = eb
				}
				if re == nil || !classOK(re) {
					t.Fatalf("pair %v old-first=%v receiver %d: want Cryptographic or Transport, got %v", pr, oldIsFirst, recv, re)
				}
				t.Logf("pair %v old-first=%v receiver=%d: receiver %s, other %v", pr, oldIsFirst, recv, KindOf(re), kindStr(ea, eb, recv, pr))
			}
		}
	}
	half := nk
	half[2] = ks[2]
	errs := tSelfTest(ctx, half, []byte("half"))
	if errs[0] == nil && errs[1] == nil && errs[2] == nil {
		t.Fatal("SelfTest passed on a half-refreshed key set")
	}
	if errs[0] == nil && errs[1] == nil {
		t.Fatal("members 0 and 1 both passed although each pairs with the stale member 2")
	}
}

func TestEdThresholdLoadAndInfo(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	ec := tDKG(t)
	for m := Member(0); m < NumMembers; m++ {
		b := tBlob(t, ks[m])
		k, err := LoadTKeyAlg(Ed25519, m, append([]byte(nil), b...))
		must(t, err)
		if k.Alg() != Ed25519 || !bytes.Equal(k.PublicKey(), ks[m].PublicKey()) || !bytes.Equal(k.SharePoint(), ks[m].SharePoint()) {
			t.Fatal("reloaded share differs")
		}
		k.Wipe()
		if _, err := LoadTKeyAlg(Ed25519, (m+1)%NumMembers, append([]byte(nil), b...)); !IsInternal(err) {
			t.Fatalf("share of %d loaded as another member: %v", m, err)
		}
		// an Ed25519 share is not an ECDSA share and the other way round
		if _, err := LoadTKey(m, append([]byte(nil), b...)); !IsInternal(err) {
			t.Fatalf("Ed25519 share loaded as ECDSA: %v", err)
		}
		if _, err := LoadTKeyAlg(Ed25519, m, tBlob(t, ec[m])); !IsInternal(err) {
			t.Fatalf("ECDSA share loaded as Ed25519: %v", err)
		}
		for _, mut := range []func([]byte) []byte{
			func(x []byte) []byte { return x[:len(x)-1] },
			func(x []byte) []byte { return x[:len(x)/2] },
			func(x []byte) []byte { x[len(x)-1] ^= 1; return x },
			func(x []byte) []byte { x[len(x)/2] ^= 1; return x },
			func(x []byte) []byte { return append(x, 0) },
			func(x []byte) []byte { return nil },
		} {
			if k, err := LoadTKeyAlg(Ed25519, m, mut(append([]byte(nil), b...))); err == nil {
				if !bytes.Equal(k.PublicKey(), ks[m].PublicKey()) || !bytes.Equal(k.SharePoint(), ks[m].SharePoint()) {
					t.Fatal("a damaged share loaded as a different key")
				}
				k.Wipe()
			} else if !IsInternal(err) && !IsCryptographic(err) {
				t.Fatalf("damaged share: want internal or cryptographic, got %v", err)
			}
		}
	}
	if _, err := LoadTKeyAlg(Ed25519, 3, []byte{1}); !IsInternal(err) {
		t.Fatalf("member 3: %v", err)
	}
	if _, err := LoadTKeyAlg(BIP340, 0, []byte{1}); !IsInternal(err) {
		t.Fatalf("BIP340: %v", err)
	}
}

func TestEdThresholdBadArguments(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	ctx := ctx5(t)
	mesh := NewMemMesh()
	m := edMsg(32, 1)
	for name, f := range map[string]func() error{
		"self-as-peer": func() error { _, err := ks[0].Sign(ctx, mesh[0], 0, 0, m); return err },
		"peer 3":       func() error { _, err := ks[0].Sign(ctx, mesh[0], 3, 0, m); return err },
		"receiver 2":   func() error { _, err := ks[0].Sign(ctx, mesh[0], 1, 2, m); return err },
		"empty msg":    func() error { _, err := ks[0].Sign(ctx, mesh[0], 1, 0, nil); return err },
		"huge msg":     func() error { _, err := ks[0].Sign(ctx, mesh[0], 1, 0, make([]byte, MaxEdMessage+1)); return err },
		"nil mesh":     func() error { _, err := ks[0].Sign(ctx, nil, 1, 0, m); return err },
		"dkg member 5": func() error { _, err := TDKGAlg(ctx, mesh[0], 5, Ed25519); return err },
		"dkg bip340":   func() error { _, err := TDKGAlg(ctx, mesh[0], 0, BIP340); return err },
		"dkg nil mesh": func() error { _, err := TDKGAlg(ctx, nil, 0, Ed25519); return err },
	} {
		if err := f(); !IsInternal(err) {
			t.Errorf("%s: want internal, got %v", name, err)
		}
	}
	if _, err := ks[0].Sign(ctx, NewLinkMesh(0, nil), 1, 0, m); !IsTransport(err) {
		t.Errorf("link missing: want transport, got %v", err)
	}
	k, err := LoadTKeyAlg(Ed25519, 0, tBlob(t, ks[0]))
	must(t, err)
	k.Wipe()
	if _, err := k.Sign(ctx, mesh[0], 1, 0, m); !IsInternal(err) {
		t.Fatalf("wiped key: %v", err)
	}
}

func TestEdThresholdOverLoopbackTCP(t *testing.T) {
	ctx := ctx5(t)
	var ks [NumMembers]*TKey
	meshes := tcpMesh(t)
	errs := trioOn(ctx, meshes, func(ctx context.Context, m Member, mesh *LinkMesh) (err error) {
		ks[m], err = TDKGAlg(ctx, mesh, m, Ed25519)
		return
	})
	for _, e := range errs {
		must(t, e)
	}
	defer func() {
		for _, k := range ks {
			k.Wipe()
		}
	}()
	for _, pr := range allPairs {
		a, b := pr[0], pr[1]
		d := edMsg(150, byte(a*3+b))
		var sig []byte
		var wg sync.WaitGroup
		var ea, eb error
		wg.Add(2)
		go func() { defer wg.Done(); sig, ea = ks[a].Sign(ctx, meshes[a], b, a, d) }()
		go func() { defer wg.Done(); _, eb = ks[b].Sign(ctx, meshes[b], a, a, d) }()
		wg.Wait()
		must(t, ea)
		must(t, eb)
		verifyEd25519(t, ks[0].PublicKey(), d, sig)
	}
	errs = trioOn(ctx, meshes, func(ctx context.Context, m Member, mesh *LinkMesh) error {
		return ks[m].SelfTest(ctx, mesh, []byte("tcp"))
	})
	for _, e := range errs {
		must(t, e)
	}
}

func TestEdThresholdContextCancelAndTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	meshes := NewMemMesh()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ { // the third member never shows up
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, errs[i] = TDKGAlg(ctx, meshes[i], Member(i), Ed25519) }(i)
	}
	time.AfterFunc(300*time.Millisecond, cancel)
	wg.Wait()
	for i, e := range errs {
		if !IsTransport(e) {
			t.Fatalf("member %d: want transport after cancel, got %v", i, e)
		}
	}
	ks := tDKGAlg(t, Ed25519)
	_, err := ks[0].Sign(ctx5(t), NewMemMesh()[0], 1, 0, edMsg(8, 1), WithRecvTimeout(300*time.Millisecond))
	if !IsTransport(err) {
		t.Fatalf("want transport on silent peer, got %v", err)
	}
}

// 32 concurrent signing sessions on the same three keys, then concurrent DKG+refresh+self-test of independent keys.
func TestEdThresholdConcurrency(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	pub := ks[0].PublicKey()
	ctx := ctx5(t)
	const n = 32
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pr := allPairs[i%3]
			m := edMsg(40+i, byte(i))
			sig, ea, eb := tSign(ctx, ks, pr[0], pr[1], pr[i%2], m)
			if ea != nil || eb != nil {
				errc <- ea
				if ea == nil {
					errc <- eb
				}
				return
			}
			if !verifyQuiet(Ed25519, pub, m, sig) {
				errc <- &Error{Kind: KindInternal, Op: "test", Msg: "bad signature under concurrency"}
			}
		}(i)
	}
	wg.Wait()
	close(errc)
	for e := range errc {
		t.Error(e)
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := tDKGAlg(t, Ed25519)
			nk := tRefresh(t, k)
			for j, e := range tSelfTest(ctx5(t), nk, []byte("c")) {
				if e != nil {
					t.Errorf("member %d: %v", j, e)
				}
			}
		}()
	}
	wg.Wait()
}
