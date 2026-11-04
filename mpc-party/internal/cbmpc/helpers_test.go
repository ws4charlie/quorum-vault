package cbmpc

import (
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func ctx5(t testing.TB) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

// both runs fa (P1) and fb (P2) concurrently over a fresh in-memory link and returns both errors.
// On the first error of either side the link is closed so the other side cannot hang.
func both(fa, fb func(tr Transport) error) (ea, eb error) {
	a, b := NewMemPair()
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

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func dkgPair(t testing.TB, alg Alg) (k1, k2 *Keyset) {
	t.Helper()
	ctx := ctx5(t)
	var e1, e2 error
	e1, e2 = both(
		func(tr Transport) (err error) { k1, err = DKG(ctx, tr, P1, alg); return },
		func(tr Transport) (err error) { k2, err = DKG(ctx, tr, P2, alg); return })
	must(t, e1)
	must(t, e2)
	t.Cleanup(func() { k1.Wipe(); k2.Wipe() })
	return
}

func derivePair(t testing.TB, k1, k2 *Keyset, hardened, path []uint32) (s1, s2 *SignKey) {
	t.Helper()
	ctx := ctx5(t)
	e1, e2 := both(
		func(tr Transport) (err error) { s1, err = k1.Derive(ctx, tr, hardened, path); return },
		func(tr Transport) (err error) { s2, err = k2.Derive(ctx, tr, hardened, path); return })
	must(t, e1)
	must(t, e2)
	t.Cleanup(func() { s1.Wipe(); s2.Wipe() })
	return
}

func signPair(ctx context.Context, s1, s2 *SignKey, msg []byte) (sig []byte, e1, e2 error) {
	e1, e2 = both(
		func(tr Transport) (err error) { sig, err = s1.Sign(ctx, tr, msg); return },
		func(tr Transport) (err error) { _, err = s2.Sign(ctx, tr, msg); return })
	return
}

type derSig struct{ R, S *big.Int }

// verifyECDSA checks a DER signature with btcec (independent of cb-mpc) and that s is low.
func verifyECDSA(t testing.TB, pub33, digest, der []byte) {
	t.Helper()
	pub, err := btcec.ParsePubKey(pub33)
	must(t, err)
	var ds derSig
	rest, err := asn1.Unmarshal(der, &ds)
	if err != nil || len(rest) != 0 {
		t.Fatalf("signature is not canonical DER: %v", err)
	}
	half := new(big.Int).Rsh(btcec.S256().N, 1)
	if ds.S.Cmp(half) > 0 {
		t.Fatalf("high-S signature")
	}
	sig, err := ecdsa.ParseDERSignature(der)
	must(t, err)
	if !sig.Verify(digest, pub) {
		t.Fatalf("ECDSA signature does not verify (btcec)")
	}
}

func verifyEd25519(t testing.TB, pub, msg, sig []byte) {
	t.Helper()
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatalf("Ed25519 signature does not verify (crypto/ed25519)")
	}
}

func verifyBIP340(t testing.TB, xonly, digest, sig []byte) {
	t.Helper()
	pk, err := schnorr.ParsePubKey(xonly)
	must(t, err)
	s, err := schnorr.ParseSignature(sig)
	must(t, err)
	if !s.Verify(digest, pk) {
		t.Fatalf("BIP340 signature does not verify (btcec)")
	}
}

func digest32(seed byte) []byte {
	d := make([]byte, 32)
	for i := range d {
		d[i] = seed + byte(i)
	}
	return d
}

// verifyQuiet is verifyECDSA/verifyEd25519 without testing.TB, for use from helper goroutines.
func verifyQuiet(alg Alg, pub, msg, sig []byte) bool {
	if alg == Ed25519 {
		return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
	}
	pk, err := btcec.ParsePubKey(pub)
	if err != nil {
		return false
	}
	s, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return false
	}
	return s.Verify(msg, pk)
}
