package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, k *ecdsa.PrivateKey, d [32]byte) Signature {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return Signature{R: r, S: s}
}

func TestNormalizeLowS(t *testing.T) {
	k := newKey(t)
	d := crypto.Keccak256Hash([]byte("hello"))
	sig := sign(t, k, d)
	low := NormalizeLowS(sig)
	high := Signature{R: low.R, S: new(big.Int).Sub(curveN, low.S)}
	if high.S.Cmp(curveHalfN) <= 0 {
		t.Fatal("test setup: expected high S")
	}
	if !Verify(&k.PublicKey, d, high) {
		t.Fatal("high-S signature should verify")
	}
	flipped := NormalizeLowS(high)
	if flipped.S.Cmp(curveHalfN) > 0 || flipped.S.Cmp(low.S) != 0 {
		t.Fatal("high S not flipped to low S")
	}
	if high.S.Cmp(new(big.Int).Sub(curveN, low.S)) != 0 {
		t.Fatal("input was modified")
	}
	if !Verify(&k.PublicKey, d, flipped) {
		t.Fatal("normalized signature should verify")
	}
	if NormalizeLowS(low).S != low.S {
		t.Fatal("low S should be returned unchanged")
	}
}

func TestVerifyRejects(t *testing.T) {
	k := newKey(t)
	d := crypto.Keccak256Hash([]byte("a"))
	sig := sign(t, k, d)
	if !Verify(&k.PublicKey, d, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(&k.PublicKey, crypto.Keccak256Hash([]byte("b")), sig) {
		t.Fatal("wrong digest accepted")
	}
	if Verify(&newKey(t).PublicKey, d, sig) {
		t.Fatal("wrong key accepted")
	}
	if Verify(&k.PublicKey, d, Signature{R: sig.R, S: big.NewInt(0)}) || Verify(&k.PublicKey, d, Signature{}) || Verify(nil, d, sig) {
		t.Fatal("degenerate input accepted")
	}
}

func TestParseUncompressed(t *testing.T) {
	k := newKey(t)
	raw := crypto.FromECDSAPub(&k.PublicKey)
	got, err := ParseUncompressed(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.X.Cmp(k.X) != 0 || got.Y.Cmp(k.Y) != 0 || got.Curve != crypto.S256() {
		t.Fatal("parsed key mismatch")
	}

	bad := map[string][]byte{
		"empty":      nil,
		"short":      raw[:64],
		"long":       append(append([]byte{}, raw...), 0),
		"compressed": crypto.CompressPubkey(&k.PublicKey),
	}
	wrongPrefix := append([]byte{}, raw...)
	wrongPrefix[0] = 0x02
	bad["prefix"] = wrongPrefix
	offCurve := append([]byte{}, raw...)
	offCurve[64] ^= 0x01
	bad["off-curve"] = offCurve
	for name, b := range bad {
		if _, err := ParseUncompressed(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
