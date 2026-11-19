package attest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestUserDataBindsEveryInput(t *testing.T) {
	c := RequestContext{Party: "A", Keyset: "k", Generations: []uint64{1, 2}, Purpose: PurposeUnseal}
	blobs := [][]byte{[]byte("b1"), []byte("b2")}
	var pin [32]byte
	pin[0] = 1
	base := c.UserData(blobs, pin)
	if len(base) != 32 || !bytes.Equal(base, c.UserData(blobs, pin)) {
		t.Fatal("user_data is not a stable SHA-256")
	}
	other := pin
	other[1] = 1
	variants := map[string][]byte{
		"party":      RequestContext{Party: "B", Keyset: "k", Generations: []uint64{1, 2}, Purpose: PurposeUnseal}.UserData(blobs, pin),
		"keyset":     RequestContext{Party: "A", Keyset: "j", Generations: []uint64{1, 2}, Purpose: PurposeUnseal}.UserData(blobs, pin),
		"generation": RequestContext{Party: "A", Keyset: "k", Generations: []uint64{1, 3}, Purpose: PurposeUnseal}.UserData(blobs, pin),
		"purpose":    RequestContext{Party: "A", Keyset: "k", Generations: []uint64{1, 2}, Purpose: PurposeCreate}.UserData(blobs, pin),
		"blob":       c.UserData([][]byte{[]byte("b1"), []byte("bX")}, pin),
		"blob order": c.UserData([][]byte{[]byte("b2"), []byte("b1")}, pin),
		"blob split": c.UserData([][]byte{[]byte("b1b2")}, pin),
		"caller pin": c.UserData(blobs, other),
	}
	for name, v := range variants {
		if bytes.Equal(v, base) {
			t.Fatalf("user_data does not change with the %s", name)
		}
	}
}

func TestContextValidation(t *testing.T) {
	ok := RequestContext{Party: "A", Keyset: "k", Generations: []uint64{1}, Purpose: PurposeUnseal}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*RequestContext){
		"empty party":    func(c *RequestContext) { c.Party = "" },
		"odd party":      func(c *RequestContext) { c.Party = "A B" },
		"no keyset":      func(c *RequestContext) { c.Keyset = "" },
		"no generation":  func(c *RequestContext) { c.Generations = nil },
		"twice":          func(c *RequestContext) { c.Generations = []uint64{1, 1} },
		"too many":       func(c *RequestContext) { c.Generations = make([]uint64, MaxGenerations+1) },
		"unknown intent": func(c *RequestContext) { c.Purpose = "export" },
	} {
		c := ok
		mod(&c)
		if c.Validate() == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSealToOpensOnlyWithTheRightKeyAndContext(t *testing.T) {
	priv, pub, err := NewReleaseKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := SealTo(pub, []byte("ctx"), secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("plaintext in the output")
	}
	if got, err := OpenFrom(priv, []byte("ctx"), sealed); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %v", err)
	}
	other, _, _ := NewReleaseKey()
	if _, err := OpenFrom(other, []byte("ctx"), sealed); err == nil {
		t.Fatal("another key opened it")
	}
	if _, err := OpenFrom(priv, []byte("other ctx"), sealed); err == nil {
		t.Fatal("another context opened it")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenFrom(priv, []byte("ctx"), sealed); err == nil {
		t.Fatal("a changed byte opened")
	}
	if _, err := OpenFrom(priv, nil, []byte("short")); err == nil {
		t.Fatal("short input opened")
	}
}

func TestSealToP256AndBadKeys(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	sealed, err := SealTo(der, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	ek, _ := k.ECDH()
	if got, err := OpenFrom(ek, nil, sealed); err != nil || string(got) != "x" {
		t.Fatalf("P-256: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := SealTo(der, nil, []byte("x")); err == nil {
		t.Fatal("P-384 accepted")
	}
	if _, err := SealTo([]byte("DER-public-key"), nil, []byte("x")); err == nil {
		t.Fatal("garbage key accepted")
	}
	var _ *ecdh.PrivateKey = ek
}
