package sol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
)

// Public derivation is the BIP32 rule on Edwards points: the child of P is P + I_L*G. Checked against the private side: a node made from a
// secret scalar a derives, by adding I_L to a, the key whose public point is the child the public derivation gives.
func TestChildPublicKeyMatchesTheChildPrivateScalar(t *testing.T) {
	var seed [64]byte
	for i := range seed {
		seed[i] = byte(i*3 + 1)
	}
	a, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	var n Node
	copy(n.PublicKey[:], new(edwards25519.Point).ScalarBaseMult(a).Bytes())
	for i := range n.ChainCode {
		n.ChainCode[i] = byte(200 - i)
	}
	cur, sk := n, a
	for _, idx := range []uint32{0, 5, 1<<31 - 1} {
		m := hmac.New(sha512.New, cur.ChainCode[:])
		m.Write(cur.PublicKey[:])
		var ix [4]byte
		binary.BigEndian.PutUint32(ix[:], idx)
		m.Write(ix[:])
		I := m.Sum(nil)
		var le [64]byte
		for i := 0; i < 32; i++ {
			le[i] = I[31-i]
		}
		il, _ := edwards25519.NewScalar().SetUniformBytes(le[:])
		sk = edwards25519.NewScalar().Add(sk, il)
		next, err := cur.child(idx)
		if err != nil {
			t.Fatal(err)
		}
		if want := new(edwards25519.Point).ScalarBaseMult(sk).Bytes(); !bytes.Equal(next.PublicKey[:], want) {
			t.Fatalf("index %d: public child %x, private side %x", idx, next.PublicKey, want)
		}
		cur = next
	}
}

func TestHardenedIndexIsRefused(t *testing.T) {
	var n Node
	copy(n.PublicKey[:], edwards25519.NewGeneratorPoint().Bytes())
	if _, err := n.Derive(1 << 31); err == nil {
		t.Fatal("a hardened index derived from public data")
	}
}

func TestAddressRoundTrip(t *testing.T) {
	var p [32]byte
	copy(p[:], edwards25519.NewGeneratorPoint().Bytes())
	got, err := ParseAddress(Address(p))
	if err != nil || got != p {
		t.Fatalf("round trip: %x %v", got, err)
	}
	if _, err := ParseAddress("too-short"); err == nil {
		t.Fatal("a short address parsed")
	}
}

// The ATA is a program address: off the curve, and different per owner and per mint. (That it is the address the real program expects is checked
// on the validator in e2e/sol: creating an account there at a wrong address fails.)
func TestATAIsOffTheCurveAndPerOwnerAndMint(t *testing.T) {
	var o1, o2, m1, m2 [32]byte
	o1[0], o2[0], m1[0], m2[0] = 1, 2, 3, 4
	// make them valid-looking points, though ATA does not need that
	a11, err := ATA(o1, m1)
	if err != nil {
		t.Fatal(err)
	}
	if onCurve(a11[:]) {
		t.Fatal("an ATA must not be on the curve")
	}
	a21, _ := ATA(o2, m1)
	a12, _ := ATA(o1, m2)
	if a11 == a21 || a11 == a12 {
		t.Fatal("ATA does not depend on owner and mint")
	}
	again, _ := ATA(o1, m1)
	if again != a11 {
		t.Fatal("ATA is not deterministic")
	}
	_ = hex.EncodeToString
}

func TestConfigRefusals(t *testing.T) {
	good := Config{Chain: "sol", Network: "localnet", RPCURL: "http://x",
		AccountPublicKey: hex.EncodeToString(edwards25519.NewGeneratorPoint().Bytes()), AccountChainCode: hex.EncodeToString(make([]byte, 32))}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"unknown network":  func(c *Config) { c.Network = "moon" },
		"bad chain name":   func(c *Config) { c.Chain = "a:b" },
		"short key":        func(c *Config) { c.AccountPublicKey = "00" },
		"key off curve":    func(c *Config) { c.AccountPublicKey = "02" + hex.EncodeToString(make([]byte, 31)) },
		"short chain code": func(c *Config) { c.AccountChainCode = "00" },
		"token without decimals": func(c *Config) {
			c.Tokens = map[string]string{"TKN": Address([32]byte{1})}
		},
		"token named SOL": func(c *Config) {
			c.Tokens, c.TokenDecimals = map[string]string{"SOL": Address([32]byte{1})}, map[string]int{"SOL": 6}
		},
	} {
		c := good
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
