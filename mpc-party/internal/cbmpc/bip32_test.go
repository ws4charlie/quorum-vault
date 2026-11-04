package cbmpc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// ckdPubSecp is an independent BIP32 CKDpub in pure Go (btcec for the curve arithmetic only).
func ckdPubSecp(t testing.TB, pub, cc []byte, i uint32) ([]byte, []byte) {
	t.Helper()
	m := hmac.New(sha512.New, cc)
	m.Write(pub)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], i)
	m.Write(idx[:])
	I := m.Sum(nil)
	var il btcec.ModNScalar
	if overflow := il.SetByteSlice(I[:32]); overflow || il.IsZero() {
		t.Fatal("invalid child (probability 2^-127)")
	}
	parent, err := btcec.ParsePubKey(pub)
	must(t, err)
	var pj, ilG, sum btcec.JacobianPoint
	parent.AsJacobian(&pj)
	btcec.ScalarBaseMultNonConst(&il, &ilG)
	btcec.AddNonConst(&pj, &ilG, &sum)
	sum.ToAffine()
	return btcec.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed(), I[32:]
}

// The node (public key + chain code) exported through the MPC hardened step must be a valid BIP32 xpub: children derived
// from it with an independent implementation equal the keys the MPC derives.
func TestBIP32VectorECDSA(t *testing.T) {
	ctx := ctx5(t)
	k1, k2 := dkgPair(t, ECDSA)
	hardened := []uint32{44, 60, 0}
	var n1, n2 Node
	e1, e2 := both(
		func(tr Transport) (err error) { n1, err = k1.NodeExport(ctx, tr, hardened); return },
		func(tr Transport) (err error) { n2, err = k2.NodeExport(ctx, tr, hardened); return })
	must(t, e1)
	must(t, e2)
	if !bytes.Equal(n1.PublicKey, n2.PublicKey) || !bytes.Equal(n1.ChainCode, n2.ChainCode) {
		t.Fatal("parties disagree on the node")
	}
	if len(n1.PublicKey) != 33 || len(n1.ChainCode) != 32 {
		t.Fatalf("sizes %d %d", len(n1.PublicKey), len(n1.ChainCode))
	}
	// The node must also be what Derive uses internally (empty non-hardened path = the node itself).
	s1, s2 := derivePair(t, k1, k2, hardened, nil)
	_ = s2
	dp, err := s1.PublicKey()
	must(t, err)
	if !bytes.Equal(dp, n1.PublicKey) {
		t.Fatalf("NodeExport public key %x != Derive(no path) %x: shim's copy of the VRF step diverged from upstream", n1.PublicKey, dp)
	}

	xpub := hdkeychain.NewExtendedKey(chaincfg.MainNetParams.HDPublicKeyID[:], n1.PublicKey, n1.ChainCode, []byte{0, 0, 0, 0}, 3, 0, false)
	for _, path := range [][]uint32{{0}, {1}, {0, 0}, {1, 5}, {0, 4242}, {2147483647}} {
		c1, c2 := derivePair(t, k1, k2, hardened, path)
		got, err := c1.PublicKey()
		must(t, err)
		_ = c2

		// (a) hdkeychain (btcutil)
		ek := xpub
		for _, i := range path {
			ek, err = ek.Derive(i)
			must(t, err)
		}
		want, err := ek.ECPubKey()
		must(t, err)
		if !bytes.Equal(got, want.SerializeCompressed()) {
			t.Fatalf("path %v: MPC %x != hdkeychain %x", path, got, want.SerializeCompressed())
		}
		// (b) our own few lines of CKDpub
		pub, cc := n1.PublicKey, n1.ChainCode
		for _, i := range path {
			pub, cc = ckdPubSecp(t, pub, cc, i)
		}
		if !bytes.Equal(got, pub) {
			t.Fatalf("path %v: MPC %x != pure-Go CKDpub %x", path, got, pub)
		}
	}
	// The xpub serializes (sanity: it is what P7 will store).
	t.Logf("xpub %s", xpub.String())
}

// Ed25519: cb-mpc applies the BIP32 rule on Edwards points (not SLIP-0010). Independent check with filippo.io/edwards25519.
func TestBIP32StyleVectorEd25519(t *testing.T) {
	ctx := ctx5(t)
	k1, k2 := dkgPair(t, Ed25519)
	hardened := []uint32{44, 501, 0}
	var n1, n2 Node
	e1, e2 := both(
		func(tr Transport) (err error) { n1, err = k1.NodeExport(ctx, tr, hardened); return },
		func(tr Transport) (err error) { n2, err = k2.NodeExport(ctx, tr, hardened); return })
	must(t, e1)
	must(t, e2)
	if !bytes.Equal(n1.PublicKey, n2.PublicKey) || !bytes.Equal(n1.ChainCode, n2.ChainCode) || len(n1.PublicKey) != 32 {
		t.Fatal("parties disagree or bad node size")
	}
	s1, _ := derivePair(t, k1, k2, hardened, nil)
	dp, _ := s1.PublicKey()
	if !bytes.Equal(dp, n1.PublicKey) {
		t.Fatalf("NodeExport %x != Derive(no path) %x", n1.PublicKey, dp)
	}
	for _, path := range [][]uint32{{0}, {3}, {1, 5}, {7, 7, 7}} {
		c1, _ := derivePair(t, k1, k2, hardened, path)
		got, _ := c1.PublicKey()
		pub, cc := n1.PublicKey, n1.ChainCode
		for _, i := range path {
			m := hmac.New(sha512.New, cc)
			m.Write(pub)
			var idx [4]byte
			binary.BigEndian.PutUint32(idx[:], i)
			m.Write(idx[:])
			I := m.Sum(nil)
			// I_L is a big-endian integer reduced mod the group order l (cb-mpc: bn_t::from_bin(...) % q).
			il := new(edwards25519Scalar).fromBE(I[:32])
			P, err := new(edwards25519.Point).SetBytes(pub)
			must(t, err)
			child := new(edwards25519.Point).Add(P, new(edwards25519.Point).ScalarBaseMult(il.s))
			pub, cc = child.Bytes(), I[32:]
		}
		if !bytes.Equal(got, pub) {
			t.Fatalf("path %v: MPC %x != independent derivation %x", path, got, pub)
		}
	}
}

type edwards25519Scalar struct{ s *edwards25519.Scalar }

// fromBE reduces a big-endian 32-byte integer mod l.
func (e *edwards25519Scalar) fromBE(b []byte) *edwards25519Scalar {
	le := make([]byte, 64)
	for i := 0; i < 32; i++ {
		le[i] = b[31-i]
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(le)
	if err != nil {
		panic(err)
	}
	e.s = s
	return e
}
