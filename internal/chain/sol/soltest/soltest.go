// Package soltest holds what tests of the Solana cell need and production code never does: Ed25519 signing from a raw scalar with a fresh
// random nonce (the way cb-mpc's Ed25519 is randomized), and a private HD node that derives private child scalars by the same rule as the
// public derivation in package sol. Nothing here may be linked into a command.
package soltest

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
)

// Key is an Ed25519 key held as a raw scalar, so it can be HD-derived like cb-mpc's keys.
type Key struct {
	Scalar *edwards25519.Scalar
	Pub    [32]byte
}

// NewKey returns a random key.
func NewKey() Key {
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		panic(err)
	}
	return fromScalar(s)
}

func fromScalar(s *edwards25519.Scalar) Key {
	k := Key{Scalar: s}
	copy(k.Pub[:], new(edwards25519.Point).ScalarBaseMult(s).Bytes())
	return k
}

// Sign signs msg with a fresh random nonce: two signatures over one message differ, and both verify with crypto/ed25519.
func (k Key) Sign(msg []byte) []byte {
	var rb [64]byte
	if _, err := rand.Read(rb[:]); err != nil {
		panic(err)
	}
	r, err := edwards25519.NewScalar().SetUniformBytes(rb[:])
	if err != nil {
		panic(err)
	}
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	h := sha512.New()
	h.Write(R)
	h.Write(k.Pub[:])
	h.Write(msg)
	kk, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	s := edwards25519.NewScalar().MultiplyAdd(kk, k.Scalar, r)
	sig := append(append([]byte(nil), R...), s.Bytes()...)
	if !ed25519.Verify(k.Pub[:], msg, sig) {
		panic("soltest: a signature made from a raw scalar does not verify")
	}
	return sig
}

// Node is a private HD node: a key and a chain code.
type Node struct {
	Key
	ChainCode [32]byte
}

// NewNode returns a random private node.
func NewNode() Node {
	n := Node{Key: NewKey()}
	if _, err := rand.Read(n.ChainCode[:]); err != nil {
		panic(err)
	}
	return n
}

// Public is the node's public part, what the core and the zone are configured with.
func (n Node) Public() sol.Node { return sol.Node{PublicKey: n.Pub, ChainCode: n.ChainCode} }

// Child is the non-hardened child at index, by the rule package sol applies to public keys.
func (n Node) Child(index uint32) Node {
	m := hmac.New(sha512.New, n.ChainCode[:])
	m.Write(n.Pub[:])
	m.Write(binary.BigEndian.AppendUint32(nil, index))
	I := m.Sum(nil)
	var le [64]byte
	for i := 0; i < 32; i++ {
		le[i] = I[31-i]
	}
	il, err := edwards25519.NewScalar().SetUniformBytes(le[:])
	if err != nil {
		panic(err)
	}
	c := Node{Key: fromScalar(edwards25519.NewScalar().Add(n.Scalar, il))}
	copy(c.ChainCode[:], I[32:])
	return c
}

// At walks a non-hardened path.
func (n Node) At(path ...uint32) Node {
	for _, i := range path {
		n = n.Child(i)
	}
	return n
}

// MustAddress is the base58 address of a key.
func (k Key) Address() string { return sol.Address(k.Pub) }

var _ = fmt.Sprint
