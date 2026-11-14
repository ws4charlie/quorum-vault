package sol

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcutil/base58"
)

// Deposit addresses come from a 2-party HD Ed25519 keyset (cb-mpc, parties A and B). The hardened part of the path is walked by the
// two parties together once, at the account level, and yields a Node: a public key and a chain code. Everything below it is public
// derivation: cb-mpc applies the BIP32 rule on Edwards points (not SLIP-0010, which has no public derivation for Ed25519), so anyone
// holding the Node derives every child public key, with no MPC and no secret, exactly as Bitcoin does from an xpub. The path mirrors
// Bitcoin's: hardened m/44'/501'/account' (501 is Solana's SLIP-44 coin type), then the external branch 0, then the customer's index.
// The parties derive the same keys with Derive(hardened, [branch, index]); that equality is a test against real mpc-party
// (e2e/sol, TestDerivedAddressesEqualMPCDerivedKeys) and against an independent derivation in mpc-party (TestBIP32StyleVectorEd25519).

const (
	// Purpose and CoinType are the hardened levels of the account path m/44'/501'/0'.
	Purpose  = 44
	CoinType = 501
	// BranchExternal holds the customers' deposit addresses; BranchHot is reserved for hot shards (a later task).
	BranchExternal = 0
	BranchHot      = 1
)

// AccountPath is the hardened path of the account node as the plain numbers mpc-party's Node takes (the hardened bit is implied).
func AccountPath() []uint32 { return []uint32{Purpose, CoinType, 0} }

// Node is the public material of a hardened HD node.
type Node struct {
	PublicKey [32]byte
	ChainCode [32]byte
}

// ckd is the child at index (non-hardened) of a node: I = HMAC-SHA512(chain code, pub || index_be32), child = P + (I_L mod l)*G,
// child chain code = I_R. I_L is read as a big-endian integer, as cb-mpc does (bn_t::from_bin % q).
func (n Node) child(index uint32) (Node, error) {
	if index >= 1<<31 {
		return Node{}, fmt.Errorf("sol: index %d is hardened", index)
	}
	m := hmac.New(sha512.New, n.ChainCode[:])
	m.Write(n.PublicKey[:])
	var ix [4]byte
	binary.BigEndian.PutUint32(ix[:], index)
	m.Write(ix[:])
	I := m.Sum(nil)
	var le [64]byte
	for i := 0; i < 32; i++ {
		le[i] = I[31-i]
	}
	il, err := edwards25519.NewScalar().SetUniformBytes(le[:])
	if err != nil {
		return Node{}, err
	}
	p, err := new(edwards25519.Point).SetBytes(n.PublicKey[:])
	if err != nil {
		return Node{}, fmt.Errorf("sol: node public key: %w", err)
	}
	c := new(edwards25519.Point).Add(p, new(edwards25519.Point).ScalarBaseMult(il))
	var out Node
	copy(out.PublicKey[:], c.Bytes())
	copy(out.ChainCode[:], I[32:])
	return out, nil
}

// Derive walks a non-hardened path from the node.
func (n Node) Derive(path ...uint32) (Node, error) {
	cur := n
	for _, i := range path {
		var err error
		if cur, err = cur.child(i); err != nil {
			return Node{}, err
		}
	}
	return cur, nil
}

// DepositAddressAt is the deposit address of the customer index: account node -> external branch -> index.
func (n Node) DepositAddressAt(index uint32) (string, error) {
	c, err := n.Derive(BranchExternal, index)
	if err != nil {
		return "", err
	}
	return Address(c.PublicKey), nil
}

// MustDecodeBase58 decodes a base58 string (a blockhash, a signature); it is for tests and returns nil for bad input.
func MustDecodeBase58(s string) []byte { return base58.Decode(s) }
