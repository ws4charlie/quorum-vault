package sol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
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

// Address is the base58 form of a 32-byte public key: the Solana address.
func Address(pub [32]byte) string { return base58.Encode(pub[:]) }

// ParseAddress decodes a base58 address to its 32 bytes.
func ParseAddress(s string) ([32]byte, error) {
	var out [32]byte
	b := base58.Decode(s)
	if len(b) != 32 {
		return out, fmt.Errorf("sol: %q is not a 32-byte base58 address", s)
	}
	copy(out[:], b)
	return out, nil
}

// DepositAddressAt is the deposit address of the customer index: account node -> external branch -> index.
func (n Node) DepositAddressAt(index uint32) (string, error) {
	c, err := n.Derive(BranchExternal, index)
	if err != nil {
		return "", err
	}
	return Address(c.PublicKey), nil
}

// ---- Associated token accounts ----

// Program ids (classic SPL Token and the Associated Token Account program; Token-2022 is not supported).
const (
	SystemProgram       = "11111111111111111111111111111111"
	TokenProgram        = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	AssociatedTokenProg = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
)

// onCurve reports whether 32 bytes decode to a point of the Ed25519 curve.
func onCurve(b []byte) bool {
	_, err := new(edwards25519.Point).SetBytes(b)
	return err == nil
}

// findProgramAddress is Solana's PDA search: the first bump from 255 down for which sha256(seeds || bump || program || "ProgramDerivedAddress")
// is not on the curve.
func findProgramAddress(seeds [][]byte, program [32]byte) ([32]byte, error) {
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, s := range seeds {
			h.Write(s)
		}
		h.Write([]byte{byte(bump)})
		h.Write(program[:])
		h.Write([]byte("ProgramDerivedAddress"))
		var out [32]byte
		copy(out[:], h.Sum(nil))
		if !onCurve(out[:]) {
			return out, nil
		}
	}
	return [32]byte{}, errors.New("sol: no program address found")
}

// ATA is the associated token account of owner for mint: the PDA of the Associated Token program at seeds (owner, token program, mint).
// Deposits of a token are credited only when they arrive here.
func ATA(owner, mint [32]byte) ([32]byte, error) {
	tok, err := ParseAddress(TokenProgram)
	if err != nil {
		return [32]byte{}, err
	}
	ata, err := ParseAddress(AssociatedTokenProg)
	if err != nil {
		return [32]byte{}, err
	}
	return findProgramAddress([][]byte{owner[:], tok[:], mint[:]}, ata)
}

// MustDecodeBase58 decodes a base58 string (a blockhash, a signature); it is for tests and returns nil for bad input.
func MustDecodeBase58(s string) []byte { return base58.Decode(s) }
