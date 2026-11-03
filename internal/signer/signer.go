// Package signer defines the backend-neutral signing interface (HSM and MPC
// both implement Signer) and secp256k1 helpers shared by every backend.
package signer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

type Signature struct{ R, S *big.Int } // S always low-S normalized (S <= N/2, secp256k1)

type SignOptions struct{ Quorum int } // MPC: 0 = threshold (2 parties), 3 = full quorum. HSM ignores it.

type Result struct {
	Sig          Signature
	Participants []string       // HSM: ["hsm:<token label>"]; MPC: ["party-1","party-3"] etc.
	Meta         map[string]any // e.g. MPC rounds, messages, duration_ms
}

type Signer interface {
	Backend() domain.Backend
	Key() domain.Key
	PublicKey() *ecdsa.PublicKey // curve = go-ethereum crypto.S256()
	SignDigest(ctx context.Context, digest [32]byte, opts SignOptions) (Result, error)
}

var (
	curveN     = crypto.S256().Params().N
	curveHalfN = new(big.Int).Rsh(curveN, 1)
)

// NormalizeLowS returns sig with S replaced by N-S when S > N/2. Ethereum
// (EIP-2) rejects high-S signatures; (r, s) and (r, N-s) are both valid ECDSA
// signatures, so flipping keeps the signature valid. The input is not modified.
func NormalizeLowS(sig Signature) Signature {
	if sig.S == nil || sig.S.Cmp(curveHalfN) <= 0 {
		return sig
	}
	return Signature{R: sig.R, S: new(big.Int).Sub(curveN, sig.S)}
}

// Verify reports whether sig is a valid secp256k1 ECDSA signature of digest
// under pub. Both low-S and high-S forms are accepted.
func Verify(pub *ecdsa.PublicKey, digest [32]byte, sig Signature) bool {
	if pub == nil || sig.R == nil || sig.S == nil {
		return false
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.Cmp(curveN) >= 0 || sig.S.Cmp(curveN) >= 0 {
		return false
	}
	return ecdsa.Verify(pub, digest[:], sig.R, sig.S)
}

// ParseUncompressed parses a 65-byte SEC1 uncompressed point (0x04 || X || Y)
// into a secp256k1 public key, rejecting points not on the curve.
func ParseUncompressed(pub []byte) (*ecdsa.PublicKey, error) {
	if len(pub) != 65 {
		return nil, errors.New("signer: public key must be 65 bytes")
	}
	if pub[0] != 0x04 {
		return nil, errors.New("signer: public key must start with 0x04 (uncompressed)")
	}
	k, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		return nil, errors.New("signer: public key is not a valid secp256k1 point")
	}
	return k, nil
}
