package signer

import (
	"context"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// Ed25519 signs the whole message, not a 32-byte digest, and its keys and signatures are not secp256k1's. MessageSigner is the sibling of
// Signer for such chains (Solana). It does not replace Signer: ECDSA signing is unchanged. A chain's jobs use one kind or the other, and the
// gateway picks by the chain's codec.

// MessageResult is the result of signing a message.
type MessageResult struct {
	Signature    []byte         // 64 bytes, R || s, to be checked with crypto/ed25519 by the caller
	Participants []string       // as Result.Participants
	Meta         map[string]any // as Result.Meta
}

// MessageSigner signs whole messages with one Ed25519 key.
type MessageSigner interface {
	Backend() domain.Backend
	// PublicKey is the 32-byte Ed25519 public key that signs.
	PublicKey() []byte
	// SignMessage signs msg. opts is as for SignDigest: the job id is the idempotency key, the intent package goes to the cosigners.
	SignMessage(ctx context.Context, msg []byte, opts SignOptions) (MessageResult, error)
}

// MessageDeriver is a signer for a whole tree of Ed25519 keys: At returns the signer of the key at path below the tree's hardened prefix.
type MessageDeriver interface {
	MessageSigner
	At(ctx context.Context, path []uint32) (MessageSigner, error)
}
