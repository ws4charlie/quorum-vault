// Package hsmsigner adapts an hsm.Token to the shared interfaces: a
// domain.KeyGenerator that creates secp256k1 keys inside the token, and a
// signer.Signer that signs digests with them.
package hsmsigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// Purpose is the domain.Key.Purpose of every key this package generates.
const Purpose = "signing"

// Generator creates HSM keys, and can destroy the private key of one it made.
type Generator struct{ tok *hsm.Token }

// NewGenerator returns a KeyGenerator for the HSM backend on tok.
func NewGenerator(tok *hsm.Token) domain.KeyGenerator { return &Generator{tok: tok} }

func (g *Generator) Backend() domain.Backend { return domain.BackendHSM }

// Label is the CKA_LABEL of a wallet's key version.
func Label(walletID string, version int) string {
	return fmt.Sprintf("qv-%s-v%d", walletID, version)
}

// Generate creates a secp256k1 key pair in the token with a random 16-byte
// CKA_ID and returns its metadata.
func (g *Generator) Generate(ctx context.Context, walletID string, version int) (domain.Key, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return domain.Key{}, err
	}
	label := Label(walletID, version)
	pubBytes, err := g.tok.GenerateECKeyPair(ctx, domain.CurveSecp256k1, label, id)
	if err != nil {
		return domain.Key{}, err
	}
	pub, err := signer.ParseUncompressed(pubBytes)
	if err != nil {
		g.tok.DestroyPrivateKey(ctx, id)
		return domain.Key{}, fmt.Errorf("hsmsigner: generated key: %w", err)
	}
	return domain.Key{
		ID:        uuid.NewString(),
		WalletID:  walletID,
		Version:   version,
		Curve:     domain.CurveSecp256k1,
		Backend:   domain.BackendHSM,
		Purpose:   Purpose,
		HSMLabel:  label,
		HSMKeyID:  id,
		PublicKey: pubBytes,
		Address:   crypto.PubkeyToAddress(*pub).Hex(),
	}, nil
}

// DestroyKey destroys key's private key object in the token. A key that is
// already gone is not an error, so retiring is idempotent.
func (g *Generator) DestroyKey(ctx context.Context, key domain.Key) error {
	if key.Backend != domain.BackendHSM {
		return fmt.Errorf("hsmsigner: key %s has backend %q", key.ID, key.Backend)
	}
	err := g.tok.DestroyPrivateKey(ctx, key.HSMKeyID)
	if errors.Is(err, hsm.ErrKeyNotFound) {
		return nil
	}
	return err
}

// Signer signs with one HSM key. It does not check the key's lifecycle state:
// callers decide whether the key may sign.
type Signer struct {
	tok *hsm.Token
	key domain.Key
	pub *ecdsa.PublicKey
}

// New returns a Signer for key, which must be an HSM secp256k1 key.
func New(tok *hsm.Token, key domain.Key) (signer.Signer, error) {
	if key.Backend != domain.BackendHSM {
		return nil, fmt.Errorf("hsmsigner: key %s has backend %q, want %q", key.ID, key.Backend, domain.BackendHSM)
	}
	if len(key.HSMKeyID) == 0 {
		return nil, fmt.Errorf("hsmsigner: key %s has no HSM key id", key.ID)
	}
	pub, err := signer.ParseUncompressed(key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("hsmsigner: key %s: %w", key.ID, err)
	}
	return &Signer{tok: tok, key: key, pub: pub}, nil
}

func (s *Signer) Backend() domain.Backend     { return domain.BackendHSM }
func (s *Signer) Key() domain.Key             { return s.key }
func (s *Signer) PublicKey() *ecdsa.PublicKey { return s.pub }

// SignDigest signs digest in the token. opts is ignored (one HSM, no quorum).
// The signature is low-S and checked against the key's public key before it is
// returned, so a token that signed with the wrong key is caught here.
func (s *Signer) SignDigest(ctx context.Context, digest [32]byte, _ signer.SignOptions) (signer.Result, error) {
	r, sv, err := s.tok.SignECDSA(ctx, s.key.HSMKeyID, digest)
	if err != nil {
		return signer.Result{}, err
	}
	sig := signer.NormalizeLowS(signer.Signature{R: r, S: sv})
	if !signer.Verify(s.pub, digest, sig) {
		return signer.Result{}, fmt.Errorf("hsmsigner: signature from key %s does not verify", s.key.ID)
	}
	return signer.Result{Sig: sig, Participants: []string{"hsm:" + s.tok.Label()}}, nil
}
