package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// SOLCodec is the ChainCodec of one Solana chain. Verification, the guard's view of a job and the key of every signer come from the signing
// zone's own config (hot shard addresses, the account node, tokens, caps), never from the payload or the business zone.
//
// Solana differs from the other families in three ways the gateway has to know. Ed25519 signs the whole message, so a job's digest IS the
// message. A transaction can need two signatures (a sweep: the hot shard as fee payer and the deposit key as owner), both over the same
// message, so the replay guard keys a job by message AND signer (GuardKey) instead of by the digest alone. And the keys are Ed25519: the
// codec implements EdSignerCodec, not CheckSigner.
type SOLCodec struct{ *sol.Verifier }

var (
	_ ChainCodec    = (*SOLCodec)(nil)
	_ IntentDecoder = (*SOLCodec)(nil)
	_ EdSignerCodec = (*SOLCodec)(nil)
	_ GuardKeyCodec = (*SOLCodec)(nil)
	_ MessageCodec  = (*SOLCodec)(nil)

	_ StrictCancelCodec = (*SOLCodec)(nil)
)

// NewSOLCodec builds the codec from the signing-zone chain config.
func NewSOLCodec(cfg sol.SigningConfig) (*SOLCodec, error) {
	v, err := sol.NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	return &SOLCodec{Verifier: v}, nil
}

// Decode implements ChainCodec. A Solana job cannot be read without its intent (the message alone does not say which instructions the
// intent allows), so the decider uses DecodeFor; this refuses.
func (c *SOLCodec) Decode(chain.UnsignedTx) (TxInfo, error) {
	return TxInfo{}, errors.New("gateway: a solana job is decoded against its intent")
}

// DecodeFor implements IntentDecoder.
func (c *SOLCodec) DecodeFor(u chain.UnsignedTx, i signjob.Intent) (TxInfo, error) {
	in, err := c.Verifier.Decode(u, i)
	if err != nil {
		return TxInfo{}, fmt.Errorf("gateway: decode sol payload: %w", err)
	}
	return TxInfo{Sender: in.Sender, Destination: in.Destination, Claims: in.Claims, SignerKey: in.SignerKey, Fees: in.Fees}, nil
}

// CheckSigner implements ChainCodec: a Solana key is never a secp256k1 key.
func (c *SOLCodec) CheckSigner(TxInfo, *ecdsa.PublicKey) error {
	return errors.New("solana jobs are signed with Ed25519 keys")
}

// CheckEd25519Signer implements EdSignerCodec: the key that would sign is the one this job asks for (the hot shard's, or the derived
// deposit key).
func (c *SOLCodec) CheckEd25519Signer(info TxInfo, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("no public key")
	}
	if !bytes.Equal(pub, info.SignerKey) {
		return fmt.Errorf("signer key %s is not the key %s this job needs", sol.Address([32]byte(pub)), sol.Address([32]byte(info.SignerKey)))
	}
	return nil
}

// FeesRaised implements ChainCodec. A withdrawal or cancel is signed as versions of one nonce: a version may raise the compute unit price and change
// nothing else, so the fees are [price, limit] and next must have the same limit and a higher price. (The nonce itself is the claim: the guard
// refuses a version with another nonce account or value as "nonce changed" before it gets here.) A sweep carries one fee component and is never
// replaced: it signs a recent blockhash, and a second message for it could land as well as the first.
func (c *SOLCodec) FeesRaised(prev, next []*big.Int) bool {
	return len(prev) == 2 && len(next) == 2 && next[1].Cmp(prev[1]) == 0 && next[0].Cmp(prev[0]) > 0
}

// StrictCancel implements StrictCancelCodec: a Solana cancel advances exactly the nonce of the attempt it frees.
func (c *SOLCodec) StrictCancel() bool { return true }

// GuardKey implements GuardKeyCodec: the two jobs of a sweep sign the same message under different keys and must not collide in the guard.
func (c *SOLCodec) GuardKey(u chain.UnsignedTx, info TxInfo) []byte {
	h := sha256.New()
	h.Write([]byte("qv-sol-guard-v1"))
	h.Write(info.SignerKey)
	h.Write(u.Digest)
	return h.Sum(nil)
}

// SignerFor implements MessageCodec: the hot shard's key, or the deposit key at a path below the account.
func (c *SOLCodec) SignerFor(keyRef string) (deposit bool, path []uint32, err error) {
	dep, idx, err := sol.ParseKeyPath(keyRef)
	if err != nil || !dep {
		return false, nil, err
	}
	return true, []uint32{sol.BranchExternal, idx}, nil
}

// EdSignerCodec is implemented by codecs whose jobs are signed with Ed25519 keys.
type EdSignerCodec interface {
	CheckEd25519Signer(info TxInfo, pub ed25519.PublicKey) error
}

// IntentDecoder is implemented by codecs that need the intent to read a job.
type IntentDecoder interface {
	DecodeFor(u chain.UnsignedTx, i signjob.Intent) (TxInfo, error)
}

// GuardKeyCodec is implemented by codecs for which the digest alone does not name what the guard records (Solana: one message, several signers).
// Codecs without it key the guard by the job's digest, as before.
type GuardKeyCodec interface {
	GuardKey(u chain.UnsignedTx, info TxInfo) []byte
}

// MessageCodec is implemented by codecs whose jobs are signed by a signer.MessageSigner; SignerFor says which key a job's reference names:
// the partition's own hot signer, or a key below the deposit tree at path.
type MessageCodec interface {
	SignerFor(keyRef string) (deposit bool, path []uint32, err error)
}
