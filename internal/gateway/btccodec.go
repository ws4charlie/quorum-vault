package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// BTCCodec is the ChainCodec of one Bitcoin chain. Verification, the guard's claims and the signing key of every input all come
// from the signing zone's own account xpub and config, never from the payload or the business zone.
type BTCCodec struct{ *btc.Verifier }

var _ ChainCodec = (*BTCCodec)(nil)

// NewBTCCodec builds the codec from the signing-zone chain config.
func NewBTCCodec(cfg btc.SigningConfig) (*BTCCodec, error) {
	v, err := btc.NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	return &BTCCodec{Verifier: v}, nil
}

// Decode implements ChainCodec: claims are outpoints "<txid>:<vout>" pinned to the value of the input, the identity is the txid, the fee
// is one component, and the sender is the derivation path of the first input (the same for every job of one transaction).
func (c *BTCCodec) Decode(u chain.UnsignedTx) (TxInfo, error) {
	i, err := c.Verifier.Decode(u)
	if err != nil {
		return TxInfo{}, fmt.Errorf("gateway: decode btc payload: %w", err)
	}
	return TxInfo{Sender: i.Sender, Destination: i.Destination, Claims: i.Claims, Pins: i.Pins, Identity: i.Identity, SignerKey: i.SignerKey,
		Fees: []*big.Int{new(big.Int).SetUint64(i.Fee)}}, nil
}

// OwnsSender implements ChainCodec: the sender is a derivation path on a branch the zone signs for.
func (c *BTCCodec) OwnsSender(sender string) bool { return c.Verifier.OwnsPath(sender) }

// CheckSigner implements ChainCodec: the key that would sign is the derived key of the input being signed.
func (c *BTCCodec) CheckSigner(info TxInfo, pub *ecdsa.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("no public key")
	}
	if got := crypto.CompressPubkey(pub); !bytes.Equal(got, info.SignerKey) {
		return fmt.Errorf("signer key %x is not the derived key %x of the input being signed", got, info.SignerKey)
	}
	return nil
}

// FeesRaised implements ChainCodec: the absolute fee must be higher.
func (c *BTCCodec) FeesRaised(prev, next []*big.Int) bool {
	return len(prev) == 1 && len(next) == 1 && next[0].Cmp(prev[0]) > 0
}

// KeyPath implements KeyPathCodec: the key reference of a job is the derivation path "<branch>/<index>".
func (c *BTCCodec) KeyPath(keyRef string) ([]uint32, error) { return btc.ParsePath(keyRef) }
