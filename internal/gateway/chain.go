package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
)

// TxInfo is what the replay guard needs from a built transaction. Other chains
// plug in by implementing ChainCodec; Nonce is the chain's sequence number
// (EVM nonce), Sender the account it belongs to.
type TxInfo struct {
	Sender string
	// Destination is who the transaction pays, read from the transaction itself (the recipient of an ERC-20 transfer, not the
	// token contract). Empty when the chain codec cannot say.
	Destination string
	Nonce       uint64
	Tip         *big.Int // priority fee; the guard compares fees to allow replacements
	FeeCap      *big.Int
}

// ChainCodec is the per-chain part of the gateway: offline verification, the
// guard's view of a payload, and which senders the gateway owns.
type ChainCodec interface {
	chain.TxVerifier
	// Decode reads the nonce, sender and fees from the payload. It is called
	// only after Verify accepted the payload.
	Decode(payload []byte) (TxInfo, error)
	// OwnsSender reports whether sender is a hot address the gateway signs for.
	OwnsSender(sender string) bool
	// CheckSigner reports whether pub is the key of info.Sender.
	CheckSigner(info TxInfo, pub *ecdsa.PublicKey) error
}

// EVMCodec is the ChainCodec of one EVM chain.
type EVMCodec struct {
	*evm.Verifier
	hot map[common.Address]bool
}

// NewEVMCodec builds the codec from the signing-zone chain config.
func NewEVMCodec(cfg evm.Config) (*EVMCodec, error) {
	v, err := evm.NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	hot := map[common.Address]bool{}
	for _, a := range cfg.HotAddresses {
		hot[a] = true
	}
	return &EVMCodec{Verifier: v, hot: hot}, nil
}

// Decode implements ChainCodec for the evm.Payload JSON.
func (c *EVMCodec) Decode(payload []byte) (TxInfo, error) {
	var p evm.Payload
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return TxInfo{}, fmt.Errorf("gateway: decode evm payload: %w", err)
	}
	tip, ok1 := new(big.Int).SetString(p.Tip, 10)
	feeCap, ok2 := new(big.Int).SetString(p.FeeCap, 10)
	if !ok1 || !ok2 || !common.IsHexAddress(p.From) {
		return TxInfo{}, fmt.Errorf("gateway: decode evm payload: bad fee or sender")
	}
	dest, err := c.Verifier.Recipient(payload)
	if err != nil {
		return TxInfo{}, fmt.Errorf("gateway: decode evm payload: %w", err)
	}
	return TxInfo{Sender: common.HexToAddress(p.From).Hex(), Destination: dest.Hex(), Nonce: p.Nonce, Tip: tip, FeeCap: feeCap}, nil
}

// OwnsSender implements ChainCodec.
func (c *EVMCodec) OwnsSender(sender string) bool {
	return common.IsHexAddress(sender) && c.hot[common.HexToAddress(sender)]
}

// CheckSigner implements ChainCodec: the signing key must be the sender's.
func (c *EVMCodec) CheckSigner(info TxInfo, pub *ecdsa.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("no public key")
	}
	if got := crypto.PubkeyToAddress(*pub).Hex(); got != info.Sender {
		return fmt.Errorf("signer key address %s is not the sender %s", got, info.Sender)
	}
	return nil
}
