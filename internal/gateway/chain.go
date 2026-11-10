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

// TxInfo is what the replay guard and the policy need from a built transaction,
// as the chain codec reads it from the payload.
type TxInfo struct {
	// Sender is the account the transaction belongs to; OwnsSender and CheckSigner judge it.
	Sender string
	// Destination is who the transaction pays, read from the transaction itself (the recipient of an ERC-20 transfer, not the
	// token contract). Empty when the chain codec cannot say. Compare it after Canonical.
	Destination string
	// Claims names what the transaction consumes, so that no two intents can both confirm
	// (EVM: one claim, the sender's nonce; Bitcoin, later: one claim per spent output). A claim is
	// an opaque string, compared for equality.
	Claims []string
	// Pins has one opaque string per claim, or none. The guard refuses a claim that exists when it is named again with
	// another pin, in every path and for every intent (Bitcoin: the value of the input; EVM: no pins).
	Pins []string
	// Identity names the transaction all signatures of one attempt belong to (Bitcoin: the txid, which does not commit to input
	// values). The guard refuses an identity that was signed under another payload. Empty: the chain has none (EVM).
	Identity string
	// SignerKey is the public key (compressed, 33 bytes) that must sign this job, when the codec knows it from the payload and its
	// own config (Bitcoin: the derived key of the input the job's digest names). CheckSigner compares it.
	SignerKey []byte
	// Fees are the fee components of the transaction (EVM: fee cap, tip; Bitcoin: the absolute fee). A replacement
	// of a signed transaction must satisfy FeesRaised against them.
	Fees []*big.Int
}

// ChainCodec is the per-chain part of the gateway: offline verification, the
// guard's view of a payload, and which senders the gateway owns. The guard's rules for
// claims and fees are generic; what a claim is and what raising fees means is decided here.
type ChainCodec interface {
	chain.TxVerifier
	// Decode reads the claims, sender, destination and fees from the payload of one job (u: its digest, key reference and the
	// shared payload). It is called only after Verify accepted u.
	Decode(u chain.UnsignedTx) (TxInfo, error)
	// OwnsSender reports whether sender is a hot address the gateway signs for.
	OwnsSender(sender string) bool
	// CheckSigner reports whether pub is the key of info.Sender.
	CheckSigner(info TxInfo, pub *ecdsa.PublicKey) error
	// Canonical returns the canonical form of an address (EVM: checksum case; case never matters).
	// Destinations are compared as canonical strings, so a policy list works for any chain.
	Canonical(address string) (string, error)
	// FeesRaised reports whether next may replace a transaction signed with prev: no component lower, at least one higher.
	FeesRaised(prev, next []*big.Int) bool
}

// Chain families the gateway knows. A configured family it does not know refuses to start.
const (
	FamilyEVM = "evm"
	FamilyBTC = "btc"
	FamilySOL = "sol"
)

func familyOf(f string) (string, error) {
	switch f {
	case "", FamilyEVM:
		return FamilyEVM, nil
	case FamilyBTC:
		return FamilyBTC, nil
	case FamilySOL:
		return FamilySOL, nil
	}
	return "", fmt.Errorf("unknown chain family %q (known: %s, %s, %s)", f, FamilyEVM, FamilyBTC, FamilySOL)
}

// NewCodec is the one place a family picks its codec. qv-gateway and qv-cosigner reach it through NewCodecs.
func NewCodec(cc *ChainConfig) (ChainCodec, error) {
	switch cc.Family {
	case "", FamilyEVM:
		return NewEVMCodec(cc.EVM)
	case FamilyBTC:
		return NewBTCCodec(cc.BTC)
	case FamilySOL:
		return NewSOLCodec(cc.SOL)
	}
	return nil, fmt.Errorf("gateway: chain %q: unknown chain family %q", cc.Name, cc.Family)
}

// StrictCancelCodec is implemented by codecs for chains where a cancel can only free what was claimed (Bitcoin: it spends the very inputs of a
// signed attempt back to a hot shard, so every one of its claims must already exist, with the same pin, under one signed intent of its partition,
// and be all of that intent's claims). EVM does not have it: a cancel may free a reserved nonce that nothing was ever signed at.
type StrictCancelCodec interface {
	StrictCancel() bool
}

// KeyPathCodec is implemented by codecs whose jobs name the key to sign with by a derivation path in KeyRef (Bitcoin). The gateway asks a
// signer.Deriver for that key before it decides.
type KeyPathCodec interface {
	KeyPath(keyRef string) ([]uint32, error)
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
func (c *EVMCodec) Decode(u chain.UnsignedTx) (TxInfo, error) {
	payload := u.Payload
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
	sender := common.HexToAddress(p.From).Hex()
	return TxInfo{Sender: sender, Destination: dest.Hex(), Claims: []string{fmt.Sprintf("%s#%d", sender, p.Nonce)},
		Fees: []*big.Int{feeCap, tip}}, nil
}

// Canonical implements ChainCodec: the EIP-55 checksum form.
func (c *EVMCodec) Canonical(address string) (string, error) {
	if !common.IsHexAddress(address) {
		return "", fmt.Errorf("%q is not an address", address)
	}
	return common.HexToAddress(address).Hex(), nil
}

// FeesRaised implements ChainCodec for [fee cap, tip]: neither drops and at least one rises.
func (c *EVMCodec) FeesRaised(prev, next []*big.Int) bool {
	if len(prev) != len(next) {
		return false
	}
	raised := false
	for i := range prev {
		switch next[i].Cmp(prev[i]) {
		case -1:
			return false
		case 1:
			raised = true
		}
	}
	return raised
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
