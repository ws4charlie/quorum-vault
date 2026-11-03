package evm

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// ErrRejected wraps every Verify rejection.
var ErrRejected = errors.New("evm: transaction does not match intent")

// Verifier implements chain.TxVerifier from configuration alone: no RPC, no
// database. The signing gateway runs it with no chain access.
type Verifier struct{ cfg Config }

var _ chain.TxVerifier = (*Verifier)(nil)

// NewVerifier validates cfg (RPCURL is not needed) and returns a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Verifier{cfg: cfg}, nil
}

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRejected}, args...)...)
}

// Verify recomputes the digest from u.Payload and checks that the decoded
// transaction does exactly what i says.
func (v *Verifier) Verify(u chain.UnsignedTx, i signjob.Intent) error {
	cfg := v.cfg
	if u.Chain != cfg.Chain || i.Chain != cfg.Chain {
		return reject("chain %q/%q, want %q", u.Chain, i.Chain, cfg.Chain)
	}
	pl, err := decodePayload(u.Payload)
	if err != nil {
		return reject("%v", err)
	}
	if pl.ChainID != cfg.ChainID {
		return reject("chain id %d, want %d", pl.ChainID, cfg.ChainID)
	}
	tx, digest, from, err := pl.tx()
	if err != nil {
		return reject("%v", err)
	}
	if !bytes.Equal(digest[:], u.Digest) {
		return reject("digest does not match payload")
	}
	if u.KeyRef.PartitionID != i.PartitionID {
		return reject("key partition %q, intent partition %q", u.KeyRef.PartitionID, i.PartitionID)
	}
	hot, err := cfg.hot(i.PartitionID)
	if err != nil {
		return reject("%v", err)
	}
	if from != hot {
		return reject("sender %s is not the hot address %s of partition %q", from, hot, i.PartitionID)
	}
	amount, err := parseAmount(i.Amount)
	if err != nil {
		return reject("%v", err)
	}
	tok, native, err := cfg.asset(i.Asset)
	if err != nil {
		return reject("%v", err)
	}
	if len(tx.AccessList()) != 0 {
		return reject("unexpected access list")
	}
	switch i.Kind {
	case "withdrawal":
		return v.verifyWithdrawal(tx.To(), tx.Value(), tx.Data(), i, amount, tok, native)
	case "sweep":
		return v.verifySweep(tx.To(), tx.Value(), tx.Data(), i, tok, native)
	default:
		return reject("intent kind %q", i.Kind)
	}
}

// parseIntentAddress accepts a 0x address; mixed-case input must carry a valid
// EIP-55 checksum. The zero address is refused.
func parseIntentAddress(s string) (common.Address, error) {
	if !strings.HasPrefix(s, "0x") || !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("address %q is not 0x-prefixed hex", s)
	}
	a := common.HexToAddress(s)
	if hexPart := s[2:]; hexPart != strings.ToLower(hexPart) && hexPart != strings.ToUpper(hexPart) && a.Hex() != s {
		return common.Address{}, fmt.Errorf("address %q has a bad checksum", s)
	}
	if a == (common.Address{}) {
		return common.Address{}, fmt.Errorf("zero address")
	}
	return a, nil
}

func (v *Verifier) verifyWithdrawal(to *common.Address, value *big.Int, data []byte, i signjob.Intent, amount *big.Int, tok Token, native bool) error {
	if i.From != "" {
		return reject("withdrawal intent has a source address")
	}
	if amount.Sign() == 0 {
		return reject("zero amount")
	}
	dest, err := parseIntentAddress(i.To)
	if err != nil {
		return reject("%v", err)
	}
	if to == nil {
		return reject("contract creation")
	}
	if native {
		if *to != dest || value.Cmp(amount) != 0 || len(data) != 0 {
			return reject("native transfer is to %s value %s data %d bytes; intent says %s %s", to, value, len(data), dest, amount)
		}
		return nil
	}
	if *to != tok.Address {
		return reject("call target %s is not the %s token %s", to, i.Asset, tok.Address)
	}
	if value.Sign() != 0 {
		return reject("token transfer carries value %s", value)
	}
	want, err := packTransfer(dest, amount)
	if err != nil {
		return reject("%v", err)
	}
	if !bytes.Equal(want, data) {
		return reject("calldata is not transfer(%s, %s)", dest, amount)
	}
	return nil
}

func (v *Verifier) verifySweep(to *common.Address, value *big.Int, data []byte, i signjob.Intent, tok Token, native bool) error {
	cfg := v.cfg
	if to == nil || *to != cfg.Factory {
		return reject("sweep target is not the factory %s", cfg.Factory)
	}
	if value.Sign() != 0 {
		return reject("sweep carries value %s", value)
	}
	salt, tokens, err := unpackDeployAndFlush(data)
	if err != nil {
		return reject("%v", err)
	}
	if native {
		if len(tokens) != 0 {
			return reject("native sweep lists %d tokens", len(tokens))
		}
	} else if len(tokens) != 1 || tokens[0] != tok.Address {
		return reject("sweep tokens %v, want [%s]", tokens, tok.Address)
	}
	from, err := parseIntentAddress(i.From)
	if err != nil {
		return reject("sweep source: %v", err)
	}
	if got := PredictAddress(cfg.Factory, cfg.SweepDestination, salt); got != from {
		return reject("salt resolves to %s, intent source is %s", got, from)
	}
	dest, err := parseIntentAddress(i.To)
	if err != nil {
		return reject("%v", err)
	}
	if dest != cfg.SweepDestination {
		return reject("intent destination %s is not the configured sweep destination %s", dest, cfg.SweepDestination)
	}
	return nil
}
