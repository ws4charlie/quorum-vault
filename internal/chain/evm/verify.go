package evm

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

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
	if tx.GasTipCap().Cmp(tx.GasFeeCap()) > 0 {
		return reject("max priority fee %s exceeds max fee %s", tx.GasTipCap(), tx.GasFeeCap())
	}
	if fee := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap()); fee.Cmp(cfg.MaxTxFeeWei) > 0 {
		return reject("worst-case fee %s exceeds the cap %s", fee, cfg.MaxTxFeeWei)
	}
	switch i.Kind {
	case "withdrawal":
		return v.verifyWithdrawal(tx.To(), tx.Value(), tx.Data(), i, amount, tok, native)
	case "sweep":
		return v.verifySweep(tx.To(), tx.Value(), tx.Data(), i, tok, native)
	case "to-cold":
		return v.verifyToCold(tx.To(), tx.Value(), tx.Data(), i, amount, tok, native)
	case "cancel":
		return v.verifyCancel(tx, from, i, amount)
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
	if got := PredictAddress(cfg.Factory, salt); got != from {
		return reject("salt resolves to %s, intent source is %s", got, from)
	}
	// The destination itself lives in the factory (changed by its cold-key admin).
	// The signing zone's Config.SweepDestination must be updated by hand whenever the
	// admin changes it; until then every sweep is refused here, which is the point:
	// the gateway never learns the destination from the business side.
	dest, err := parseIntentAddress(i.To)
	if err != nil {
		return reject("%v", err)
	}
	if dest != cfg.SweepDestination {
		return reject("intent destination %s is not the configured sweep destination %s", dest, cfg.SweepDestination)
	}
	return nil
}

// verifyToCold accepts a hot-to-cold move only when its destination is the cold address that signing-zone config names for
// the partition's pool and the asset class, and the transaction is a plain transfer of exactly the intent's amount to it:
// native value, or an ERC-20 transfer(cold, amount) on the configured token. The intent's own To is checked too, so an intent
// that names another destination is refused even if the transaction happens to match it.
func (v *Verifier) verifyToCold(to *common.Address, value *big.Int, data []byte, i signjob.Intent, amount *big.Int, tok Token, native bool) error {
	if i.From != "" {
		return reject("to-cold intent has a source address")
	}
	if amount.Sign() == 0 {
		return reject("zero amount")
	}
	cold, err := v.cfg.ColdAddress(i.PartitionID, i.Asset)
	if err != nil {
		return reject("%v", err)
	}
	dest, err := parseIntentAddress(i.To)
	if err != nil {
		return reject("%v", err)
	}
	if dest != cold {
		return reject("to-cold destination %s is not the configured cold address %s", dest, cold)
	}
	if to == nil {
		return reject("contract creation")
	}
	if native {
		if *to != cold || value.Cmp(amount) != 0 || len(data) != 0 {
			return reject("to-cold transfer is to %s value %s data %d bytes; the cold address is %s and the amount %s", to, value, len(data), cold, amount)
		}
		return nil
	}
	if *to != tok.Address {
		return reject("call target %s is not the %s token %s", to, i.Asset, tok.Address)
	}
	if value.Sign() != 0 {
		return reject("token transfer carries value %s", value)
	}
	want, err := packTransfer(cold, amount)
	if err != nil {
		return reject("%v", err)
	}
	if !bytes.Equal(want, data) {
		return reject("calldata is not transfer(%s, %s)", cold, amount)
	}
	return nil
}

// verifyCancel accepts only a zero-value, empty-data self-send of 21,000 gas:
// the transaction that frees a nonce whose job was refused.
func (v *Verifier) verifyCancel(tx *types.Transaction, from common.Address, i signjob.Intent, amount *big.Int) error {
	if i.From != "" {
		return reject("cancel intent has a source address")
	}
	if amount.Sign() != 0 {
		return reject("cancel amount %s, want 0", amount)
	}
	dest, err := parseIntentAddress(i.To)
	if err != nil {
		return reject("%v", err)
	}
	if dest != from {
		return reject("cancel intent address %s is not the hot address %s", dest, from)
	}
	if tx.To() == nil || *tx.To() != from || tx.Value().Sign() != 0 || len(tx.Data()) != 0 || tx.Gas() != 21000 {
		return reject("cancel transaction is not a zero-value 21000-gas self-send")
	}
	return nil
}
