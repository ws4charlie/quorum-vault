// Package evm is the EVM chain cell behind chain.Adapter and chain.TxVerifier:
// key-less CREATE2 deposit addresses (forwarders), deposit scanning, sweeps
// through the factory, a persisted nonce manager, and offline verification.
// It never holds a key; signatures come back through the sign-job path.
package evm

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// Defaults.
const (
	DefaultNativeAsset    = "ETH"
	DefaultFeeBumpPercent = 15
	DefaultStuckAfter     = 50
)

// Token is a configured ERC-20.
type Token struct {
	Address  common.Address
	Decimals uint8
}

// Config configures one EVM chain cell. The same code serves several chains;
// Chain is a config value, not a constant.
type Config struct {
	Chain            string // e.g. "eth-sepolia"; stored in deposit_addresses.chain
	ChainID          uint64
	RPCURL           string // not needed by the Verifier
	Confirmations    uint64 // blocks on top of a block before it counts as final
	Factory          common.Address
	SweepDestination common.Address
	HotAddresses     map[string]common.Address // partition ID -> hot address
	Assets           map[string]Token          // symbol -> token (the native asset is implicit)
	NativeAsset      string                    // default "ETH"
	FeeBumpPercent   uint64                    // replacement bump, default 15
	StuckAfterBlocks uint64                    // default 50
	// MaxTxFeeWei caps gas x max_fee_per_gas of every transaction. Required: the
	// hot wallet pays it and it is not part of the intent.
	MaxTxFeeWei *big.Int
}

// ErrUnknownAsset is returned for an asset that is neither native nor configured.
var ErrUnknownAsset = errors.New("evm: unknown asset")

// withDefaults returns a copy with zero values replaced by defaults.
func (c Config) withDefaults() Config {
	if c.NativeAsset == "" {
		c.NativeAsset = DefaultNativeAsset
	}
	if c.FeeBumpPercent == 0 {
		c.FeeBumpPercent = DefaultFeeBumpPercent
	}
	if c.StuckAfterBlocks == 0 {
		c.StuckAfterBlocks = DefaultStuckAfter
	}
	return c
}

// validate checks everything the Verifier needs (no RPC URL).
func (c Config) validate() error {
	switch {
	case strings.TrimSpace(c.Chain) == "" || strings.Contains(c.Chain, ":"):
		return errors.New("evm: config: chain name must be non-empty and contain no ':'")
	case c.MaxTxFeeWei == nil || c.MaxTxFeeWei.Sign() <= 0:
		return errors.New("evm: config: MaxTxFeeWei is required and must be > 0")
	case c.ChainID == 0:
		return errors.New("evm: config: chain id must be > 0")
	case c.Factory == (common.Address{}):
		return errors.New("evm: config: factory address is required")
	case c.SweepDestination == (common.Address{}):
		return errors.New("evm: config: sweep destination is required")
	}
	for p, a := range c.HotAddresses {
		if p == "" || a == (common.Address{}) {
			return fmt.Errorf("evm: config: bad hot address entry %q", p)
		}
	}
	for s, t := range c.Assets {
		if s == "" || s == c.NativeAsset || t.Address == (common.Address{}) {
			return fmt.Errorf("evm: config: bad asset entry %q", s)
		}
	}
	return nil
}

// asset resolves a symbol: (zero Token, true) for native, else the token.
func (c Config) asset(sym string) (tok Token, native bool, err error) {
	if sym == c.NativeAsset {
		return Token{}, true, nil
	}
	t, ok := c.Assets[sym]
	if !ok {
		return Token{}, false, fmt.Errorf("%w: %q", ErrUnknownAsset, sym)
	}
	return t, false, nil
}

func (c Config) hot(partitionID string) (common.Address, error) {
	a, ok := c.HotAddresses[partitionID]
	if !ok {
		return common.Address{}, fmt.Errorf("evm: no hot address configured for partition %q", partitionID)
	}
	return a, nil
}

func (c Config) symbolOf(token common.Address) (string, bool) {
	for s, t := range c.Assets {
		if t.Address == token {
			return s, true
		}
	}
	return "", false
}

func (c Config) partitionOf(hot common.Address) string {
	best := ""
	for p, a := range c.HotAddresses {
		if a == hot && (best == "" || p < best) {
			best = p
		}
	}
	return best
}

// parseAmount accepts only canonical non-negative decimal strings: digits, no
// leading zeros (except "0" itself), no sign, no whitespace, no exponent.
func parseAmount(s string) (*big.Int, error) {
	if s == "" || len(s) > 78 {
		return nil, fmt.Errorf("evm: amount %q is not a canonical decimal", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return nil, fmt.Errorf("evm: amount %q is not a canonical decimal", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return nil, fmt.Errorf("evm: amount %q has leading zeros", s)
	}
	n, _ := new(big.Int).SetString(s, 10)
	if n.BitLen() > 256 {
		return nil, fmt.Errorf("evm: amount %q exceeds 256 bits", s)
	}
	return n, nil
}
