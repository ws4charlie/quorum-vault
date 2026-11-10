// Package sol is the Solana chain cell. This step: deposit addresses derived from a 2-party HD Ed25519 keyset's account node, a
// scanner over the node's JSON-RPC, SOL and classic SPL token deposits credited at finalized commitment, and balance reads for
// Reconcile. Building, signing and broadcasting transactions come in later tasks and return chain.ErrNotSupported.
package sol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Native is the symbol of SOL in the ledger; its base unit is the lamport (9 decimals).
const (
	Native   = "SOL"
	Decimals = 9
)

// Config is the chain cell's configuration.
type Config struct {
	Chain   string // the chain name in the ledger and the database
	Network string // "localnet", "devnet", "testnet" or "mainnet"
	RPCURL  string
	// AccountPublicKey and AccountChainCode (hex) are the account node m/44'/501'/0' of the 2-party HD keyset, from mpc-party's Node.
	AccountPublicKey string
	AccountChainCode string
	// Tokens maps the ledger symbol of each classic SPL token to its mint address. The mint's decimals are read from the chain at start
	// and must equal TokenDecimals[symbol] (the books and the config must agree with the chain before anything is credited).
	Tokens        map[string]string
	TokenDecimals map[string]int
}

// genesis hashes of the public clusters; a node of another cluster than the config names is refused at start. A local validator has a
// genesis hash of its own and is not checked.
var genesis = map[string]string{
	"mainnet": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", // public genesis hash, not a secret; ggignore
	"devnet":  "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG", // public genesis hash, not a secret; ggignore
	"testnet": "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY", // public genesis hash, not a secret; ggignore
}

type mint struct {
	symbol  string
	address string
	raw     [32]byte
	ata     map[string]string // not used; ATAs are per owner
}

type validatedConfig struct {
	Config
	node  Node
	mints []mint // sorted by symbol
}

// Validate checks the config without any network access.
func (c Config) Validate() error { _, err := c.validated(); return err }

func (c Config) validated() (*validatedConfig, error) {
	if c.Chain == "" || strings.ContainsAny(c.Chain, ":/") {
		return nil, errors.New("sol: config: chain name must be non-empty and contain no ':' or '/'")
	}
	switch c.Network {
	case "localnet", "devnet", "testnet", "mainnet":
	default:
		return nil, fmt.Errorf("sol: config: unknown network %q (localnet, devnet, testnet, mainnet)", c.Network)
	}
	v := &validatedConfig{Config: c}
	pub, err := hex.DecodeString(c.AccountPublicKey)
	if err != nil || len(pub) != 32 {
		return nil, errors.New("sol: config: account_public_key must be 32 bytes of hex (the Ed25519 account node from mpc-party Node)")
	}
	cc, err := hex.DecodeString(c.AccountChainCode)
	if err != nil || len(cc) != 32 {
		return nil, errors.New("sol: config: account_chain_code must be 32 bytes of hex")
	}
	copy(v.node.PublicKey[:], pub)
	copy(v.node.ChainCode[:], cc)
	if !onCurve(pub) {
		return nil, errors.New("sol: config: account_public_key is not a point of the Ed25519 curve")
	}
	seen := map[string]string{}
	for sym, addr := range c.Tokens {
		if sym == "" || sym == Native || strings.ContainsAny(sym, ":/") {
			return nil, fmt.Errorf("sol: config: token symbol %q is not usable", sym)
		}
		raw, err := ParseAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("sol: config: token %s: %w", sym, err)
		}
		if other, dup := seen[addr]; dup {
			return nil, fmt.Errorf("sol: config: tokens %s and %s are the same mint", sym, other)
		}
		seen[addr] = sym
		if d, ok := c.TokenDecimals[sym]; !ok || d < 0 || d > 18 {
			return nil, fmt.Errorf("sol: config: token %s needs decimals between 0 and 18", sym)
		}
		v.mints = append(v.mints, mint{symbol: sym, address: addr, raw: raw})
	}
	sort.Slice(v.mints, func(i, j int) bool { return v.mints[i].symbol < v.mints[j].symbol })
	return v, nil
}
