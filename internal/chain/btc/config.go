// Package btc is the Bitcoin chain cell: native SegWit (P2WPKH) deposit addresses derived offline from an account xpub, and a
// block scanner over bitcoind's JSON-RPC. Nothing leaves an address yet: building, signing and broadcasting are later tasks and
// return chain.ErrNotSupported.
package btc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// Native is the symbol of bitcoin in the ledger; its base unit is the satoshi (8 decimals).
const (
	Native   = "BTC"
	Decimals = 8
)

// CoinbaseMaturity is how many confirmations a coinbase output needs before it may be spent, and so before it is credited.
const CoinbaseMaturity = 100

// Config is the chain cell's configuration.
type Config struct {
	Chain   string // the chain name in the ledger and the database
	Network string // "regtest", "testnet3", "signet" or "mainnet"
	RPCURL  string // bitcoind JSON-RPC, e.g. http://127.0.0.1:18443
	RPCUser string
	RPCPass string
	// Confirmations is the depth at which a block is final for crediting (default 6). A block with this many confirmations
	// is read; a deposit in it is credited.
	Confirmations uint64
	// AccountXpub is the account-level extended public key (BIP84 shape m/84'/coin'/0') of the hot MPC keyset. Addresses are
	// derived from it offline, on the external branch.
	AccountXpub string
	// HotAddresses are fixed addresses of the cell, if any (later tasks); each must belong to Network.
	HotAddresses []string
	// BatchBlocks bounds how many blocks one Scan call reads (default 100).
	BatchBlocks uint64
}

// Params returns the chain parameters of a network name.
func Params(network string) (*chaincfg.Params, error) {
	switch network {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet3":
		return &chaincfg.TestNet3Params, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	}
	return nil, fmt.Errorf("btc: unknown network %q (mainnet, testnet3, signet, regtest)", network)
}

// CoinType is the BIP44 coin type of a network: 0 for mainnet, 1 for every test network.
func CoinType(network string) uint32 {
	if network == "mainnet" {
		return 0
	}
	return 1
}

// AccountPath is the hardened path of the account key, m/84'/coin'/0', as the plain numbers mpc-party Node takes (the
// hardened bit is implied).
func AccountPath(network string) []uint32 { return []uint32{84, CoinType(network), 0} }

func (c Config) withDefaults() Config {
	if c.Confirmations == 0 {
		c.Confirmations = 6
	}
	if c.BatchBlocks == 0 {
		c.BatchBlocks = 100
	}
	return c
}

// Validate checks the config without any network access. A key or address of another network refuses.
func (c Config) Validate() error {
	_, err := c.validated()
	return err
}

type validatedConfig struct {
	Config
	params  *chaincfg.Params
	account *hdkeychain.ExtendedKey
	branch  *hdkeychain.ExtendedKey // external branch: account/0
}

func (c Config) validated() (*validatedConfig, error) {
	c = c.withDefaults()
	if c.Chain == "" || strings.ContainsAny(c.Chain, ":/") {
		return nil, errors.New("btc: config: chain name must be non-empty and contain no ':' or '/'")
	}
	params, err := Params(c.Network)
	if err != nil {
		return nil, err
	}
	if c.AccountXpub == "" {
		return nil, errors.New("btc: config: account_xpub is required")
	}
	acct, err := hdkeychain.NewKeyFromString(c.AccountXpub)
	if err != nil {
		return nil, fmt.Errorf("btc: config: account_xpub: %w", err)
	}
	if acct.IsPrivate() {
		return nil, errors.New("btc: config: account_xpub is a private key; the core must hold only the public one")
	}
	if !acct.IsForNet(params) {
		return nil, fmt.Errorf("btc: config: account_xpub is not a %s key (its version bytes belong to another network)", c.Network)
	}
	branch, err := acct.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("btc: config: external branch: %w", err)
	}
	v := &validatedConfig{Config: c, params: params, account: acct, branch: branch}
	for _, a := range c.HotAddresses {
		if err := v.checkAddress(a); err != nil {
			return nil, fmt.Errorf("btc: config: hot address: %w", err)
		}
	}
	// The form of an address this config derives must belong to the network it names.
	probe, err := v.addressAt(0)
	if err != nil {
		return nil, err
	}
	if err := v.checkAddress(probe); err != nil {
		return nil, fmt.Errorf("btc: config: %w", err)
	}
	return v, nil
}

// checkAddress refuses an address that does not decode for the configured network.
func (v *validatedConfig) checkAddress(a string) error {
	addr, err := btcutil.DecodeAddress(a, v.params)
	if err != nil {
		return fmt.Errorf("address %q is not valid on %s: %w", a, v.Network, err)
	}
	if !addr.IsForNet(v.params) {
		return fmt.Errorf("address %q is not a %s address", a, v.Network)
	}
	return nil
}
