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
	// HotShards are the cell's hot addresses, in shard order (shard i is HotShards[i]). Each must be the key of the account at its path.
	HotShards []HotShardConfig
	// SpendConfirmations is the depth at which a transaction of ours settles and its change is released (default 2). Our own transactions
	// spend only our own inputs and nobody else can double-spend them, so a reorganization can only delay them.
	SpendConfirmations uint64
	// MaxInputs bounds the inputs of one transaction (default 20); the signing zone's cap must be at least as high.
	MaxInputs int
	// FallbackFeeRate is the fee rate in satoshis per virtual byte when the node has no estimate (default 5). MaxFeeRate is the ceiling
	// (default 100), which must be below the signing zone's.
	FallbackFeeRate uint64
	MaxFeeRate      uint64
	// MaxTxFeeSats is the most a transaction may pay in fee (default 100000, below the signing zone's cap).
	MaxTxFeeSats uint64
	// SweepMaxFeeRate is the most a routine sweep pays per virtual byte (default MaxFeeRate; it must not be above it). Above it routine sweeps wait.
	// SweepUrgentValue, in satoshis, is the amount from which a sweep goes regardless of that ceiling, up to MaxFeeRate (0: no such exception).
	SweepMaxFeeRate uint64
	// ColdAddresses is where hot-to-cold moves pay, "<pool>/native" -> address; it must match the signing zone's pin. Checked against the network.
	ColdAddresses    map[string]string
	SweepUrgentValue uint64
	// SweepK and MinSweep are the sweep rule (value >= max(MinSweep, SweepK x fee)); the adapter needs them to refuse a fee bump that would break it.
	// SweepK 0 and MinSweep 0 mean no rule.
	SweepK   uint64
	MinSweep uint64
}

// HotShardConfig is one hot shard: the partition it serves, its address and the path of its key below the account.
type HotShardConfig struct {
	PartitionID string
	Address     string
	Path        []uint32 // [BranchHot, index]
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
	if c.SpendConfirmations == 0 {
		c.SpendConfirmations = 2
	}
	if c.MaxInputs == 0 {
		c.MaxInputs = 20
	}
	if c.FallbackFeeRate == 0 {
		c.FallbackFeeRate = 5
	}
	if c.MaxFeeRate == 0 {
		c.MaxFeeRate = 100
	}
	if c.MaxTxFeeSats == 0 {
		c.MaxTxFeeSats = 100_000
	}
	if c.SweepMaxFeeRate == 0 {
		c.SweepMaxFeeRate = c.MaxFeeRate
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
	ids := make([]string, 0, len(c.HotShards))
	for _, h := range c.HotShards {
		ids = append(ids, h.PartitionID)
	}
	if err := OneShardPerPool(ids); err != nil {
		return nil, fmt.Errorf("btc: config: %w", err)
	}
	for i, h := range c.HotShards {
		if len(h.Path) != 2 || h.Path[0] != BranchHot {
			return nil, fmt.Errorf("btc: config: hot shard %d: path %v is not on the hot branch [%d, index]", i, h.Path, BranchHot)
		}
		if err := v.checkAddress(h.Address); err != nil {
			return nil, fmt.Errorf("btc: config: hot shard %d: %w", i, err)
		}
		want, err := v.addressAt2(h.Path)
		if err != nil {
			return nil, err
		}
		if d, err := DecodeAddress(h.Address, params); err != nil || d.Canonical != want {
			return nil, fmt.Errorf("btc: config: hot shard %d: address %s is not the account's key at %s (that is %s)", i, h.Address, PathString(h.Path), want)
		}
	}
	hotSet := map[string]bool{}
	for _, h := range c.HotShards {
		if d, err := DecodeAddress(h.Address, params); err == nil {
			hotSet[d.Canonical] = true
		}
	}
	for k, a := range c.ColdAddresses {
		if !strings.HasSuffix(k, "/native") || len(k) <= len("/native") {
			return nil, fmt.Errorf("btc: config: cold address key %q: want <pool>/native", k)
		}
		d, err := DecodeAddress(a, params)
		if err != nil {
			return nil, fmt.Errorf("btc: config: cold address for %q: %w", k, err)
		}
		if hotSet[d.Canonical] {
			return nil, fmt.Errorf("btc: config: cold address for %q is a hot shard address", k)
		}
	}
	if c.MaxInputs < 1 || c.SpendConfirmations < 1 {
		return nil, errors.New("btc: config: max_inputs and spend_confirmations must be positive")
	}
	if c.SweepMaxFeeRate > c.MaxFeeRate {
		return nil, errors.New("btc: config: sweep_max_fee_rate is above max_fee_rate")
	}
	if c.FallbackFeeRate > c.MaxFeeRate {
		return nil, errors.New("btc: config: fallback_fee_rate is above max_fee_rate")
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

// addressAt2 derives the P2WPKH address at a two-element path from the account key.
func (v *validatedConfig) addressAt2(path []uint32) (string, error) {
	a := &Account{Params: v.params, key: v.account}
	return a.Address(path)
}

// CanonicalAddress validates an address for the network and returns its canonical form.
func CanonicalAddress(network, address string) (string, error) {
	params, err := Params(network)
	if err != nil {
		return "", err
	}
	d, err := DecodeAddress(address, params)
	if err != nil {
		return "", err
	}
	return d.Canonical, nil
}
