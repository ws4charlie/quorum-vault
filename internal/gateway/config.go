// Package gateway is the signing gateway: it pulls sign jobs, trusts nothing
// in the business database, and independently decides whether to sign.
//
// Everything it trusts comes from a signing-zone config file (this file) and a
// replay-guard database of its own (store.go). The business database supplies
// only the job to look at.
package gateway

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
)

// File is the on-disk signing-zone config (JSON). See config.example.json.
type File struct {
	Comment string `json:"_comment,omitempty"`
	// Approvers maps actor name to its Ed25519 public key.
	Approvers map[string]ApproverFile `json:"approvers"`
	// Chains maps chain name to its settings.
	Chains map[string]ChainFile `json:"chains"`
	// Signers maps partition ID to the HSM key that signs for it. Optional for
	// tests, required by cmd/qv-gateway.
	Signers map[string]SignerFile `json:"signers"`
	// MaxIntentAge bounds how far ahead a new withdrawal's not_after may be
	// (Go duration, default "24h"). SignTimeout bounds one signer call and is
	// also how long a reservation counts as "being signed" (default "30s").
	MaxIntentAge string `json:"max_intent_age,omitempty"`
	SignTimeout  string `json:"sign_timeout,omitempty"`
}

// SignerFile locates a partition's key in an HSM token.
type SignerFile struct {
	Token     string `json:"token"`      // token label
	KeyID     string `json:"key_id"`     // CKA_ID, hex
	PublicKey string `json:"public_key"` // 65-byte uncompressed secp256k1, hex
}

// ApproverFile is one approver. Disabled approvers never count.
type ApproverFile struct {
	PublicKey string `json:"public_key"` // 64 hex chars
	Enabled   bool   `json:"enabled"`
}

// ChainFile is one chain's verifier config and withdrawal policy.
type ChainFile struct {
	EVM *EVMFile `json:"evm"`
	// Assets maps asset symbol to its withdrawal policy. Every asset the chain
	// verifier knows (including the native one) needs an entry.
	Assets         map[string]AssetFile `json:"assets"`
	SweepsPerHour  int                  `json:"sweeps_per_hour"`
	CancelsPerHour int                  `json:"cancels_per_hour"`
}

// AssetFile is the withdrawal policy of one (chain, asset), amounts in base units.
type AssetFile struct {
	PerTxCap string     `json:"per_tx_cap"`
	DailyCap string     `json:"daily_cap"` // rolling 24 hours
	Tiers    []TierFile `json:"tiers"`
}

// TierFile: withdrawals of at least MinAmount need Approvals distinct approvers.
type TierFile struct {
	MinAmount string `json:"min_amount"`
	Approvals int    `json:"approvals"`
}

// EVMFile is the JSON form of evm.Config (no RPC: the gateway has no chain access).
type EVMFile struct {
	ChainID          uint64               `json:"chain_id"`
	Factory          string               `json:"factory"`
	SweepDestination string               `json:"sweep_destination"`
	HotAddresses     map[string]string    `json:"hot_addresses"` // partition ID -> address
	Tokens           map[string]TokenFile `json:"tokens"`
	NativeAsset      string               `json:"native_asset"`
	MaxTxFeeWei      string               `json:"max_tx_fee_wei"`
}

// TokenFile is a configured ERC-20.
type TokenFile struct {
	Address  string `json:"address"`
	Decimals uint8  `json:"decimals"`
}

// Config is the validated form of File.
type Config struct {
	Approvers map[string]Approver
	Chains    map[string]*ChainConfig
	Signers   map[string]SignerFile

	MaxIntentAge time.Duration
	SignTimeout  time.Duration
}

// Approver is a configured approver key.
type Approver struct {
	Key     ed25519.PublicKey
	Enabled bool
}

// ChainConfig is one chain's trust root.
type ChainConfig struct {
	Name           string
	EVM            evm.Config
	Assets         map[string]AssetPolicy
	SweepsPerHour  int
	CancelsPerHour int
}

// AssetPolicy is the withdrawal policy of one asset.
type AssetPolicy struct {
	PerTxCap *big.Int
	DailyCap *big.Int
	Tiers    []Tier // ascending MinAmount
}

// Tier: amounts >= Min need Approvals distinct approvers.
type Tier struct {
	Min       *big.Int
	Approvals int
}

// RequiredApprovals returns how many distinct approvers an amount needs.
func (p AssetPolicy) RequiredApprovals(amount *big.Int) int {
	n := 0
	for _, t := range p.Tiers {
		if amount.Cmp(t.Min) >= 0 {
			n = t.Approvals
		}
	}
	return n
}

// LoadConfig reads and validates the config file at path.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gateway: read config: %w", err)
	}
	return ParseConfig(b)
}

// ParseConfig validates JSON config bytes. Unknown fields are errors.
func ParseConfig(b []byte) (*Config, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("gateway: config: %w", err)
	}
	if dec.More() {
		return nil, errors.New("gateway: config: trailing data")
	}
	return f.build()
}

func (f File) build() (*Config, error) {
	c := &Config{Approvers: map[string]Approver{}, Chains: map[string]*ChainConfig{}, Signers: f.Signers,
		MaxIntentAge: 24 * time.Hour, SignTimeout: 30 * time.Second}
	for _, d := range []struct {
		name, val string
		dst       *time.Duration
	}{{"max_intent_age", f.MaxIntentAge, &c.MaxIntentAge}, {"sign_timeout", f.SignTimeout, &c.SignTimeout}} {
		if d.val == "" {
			continue
		}
		v, err := time.ParseDuration(d.val)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("gateway: config: %s %q is not a positive duration", d.name, d.val)
		}
		*d.dst = v
	}
	keys := map[string]string{}
	enabled := 0
	for name, a := range f.Approvers {
		if name == "" {
			return nil, errors.New("gateway: config: empty approver name")
		}
		raw, err := hex.DecodeString(a.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("gateway: config: approver %q: public_key must be %d hex bytes", name, ed25519.PublicKeySize)
		}
		if other, dup := keys[string(raw)]; dup {
			return nil, fmt.Errorf("gateway: config: approvers %q and %q share one public key", other, name)
		}
		keys[string(raw)] = name
		c.Approvers[name] = Approver{Key: ed25519.PublicKey(raw), Enabled: a.Enabled}
		if a.Enabled {
			enabled++
		}
	}
	if len(f.Chains) == 0 {
		return nil, errors.New("gateway: config: no chains")
	}
	for name, cf := range f.Chains {
		cc, err := cf.build(name, enabled)
		if err != nil {
			return nil, err
		}
		c.Chains[name] = cc
	}
	return c, nil
}

func amount(what, s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || s != n.String() {
		return nil, fmt.Errorf("gateway: config: %s %q is not a canonical non-negative decimal", what, s)
	}
	return n, nil
}

func addr(what, s string) (common.Address, error) {
	if !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("gateway: config: %s %q is not an address", what, s)
	}
	return common.HexToAddress(s), nil
}

func (cf ChainFile) build(name string, enabledApprovers int) (*ChainConfig, error) {
	if cf.EVM == nil {
		return nil, fmt.Errorf("gateway: config: chain %q has no supported chain section (only evm)", name)
	}
	if cf.SweepsPerHour < 0 || cf.CancelsPerHour < 0 {
		return nil, fmt.Errorf("gateway: config: chain %q: rate limits must be >= 0", name)
	}
	e := cf.EVM
	ec := evm.Config{Chain: name, ChainID: e.ChainID, NativeAsset: e.NativeAsset,
		HotAddresses: map[string]common.Address{}, Assets: map[string]evm.Token{}}
	var err error
	if ec.Factory, err = addr("factory", e.Factory); err != nil {
		return nil, err
	}
	if ec.SweepDestination, err = addr("sweep_destination", e.SweepDestination); err != nil {
		return nil, err
	}
	for p, a := range e.HotAddresses {
		if ec.HotAddresses[p], err = addr("hot address of "+p, a); err != nil {
			return nil, err
		}
	}
	for s, t := range e.Tokens {
		a, err := addr("token "+s, t.Address)
		if err != nil {
			return nil, err
		}
		ec.Assets[s] = evm.Token{Address: a, Decimals: t.Decimals}
	}
	if ec.MaxTxFeeWei, err = amount("max_tx_fee_wei", e.MaxTxFeeWei); err != nil {
		return nil, err
	}
	if len(ec.HotAddresses) == 0 {
		return nil, fmt.Errorf("gateway: config: chain %q has no hot addresses", name)
	}
	if _, err := evm.NewVerifier(ec); err != nil {
		return nil, fmt.Errorf("gateway: config: chain %q: %w", name, err)
	}
	native := ec.NativeAsset
	if native == "" {
		native = evm.DefaultNativeAsset
	}
	want := []string{native}
	for s := range ec.Assets {
		want = append(want, s)
	}
	sort.Strings(want)
	cc := &ChainConfig{Name: name, EVM: ec, Assets: map[string]AssetPolicy{},
		SweepsPerHour: cf.SweepsPerHour, CancelsPerHour: cf.CancelsPerHour}
	for _, s := range want {
		af, ok := cf.Assets[s]
		if !ok {
			return nil, fmt.Errorf("gateway: config: chain %q: asset %q has no policy", name, s)
		}
		if cc.Assets[s], err = af.build(name+"/"+s, enabledApprovers); err != nil {
			return nil, err
		}
	}
	for s := range cf.Assets {
		if _, ok := cc.Assets[s]; !ok {
			return nil, fmt.Errorf("gateway: config: chain %q: policy for unknown asset %q", name, s)
		}
	}
	return cc, nil
}

func (af AssetFile) build(where string, enabledApprovers int) (AssetPolicy, error) {
	var p AssetPolicy
	var err error
	if p.PerTxCap, err = amount(where+" per_tx_cap", af.PerTxCap); err != nil {
		return p, err
	}
	if p.DailyCap, err = amount(where+" daily_cap", af.DailyCap); err != nil {
		return p, err
	}
	if p.PerTxCap.Sign() == 0 || p.DailyCap.Cmp(p.PerTxCap) < 0 {
		return p, fmt.Errorf("gateway: config: %s: need 0 < per_tx_cap <= daily_cap", where)
	}
	if len(af.Tiers) == 0 {
		return p, fmt.Errorf("gateway: config: %s: no approval tiers", where)
	}
	prevMin, prevAppr := big.NewInt(-1), 0
	for i, t := range af.Tiers {
		min, err := amount(fmt.Sprintf("%s tier %d min_amount", where, i), t.MinAmount)
		if err != nil {
			return p, err
		}
		switch {
		case i == 0 && min.Sign() != 0:
			return p, fmt.Errorf("gateway: config: %s: first tier must start at 0", where)
		case min.Cmp(prevMin) <= 0:
			return p, fmt.Errorf("gateway: config: %s: tiers must ascend", where)
		case t.Approvals < 1:
			return p, fmt.Errorf("gateway: config: %s: every withdrawal needs at least one approval", where)
		case t.Approvals < prevAppr:
			return p, fmt.Errorf("gateway: config: %s: approvals must not decrease with amount", where)
		case t.Approvals > enabledApprovers:
			return p, fmt.Errorf("gateway: config: %s: tier needs %d approvals but only %d approvers are enabled", where, t.Approvals, enabledApprovers)
		}
		p.Tiers = append(p.Tiers, Tier{Min: min, Approvals: t.Approvals})
		prevMin, prevAppr = min, t.Approvals
	}
	return p, nil
}
