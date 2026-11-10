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

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
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

// SignerFile locates a partition's key: in an HSM token (backend "hsm", the default) or in the cb-mpc service
// (backend "mpc": party A's key id and address, in MPC).
type SignerFile struct {
	Backend   string `json:"backend,omitempty"` // "hsm" (default) or "mpc"
	Token     string `json:"token,omitempty"`   // hsm: token label
	KeyID     string `json:"key_id"`            // hsm: CKA_ID, hex; mpc: key id returned by party A's Derive
	PublicKey string `json:"public_key"`        // 65-byte uncompressed secp256k1, hex
	// KeysetID and HardenedPath make an mpc signer for a whole key tree instead of one key (Bitcoin: every input has its own
	// key). The job's key reference picks the key below HardenedPath, and party A derives it on demand. Instead of KeyID and PublicKey.
	KeysetID     string         `json:"keyset_id,omitempty"`
	HardenedPath []uint32       `json:"hardened_path,omitempty"`
	MPC          *MPCSignerFile `json:"mpc,omitempty"`
	// Scheme "ecdsa-2of3" makes an EVM hot shard a 2-of-3 keyset on parties A, B and C (E23-3): keyset_id and public_key (the
	// keyset's key, which the hot address is checked against) and Coordinators instead of mpc: party A first, then party B. The
	// gateway moves to the next coordinator only when the party says nothing had been exchanged yet (see internal/mpcsigner).
	Scheme       string          `json:"scheme,omitempty"`
	Coordinators []MPCSignerFile `json:"coordinators,omitempty"`
	// Deposit (scheme "ed25519-2of3" only, Solana): the 2-party HD Ed25519 keyset the deposit addresses come from. A sweep needs its deposit
	// key's signature next to the hot shard's: keyset_id, hardened_path (the account path m/44'/501'/0') and mpc, as for a Bitcoin key tree.
	Deposit *SignerFile `json:"deposit,omitempty"`
}

// MPCSignerFile is how the gateway reaches party A (the caller port of mpc-party).
type MPCSignerFile struct {
	Name       string `json:"name,omitempty"` // coordinators of a 2-of-3 signer: "A" or "B"
	Address    string `json:"address"`        // host:port of party A's caller port
	CertFile   string `json:"cert_file"`      // the gateway's client certificate (pinned by party A)
	KeyFile    string `json:"key_file"`
	ServerPin  string `json:"server_pin"`  // sha256 hex of party A's certificate
	MaxRetries int    `json:"max_retries"` // transport/limit retries inside sign_timeout (default 3)
}

// ApproverFile is one approver. Disabled approvers never count.
type ApproverFile struct {
	PublicKey string `json:"public_key"` // 64 hex chars
	Enabled   bool   `json:"enabled"`
}

// ChainFile is one chain's verifier config and withdrawal policy.
type ChainFile struct {
	// Family names the kind of chain and so which section below is read, which codec verifies its transactions and how
	// its addresses are written. Default "evm". An unknown family refuses to start.
	Family string   `json:"family,omitempty"`
	EVM    *EVMFile `json:"evm"`
	// BTC is the section of the btc family.
	BTC *BTCFile `json:"btc,omitempty"`
	// SOL is the section of the sol family.
	SOL *SOLFile `json:"sol,omitempty"`
	// Assets maps asset symbol to its withdrawal policy. Every asset the chain
	// verifier knows (including the native one) needs an entry.
	Assets        map[string]AssetFile `json:"assets"`
	SweepsPerHour int                  `json:"sweeps_per_hour"`
	// WithdrawalsPerHour limits how many withdrawals are first signed in a rolling hour on this chain. Required, > 0.
	WithdrawalsPerHour int `json:"withdrawals_per_hour"`
	CancelsPerHour     int `json:"cancels_per_hour"`
	// ToColdPerHour limits hot-to-cold moves; 0 refuses them all.
	ToColdPerHour int `json:"to_cold_per_hour"`
	// RebalancePerHour limits moves between hot shards; 0 refuses them all.
	RebalancePerHour int `json:"rebalance_per_hour"`
	// ConsolidationsPerHour limits how many consolidations of a Bitcoin shard are first signed in a rolling hour; 0 refuses them all. A consolidation
	// leaves the money on the same shard, so what it can cost is bounded by this number times max_tx_fee_sats.
	ConsolidationsPerHour int `json:"consolidations_per_hour"`
}

// AssetFile is the withdrawal policy of one (chain, asset), amounts in base units.
type AssetFile struct {
	PerTxCap string     `json:"per_tx_cap"`
	DailyCap string     `json:"daily_cap"` // rolling 24 hours
	Tiers    []TierFile `json:"tiers"`
	// ToColdDailyCap caps what hot-to-cold moves of this asset may carry in a rolling 24 hours. Empty or 0 refuses the moves.
	ToColdDailyCap string `json:"to_cold_daily_cap"`
	// RebalanceDailyCap caps what moves between hot shards may carry in a rolling 24 hours, per asset. Empty or 0 refuses them.
	RebalanceDailyCap string `json:"rebalance_daily_cap"`
	// WithdrawalDestinations lists the only addresses withdrawals of this asset may pay. Either this list or AnyDestination must
	// be set, never both and never neither: an open policy is written down on purpose.
	WithdrawalDestinations []string `json:"withdrawal_destinations,omitempty"`
	AnyDestination         bool     `json:"any_destination,omitempty"`
}

// TierFile: withdrawals of at least MinAmount need Approvals distinct approvers.
type TierFile struct {
	MinAmount string `json:"min_amount"`
	Approvals int    `json:"approvals"`
}

// EVMFile is the JSON form of evm.Config (no RPC: the gateway has no chain access).
type EVMFile struct {
	ChainID          uint64            `json:"chain_id"`
	Factory          string            `json:"factory"`
	SweepDestination string            `json:"sweep_destination"`
	HotAddresses     map[string]string `json:"hot_addresses"` // partition ID -> address
	// ColdAddresses: where hot-to-cold moves may go, "<pool>/native" or "<pool>/token" -> address. Only this zone's config can
	// change it; a move to any other address is refused.
	ColdAddresses map[string]string    `json:"cold_addresses"`
	Tokens        map[string]TokenFile `json:"tokens"`
	NativeAsset   string               `json:"native_asset"`
	MaxTxFeeWei   string               `json:"max_tx_fee_wei"`
}

// BTCFile is the signing-zone config of a Bitcoin chain. Everything the zone trusts about keys and addresses is here.
type BTCFile struct {
	Network     string `json:"network"`      // mainnet, testnet3, signet or regtest
	AccountXpub string `json:"account_xpub"` // m/84'/coin'/0'
	// HotShards maps a partition ID to its pinned hot address and the path it derives at; the address must be the account's key at that path.
	HotShards map[string]HotShardFile `json:"hot_shards"`
	// ColdAddresses: where hot-to-cold moves may go, "<pool>/native" -> address.
	ColdAddresses map[string]string `json:"cold_addresses"`
	MaxTxFeeSats  uint64            `json:"max_tx_fee_sats"`
	MaxFeeRate    uint64            `json:"max_fee_rate"` // satoshis per virtual byte
	MaxInputs     int               `json:"max_inputs"`
}

// HotShardFile is one pinned hot shard.
type HotShardFile struct {
	Address string   `json:"address"`
	Path    []uint32 `json:"path"` // [1, index]
}

// buildBTC reads a btc chain: its verifier config, its one asset policy (BTC, amounts in satoshis) and the rate limits.
func (cf ChainFile) buildBTC(name string, enabledApprovers int) (*ChainConfig, error) {
	b := cf.BTC
	if b == nil {
		return nil, fmt.Errorf("gateway: config: chain %q has no btc section", name)
	}
	if cf.WithdrawalsPerHour <= 0 {
		return nil, fmt.Errorf("gateway: config: chain %q: withdrawals_per_hour is required and must be > 0", name)
	}
	if cf.SweepsPerHour < 0 || cf.CancelsPerHour < 0 || cf.ToColdPerHour < 0 || cf.RebalancePerHour < 0 || cf.ConsolidationsPerHour < 0 {
		return nil, fmt.Errorf("gateway: config: chain %q: rate limits must be >= 0", name)
	}
	sc := btc.SigningConfig{Chain: name, Network: b.Network, AccountXpub: b.AccountXpub, HotShards: map[string]btc.HotShard{},
		ColdAddresses: b.ColdAddresses, MaxTxFeeSats: b.MaxTxFeeSats, MaxFeeRate: b.MaxFeeRate, MaxInputs: b.MaxInputs}
	for p, h := range b.HotShards {
		sc.HotShards[p] = btc.HotShard{Address: h.Address, Path: h.Path}
	}
	v, err := btc.NewVerifier(sc)
	if err != nil {
		return nil, fmt.Errorf("gateway: config: chain %q: %w", name, err)
	}
	if len(cf.Assets) != 1 {
		return nil, fmt.Errorf("gateway: config: chain %q: a btc chain has exactly one asset, %s", name, btc.Native)
	}
	af, ok := cf.Assets[btc.Native]
	if !ok {
		return nil, fmt.Errorf("gateway: config: chain %q: asset %q has no policy", name, btc.Native)
	}
	pol, err := af.build(name+"/"+btc.Native, enabledApprovers, v.Canonical)
	if err != nil {
		return nil, err
	}
	return &ChainConfig{Name: name, Family: FamilyBTC, BTC: sc, Assets: map[string]AssetPolicy{btc.Native: pol},
		SweepsPerHour: cf.SweepsPerHour, WithdrawalsPerHour: cf.WithdrawalsPerHour, CancelsPerHour: cf.CancelsPerHour,
		ToColdPerHour: cf.ToColdPerHour, RebalancePerHour: cf.RebalancePerHour, ConsolidationsPerHour: cf.ConsolidationsPerHour}, nil
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
	Family         string // FamilyEVM, FamilyBTC or FamilySOL
	EVM            evm.Config
	BTC            btc.SigningConfig
	SOL            sol.SigningConfig
	Assets         map[string]AssetPolicy
	SweepsPerHour  int
	CancelsPerHour int
	ToColdPerHour  int
	// WithdrawalsPerHour limits withdrawals first signed per rolling hour.
	WithdrawalsPerHour int
	// RebalancePerHour limits moves between hot shards (zero: none allowed).
	RebalancePerHour int
	// ConsolidationsPerHour limits consolidations first signed per rolling hour (Bitcoin; zero: none allowed).
	ConsolidationsPerHour int
}

// AssetPolicy is the withdrawal policy of one asset.
type AssetPolicy struct {
	PerTxCap *big.Int
	DailyCap *big.Int
	Tiers    []Tier // ascending MinAmount
	// ToColdDailyCap caps hot-to-cold moves per rolling day (zero: none allowed).
	ToColdDailyCap *big.Int
	// RebalanceDailyCap caps moves between hot shards per rolling day (zero: none allowed).
	RebalanceDailyCap *big.Int
	// Destinations is the set withdrawals may pay, as canonical address strings of the chain's family (ChainCodec.Canonical;
	// on EVM checksum case never matters); AnyDestination means the config said so explicitly.
	Destinations   map[string]bool
	AnyDestination bool
}

// AllowsDestination reports whether a withdrawal of this asset may pay dest, a canonical address string.
func (p AssetPolicy) AllowsDestination(dest string) bool {
	return p.AnyDestination || p.Destinations[dest]
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
	for p, sf := range f.Signers {
		switch sf.Backend {
		case "", "hsm":
			if sf.Token == "" {
				return nil, fmt.Errorf("gateway: config: signer %q: token is required for the hsm backend", p)
			}
		case "mpc":
			if sf.Scheme != "" {
				if sf.Scheme != "ecdsa-2of3" && sf.Scheme != "ed25519-2of3" {
					return nil, fmt.Errorf("gateway: config: signer %q: unknown scheme %q", p, sf.Scheme)
				}
				if sf.Scheme == "ed25519-2of3" {
					if err := checkDepositSigner(p, sf); err != nil {
						return nil, err
					}
				} else if sf.Deposit != nil {
					return nil, fmt.Errorf("gateway: config: signer %q: deposit is for ed25519-2of3 signers only", p)
				}
				if sf.KeysetID == "" || sf.PublicKey == "" || sf.KeyID != "" || len(sf.HardenedPath) > 0 || sf.MPC != nil || len(sf.Coordinators) == 0 {
					return nil, fmt.Errorf("gateway: config: signer %q: a 2-of-3 signer needs keyset_id, public_key and coordinators (party A, then party B), and no key_id, hardened_path or mpc", p)
				}
				seen := map[string]bool{}
				for i, c := range sf.Coordinators {
					if c.Name != "A" && c.Name != "B" || seen[c.Name] || c.Address == "" || c.CertFile == "" || c.KeyFile == "" || c.ServerPin == "" {
						return nil, fmt.Errorf("gateway: config: signer %q: coordinator %d needs a distinct name (A or B) and address, cert_file, key_file and server_pin", p, i)
					}
					seen[c.Name] = true
				}
				if sf.Coordinators[0].Name != "A" {
					return nil, fmt.Errorf("gateway: config: signer %q: the first coordinator is party A", p)
				}
				continue
			}
			deriving := sf.KeysetID != "" || len(sf.HardenedPath) > 0
			if deriving && (sf.KeysetID == "" || len(sf.HardenedPath) == 0 || sf.KeyID != "" || sf.PublicKey != "") {
				return nil, fmt.Errorf("gateway: config: signer %q: a key tree needs keyset_id and hardened_path, and no key_id or public_key", p)
			}
			if sf.MPC == nil || sf.MPC.Address == "" || sf.MPC.CertFile == "" || sf.MPC.KeyFile == "" || sf.MPC.ServerPin == "" || (sf.KeyID == "" && !deriving) {
				return nil, fmt.Errorf("gateway: config: signer %q: the mpc backend needs key_id (or keyset_id and hardened_path) and mpc.{address,cert_file,key_file,server_pin}", p)
			}
		default:
			return nil, fmt.Errorf("gateway: config: signer %q: unknown backend %q", p, sf.Backend)
		}
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
	family, err := familyOf(cf.Family)
	if err != nil {
		return nil, fmt.Errorf("gateway: config: chain %q: %w", name, err)
	}
	if family == FamilyBTC {
		return cf.buildBTC(name, enabledApprovers)
	}
	if family == FamilySOL {
		return cf.buildSOL(name, enabledApprovers)
	}
	canon := (&EVMCodec{}).Canonical
	if cf.EVM == nil {
		return nil, fmt.Errorf("gateway: config: chain %q has no %s section", name, family)
	}
	if cf.WithdrawalsPerHour <= 0 {
		return nil, fmt.Errorf("gateway: config: chain %q: withdrawals_per_hour is required and must be > 0", name)
	}
	if cf.SweepsPerHour < 0 || cf.CancelsPerHour < 0 || cf.ToColdPerHour < 0 || cf.RebalancePerHour < 0 {
		return nil, fmt.Errorf("gateway: config: chain %q: rate limits must be >= 0", name)
	}
	e := cf.EVM
	ec := evm.Config{Chain: name, ChainID: e.ChainID, NativeAsset: e.NativeAsset,
		HotAddresses: map[string]common.Address{}, Assets: map[string]evm.Token{}, ColdAddresses: map[string]common.Address{}}
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
	for k, a := range e.ColdAddresses {
		if ec.ColdAddresses[k], err = addr("cold address "+k, a); err != nil {
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
	cc := &ChainConfig{Name: name, Family: family, EVM: ec, Assets: map[string]AssetPolicy{},
		SweepsPerHour: cf.SweepsPerHour, WithdrawalsPerHour: cf.WithdrawalsPerHour, CancelsPerHour: cf.CancelsPerHour, ToColdPerHour: cf.ToColdPerHour, RebalancePerHour: cf.RebalancePerHour}
	for _, s := range want {
		af, ok := cf.Assets[s]
		if !ok {
			return nil, fmt.Errorf("gateway: config: chain %q: asset %q has no policy", name, s)
		}
		if cc.Assets[s], err = af.build(name+"/"+s, enabledApprovers, canon); err != nil {
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

func (af AssetFile) build(where string, enabledApprovers int, canon func(string) (string, error)) (AssetPolicy, error) {
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
	p.ToColdDailyCap = new(big.Int)
	if af.ToColdDailyCap != "" {
		if p.ToColdDailyCap, err = amount(where+" to_cold_daily_cap", af.ToColdDailyCap); err != nil {
			return p, err
		}
	}
	p.RebalanceDailyCap = new(big.Int)
	if af.RebalanceDailyCap != "" {
		if p.RebalanceDailyCap, err = amount(where+" rebalance_daily_cap", af.RebalanceDailyCap); err != nil {
			return p, err
		}
	}
	switch {
	case af.AnyDestination && len(af.WithdrawalDestinations) > 0:
		return p, fmt.Errorf("gateway: config: %s: withdrawal_destinations and any_destination are both set; choose one", where)
	case !af.AnyDestination && len(af.WithdrawalDestinations) == 0:
		return p, fmt.Errorf("gateway: config: %s: set withdrawal_destinations (a list) or any_destination: true; withdrawals to no one in particular are not the default", where)
	}
	p.AnyDestination = af.AnyDestination
	p.Destinations = map[string]bool{}
	for _, d := range af.WithdrawalDestinations {
		a, err := canon(d)
		if err != nil {
			return p, fmt.Errorf("gateway: config: %s withdrawal destination: %w", where, err)
		}
		if a == (common.Address{}).Hex() { // the burn address of the evm family
			return p, fmt.Errorf("gateway: config: %s: the zero address is not a withdrawal destination", where)
		}
		p.Destinations[a] = true
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

// SOLFile is the signing-zone config of a Solana chain. Everything the zone trusts about keys and addresses is here.
type SOLFile struct {
	// AccountPublicKey and AccountChainCode (hex): the account node m/44'/501'/0' of the 2-party HD keyset. Deposit keys derive from it.
	AccountPublicKey string `json:"account_public_key"`
	AccountChainCode string `json:"account_chain_code"`
	// HotShards maps a partition ID to the address of its hot shard (the SOL partition and the token partitions of one shard share it).
	HotShards map[string]string       `json:"hot_shards"`
	Tokens    map[string]SOLTokenFile `json:"tokens"`
	// Caps on what a transaction may pay beyond the signature fee.
	MaxComputeUnits         uint32 `json:"max_compute_units"`
	MaxMicroLamportsPerUnit uint64 `json:"max_micro_lamports_per_unit"`
	MaxPriorityFeeLamports  uint64 `json:"max_priority_fee_lamports"`
	// NoncePool is the number of durable-nonce accounts each hot shard owns, and NonceRentLamports the rent-exempt minimum each is created with.
	// Withdrawals sign the nonce of one of these accounts; the zone derives every address from the hot shard.
	NoncePool         int    `json:"nonce_pool"`
	NonceRentLamports uint64 `json:"nonce_rent_lamports"`
}

// SOLTokenFile is a configured classic SPL token.
type SOLTokenFile struct {
	Mint     string `json:"mint"`
	Decimals uint8  `json:"decimals"`
}

// buildSOL reads a sol chain: its verifier config, one asset policy per asset (SOL and each token) and the rate limits.
func (cf ChainFile) buildSOL(name string, enabledApprovers int) (*ChainConfig, error) {
	s := cf.SOL
	if s == nil {
		return nil, fmt.Errorf("gateway: config: chain %q has no sol section", name)
	}
	if cf.WithdrawalsPerHour <= 0 {
		return nil, fmt.Errorf("gateway: config: chain %q: withdrawals_per_hour is required and must be > 0", name)
	}
	if cf.SweepsPerHour < 0 || cf.CancelsPerHour < 0 || cf.ToColdPerHour < 0 || cf.RebalancePerHour < 0 || cf.ConsolidationsPerHour < 0 {
		return nil, fmt.Errorf("gateway: config: chain %q: rate limits must be >= 0", name)
	}
	pub, err1 := hex.DecodeString(s.AccountPublicKey)
	cc, err2 := hex.DecodeString(s.AccountChainCode)
	if err1 != nil || err2 != nil || len(pub) != 32 || len(cc) != 32 {
		return nil, fmt.Errorf("gateway: config: chain %q: account_public_key and account_chain_code are 32 bytes of hex", name)
	}
	sc := sol.SigningConfig{Chain: name, HotShards: s.HotShards, Tokens: map[string]sol.Token{}, MaxComputeUnits: s.MaxComputeUnits,
		MaxMicroLamportsPerUnit: s.MaxMicroLamportsPerUnit, MaxPriorityFeeLamports: s.MaxPriorityFeeLamports,
		NoncePool: s.NoncePool, NonceRent: s.NonceRentLamports}
	copy(sc.AccountPublicKey[:], pub)
	copy(sc.AccountChainCode[:], cc)
	for sym, t := range s.Tokens {
		sc.Tokens[sym] = sol.Token{Mint: t.Mint, Decimals: t.Decimals}
	}
	v, err := sol.NewVerifier(sc)
	if err != nil {
		return nil, fmt.Errorf("gateway: config: chain %q: %w", name, err)
	}
	want := map[string]bool{sol.Native: true}
	for sym := range s.Tokens {
		want[sym] = true
	}
	if len(cf.Assets) != len(want) {
		return nil, fmt.Errorf("gateway: config: chain %q: a sol chain has exactly the assets %s and its tokens, each with a policy", name, sol.Native)
	}
	assets := map[string]AssetPolicy{}
	for sym := range want {
		af, ok := cf.Assets[sym]
		if !ok {
			return nil, fmt.Errorf("gateway: config: chain %q: asset %q has no policy", name, sym)
		}
		pol, err := af.build(name+"/"+sym, enabledApprovers, v.Canonical)
		if err != nil {
			return nil, err
		}
		assets[sym] = pol
	}
	return &ChainConfig{Name: name, Family: FamilySOL, SOL: sc, Assets: assets,
		SweepsPerHour: cf.SweepsPerHour, WithdrawalsPerHour: cf.WithdrawalsPerHour, CancelsPerHour: cf.CancelsPerHour,
		ToColdPerHour: cf.ToColdPerHour, RebalancePerHour: cf.RebalancePerHour, ConsolidationsPerHour: cf.ConsolidationsPerHour}, nil
}

// checkDepositSigner validates an ed25519-2of3 signer entry: the hot keyset's 32-byte public key and the optional deposit key tree.
func checkDepositSigner(p string, sf SignerFile) error {
	if pk, err := hex.DecodeString(sf.PublicKey); err != nil || len(pk) != 32 {
		return fmt.Errorf("gateway: config: signer %q: an ed25519-2of3 signer's public_key is 32 bytes of hex", p)
	}
	if d := sf.Deposit; d != nil {
		if d.KeysetID == "" || len(d.HardenedPath) == 0 || d.MPC == nil || d.MPC.Address == "" || d.MPC.CertFile == "" || d.MPC.KeyFile == "" || d.MPC.ServerPin == "" ||
			d.KeyID != "" || d.PublicKey != "" || d.Scheme != "" || len(d.Coordinators) > 0 || d.Deposit != nil {
			return fmt.Errorf("gateway: config: signer %q: deposit needs keyset_id, hardened_path and mpc.{address,cert_file,key_file,server_pin}, and nothing else", p)
		}
		if fmt.Sprint(d.HardenedPath) != fmt.Sprint(sol.AccountPath()) {
			return fmt.Errorf("gateway: config: signer %q: deposit hardened_path %v is not the account path %v", p, d.HardenedPath, sol.AccountPath())
		}
	}
	return nil
}
