// Package custody is the business core of the closed loop: the chart of
// accounts, the ledger flows for deposits, sweeps and withdrawals, balance
// reconciliation against the chain, and the HTTP API. It holds no key.
// Temporal workflows (internal/workflow) only orchestrate calls into it.
package custody

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// Chain families.
const (
	FamilyEVM = "evm"
	FamilyBTC = "btc"
	FamilySOL = "sol"
)

// File is the JSON form of Config. Amounts are canonical decimal strings,
// durations are Go duration strings.
type File struct {
	Comment    string         `json:"_comment,omitempty"`
	Entity     string         `json:"entity"` // default "qv-us"
	Chain      ChainFile      `json:"chain"`
	Sweep      SweepFile      `json:"sweep"`
	Withdrawal WithdrawalFile `json:"withdrawal"`
	Scan       ScanFile       `json:"scan"`
	Cold       ColdFile       `json:"cold"`
	Reconcile  ReconcileFile  `json:"reconcile"`
}

// ReconcileFile configures Reconcile.
type ReconcileFile struct {
	// MaxSkip is how long the chain comparisons may be skipped (a block kept arriving during each read) before an ALERT is raised. Default 15m.
	MaxSkip string `json:"max_skip"`
}

// ColdFile configures hot-to-cold moves. Without addresses and limits nothing is moved. The business config's copy of the
// cold addresses only decides where the move transaction is built to; the signing zone has its own copy and refuses a
// move to any other address.
type ColdFile struct {
	// Addresses: "<pool>/native" or "<pool>/token" -> the cold address (the same keys as the signing zone's cold_addresses).
	Addresses map[string]string `json:"addresses"`
	// Limits per asset, applied to every hot shard: Low raises an ALERT (the refill is a later task), High triggers a move, and
	// the move brings the shard down to Target (default: halfway between Low and High). Base units.
	Limits map[string]LimitFile `json:"limits"`
	// ShardLimits overrides Limits for one shard: key "<asset>/<shard index>".
	ShardLimits  map[string]LimitFile `json:"shard_limits"`
	PlanInterval string               `json:"plan_interval"` // default 5s
	Refill       RefillFile           `json:"refill"`
	// Rebalance configures moves between the hot shards of a pool.
	Rebalance RebalanceFile `json:"rebalance"`
}

// RebalanceFile configures the rebalance of hot shards. Without targets nothing is moved.
type RebalanceFile struct {
	// Targets: what a shard should hold, per asset ("ETH": applies to every shard) or per shard ("ETH/1": overrides). Base units.
	// A shard below its target receives from the fullest shard, if that holds more than its own target. With cold limits the target
	// must lie between the shard's low-water mark and its cold target (see docs/learn/p6-4-shard-rebalance.md).
	Targets map[string]string `json:"targets"`
}

// RefillFile configures refills (cold to hot, through an offline ceremony).
type RefillFile struct {
	TokenGas   uint64 `json:"token_gas"`   // gas limit written into a token refill request, default 90000
	StuckAfter string `json:"stuck_after"` // ALERT when a broadcast refill has not confirmed after this, default 30m
	Poll       string `json:"poll"`        // how often the refill workflow looks for the imported file, default 15s
	// RequestTTL: a Bitcoin refill request that is not imported within this ends (nothing was reserved), default 24h.
	RequestTTL string `json:"request_ttl"`
}

// LimitFile is the low-water mark, high-water mark and target of one hot partition.
type LimitFile struct {
	Low    string `json:"low"`
	High   string `json:"high"`
	Target string `json:"target"`
}

// HotLimits is a validated LimitFile.
type HotLimits struct{ Low, High, Target *big.Int }

// ChainFile configures the one EVM chain this core serves.
type ChainFile struct {
	// Family names the kind of chain: which adapter and reader a process opens for it (internal/chainfactory). Default
	// "evm". An unknown family refuses to start. The fields below are those of the evm family.
	Family string `json:"family,omitempty"`
	// BTC is the section of the btc family; the evm fields below are not read for it.
	BTC *BTCFile `json:"btc,omitempty"`
	// SOL is the section of the sol family (Solana); the evm fields below are not read for it.
	SOL              *SOLFile             `json:"sol,omitempty"`
	Name             string               `json:"name"`
	ChainID          uint64               `json:"chain_id"`
	RPCURL           string               `json:"rpc_url"`
	Confirmations    uint64               `json:"confirmations"`
	Factory          string               `json:"factory"`
	SweepDestination string               `json:"sweep_destination"` // must be a hot shard address (the factory pays it)
	HotShards        []string             `json:"hot_shards"`        // shard i = HotShards[i]
	NativeAsset      string               `json:"native_asset"`      // default "ETH"
	MaxTxFeeWei      string               `json:"max_tx_fee_wei"`
	StuckAfterBlocks uint64               `json:"stuck_after_blocks"`
	Assets           map[string]AssetFile `json:"assets"`
}

// AssetFile is one asset. Address is empty for the native asset.
type AssetFile struct {
	Address    string `json:"address"`
	Decimals   int    `json:"decimals"`
	MinDeposit string `json:"min_deposit"` // base units; below it a deposit goes to suspense
	// PriceWei is the value of one base unit in wei: the fixed price table the
	// sweep rule compares in. The native asset is 1.
	PriceWei string `json:"price_wei"`
}

// SweepFile configures the sweep rule.
type SweepFile struct {
	K            int    `json:"k"`             // fee multiple, PLAN says 20-50
	MinSweepWei  string `json:"min_sweep_wei"` // floor of the rule, in wei value
	PlanInterval string `json:"plan_interval"` // how often the planner runs, default 5s
	// RetryAfter is how long the planner leaves an address alone after a sweep of it failed (a refusal by the gateway, for example its rate limit),
	// doubling for each failure in a row up to an hour. Default 1m. Bitcoin only.
	RetryAfter string `json:"retry_after"`
}

// WithdrawalFile configures withdrawals.
type WithdrawalFile struct {
	ApprovalWindow  string `json:"approval_window"`  // intent validity, default 1h (NotAfter = request time + this)
	ApprovalTimeout string `json:"approval_timeout"` // how long to wait for approvals, default = approval_window minus 5m
	SignTimeout     string `json:"sign_timeout"`     // gateway sign_timeout; wait this long before re-enqueueing a failed job
	StuckAfter      string `json:"stuck_after"`      // replace a broadcast tx that has not mined after this, default 2m
	HotWait         string `json:"hot_wait"`         // give up waiting for hot liquidity after this, default 30m
	MaxReplacements int    `json:"max_replacements"` // default 5
	// ActivityTimeout, when set, shortens how long the workflow engine waits before it notices an activity died with its worker
	// (production: 20 s to run, 30 s for a build). For tests that kill the worker; leave it empty in production.
	ActivityTimeout string `json:"activity_timeout"`
	// Tiers are the business zone's advisory copy of the gateway's approval
	// tiers (the gateway is the authority): how many approvals an amount needs
	// and whether the worker's automated key may supply them.
	Tiers map[string][]TierFile `json:"tiers"` // asset -> ascending tiers
}

// TierFile: amounts >= MinAmount need Approvals distinct approvals. Auto: the
// worker's automated key approves on its own (the lowest tier only).
type TierFile struct {
	MinAmount string `json:"min_amount"`
	Approvals int    `json:"approvals"`
	Auto      bool   `json:"auto"`
}

// ScanFile configures the deposit scanner.
type ScanFile struct {
	Interval    string `json:"interval"`     // default 2s
	StartHeight uint64 `json:"start_height"` // first height ever scanned
}

// Config is the validated form of File.
type Config struct {
	Entity string
	Family string // FamilyEVM or FamilyBTC
	EVM    evm.Config
	BTC    btc.Config // the btc family
	SOL    sol.Config // the sol family
	SOLHot []string   // the sol family: the hot shard addresses in shard order
	// SweepBatch and CloseQuiet: see SOLFile.
	SweepBatch int
	CloseQuiet time.Duration
	Chain      string
	Native     string

	HotShards []common.Address
	SinkShard int
	Assets    map[string]Asset
	AssetList []string // sorted

	SweepK           int
	SweepRetryAfter  time.Duration
	ReconcileMaxSkip time.Duration
	MinSweepWei      *big.Int
	PlanInterval     time.Duration

	ApprovalWindow  time.Duration
	ApprovalTimeout time.Duration
	SignTimeout     time.Duration
	StuckAfter      time.Duration
	HotWait         time.Duration
	MaxReplacements int
	Tiers           map[string][]Tier

	ScanInterval time.Duration
	StartHeight  uint64

	// Cold: limits per hot partition ID; empty when hot-to-cold is not configured.
	ActivityTimeout  time.Duration // 0 = the workflows' production activity timeouts
	ColdLimits       map[string]HotLimits
	ColdPlanInterval time.Duration
	// RebalanceTargets: the target per hot partition ID; empty when rebalance is not configured.
	RebalanceTargets map[string]*big.Int
	RefillTokenGas   uint64
	RefillStuckAfter time.Duration
	RefillPoll       time.Duration
	RefillRequestTTL time.Duration
}

// Asset is a configured asset.
type Asset struct {
	Symbol     string
	Address    common.Address // zero for native (EVM tokens)
	Mint       string         // the mint address of a Solana token; empty otherwise
	Decimals   int
	MinDeposit *big.Int
	PriceWei   *big.Int
}

// Native reports whether the asset is the chain's native one.
func (a Asset) Native() bool { return a.Address == (common.Address{}) && a.Mint == "" }

// Tier is a validated approval tier.
type Tier struct {
	Min       *big.Int
	Approvals int
	Auto      bool
}

// LoadConfig reads and validates a JSON config file. Unknown fields are errors.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("custody: read config: %w", err)
	}
	return ParseConfig(b)
}

// ParseConfig validates JSON config bytes.
func ParseConfig(b []byte) (*Config, error) {
	var f File
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("custody: config: %w", err)
	}
	return f.Build()
}

func dur(what, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("custody: config: %s %q is not a positive duration", what, s)
	}
	return d, nil
}

func amount(what, s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || s != n.String() {
		return nil, fmt.Errorf("custody: config: %s %q is not a canonical non-negative decimal", what, s)
	}
	return n, nil
}

// BTCFile is the btc family's section of the business config. The core holds only the account's public key.
type BTCFile struct {
	Network       string   `json:"network"` // regtest, testnet3, signet or mainnet
	RPCURL        string   `json:"rpc_url"`
	RPCUser       string   `json:"rpc_user"`
	RPCPassword   string   `json:"rpc_password"`
	Confirmations uint64   `json:"confirmations"` // default 6
	AccountXpub   string   `json:"account_xpub"`  // m/84'/coin'/0', from mpc-party Node
	HotAddresses  []string `json:"hot_addresses"`
	BatchBlocks   uint64   `json:"batch_blocks"` // blocks per scan call, default 100
	// HotShards are the hot addresses in shard order with the path of each key below the account (shard i serves the partition of shard i). The
	// core derives each address from the xpub at start and refuses one that does not match.
	HotShards []BTCShardFile `json:"hot_shards"`
	// SpendConfirmations is the depth at which a withdrawal settles (default 2). MaxInputs, FallbackFeeRate, MaxFeeRate (sat/vB) and
	// MaxTxFeeSats bound what the builder makes, and must stay below the signing zone's own caps.
	SpendConfirmations uint64 `json:"spend_confirmations"`
	MaxInputs          int    `json:"max_inputs"`
	FallbackFeeRate    uint64 `json:"fallback_fee_rate"`
	MaxFeeRate         uint64 `json:"max_fee_rate"`
	MaxTxFeeSats       uint64 `json:"max_tx_fee_sats"`
	// SweepMaxFeeRate (sat/vB) is the most a routine sweep pays (default max_fee_rate); SweepUrgentValue (sats) is the amount from which a sweep
	// goes regardless, up to max_fee_rate. Both are checked at start.
	SweepMaxFeeRate  uint64 `json:"sweep_max_fee_rate"`
	SweepUrgentValue uint64 `json:"sweep_urgent_value"`
	// ConsolidateAbove is how many available outputs a hot shard may hold before its small ones are merged into one; 0 turns consolidation off.
	// When on it must exceed max_inputs. ConsolidateMaxFeeRate (sat/vB) is the most a consolidation pays: above it the merge waits; it must be
	// positive and not above sweep_max_fee_rate.
	ConsolidateAbove      int    `json:"consolidate_above"`
	ConsolidateMaxFeeRate uint64 `json:"consolidate_max_fee_rate"`
}

// BTCShardFile is one hot shard of the btc family.
type BTCShardFile struct {
	Address string   `json:"address"`
	Path    []uint32 `json:"path"` // [1, index]
}

// SOLFile is the sol family's section of the business config. The core holds only the account node (public key and chain code).
type SOLFile struct {
	Network          string `json:"network"` // localnet, devnet, testnet or mainnet
	RPCURL           string `json:"rpc_url"`
	AccountPublicKey string `json:"account_public_key"` // hex, m/44'/501'/0' from mpc-party Node
	AccountChainCode string `json:"account_chain_code"` // hex
	// HotShards are the hot shard addresses in shard order (a 2-of-3 Ed25519 keyset each; shard i serves the partitions of shard i).
	HotShards []string `json:"hot_shards"`
	// NoncePool is how many durable-nonce accounts each shard owns (one withdrawal in flight per account); NonceRentLamports is what each holds.
	NoncePool         int    `json:"nonce_pool"`
	NonceRentLamports uint64 `json:"nonce_rent_lamports"`
	// ComputeUnitLimit and ComputeUnitPrice (micro-lamports per unit) are what withdrawals are built with; a fee raise adds FeeBumpPercent to the
	// price, up to MaxMicroLamports (which must not exceed the signing zone's cap).
	ComputeUnitLimit uint32 `json:"compute_unit_limit"`
	ComputeUnitPrice uint64 `json:"compute_unit_price"`
	FeeBumpPercent   int    `json:"fee_bump_percent"`
	MaxMicroLamports uint64 `json:"max_micro_lamports"`
	// SweepBatch is how many deposit addresses of one asset a sweep takes at most (default 4; the transaction size bounds it: see the Solana page).
	// CloseQuietAfter: a token sweep also closes the deposit token account, rent to the hot shard, when the address has had no credited deposit of
	// that token for this long ("" or 0: never).
	SweepBatch      int    `json:"sweep_batch"`
	CloseQuietAfter string `json:"close_quiet_after"`
}

// buildSOL reads the sol family's section and its assets: SOL (no address) and classic SPL tokens (address = the mint).
func (c *Config) buildSOL(cf ChainFile) error {
	s := cf.SOL
	if s == nil {
		return errors.New("custody: config: family sol needs a chain.sol section")
	}
	c.SOL = sol.Config{Chain: cf.Name, Network: s.Network, RPCURL: s.RPCURL, AccountPublicKey: s.AccountPublicKey, AccountChainCode: s.AccountChainCode,
		Tokens: map[string]string{}, TokenDecimals: map[string]int{}, NoncePool: s.NoncePool, NonceRent: s.NonceRentLamports,
		ComputeUnitLimit: s.ComputeUnitLimit, ComputeUnitPrice: s.ComputeUnitPrice, FeeBumpPercent: s.FeeBumpPercent, MaxMicroLamports: s.MaxMicroLamports}
	c.SOLHot = append([]string(nil), s.HotShards...)
	c.SweepBatch = s.SweepBatch
	if c.SweepBatch == 0 {
		c.SweepBatch = 4
	}
	if max := sol.MaxBatch(true); c.SweepBatch < 1 || c.SweepBatch > max {
		return fmt.Errorf("custody: config: sweep_batch must be 1 to %d (what a token sweep that opens the hot account and closes every deposit account fits in one transaction)", max)
	}
	if s.CloseQuietAfter != "" {
		d, err := time.ParseDuration(s.CloseQuietAfter)
		if err != nil || d < 0 {
			return fmt.Errorf("custody: config: close_quiet_after %q", s.CloseQuietAfter)
		}
		c.CloseQuiet = d
	}
	if c.Native != sol.Native {
		return fmt.Errorf("custody: config: family sol has the native asset %s", sol.Native)
	}
	af, ok := cf.Assets[sol.Native]
	if !ok || af.Address != "" || af.Decimals != sol.Decimals {
		return fmt.Errorf("custody: config: family sol needs the asset %s with no address and %d decimals", sol.Native, sol.Decimals)
	}
	for sym, a := range cf.Assets {
		min, err := amount(sym+" min_deposit", orZero(a.MinDeposit))
		if err != nil {
			return err
		}
		if sym != sol.Native {
			if a.Address == "" {
				return fmt.Errorf("custody: config: token %s needs its mint address", sym)
			}
			c.SOL.Tokens[sym], c.SOL.TokenDecimals[sym] = a.Address, a.Decimals
		}
		price := big.NewInt(1)
		if a.PriceWei != "" {
			if price, err = amount(sym+" price_wei", a.PriceWei); err != nil {
				return err
			}
		}
		c.Assets[sym] = Asset{Symbol: sym, Mint: a.Address, Decimals: a.Decimals, MinDeposit: min, PriceWei: price}
		c.AssetList = append(c.AssetList, sym)
	}
	sort.Strings(c.AssetList)
	// Every asset's partition of shard i is served by the one hot address of shard i.
	c.SOL.HotShards = map[string]string{}
	for i, h := range s.HotShards {
		for _, sym := range c.AssetList {
			c.SOL.HotShards[c.PartitionKey(sym, i).String()] = h
		}
	}
	if err := c.SOL.Validate(); err != nil {
		return fmt.Errorf("custody: config: %w", err)
	}
	c.SinkShard = 0
	return nil
}

// buildBTC reads the btc family's section and its assets (the native one only: bitcoin has no tokens here). It refuses a key or
// address that belongs to another network than the config names.
func (c *Config) buildBTC(cf ChainFile) error {
	b := cf.BTC
	if b == nil {
		return errors.New("custody: config: family btc needs a chain.btc section")
	}
	c.BTC = btc.Config{Chain: cf.Name, Network: b.Network, RPCURL: b.RPCURL, RPCUser: b.RPCUser, RPCPass: b.RPCPassword,
		Confirmations: b.Confirmations, AccountXpub: b.AccountXpub, HotAddresses: b.HotAddresses, BatchBlocks: b.BatchBlocks,
		SpendConfirmations: b.SpendConfirmations, MaxInputs: b.MaxInputs, FallbackFeeRate: b.FallbackFeeRate, MaxFeeRate: b.MaxFeeRate,
		MaxTxFeeSats: b.MaxTxFeeSats, SweepMaxFeeRate: b.SweepMaxFeeRate, SweepUrgentValue: b.SweepUrgentValue,
		ConsolidateAbove: b.ConsolidateAbove, ConsolidateMaxFeeRate: b.ConsolidateMaxFeeRate}
	for i, h := range b.HotShards {
		c.BTC.HotShards = append(c.BTC.HotShards, btc.HotShardConfig{PartitionID: c.PartitionKey(btc.Native, i).String(), Address: h.Address, Path: h.Path})
	}
	if err := c.BTC.Validate(); err != nil {
		return fmt.Errorf("custody: config: %w", err)
	}
	c.SinkShard = 0 // sweeps pay the first hot shard
	if len(cf.Assets) != 1 {
		return fmt.Errorf("custody: config: family btc has exactly one asset, %s", btc.Native)
	}
	af, ok := cf.Assets[btc.Native]
	if !ok || af.Address != "" || c.Native != btc.Native {
		return fmt.Errorf("custody: config: family btc has exactly one asset, %s, with no address", btc.Native)
	}
	if af.Decimals != btc.Decimals {
		return fmt.Errorf("custody: config: %s has %d decimals", btc.Native, btc.Decimals)
	}
	min, err := amount(btc.Native+" min_deposit", orZero(af.MinDeposit))
	if err != nil {
		return err
	}
	// PriceWei 1: the sweep rule compares in the chain's own smallest unit (satoshis here), so min_sweep_wei is satoshis for this family.
	c.Assets[btc.Native] = Asset{Symbol: btc.Native, Decimals: btc.Decimals, MinDeposit: min, PriceWei: big.NewInt(1)}
	c.AssetList = []string{btc.Native}
	return nil
}

// Build validates f.
func (f File) Build() (*Config, error) {
	c := &Config{Entity: f.Entity, Chain: f.Chain.Name, Native: f.Chain.NativeAsset, Assets: map[string]Asset{}, Tiers: map[string][]Tier{}}
	if c.Entity == "" {
		c.Entity = "qv-us"
	}
	if c.Native == "" {
		c.Native = evm.DefaultNativeAsset
	}
	cf := f.Chain
	switch cf.Family {
	case "", FamilyEVM:
		c.Family = FamilyEVM
	case FamilyBTC:
		c.Family = FamilyBTC
		if f.Chain.NativeAsset == "" {
			c.Native = btc.Native
		}
	case FamilySOL:
		c.Family = FamilySOL
		if f.Chain.NativeAsset == "" {
			c.Native = sol.Native
		}
	default:
		return nil, fmt.Errorf("custody: config: unknown chain family %q (known: %s, %s, %s)", cf.Family, FamilyEVM, FamilyBTC, FamilySOL)
	}
	if cf.Name == "" || strings.ContainsAny(cf.Name, ":/") {
		return nil, errors.New("custody: config: chain name must be non-empty and contain no ':' or '/'")
	}
	var hot map[string]common.Address
	var err error
	switch c.Family {
	case FamilyBTC:
		err = c.buildBTC(cf)
	case FamilySOL:
		err = c.buildSOL(cf)
	default:
		hot, err = c.buildEVM(cf)
	}
	if err != nil {
		return nil, err
	}

	s := f.Sweep
	c.SweepK = s.K
	if c.SweepK <= 0 {
		c.SweepK = 20
	}
	if c.MinSweepWei, err = amount("min_sweep_wei", orZero(s.MinSweepWei)); err != nil {
		return nil, err
	}
	if c.PlanInterval, err = dur("plan_interval", s.PlanInterval, 5*time.Second); err != nil {
		return nil, err
	}
	if c.SweepRetryAfter, err = dur("retry_after", s.RetryAfter, time.Minute); err != nil {
		return nil, err
	}
	if c.ReconcileMaxSkip, err = dur("reconcile max_skip", f.Reconcile.MaxSkip, 15*time.Minute); err != nil {
		return nil, err
	}
	if c.Family == FamilyBTC {
		c.BTC.SweepK = uint64(c.SweepK)
		if c.MinSweepWei.IsUint64() {
			c.BTC.MinSweep = c.MinSweepWei.Uint64()
		}
	}

	w := f.Withdrawal
	if c.ApprovalWindow, err = dur("approval_window", w.ApprovalWindow, time.Hour); err != nil {
		return nil, err
	}
	defTimeout := c.ApprovalWindow - 5*time.Minute
	if defTimeout <= 0 {
		defTimeout = c.ApprovalWindow / 2
	}
	if c.ApprovalTimeout, err = dur("approval_timeout", w.ApprovalTimeout, defTimeout); err != nil {
		return nil, err
	}
	if c.ApprovalTimeout >= c.ApprovalWindow {
		return nil, errors.New("custody: config: approval_timeout must be shorter than approval_window")
	}
	if c.SignTimeout, err = dur("sign_timeout", w.SignTimeout, 30*time.Second); err != nil {
		return nil, err
	}
	if c.StuckAfter, err = dur("stuck_after", w.StuckAfter, 2*time.Minute); err != nil {
		return nil, err
	}
	if c.HotWait, err = dur("hot_wait", w.HotWait, 30*time.Minute); err != nil {
		return nil, err
	}
	if w.ActivityTimeout != "" {
		if c.ActivityTimeout, err = dur("activity_timeout", w.ActivityTimeout, 0); err != nil {
			return nil, err
		}
	}
	c.MaxReplacements = w.MaxReplacements
	if c.MaxReplacements <= 0 {
		c.MaxReplacements = 5
	}
	for _, sym := range c.AssetList {
		tf := w.Tiers[sym]
		if len(tf) == 0 {
			tf = []TierFile{{MinAmount: "0", Approvals: 1, Auto: true}}
		}
		prev := big.NewInt(-1)
		for i, t := range tf {
			m, err := amount(fmt.Sprintf("%s tier %d min_amount", sym, i), t.MinAmount)
			if err != nil {
				return nil, err
			}
			if (i == 0 && m.Sign() != 0) || m.Cmp(prev) <= 0 || t.Approvals < 1 {
				return nil, fmt.Errorf("custody: config: bad tiers for %s", sym)
			}
			if t.Auto && i != 0 {
				return nil, fmt.Errorf("custody: config: %s: only the lowest tier may be auto-approved", sym)
			}
			prev = m
			c.Tiers[sym] = append(c.Tiers[sym], Tier{Min: m, Approvals: t.Approvals, Auto: t.Auto})
		}
	}
	if c.ScanInterval, err = dur("scan interval", f.Scan.Interval, 2*time.Second); err != nil {
		return nil, err
	}
	c.StartHeight = f.Scan.StartHeight
	if err := c.buildCold(f.Cold, hot); err != nil {
		return nil, err
	}
	if err := c.buildRebalance(f.Cold.Rebalance); err != nil {
		return nil, err
	}
	return c, nil
}

// buildEVM reads the evm family's fields: hot shards, factory, sweep destination, assets (with their tokens). It returns the hot
// address of every (asset, shard) partition.
func (c *Config) buildEVM(cf ChainFile) (map[string]common.Address, error) {
	if len(cf.HotShards) == 0 {
		return nil, errors.New("custody: config: at least one hot shard")
	}
	for i, a := range cf.HotShards {
		if !common.IsHexAddress(a) {
			return nil, fmt.Errorf("custody: config: hot shard %d %q is not an address", i, a)
		}
		c.HotShards = append(c.HotShards, common.HexToAddress(a))
	}
	if !common.IsHexAddress(cf.Factory) || !common.IsHexAddress(cf.SweepDestination) {
		return nil, errors.New("custody: config: factory and sweep_destination must be addresses")
	}
	dest := common.HexToAddress(cf.SweepDestination)
	c.SinkShard = -1
	for i, a := range c.HotShards {
		if a == dest {
			c.SinkShard = i
			break
		}
	}
	if c.SinkShard < 0 {
		return nil, errors.New("custody: config: sweep_destination must be one of hot_shards (swept funds land on a hot wallet)")
	}
	var err error
	fee, err := amount("max_tx_fee_wei", cf.MaxTxFeeWei)
	if err != nil {
		return nil, err
	}
	if len(cf.Assets) == 0 {
		return nil, errors.New("custody: config: no assets")
	}
	evmAssets := map[string]evm.Token{}
	for sym, af := range cf.Assets {
		if sym == "" || strings.ContainsAny(sym, ":/") {
			return nil, fmt.Errorf("custody: config: bad asset symbol %q", sym)
		}
		a := Asset{Symbol: sym, Decimals: af.Decimals}
		if af.Address != "" {
			if !common.IsHexAddress(af.Address) {
				return nil, fmt.Errorf("custody: config: asset %s address %q", sym, af.Address)
			}
			a.Address = common.HexToAddress(af.Address)
			evmAssets[sym] = evm.Token{Address: a.Address, Decimals: uint8(af.Decimals)}
		} else if sym != c.Native {
			return nil, fmt.Errorf("custody: config: asset %s has no address and is not the native asset %s", sym, c.Native)
		}
		if a.MinDeposit, err = amount(sym+" min_deposit", orZero(af.MinDeposit)); err != nil {
			return nil, err
		}
		if a.PriceWei, err = amount(sym+" price_wei", orZero(af.PriceWei)); err != nil {
			return nil, err
		}
		if a.PriceWei.Sign() == 0 {
			return nil, fmt.Errorf("custody: config: asset %s needs price_wei > 0", sym)
		}
		c.Assets[sym] = a
		c.AssetList = append(c.AssetList, sym)
	}
	sort.Strings(c.AssetList)
	if _, ok := c.Assets[c.Native]; !ok {
		return nil, fmt.Errorf("custody: config: native asset %s is not configured", c.Native)
	}
	// Each (asset, shard) is a partition; the hot address is the shard's.
	hot := map[string]common.Address{}
	for _, sym := range c.AssetList {
		for i, a := range c.HotShards {
			hot[c.PartitionKey(sym, i).String()] = a
		}
	}
	c.EVM = evm.Config{
		Chain: cf.Name, ChainID: cf.ChainID, RPCURL: cf.RPCURL, Confirmations: cf.Confirmations,
		Factory: common.HexToAddress(cf.Factory), SweepDestination: dest, HotAddresses: hot,
		Assets: evmAssets, NativeAsset: c.Native, MaxTxFeeWei: fee, StuckAfterBlocks: cf.StuckAfterBlocks,
	}
	return hot, nil
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// PartitionKey is the partition of (asset, shard): hot, omnibus.
func (c *Config) PartitionKey(asset string, shard int) partition.Key {
	return partition.Key{Entity: c.Entity, Chain: c.Chain, Asset: asset, Tier: partition.TierHot, Pool: partition.PoolOmnibus, Shard: shard}
}

// ColdAddressOf is the cold address of a partition's pool and asset, for any family, in the form the family's chain cell takes (an evm address in
// hex, a canonical bitcoin address).
func (c *Config) ColdAddressOf(partitionID, asset string) (string, error) {
	if c.Family == FamilySOL {
		k, err := partition.Parse(partitionID)
		if err != nil {
			return "", err
		}
		a, ok := c.SOL.ColdAddresses[string(k.Pool)]
		if !ok {
			return "", fmt.Errorf("custody: no cold address for pool %q", k.Pool)
		}
		return a, nil
	}
	if c.Family == FamilyBTC {
		k, err := partition.Parse(partitionID)
		if err != nil {
			return "", err
		}
		a, ok := c.BTC.ColdAddresses[string(k.Pool)+"/native"]
		if !ok {
			return "", fmt.Errorf("custody: no cold address for pool %q", k.Pool)
		}
		return btc.CanonicalAddress(c.BTC.Network, a)
	}
	a, err := c.EVM.ColdAddress(partitionID, asset)
	return a.Hex(), err
}

// BTCShardAddress is the canonical address of the hot shard that serves a partition of the btc family.
func (c *Config) BTCShardAddress(partitionID string) (string, error) {
	for _, h := range c.BTC.HotShards {
		if h.PartitionID == partitionID {
			return btc.CanonicalAddress(c.BTC.Network, h.Address)
		}
	}
	return "", fmt.Errorf("custody: partition %q has no hot shard", partitionID)
}

// SinkPartition is where swept funds of asset land.
func (c *Config) SinkPartition(asset string) string {
	return c.PartitionKey(asset, c.SinkShard).String()
}

// ShardAddress returns the hot address of a partition ID.
func (c *Config) ShardAddress(partitionID string) (common.Address, int, error) {
	k, err := partition.Parse(partitionID)
	if err != nil {
		return common.Address{}, 0, err
	}
	if k.Chain != c.Chain || k.Shard >= len(c.HotShards) {
		return common.Address{}, 0, fmt.Errorf("custody: unknown partition %q", partitionID)
	}
	return c.HotShards[k.Shard], k.Shard, nil
}

// ShardAddressOf is the hot address of a partition's shard in the form the family's chain cell takes, and the shard's index.
func (c *Config) ShardAddressOf(partitionID string) (string, int, error) {
	switch c.Family {
	case FamilySOL:
		i, err := c.ShardIndex(partitionID)
		if err != nil {
			return "", 0, err
		}
		return c.SOLHot[i], i, nil
	case FamilyBTC:
		i, err := c.ShardIndex(partitionID)
		if err != nil {
			return "", 0, err
		}
		a, err := c.BTCShardAddress(partitionID)
		return a, i, err
	}
	a, i, err := c.ShardAddress(partitionID)
	return a.Hex(), i, err
}

// NativeReserve is the native balance a hot shard needs to pay the fee of a token transaction, and what a rebalance or refill of a token checks.
func (c *Config) NativeReserve() *big.Int {
	if c.Family == FamilySOL {
		// the worst-case priority fee and the base fee of two signatures, plus the rent of a token account the transaction may open
		fee := new(big.Int).Mul(new(big.Int).SetUint64(uint64(c.SOL.ComputeUnitLimit)), new(big.Int).SetUint64(c.SOL.MaxMicroLamports))
		fee.Div(fee, big.NewInt(1_000_000))
		return fee.Add(fee, big.NewInt(10_000+2_039_280))
	}
	return c.EVM.MaxTxFeeWei
}

// Required returns the approvals an amount of asset needs and whether the
// automated key may supply them.
func (c *Config) Required(asset string, amount *big.Int) (n int, auto bool) {
	for _, t := range c.Tiers[asset] {
		if amount.Cmp(t.Min) >= 0 {
			n, auto = t.Approvals, t.Auto
		}
	}
	return n, auto
}

func (c *Config) buildCold(cf ColdFile, hot map[string]common.Address) error {
	var err error
	if c.ColdPlanInterval, err = dur("cold plan_interval", cf.PlanInterval, 5*time.Second); err != nil {
		return err
	}
	c.RefillTokenGas = cf.Refill.TokenGas
	if c.RefillTokenGas == 0 {
		c.RefillTokenGas = 90000
	}
	if c.RefillStuckAfter, err = dur("cold refill stuck_after", cf.Refill.StuckAfter, 30*time.Minute); err != nil {
		return err
	}
	if c.RefillRequestTTL, err = dur("cold refill request_ttl", cf.Refill.RequestTTL, 24*time.Hour); err != nil {
		return err
	}
	if c.RefillPoll, err = dur("cold refill poll", cf.Refill.Poll, 15*time.Second); err != nil {
		return err
	}
	if len(cf.Addresses) == 0 && len(cf.Limits) == 0 && len(cf.ShardLimits) == 0 {
		return nil
	}
	if c.Family == FamilySOL {
		// One cold key per pool: its address owns the pool's SOL and its token accounts. The signing zone pins the same addresses.
		c.SOL.ColdAddresses = map[string]string{}
		for pool, a := range cf.Addresses {
			raw, err := sol.ParseAddress(a)
			if err != nil {
				return fmt.Errorf("custody: config: cold address of pool %q: %w", pool, err)
			}
			for _, h := range c.SOLHot {
				if h == a {
					return fmt.Errorf("custody: config: the cold address of pool %q is a hot shard", pool)
				}
			}
			c.SOL.ColdAddresses[pool] = sol.Address(raw)
		}
	} else if c.Family == FamilyBTC {
		c.BTC.ColdAddresses = map[string]string{}
		for k, a := range cf.Addresses {
			c.BTC.ColdAddresses[k] = a
		}
		if err := c.BTC.Validate(); err != nil { // the cold addresses belong to the network and are not hot shards
			return fmt.Errorf("custody: config: %w", err)
		}
	} else {
		c.EVM.ColdAddresses = map[string]common.Address{}
		for k, a := range cf.Addresses {
			if !common.IsHexAddress(a) {
				return fmt.Errorf("custody: config: cold address %q is not an address", k)
			}
			c.EVM.ColdAddresses[k] = common.HexToAddress(a)
		}
	}
	parse := func(where string, lf LimitFile) (HotLimits, error) {
		var l HotLimits
		var err error
		if l.Low, err = amount(where+" low", orZero(lf.Low)); err != nil {
			return l, err
		}
		if l.High, err = amount(where+" high", lf.High); err != nil {
			return l, err
		}
		if l.High.Sign() == 0 || l.High.Cmp(l.Low) <= 0 {
			return l, fmt.Errorf("custody: config: %s: need 0 <= low < high", where)
		}
		if lf.Target == "" {
			l.Target = new(big.Int).Rsh(new(big.Int).Add(l.Low, l.High), 1)
		} else if l.Target, err = amount(where+" target", lf.Target); err != nil {
			return l, err
		}
		if l.Target.Cmp(l.Low) < 0 || l.Target.Cmp(l.High) >= 0 {
			return l, fmt.Errorf("custody: config: %s: need low <= target < high", where)
		}
		return l, nil
	}
	c.ColdLimits = map[string]HotLimits{}
	for _, sym := range c.AssetList {
		for i := 0; i < c.shardCount(); i++ {
			lf, ok := cf.ShardLimits[fmt.Sprintf("%s/%d", sym, i)]
			if !ok {
				if lf, ok = cf.Limits[sym]; !ok {
					continue
				}
			}
			p := c.PartitionKey(sym, i).String()
			if c.ColdLimits[p], err = parse("cold limits of "+p, lf); err != nil {
				return err
			}
			if _, err := c.ColdAddressOf(p, sym); err != nil {
				return fmt.Errorf("custody: config: %s has limits but no cold address: %w", p, err)
			}
		}
	}
	for k := range cf.Limits {
		if _, ok := c.Assets[k]; !ok {
			return fmt.Errorf("custody: config: cold limits for unknown asset %q", k)
		}
	}
	_ = hot
	return nil
}

func (c *Config) shardCount() int {
	if c.Family == FamilyBTC {
		return len(c.BTC.HotShards)
	}
	if c.Family == FamilySOL {
		return len(c.SOLHot)
	}
	return len(c.HotShards)
}

// ShardIndex is the shard of a partition ID of this chain, for any family.
func (c *Config) ShardIndex(partitionID string) (int, error) {
	k, err := partition.Parse(partitionID)
	if err != nil {
		return 0, err
	}
	if k.Chain != c.Chain || k.Shard >= c.shardCount() {
		return 0, fmt.Errorf("custody: unknown partition %q", partitionID)
	}
	return k.Shard, nil
}

// buildRebalance validates the targets. Every shard of an asset needs one (a partial list would starve the shards left out), there
// must be a second shard to move to, and with cold limits the target must lie in low <= target <= cold target, which is what keeps
// a rebalance and a move to cold from undoing each other.
func (c *Config) buildRebalance(rf RebalanceFile) error {
	if len(rf.Targets) == 0 {
		return nil
	}
	if c.shardCount() < 2 {
		return errors.New("custody: config: rebalance targets need at least two hot shards")
	}
	c.RebalanceTargets = map[string]*big.Int{}
	for k, v := range rf.Targets {
		sym, shard, hasShard := strings.Cut(k, "/")
		if _, ok := c.Assets[sym]; !ok {
			return fmt.Errorf("custody: config: rebalance target for unknown asset %q", k)
		}
		if hasShard {
			i, err := strconv.Atoi(shard)
			if err != nil || i < 0 || i >= c.shardCount() {
				return fmt.Errorf("custody: config: rebalance target %q: shard must be 0..%d", k, c.shardCount()-1)
			}
		}
		if _, err := amount("rebalance target "+k, v); err != nil {
			return err
		}
	}
	for _, sym := range c.AssetList {
		_, all := rf.Targets[sym]
		anyShard := false
		for i := 0; i < c.shardCount(); i++ {
			if _, ok := rf.Targets[fmt.Sprintf("%s/%d", sym, i)]; ok {
				anyShard = true
			}
		}
		for i := 0; i < c.shardCount(); i++ {
			v, ok := rf.Targets[fmt.Sprintf("%s/%d", sym, i)]
			if !ok {
				v, ok = rf.Targets[sym]
			}
			if !ok {
				if all || anyShard {
					return fmt.Errorf("custody: config: rebalance: %s has no target for shard %d", sym, i)
				}
				continue
			}
			t, _ := amount("rebalance target", v)
			p := c.PartitionKey(sym, i).String()
			if lim, ok := c.ColdLimits[p]; ok && (t.Cmp(lim.Low) < 0 || t.Cmp(lim.Target) > 0) {
				return fmt.Errorf("custody: config: rebalance target %s of %s must lie between its cold low-water mark %s and its cold target %s",
					t, p, lim.Low, lim.Target)
			}
			c.RebalanceTargets[p] = t
		}
	}
	return nil
}
