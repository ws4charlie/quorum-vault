package btc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// Adapter is the Bitcoin chain cell. Address derivation and deposit scanning work; everything that moves funds out returns
// chain.ErrNotSupported until the tasks that build it.
type Adapter struct {
	cfg    *validatedConfig
	rpc    *RPC
	pool   *pgxpool.Pool
	acct   *Account
	shards []shard           // in shard order
	byAddr map[string]shard  // canonical address -> shard
	cold   map[string]string // canonical cold address -> pool
	coldBy map[string]string // pool -> canonical cold address
	oldBy  map[string]string // pool -> canonical retiring cold address (a key replacement), also in cold

	view *FeeCapsView // the fee caps in force: the configured ones, or the newest signed change (feecaps.go)

	gs       genShards
	waitMu   sync.Mutex
	sweepWhy string // why sweeps are waiting now ("" when they are not), to log a change once
	// consolidateWhy is the same for consolidation.
	consolidateWhy string
}

// shard is one hot shard of the cell.
type shard struct {
	partition string
	address   string // canonical
	path      []uint32
	script    []byte
	gen       int // the generation of the account key it derives from (0 and 1: the configured one)
}

var _ chain.Adapter = (*Adapter)(nil)

// New validates cfg, connects to the node and refuses a node that is on another network than the config names.
func New(ctx context.Context, cfg Config, pool *pgxpool.Pool) (*Adapter, error) {
	v, err := cfg.validated()
	if err != nil {
		return nil, err
	}
	if cfg.RPCURL == "" {
		return nil, errors.New("btc: config: rpc_url is required")
	}
	if pool == nil {
		return nil, errors.New("btc: nil database pool")
	}
	a := &Adapter{cfg: v, rpc: NewRPC(cfg.RPCURL, cfg.RPCUser, cfg.RPCPass), pool: pool, acct: &Account{Params: v.params, key: v.account}, byAddr: map[string]shard{}, cold: map[string]string{}, coldBy: map[string]string{}, oldBy: map[string]string{}}
	a.acct.SetGenerationLoader(func(gen uint32) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		k, err := partition.DepositGeneration(ctx, pool, cfg.Chain, int(gen))
		if err != nil {
			return "", err
		}
		return k.Address, nil
	})
	for _, h := range v.HotShards {
		d, err := DecodeAddress(h.Address, v.params)
		if err != nil {
			return nil, err
		}
		script, err := OutputScript(h.Address, v.params)
		if err != nil {
			return nil, err
		}
		sh := shard{partition: h.PartitionID, address: d.Canonical, path: h.Path, script: script}
		a.shards = append(a.shards, sh)
		a.byAddr[sh.address] = sh
	}
	for k, addr := range v.ColdAddresses {
		d, err := DecodeAddress(addr, v.params)
		if err != nil {
			return nil, err
		}
		pool := strings.TrimSuffix(k, "/native")
		a.cold[d.Canonical], a.coldBy[pool] = pool, d.Canonical
	}
	for k, addr := range v.ColdRetiring {
		d, err := DecodeAddress(addr, v.params)
		if err != nil {
			return nil, err
		}
		pool := strings.TrimSuffix(k, "/native")
		a.cold[d.Canonical], a.oldBy[pool] = pool, d.Canonical
	}
	static := FeeCaps{MaxTxFeeSats: v.MaxTxFeeSats, MaxFeeRate: v.MaxFeeRate}
	if v.FeeCaps != nil {
		// the core keeps no approver list: it reads its own rows by shape, the zone judges the signatures (top of feecaps.go)
		a.view = NewFeeCapsView(static, &FeeCapsRules{Chain: v.Chain, StoreTrusted: true}, pool, func(n int) {
			slog.Error("ALERT btc fee caps: rows of the fee-cap table are malformed and are ignored", "chain", v.Chain, "rows", n)
		})
	} else {
		a.view = NewFeeCapsView(static, nil, nil, nil)
	}
	var info struct {
		Chain string `json:"chain"`
	}
	if err := a.rpc.Call(ctx, &info, "getblockchaininfo"); err != nil {
		return nil, fmt.Errorf("btc: node: %w", err)
	}
	if want := nodeChain(v.Network); info.Chain != want {
		return nil, fmt.Errorf("btc: node is on %q, config says network %s (%q)", info.Chain, v.Network, want)
	}
	return a, nil
}

// nodeChain is the name bitcoind gives a network in getblockchaininfo.
func nodeChain(network string) string {
	switch network {
	case "mainnet":
		return "main"
	case "testnet3":
		return "test"
	}
	return network
}

// Close releases nothing: the client keeps no connection of its own.
func (a *Adapter) Close() {}

// RPC exposes the node client (tests and the Reader).
func (a *Adapter) RPC() *RPC { return a.rpc }

// Chain returns the configured chain name.
func (a *Adapter) Chain() string { return a.cfg.Chain }

// DeriveDepositAddress is pure: the P2WPKH address at account/0/index from the account xpub. No RPC, no key, no MPC. The caller
// owns the index and hands out each once.
func (a *Adapter) DeriveDepositAddress(_ context.Context, customerID string, index uint64) (chain.DepositAddress, error) {
	if customerID == "" {
		return chain.DepositAddress{}, errors.New("btc: empty customer id")
	}
	if index >= 1<<31 {
		return chain.DepositAddress{}, fmt.Errorf("btc: derivation index %d is hardened", index)
	}
	addr, err := a.cfg.addressAt(uint32(index))
	if err != nil {
		return chain.DepositAddress{}, err
	}
	return chain.DepositAddress{Chain: a.cfg.Chain, Address: addr, Kind: chain.KindXpub, DerivationIndex: index, Asset: Native}, nil
}

// DepositIdentity is what the keyset registry records of the chain's deposit key tree at generation 1: the account xpub (the identity the addresses derive
// from) and the account's compressed public key. The hot shard addresses derive from the same account (branch 1), so the registry's deposit-tree entry and its
// hot shard entries name one key until the hot shards get their own (research/Key-replacement.md D1).
func DepositIdentity(network, accountXpub string) (identity string, pub []byte, err error) {
	acct, err := NewAccount(network, accountXpub)
	if err != nil {
		return "", nil, err
	}
	pk, err := acct.key.ECPubKey()
	if err != nil {
		return "", nil, err
	}
	return accountXpub, pk.SerializeCompressed(), nil
}

// DeriveDepositAddressAt is DeriveDepositAddress under the account key of a generation of the deposit tree (chain.GenerationDeriver). Generation 1 is the
// configured key: the same address as DeriveDepositAddress.
func (a *Adapter) DeriveDepositAddressAt(ctx context.Context, key chain.DepositKey, customerID string, index uint64) (chain.DepositAddress, error) {
	if key.Generation <= 1 {
		return a.DeriveDepositAddress(ctx, customerID, index)
	}
	if customerID == "" {
		return chain.DepositAddress{}, errors.New("btc: empty customer id")
	}
	if index >= 1<<31 {
		return chain.DepositAddress{}, fmt.Errorf("btc: derivation index %d is hardened", index)
	}
	acct, err := NewAccount(a.cfg.Network, key.Identity)
	if err != nil {
		return chain.DepositAddress{}, err
	}
	addr, err := acct.Address([]uint32{BranchDeposit, uint32(index)})
	if err != nil {
		return chain.DepositAddress{}, err
	}
	return chain.DepositAddress{Chain: a.cfg.Chain, Address: addr, Kind: chain.KindXpub, DerivationIndex: index, Asset: Native}, nil
}

var _ chain.GenerationDeriver = (*Adapter)(nil)

var errLater = fmt.Errorf("btc: %w (a later P7 task)", chain.ErrNotSupported)

// The Adapter is also the custody.Reader of the chain: SafeHead, TxBlock and Balance (cold.go).

// caps is the fee caps in force now. Each public build or bump starts with refreshCaps, so it works under the newest signed record; a build that is
// under way finishes under the caps it started with or a newer record, never a mixture the zone would not accept (it stamps the sequence number).
func (a *Adapter) caps() FeeCaps {
	if c, seq := a.view.Now(); seq > 0 {
		return c
	}
	return FeeCaps{MaxTxFeeSats: a.cfg.MaxTxFeeSats, MaxFeeRate: a.cfg.MaxFeeRate} // no signed change: the configuration
}

// capsSeq is the sequence number of the change in force (0: the configuration).
func (a *Adapter) capsSeq() int64 {
	_, s := a.view.Now()
	return s
}

// refreshCaps reads the newest signed record. When it cannot, the build does not start.
func (a *Adapter) refreshCaps(ctx context.Context) error { return a.view.Refresh(ctx) }

// FeeCapsNow is the caps and the sequence number the core builds under now (for metrics and tests).
func (a *Adapter) FeeCapsNow() (FeeCaps, int64) { return a.view.Now() }
