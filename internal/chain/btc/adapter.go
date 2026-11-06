package btc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Adapter is the Bitcoin chain cell. Address derivation and deposit scanning work; everything that moves funds out returns
// chain.ErrNotSupported until the tasks that build it.
type Adapter struct {
	cfg    *validatedConfig
	rpc    *RPC
	pool   *pgxpool.Pool
	acct   *Account
	shards []shard          // in shard order
	byAddr map[string]shard // canonical address -> shard

	waitMu   sync.Mutex
	sweepWhy string // why sweeps are waiting now ("" when they are not), to log a change once
}

// shard is one hot shard of the cell.
type shard struct {
	partition string
	address   string // canonical
	path      []uint32
	script    []byte
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
	a := &Adapter{cfg: v, rpc: NewRPC(cfg.RPCURL, cfg.RPCUser, cfg.RPCPass), pool: pool, acct: &Account{Params: v.params, key: v.account}, byAddr: map[string]shard{}}
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

var errLater = fmt.Errorf("btc: %w (a later P7 task)", chain.ErrNotSupported)

// The Adapter is also the custody.Reader of the chain. SafeHead works; the balance of an address and the height of a
// transaction are needed by reconciliation, settlement of withdrawals and sweeps, which are later tasks.

// Balance is not supported yet: reconciliation of hot, cold and deposit balances against the chain needs it.
func (a *Adapter) Balance(context.Context, string, string, uint64) (*big.Int, error) {
	return nil, errLater
}
