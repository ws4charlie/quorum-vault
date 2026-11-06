package btc

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Adapter is the Bitcoin chain cell. Address derivation and deposit scanning work; everything that moves funds out returns
// chain.ErrNotSupported until the tasks that build it.
type Adapter struct {
	cfg  *validatedConfig
	rpc  *RPC
	pool *pgxpool.Pool
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
	a := &Adapter{cfg: v, rpc: NewRPC(cfg.RPCURL, cfg.RPCUser, cfg.RPCPass), pool: pool}
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

func (a *Adapter) BuildWithdrawal(context.Context, pgx.Tx, chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, errLater
}
func (a *Adapter) BuildSweep(context.Context, pgx.Tx, chain.SweepIntent) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, errLater
}
func (a *Adapter) BuildReplacement(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, errLater
}
func (a *Adapter) BuildCancel(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, errLater
}
func (a *Adapter) Assemble(chain.UnsignedTx, []chain.Signature) (chain.SignedTx, error) {
	return chain.SignedTx{}, errLater
}
func (a *Adapter) Broadcast(context.Context, chain.SignedTx) (string, error) { return "", errLater }
func (a *Adapter) Status(context.Context, string) (chain.TxStatus, error)    { return "", errLater }
func (a *Adapter) EstimateSweepFee(context.Context, chain.SweepIntent) (*big.Int, error) {
	return nil, errLater
}
func (a *Adapter) TxFee(context.Context, string) (*big.Int, error) { return nil, errLater }
func (a *Adapter) MovedAssets(context.Context, string) ([]chain.MovedAsset, error) {
	return nil, errLater
}
func (a *Adapter) Outcome(context.Context, string, string) (chain.Outcome, error) {
	return chain.Outcome{}, errLater
}
func (a *Adapter) Reservation(context.Context, chain.Querier, string, string) (chain.Reservation, error) {
	return chain.Reservation{}, errLater
}

// The Adapter is also the custody.Reader of the chain. SafeHead works; the balance of an address and the height of a
// transaction are needed by reconciliation, settlement of withdrawals and sweeps, which are later tasks.

// TxBlock is not supported yet.
func (a *Adapter) TxBlock(context.Context, string) (uint64, error) { return 0, errLater }

// Balance is not supported yet: reconciliation of hot, cold and deposit balances against the chain needs it.
func (a *Adapter) Balance(context.Context, string, string, uint64) (*big.Int, error) {
	return nil, errLater
}
