package sol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Adapter is the Solana chain cell. Deposit address derivation, scanning and balance reads work; everything that moves funds out
// returns chain.ErrNotSupported until the tasks that build it.
type Adapter struct {
	cfg  *validatedConfig
	rpc  *RPC
	pool *pgxpool.Pool
}

var (
	_ chain.Adapter     = (*Adapter)(nil)
	_ chain.AssetViewer = (*Adapter)(nil)
)

// New validates cfg, connects to the node, refuses a node of another cluster than the config names and refuses a token whose decimals on
// the chain differ from the config.
func New(ctx context.Context, cfg Config, pool *pgxpool.Pool) (*Adapter, error) {
	v, err := cfg.validated()
	if err != nil {
		return nil, err
	}
	if cfg.RPCURL == "" {
		return nil, errors.New("sol: config: rpc_url is required")
	}
	if pool == nil {
		return nil, errors.New("sol: nil database pool")
	}
	a := &Adapter{cfg: v, rpc: NewRPC(cfg.RPCURL), pool: pool}
	if want := genesis[v.Network]; want != "" {
		var got string
		if err := a.rpc.Call(ctx, &got, "getGenesisHash"); err != nil {
			return nil, fmt.Errorf("sol: node: %w", err)
		}
		if got != want {
			return nil, fmt.Errorf("sol: node is on cluster %s, config says network %s (%s)", got, v.Network, want)
		}
	} else if _, err := a.rpc.Slot(ctx, Finalized); err != nil {
		return nil, fmt.Errorf("sol: node: %w", err)
	}
	for _, m := range v.mints {
		d, err := a.rpc.MintDecimals(ctx, m.address)
		if err != nil {
			return nil, fmt.Errorf("sol: token %s: %w", m.symbol, err)
		}
		if d != v.TokenDecimals[m.symbol] {
			return nil, fmt.Errorf("sol: token %s: the mint has %d decimals, the config says %d", m.symbol, d, v.TokenDecimals[m.symbol])
		}
	}
	return a, nil
}

// Close releases nothing: the client keeps no connection of its own.
func (a *Adapter) Close() {}

// RPC exposes the node client (tests).
func (a *Adapter) RPC() *RPC { return a.rpc }

// Chain returns the configured chain name.
func (a *Adapter) Chain() string { return a.cfg.Chain }

// DeriveDepositAddress is pure: the address at account/0/index from the account node. No RPC, no key, no MPC. The caller owns the
// index and hands out each once.
func (a *Adapter) DeriveDepositAddress(_ context.Context, customerID string, index uint64) (chain.DepositAddress, error) {
	if customerID == "" {
		return chain.DepositAddress{}, errors.New("sol: empty customer id")
	}
	if index >= 1<<31 {
		return chain.DepositAddress{}, fmt.Errorf("sol: derivation index %d is hardened", index)
	}
	addr, err := a.cfg.node.DepositAddressAt(uint32(index))
	if err != nil {
		return chain.DepositAddress{}, err
	}
	return chain.DepositAddress{Chain: a.cfg.Chain, Address: addr, Kind: chain.KindEd25519, DerivationIndex: index, Asset: ""}, nil
}

// watched lists the deposit addresses of the chain.
func (a *Adapter) watched(ctx context.Context) ([]string, error) {
	rows, err := a.pool.Query(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 ORDER BY address`, a.cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

var errLater = fmt.Errorf("sol: %w (a later P8 task)", chain.ErrNotSupported)

func (a *Adapter) BuildWithdrawal(context.Context, pgx.Tx, chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, errLater
}
func (a *Adapter) BuildSweep(context.Context, pgx.Tx, chain.SweepIntent) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, errLater
}
func (a *Adapter) BuildReplacement(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, chain.ErrNotSupported
}
func (a *Adapter) BuildCancel(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, chain.ErrNotSupported
}
func (a *Adapter) Assemble(chain.UnsignedTx, []chain.Signature) (chain.SignedTx, error) {
	return chain.SignedTx{}, errLater
}
func (a *Adapter) Broadcast(context.Context, chain.SignedTx) (string, error) { return "", errLater }
func (a *Adapter) Status(context.Context, string) (chain.TxStatus, error) {
	return "", errLater
}
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
	return chain.Reservation{}, nil // nothing is reserved until transactions are built
}

// ---- the custody.Reader of the chain ----

// SafeHead is the highest finalized slot.
func (a *Adapter) SafeHead(ctx context.Context) (uint64, error) { return a.rpc.Slot(ctx, Finalized) }

// TxBlock is not supported until transactions of ours exist.
func (a *Adapter) TxBlock(context.Context, string) (uint64, error) { return 0, errLater }

func (a *Adapter) mintOf(symbol string) (mint, bool) {
	for _, m := range a.cfg.mints {
		if m.symbol == symbol {
			return m, true
		}
	}
	return mint{}, false
}

// Balance is the balance of address in asset at finalized commitment (the node keeps no history, so height is only the caller's label). For a
// token it is the balance of the address's ATA. Tokens held by any other token account the address owns are not part of it; they raise an
// ALERT, because the ledger cannot credit what it was never told about.
func (a *Adapter) Balance(ctx context.Context, address, asset string, _ uint64) (*big.Int, error) {
	if asset == Native {
		n, _, err := a.rpc.Lamports(ctx, address, Finalized)
		return new(big.Int).SetUint64(n), err
	}
	m, ok := a.mintOf(asset)
	if !ok {
		return nil, fmt.Errorf("sol: asset %q is not configured", asset)
	}
	owner, err := ParseAddress(address)
	if err != nil {
		return nil, err
	}
	ata, err := ATA(owner, m.raw)
	if err != nil {
		return nil, err
	}
	accts, err := a.rpc.TokenAccountsByOwner(ctx, address, m.address, Finalized)
	if err != nil {
		return nil, err
	}
	sum := new(big.Int)
	for _, t := range accts {
		if t.Pubkey == Address(ata) {
			sum.SetUint64(t.Amount)
		} else if t.Amount > 0 {
			slog.Error("ALERT tokens sit in a token account of a deposit address that is not its associated token account: they are not credited", "chain", a.cfg.Chain,
				"asset", asset, "address", address, "token_account", t.Pubkey, "amount", t.Amount)
		}
	}
	return sum, nil
}

// AssetView implements chain.AssetViewer.
func (a *Adapter) AssetView(ctx context.Context, addrs []string, cursor uint64) (chain.AssetView, error) {
	v := chain.AssetView{Balance: map[string]map[string]*big.Int{}}
	assets := []string{Native}
	for _, m := range a.cfg.mints {
		assets = append(assets, m.symbol)
	}
	for _, s := range assets {
		v.Balance[s] = map[string]*big.Int{}
	}
	for _, addr := range addrs {
		for _, s := range assets {
			b, err := a.Balance(ctx, addr, s, 0)
			if err != nil {
				return v, err
			}
			v.Balance[s][addr] = b
		}
	}
	slot, err := a.rpc.Slot(ctx, Finalized)
	if err != nil {
		return v, err
	}
	v.Slot = slot
	w, err := a.watchSet(addrs)
	if err != nil {
		return v, err
	}
	pending := map[string]bool{}
	for acct := range w.accounts {
		infos, err := a.rpc.Signatures(ctx, acct, Finalized, "", 20)
		if err != nil {
			return v, err
		}
		var newest *SigInfo // the newest successful one: a failed transaction changes nothing
		for i := range infos {
			if len(infos[i].Err) == 0 || string(infos[i].Err) == "null" {
				newest = &infos[i]
				break
			}
		}
		if newest != nil && newest.Slot >= cursor {
			if o, ok := w.atas[acct]; ok {
				pending[o.owner] = true
			} else {
				pending[acct] = true
			}
		}
	}
	for _, addr := range addrs {
		if pending[addr] {
			v.Pending = append(v.Pending, addr)
		}
	}
	return v, nil
}
