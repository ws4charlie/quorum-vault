package custody

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// The chart of accounts (docs/learn/p3b-closed-loop.md). The ledger sums to
// zero per (chain, asset): customer liabilities are positive, and every
// on-chain holding is mirrored by a negative balance.

func custAcct(customer, chain, asset string) string {
	return "cust:" + customer + ":" + chain + ":" + asset
}
func depAcct(chain, asset string) string      { return "dep:" + chain + ":" + asset }
func sweepAcct(chain, asset string) string    { return "sweep:" + chain + ":" + asset }
func wdAcct(chain, asset string) string       { return "wd:" + chain + ":" + asset }
func suspenseAcct(chain, asset string) string { return "suspense:" + chain + ":" + asset }
func feeAcct(chain, native string) string     { return "fee:" + chain + ":" + native }
func hotAcct(partitionID string) string       { return "hot:" + partitionID }

// coldAcct is minus the on-chain cold balance that hot-to-cold moves have delivered for a hot partition. toColdAcct is the
// clearing account the funds are in while a move is on its way.
func coldAcct(partitionID string) string    { return "cold:" + partitionID }
func toColdAcct(chain, asset string) string { return "tocold:" + chain + ":" + asset }

// rebalAcct is the clearing account of a rebalance between two hot shards while it is on its way.
func rebalAcct(chain, asset string) string { return "rebal:" + chain + ":" + asset }

// refillAcct is the clearing account of a refill on its way from cold to hot; opFundAcct is the operator's own money that was put
// into the cold address (booked explicitly, so Reconcile stays exact).
func refillAcct(chain, asset string) string { return "refill:" + chain + ":" + asset }
func opFundAcct(chain, asset string) string { return "opfund:" + chain + ":" + asset }

// CustomerAccount is the ledger account owing a customer an asset.
func CustomerAccount(customer, chain, asset string) string { return custAcct(customer, chain, asset) }

// DepAccount, SweepAccount, WdAccount, SuspenseAccount, FeeAccount and
// HotAccount expose the other accounts to tests and tools.
func DepAccount(chain, asset string) string       { return depAcct(chain, asset) }
func SweepAccount(chain, asset string) string     { return sweepAcct(chain, asset) }
func WdAccount(chain, asset string) string        { return wdAcct(chain, asset) }
func SuspenseAccount(chain, asset string) string  { return suspenseAcct(chain, asset) }
func FeeAccount(chain, native string) string      { return feeAcct(chain, native) }
func HotAccount(partitionID string) string        { return hotAcct(partitionID) }
func ColdAccount(partitionID string) string       { return coldAcct(partitionID) }
func ToColdAccount(chain, asset string) string    { return toColdAcct(chain, asset) }
func RebalanceAccount(chain, asset string) string { return rebalAcct(chain, asset) }
func RefillAccount(chain, asset string) string    { return refillAcct(chain, asset) }
func OpFundAccount(chain, asset string) string    { return opFundAcct(chain, asset) }

// ensureCustomerAccount creates a customer's account for asset.
func (s *Service) ensureCustomerAccount(ctx context.Context, tx pgx.Tx, customer, asset string) error {
	return s.Led.EnsureAccount(ctx, tx, ledger.Account{
		ID: custAcct(customer, s.Cfg.Chain, asset), Kind: ledger.KindCustomer, Chain: s.Cfg.Chain, Asset: asset, CustomerID: customer})
}

// Bootstrap creates the assets, hot partitions and the fixed ledger accounts.
// It is idempotent and safe to run from every process at start.
func (s *Service) Bootstrap(ctx context.Context) error {
	c := s.Cfg
	if err := s.checkColdNotForwarder(ctx); err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		for _, sym := range c.AssetList {
			a := c.Assets[sym]
			var contract any
			if !a.Native() {
				contract = a.Address.Hex()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO assets (chain, symbol, decimals, contract_address, min_deposit) VALUES ($1,$2,$3,$4,$5::numeric)
				ON CONFLICT (chain, symbol) DO UPDATE SET decimals = EXCLUDED.decimals, contract_address = EXCLUDED.contract_address, min_deposit = EXCLUDED.min_deposit`,
				c.Chain, sym, a.Decimals, contract, a.MinDeposit.String()); err != nil {
				return fmt.Errorf("custody: bootstrap asset %s: %w", sym, err)
			}
			for _, kind := range []struct {
				id   string
				kind string
				neg  bool
			}{
				{depAcct(c.Chain, sym), ledger.KindClearing, true},
				{sweepAcct(c.Chain, sym), ledger.KindClearing, true},
				{wdAcct(c.Chain, sym), ledger.KindClearing, true},
				{toColdAcct(c.Chain, sym), ledger.KindClearing, true},
				{rebalAcct(c.Chain, sym), ledger.KindClearing, true},
				{refillAcct(c.Chain, sym), ledger.KindClearing, true},
				{opFundAcct(c.Chain, sym), ledger.KindClearing, true},
				{suspenseAcct(c.Chain, sym), ledger.KindSuspense, false},
			} {
				if err := s.Led.EnsureAccount(ctx, tx, ledger.Account{ID: kind.id, Kind: kind.kind, Chain: c.Chain, Asset: sym, AllowNegative: kind.neg}); err != nil {
					return err
				}
			}
			if sym == c.Native {
				if err := s.Led.EnsureAccount(ctx, tx, ledger.Account{ID: feeAcct(c.Chain, sym), Kind: ledger.KindFee, Chain: c.Chain, Asset: sym, AllowNegative: true}); err != nil {
					return err
				}
			}
			for i := range c.HotShards {
				k := c.PartitionKey(sym, i)
				if _, err := tx.Exec(ctx, `INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ($1,$2,$3,$4,$5,$6,$7)
					ON CONFLICT (id) DO NOTHING`, k.String(), k.Entity, k.Chain, k.Asset, k.Tier, k.Pool, k.Shard); err != nil {
					return fmt.Errorf("custody: bootstrap partition %s: %w", k, err)
				}
				if err := s.Led.EnsureAccount(ctx, tx, ledger.Account{ID: hotAcct(k.String()), Kind: ledger.KindHot, Chain: c.Chain, Asset: sym,
					PartitionID: k.String(), AllowNegative: true}); err != nil {
					return err
				}
				if err := s.Led.EnsureAccount(ctx, tx, ledger.Account{ID: coldAcct(k.String()), Kind: ledger.KindCold, Chain: c.Chain, Asset: sym,
					PartitionID: k.String(), AllowNegative: true}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// coldAddressList is every configured cold address, lower case.
func (s *Service) coldAddressList() []string {
	var out []string
	for _, a := range s.Cfg.EVM.ColdAddresses {
		out = append(out, strings.ToLower(a.Hex()))
	}
	return out
}

// checkColdNotForwarder refuses to start with a cold address that is already a customer's deposit forwarder: funds sent to a
// forwarder are swept by anyone to the sweep destination, so a "cold" address that is one would not hold anything. The check is
// one query on the deposit address table; a new deposit address is checked the same way when it is issued.
func (s *Service) checkColdNotForwarder(ctx context.Context) error {
	cold := s.coldAddressList()
	if len(cold) == 0 {
		return nil
	}
	var addr string
	err := s.Pool.QueryRow(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 AND lower(address)=ANY($2) LIMIT 1`, s.Cfg.Chain, cold).Scan(&addr)
	if isNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: the cold address %s is a customer deposit forwarder", ErrInvalid, addr)
}
