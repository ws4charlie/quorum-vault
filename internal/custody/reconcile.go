package custody

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// Check is one comparison Reconcile made.
type Check struct {
	Name    string `json:"name"`
	Asset   string `json:"asset,omitempty"`
	Subject string `json:"subject,omitempty"` // hot address, account, ...
	Ledger  string `json:"ledger"`
	Chain   string `json:"chain"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Skipped bool   `json:"skipped,omitempty"`
}

// Report is the result of Reconcile. It fixes nothing.
type Report struct {
	Chain      string  `json:"chain"`
	Height     uint64  `json:"height"`      // the pinned safe block height
	ScanCursor uint64  `json:"scan_cursor"` // next height Scan will read
	InFlight   int     `json:"in_flight"`   // open sweeps and withdrawals
	Checks     []Check `json:"checks"`
	Clean      bool    `json:"clean"`
}

// Failures returns the checks that failed.
func (r Report) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if !c.OK && !c.Skipped {
			out = append(out, c)
		}
	}
	return out
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

func (s *Service) posted(ctx context.Context, acct string) (*big.Int, error) {
	var p string
	if err := s.Pool.QueryRow(ctx, `SELECT posted::text FROM ledger_accounts WHERE id=$1`, acct).Scan(&p); err != nil {
		return nil, fmt.Errorf("custody: account %s: %w", acct, err)
	}
	return parseBig(p), nil
}

// Reconcile compares the books with the chain at a pinned safe height:
//
//   - for every hot shard and asset, minus the hot account equals the on-chain
//     balance of the shard's address (fees make ETH exact);
//   - minus dep equals the sum of on-chain balances of all deposit addresses;
//   - ledger.CheckInvariants passes;
//   - for every cold address, minus the cold accounts of the partitions that use it equals its on-chain balance;
//   - sweep, wd and tocold residuals are zero when nothing is in flight (otherwise
//     they are skipped and counted in InFlight);
//   - the scan has caught up to the pinned height (otherwise deposits the
//     chain has but the books do not yet would show as differences).
//
// It reports and never repairs.
func (s *Service) Reconcile(ctx context.Context) (Report, error) {
	c := s.Cfg
	rep := Report{Chain: c.Chain}
	h, err := s.Reader.SafeHead(ctx)
	if err != nil {
		return rep, err
	}
	rep.Height = h
	cur, err := s.Cursor(ctx)
	if err != nil {
		return rep, err
	}
	rep.ScanCursor = cur
	rep.add(Check{Name: "scan_caught_up", Ledger: fmt.Sprint(cur), Chain: fmt.Sprint(h + 1), OK: cur > h,
		Detail: "the scan cursor must be past the pinned height"})

	// Hot wallets.
	for _, sym := range c.AssetList {
		for i, addr := range c.HotShards {
			p := c.PartitionKey(sym, i).String()
			posted, err := s.posted(ctx, hotAcct(p))
			if err != nil {
				return rep, err
			}
			bal, err := s.Reader.Balance(ctx, addr.Hex(), sym, h)
			if err != nil {
				return rep, err
			}
			want := new(big.Int).Neg(posted)
			rep.add(Check{Name: "hot", Asset: sym, Subject: addr.Hex(), Ledger: want.String(), Chain: bal.String(), OK: want.Cmp(bal) == 0})
		}
	}

	// Cold addresses: what hot-to-cold moves delivered, per cold address and asset, against the chain. Several hot partitions
	// (shards) may share one cold address, so their cold accounts are summed.
	if len(c.EVM.ColdAddresses) > 0 {
		type coldKey struct{ addr, asset string }
		sums := map[coldKey]*big.Int{}
		var keys []coldKey
		for _, sym := range c.AssetList {
			for i := range c.HotShards {
				p := c.PartitionKey(sym, i).String()
				ca, err := c.EVM.ColdAddress(p, sym)
				if err != nil {
					continue // no cold address configured for this pool and asset class
				}
				posted, err := s.posted(ctx, coldAcct(p))
				if err != nil {
					return rep, err
				}
				k := coldKey{ca.Hex(), sym}
				if sums[k] == nil {
					sums[k] = new(big.Int)
					keys = append(keys, k)
				}
				sums[k].Sub(sums[k], posted)
			}
		}
		for _, k := range keys {
			bal, err := s.Reader.Balance(ctx, k.addr, k.asset, h)
			if err != nil {
				return rep, err
			}
			rep.add(Check{Name: "cold", Asset: k.asset, Subject: k.addr, Ledger: sums[k].String(), Chain: bal.String(), OK: sums[k].Cmp(bal) == 0})
		}
	}

	// Deposit addresses.
	rows, err := s.Pool.Query(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 ORDER BY address`, c.Chain)
	if err != nil {
		return rep, err
	}
	var addrs []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return rep, err
		}
		addrs = append(addrs, a)
	}
	rows.Close()
	for _, sym := range c.AssetList {
		sum := new(big.Int)
		for _, a := range addrs {
			b, err := s.Reader.Balance(ctx, a, sym, h)
			if err != nil {
				return rep, err
			}
			sum.Add(sum, b)
		}
		posted, err := s.posted(ctx, depAcct(c.Chain, sym))
		if err != nil {
			return rep, err
		}
		want := new(big.Int).Neg(posted)
		rep.add(Check{Name: "deposit_addresses", Asset: sym, Ledger: want.String(), Chain: sum.String(), OK: want.Cmp(sum) == 0})
	}

	// Ledger invariants.
	if err := ledger.CheckInvariants(ctx, s.Pool); err != nil {
		rep.add(Check{Name: "ledger_invariants", OK: false, Detail: err.Error()})
	} else {
		rep.add(Check{Name: "ledger_invariants", OK: true})
	}

	// Clearing residuals.
	var open int
	if err := s.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM withdrawals WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM cold_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed'))`, c.Chain).Scan(&open); err != nil {
		return rep, err
	}
	rep.InFlight = open
	for _, sym := range c.AssetList {
		for _, id := range []string{sweepAcct(c.Chain, sym), wdAcct(c.Chain, sym), toColdAcct(c.Chain, sym)} {
			p, err := s.posted(ctx, id)
			if err != nil {
				return rep, err
			}
			ck := Check{Name: "clearing_residual", Asset: sym, Subject: id, Ledger: p.String(), Chain: "0", OK: p.Sign() == 0}
			if open > 0 {
				ck.Skipped, ck.Detail = true, fmt.Sprintf("%d sweeps or withdrawals in flight", open)
			}
			rep.add(ck)
		}
	}
	rep.Clean = len(rep.Failures()) == 0
	return rep, nil
}
