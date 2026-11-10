package custody

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// reconcileSOL compares the books with Solana. A Solana node keeps no balances of the past, so the comparison cannot be pinned to a height as
// Ethereum's can: it reads every deposit address's SOL and ATA balances at the node's finalized state and puts them beside the books. A change
// that finalized between the books' last scan and that read would show as a difference, so the cell also says which addresses have finalized
// activity at or above the scan cursor (it reads balances first and activity after); those are waited for, and the read is repeated when the
// books or the scan cursor moved during it. Only if that keeps happening is the comparison skipped, and then the report says so and is not
// Clean. What is left after that is a real difference, in the base unit.
//
// The books' side is the dep account of each asset: every deposit, credited or in suspense, is booked into it, and nothing leaves a deposit
// address yet (sweeps are a later task), so minus its posted amount is what the deposit addresses must hold.
func (s *Service) reconcileSOL(ctx context.Context, rep *Report) error {
	c := s.Cfg
	av, ok := s.Chain.(chain.AssetViewer)
	if !ok {
		rep.SkippedChainChecks++
		rep.add(Check{Name: "deposit_addresses", OK: true, Skipped: true, Detail: "this chain cell cannot read asset balances"})
		return nil
	}
	h, err := s.Reader.SafeHead(ctx)
	if err != nil {
		return err
	}
	rep.Height = h
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(700 * time.Millisecond):
			}
		}
		before, err := s.solStamp(ctx)
		if err != nil {
			return err
		}
		cur, err := s.Cursor(ctx)
		if err != nil {
			return err
		}
		rows, err := s.Pool.Query(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 ORDER BY address`, c.Chain)
		if err != nil {
			return err
		}
		var addrs []string
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				rows.Close()
				return err
			}
			addrs = append(addrs, a)
		}
		rows.Close()
		view, err := av.AssetView(ctx, addrs, cur)
		if err != nil {
			return err
		}
		posted := map[string]*big.Int{}
		for _, sym := range c.AssetList {
			p, err := s.posted(ctx, depAcct(c.Chain, sym))
			if err != nil {
				return err
			}
			posted[sym] = p
		}
		after, err := s.solStamp(ctx)
		if err != nil {
			return err
		}
		if before != after || len(view.Pending) > 0 {
			continue // the books or the chain moved during the read: read again
		}
		rep.ScanCursor = cur
		rep.ChainHeight = view.Slot
		for _, sym := range c.AssetList {
			sum := new(big.Int)
			for _, b := range view.Balance[sym] {
				sum.Add(sum, b)
			}
			want := new(big.Int).Neg(posted[sym])
			rep.add(Check{Name: "deposit_addresses", Asset: sym, Ledger: want.String(), Chain: sum.String(), OK: want.Cmp(sum) == 0,
				Detail: fmt.Sprintf("%d deposit addresses, finalized balances; the ledger side is every deposit booked, in the asset's base unit", len(addrs))})
		}
		s.ledgerInvariants(ctx, rep)
		// Nothing is swept, withdrawn or moved to cold on this family yet, so every clearing account must be empty.
		for _, sym := range c.AssetList {
			for _, id := range []string{sweepAcct(c.Chain, sym), wdAcct(c.Chain, sym), toColdAcct(c.Chain, sym), rebalAcct(c.Chain, sym), refillAcct(c.Chain, sym)} {
				p, err := s.posted(ctx, id)
				if err != nil {
					return err
				}
				rep.add(Check{Name: "clearing_residual", Asset: sym, Subject: id, Ledger: p.String(), Chain: "0", OK: p.Sign() == 0})
			}
		}
		return nil
	}
	rep.SkippedChainChecks++
	rep.add(Check{Name: "deposit_addresses", OK: true, Skipped: true,
		Detail: "finalized activity the scan has not covered yet (or a change in the books) kept arriving during the read; compared nothing this time"})
	s.ledgerInvariants(ctx, rep)
	return nil
}

// solStamp changes whenever the books' deposits or the scan cursor change.
func (s *Service) solStamp(ctx context.Context) (string, error) {
	var st string
	err := s.Pool.QueryRow(ctx, `SELECT concat_ws('|', (SELECT count(*)::text FROM deposits WHERE chain=$1), (SELECT COALESCE(next_height,0)::text FROM chain_cursors WHERE chain=$1),
		(SELECT count(*)::text FROM deposit_addresses WHERE chain=$1))`, s.Cfg.Chain).Scan(&st)
	return st, err
}
