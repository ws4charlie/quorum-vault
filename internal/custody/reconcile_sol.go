package custody

import (
	"context"
	"fmt"
	"math/big"
	"strings"
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
// The hot shards are compared the same way: the books' side is minus the hot account of each partition, the chain side the shard's balance at
// finalized commitment. A withdrawal whose transaction has finalized and that the books have not settled yet has already changed the chain: it is
// explained from the cell's own records of the transaction (what it sent and what it cost), and the comparison is repeated if the set of such
// withdrawals, or the books, changed while it ran.
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
		landed, err := s.solLanded(ctx)
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
		clearing := map[string]*big.Int{} // read inside the same window as the chain, so that a booking cannot slip between
		for _, sym := range c.AssetList {
			p, err := s.posted(ctx, depAcct(c.Chain, sym))
			if err != nil {
				return err
			}
			posted[sym] = p
			for _, id := range []string{sweepAcct(c.Chain, sym), wdAcct(c.Chain, sym), toColdAcct(c.Chain, sym), rebalAcct(c.Chain, sym), refillAcct(c.Chain, sym)} {
				q, err := s.posted(ctx, id)
				if err != nil {
					return err
				}
				clearing[id] = q
			}
		}
		hotChain, err := s.solHotBalances(ctx)
		if err != nil {
			return err
		}
		hotBooks, err := s.solHotBooks(ctx)
		if err != nil {
			return err
		}
		after, err := s.solStamp(ctx)
		if err != nil {
			return err
		}
		landedAfter, err := s.solLanded(ctx)
		if err != nil {
			return err
		}
		if before != after || len(view.Pending) > 0 || landed.key != landedAfter.key {
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
			if adj := landedAfter.depAdj[sym]; adj != nil {
				want.Add(want, adj) // swept money the books moved on broadcast and the chain has not (or the reverse)
			}
			rep.add(Check{Name: "deposit_addresses", Asset: sym, Ledger: want.String(), Chain: sum.String(), OK: want.Cmp(sum) == 0,
				Detail: fmt.Sprintf("%d deposit addresses, finalized balances; the ledger side is every deposit booked, in the asset's base unit", len(addrs))})
		}
		for _, hc := range hotChain {
			want := new(big.Int).Set(hotBooks[hc.partition])
			if adj := landedAfter.out[hc.partition]; adj != nil {
				want.Sub(want, adj) // already left the chain, not yet booked
			}
			if adj := landedAfter.in[hc.partition]; adj != nil {
				want.Add(want, adj) // already arrived (a sweep), not yet booked
			}
			rep.add(Check{Name: "hot_balance", Asset: hc.asset, Subject: hc.partition, Ledger: want.String(), Chain: hc.balance.String(), OK: want.Cmp(hc.balance) == 0,
				Detail: fmt.Sprintf("hot shard %s at finalized commitment; %d finalized withdrawal(s) not settled yet are accounted for", hc.address, landedAfter.n)})
		}
		if err := s.solColdChecks(ctx, rep, landedAfter); err != nil {
			return err
		}
		s.ledgerInvariants(ctx, rep)
		// Nothing is moved to cold on this family yet, and a withdrawal posts its hold and moves it on in one transaction, so those clearing
		// accounts must be empty. The sweep account holds what sweeps broadcast and not settled yet are taking, as a negative amount.
		for _, sym := range c.AssetList {
			for _, id := range []string{sweepAcct(c.Chain, sym), wdAcct(c.Chain, sym), toColdAcct(c.Chain, sym), rebalAcct(c.Chain, sym), refillAcct(c.Chain, sym)} {
				p := clearing[id]
				want := new(big.Int)
				if id == sweepAcct(c.Chain, sym) && landedAfter.transit[sym] != nil {
					want.Neg(landedAfter.transit[sym])
				}
				if t := landedAfter.moveTransit[id]; t != nil { // moves to cold and rebalances broadcast and not settled
					want.Neg(t)
				}
				rep.add(Check{Name: "clearing_residual", Asset: sym, Subject: id, Ledger: p.String(), Chain: want.String(), OK: p.Cmp(want) == 0})
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
		(SELECT count(*)::text FROM deposit_addresses WHERE chain=$1),
		(SELECT COALESCE(string_agg(posted::text, ',' ORDER BY id), '') FROM ledger_accounts WHERE chain=$1),
		(SELECT count(*)::text FROM withdrawals WHERE chain=$1 AND status IN ('confirmed','failed')),
		(SELECT COALESCE(string_agg(id || status, ',' ORDER BY id), '') FROM sweeps WHERE chain=$1),
		(SELECT COALESCE(string_agg(id || status, ',' ORDER BY id), '') FROM cold_moves WHERE chain=$1),
		(SELECT COALESCE(string_agg(id || status, ',' ORDER BY id), '') FROM rebalance_moves WHERE chain=$1))`, s.Cfg.Chain).Scan(&st)
	return st, err
}

type solHot struct {
	partition, asset, address string
	balance                   *big.Int
}

// solHotBalances reads the finalized balance of every hot shard and asset.
func (s *Service) solHotBalances(ctx context.Context) ([]solHot, error) {
	c := s.Cfg
	var out []solHot
	for i, addr := range c.SOLHot {
		for _, sym := range c.AssetList {
			b, err := s.Reader.Balance(ctx, addr, sym, 0)
			if err != nil {
				return nil, err
			}
			out = append(out, solHot{partition: c.PartitionKey(sym, i).String(), asset: sym, address: addr, balance: b})
		}
	}
	return out, nil
}

// solHotBooks is, per hot partition, what the books say the shard holds: minus the hot account.
func (s *Service) solHotBooks(ctx context.Context) (map[string]*big.Int, error) {
	c := s.Cfg
	out := map[string]*big.Int{}
	for i := range c.SOLHot {
		for _, sym := range c.AssetList {
			p := c.PartitionKey(sym, i).String()
			posted, err := s.posted(ctx, hotAcct(p))
			if err != nil {
				return nil, err
			}
			out[p] = new(big.Int).Neg(posted)
		}
	}
	return out, nil
}

// solLandedSet is what the finalized transactions of withdrawals that are not settled yet have already taken off the hot shards.
type solLandedSet struct {
	out map[string]*big.Int // partition -> amount that left the shard (a cost, or a withdrawal's amount; negative: rent got back)
	in  map[string]*big.Int // partition -> amount that reached the shard (a sweep)
	// depAdj, per asset, is added to what the books say the deposit addresses hold: a sweep the books took out of dep on broadcast whose
	// transaction has not moved the funds (+), or one that moved them before the books heard (-).
	depAdj map[string]*big.Int
	// transit, per asset, is what the sweeps the books have broadcast and not settled are taking.
	transit map[string]*big.Int
	// coldIn, per cold address and asset, is what finalized moves to cold have already put there and the books have not booked yet.
	coldIn map[[2]string]*big.Int
	// moveTransit, per clearing account, is what moves to cold and rebalances the books have broadcast and not settled are taking.
	moveTransit map[string]*big.Int
	n           int
	key         string
}

// solLanded asks the chain cell about every withdrawal that has a transaction out and is not settled in the books. A transaction that landed
// moved its amount (when it succeeded) and cost its fee, which the books record at settlement or void.
func (s *Service) solLanded(ctx context.Context) (solLandedSet, error) {
	res := solLandedSet{out: map[string]*big.Int{}, in: map[string]*big.Int{}, depAdj: map[string]*big.Int{}, transit: map[string]*big.Int{},
		coldIn: map[[2]string]*big.Int{}, moveTransit: map[string]*big.Int{}}
	rows, err := s.Pool.Query(ctx, `SELECT id, asset, amount::text, partition_id FROM withdrawals WHERE chain=$1 AND status IN ('signing','broadcast') ORDER BY id`, s.Cfg.Chain)
	if err != nil {
		return res, err
	}
	type wd struct{ id, asset, amount, part string }
	var ws []wd
	for rows.Next() {
		var w wd
		if err := rows.Scan(&w.id, &w.asset, &w.amount, &w.part); err != nil {
			rows.Close()
			return res, err
		}
		ws = append(ws, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	var key []string
	add := func(part string, n *big.Int) {
		if res.out[part] == nil {
			res.out[part] = new(big.Int)
		}
		res.out[part].Add(res.out[part], n)
	}
	for _, w := range ws {
		oc, err := s.Chain.Outcome(ctx, "withdrawal", w.id)
		if err != nil {
			return res, err
		}
		if oc.State != chain.OutcomeConfirmed {
			continue
		}
		fee, err := s.Chain.TxFee(ctx, oc.Hash)
		if err != nil {
			return res, err
		}
		nativePart, err := s.nativePartitionOf(w.part)
		if err != nil {
			return res, err
		}
		add(nativePart, fee)
		if oc.Kind == chain.AttemptSend && !oc.Failed {
			add(w.part, parseBig(w.amount))
		}
		res.n++
		key = append(key, w.id+":"+oc.Hash)
	}
	sk, err := s.solLandedSweeps(ctx, &res, add)
	if err != nil {
		return res, err
	}
	mk, err := s.solLandedMoves(ctx, &res, add)
	if err != nil {
		return res, err
	}
	res.key = strings.Join(append(append(key, sk...), mk...), ",")
	return res, nil
}

// solLandedSweeps adds the sweeps that are not settled to res: what each moved on the chain against what the books recorded of it.
func (s *Service) solLandedSweeps(ctx context.Context, res *solLandedSet, add func(string, *big.Int)) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, asset, amount::text, status, to_partition_id FROM sweeps WHERE chain=$1 AND status IN ('signing','broadcast') ORDER BY id`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	type sw struct{ id, asset, amount, status, part string }
	var ss []sw
	for rows.Next() {
		var w sw
		if err := rows.Scan(&w.id, &w.asset, &w.amount, &w.status, &w.part); err != nil {
			rows.Close()
			return nil, err
		}
		ss = append(ss, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	addTo := func(m map[string]*big.Int, k string, n *big.Int) {
		if m[k] == nil {
			m[k] = new(big.Int)
		}
		m[k].Add(m[k], n)
	}
	var key []string
	for _, w := range ss {
		amount := parseBig(w.amount)
		reduced := w.status == "broadcast" // the books took it out of dep at broadcast
		if reduced {
			addTo(res.transit, w.asset, amount)
		}
		oc, err := s.Chain.Outcome(ctx, "sweep", w.id)
		if err != nil {
			return nil, err
		}
		movedOnChain := new(big.Int)
		if oc.State == chain.OutcomeConfirmed {
			fee, err := s.Chain.TxFee(ctx, oc.Hash)
			if err != nil {
				return nil, err
			}
			nativePart, err := s.nativePartitionOf(w.part)
			if err != nil {
				return nil, err
			}
			add(nativePart, fee)
			if !oc.Failed {
				mv, err := s.Chain.MovedAssets(ctx, oc.Hash)
				if err != nil {
					return nil, err
				}
				for _, m := range mv {
					addTo(res.in, s.Cfg.SinkPartition(m.Asset), m.Amount)
					if m.Asset == w.asset {
						movedOnChain.Add(movedOnChain, m.Amount)
					}
				}
			}
			res.n++
			key = append(key, w.id+":"+oc.Hash)
		}
		switch {
		case reduced && movedOnChain.Sign() == 0:
			addTo(res.depAdj, w.asset, amount)
		case !reduced && movedOnChain.Sign() > 0:
			addTo(res.depAdj, w.asset, new(big.Int).Neg(movedOnChain))
		}
	}
	return key, nil
}

// solLandedMoves adds the moves to cold and the rebalances that are not settled: what each moved on the chain against what the books recorded of it.
// The books take the amount out of the source shard at broadcast and put it into the cold account or the target shard at settlement; the chain does
// both when the transaction is final.
func (s *Service) solLandedMoves(ctx context.Context, res *solLandedSet, add func(string, *big.Int)) ([]string, error) {
	c := s.Cfg
	var key []string
	for _, kind := range []struct{ owner, table, clearing string }{
		{OwnerKindToCold, "cold_moves", "to-cold"}, {OwnerKindRebalance, "rebalance_moves", "rebal"}} {
		q := `SELECT id, asset, amount::text, status, partition_id, ''::text FROM cold_moves WHERE chain=$1 AND status IN ('signing','broadcast') ORDER BY id`
		if kind.table == "rebalance_moves" {
			q = `SELECT id, asset, amount::text, status, partition_id, to_partition_id FROM rebalance_moves WHERE chain=$1 AND status IN ('signing','broadcast') ORDER BY id`
		}
		rows, err := s.Pool.Query(ctx, q, c.Chain)
		if err != nil {
			return nil, err
		}
		type mv struct{ id, asset, amount, status, part, to string }
		var ms []mv
		for rows.Next() {
			var m mv
			if err := rows.Scan(&m.id, &m.asset, &m.amount, &m.status, &m.part, &m.to); err != nil {
				rows.Close()
				return nil, err
			}
			ms = append(ms, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, m := range ms {
			amount := parseBig(m.amount)
			reduced := m.status == "broadcast" // the books took it out of the source shard at broadcast
			clearing := toColdAcct(c.Chain, m.asset)
			if kind.owner == OwnerKindRebalance {
				clearing = rebalAcct(c.Chain, m.asset)
			}
			if reduced {
				if res.moveTransit[clearing] == nil {
					res.moveTransit[clearing] = new(big.Int)
				}
				res.moveTransit[clearing].Add(res.moveTransit[clearing], amount)
			}
			oc, err := s.Chain.Outcome(ctx, kind.owner, m.id)
			if err != nil {
				return nil, err
			}
			if oc.State != chain.OutcomeConfirmed {
				if reduced { // the books have it out of the shard, the chain does not yet
					add(m.part, new(big.Int).Neg(amount))
				}
				continue
			}
			fee, err := s.Chain.TxFee(ctx, oc.Hash)
			if err != nil {
				return nil, err
			}
			nativePart, err := s.nativePartitionOf(m.part)
			if err != nil {
				return nil, err
			}
			add(nativePart, fee)
			if !oc.Failed && oc.Kind == chain.AttemptSend {
				if !reduced {
					add(m.part, amount) // already left the shard, not yet booked
				}
				if kind.owner == OwnerKindToCold {
					cold, err := c.ColdAddressOf(m.part, m.asset)
					if err != nil {
						return nil, err
					}
					k := [2]string{cold, m.asset}
					if res.coldIn[k] == nil {
						res.coldIn[k] = new(big.Int)
					}
					res.coldIn[k].Add(res.coldIn[k], amount)
				} else {
					if res.in[m.to] == nil {
						res.in[m.to] = new(big.Int)
					}
					res.in[m.to].Add(res.in[m.to], amount)
				}
			} else if reduced {
				add(m.part, new(big.Int).Neg(amount)) // the books took it out and nothing left
			}
			res.n++
			key = append(key, m.id+":"+oc.Hash)
		}
	}
	return key, nil
}

// solColdChecks compares each pool's cold address with the books: minus the cold accounts of the partitions that use it, per asset.
func (s *Service) solColdChecks(ctx context.Context, rep *Report, landed solLandedSet) error {
	c := s.Cfg
	if len(c.SOL.ColdAddresses) == 0 {
		return nil
	}
	for pool, addr := range c.SOL.ColdAddresses {
		for _, sym := range c.AssetList {
			want := new(big.Int)
			for i := 0; i < c.shardCount(); i++ {
				p := c.PartitionKey(sym, i)
				if string(p.Pool) != pool {
					continue
				}
				posted, err := s.posted(ctx, coldAcct(p.String()))
				if err != nil {
					return err
				}
				want.Sub(want, posted)
			}
			if in := landed.coldIn[[2]string{addr, sym}]; in != nil {
				want.Add(want, in)
			}
			got, err := s.Reader.Balance(ctx, addr, sym, 0)
			if err != nil {
				return err
			}
			rep.add(Check{Name: "cold_balance", Asset: sym, Subject: addr, Ledger: want.String(), Chain: got.String(), OK: want.Cmp(got) == 0,
				Detail: fmt.Sprintf("cold address of pool %s at finalized commitment", pool)})
		}
	}
	return nil
}
