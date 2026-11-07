package custody

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Receipt is what Reconcile needs of a mined EVM transaction.
type Receipt struct {
	Block   uint64
	Success bool
	Fee     *big.Int // gas used x effective gas price: paid by a reverted transaction too
}

// ReceiptReader is implemented by a Reader that can read the receipt of a transaction of ours. found is false when the node has none (the
// transaction is not mined). EVMReader has it.
type ReceiptReader interface {
	Receipt(ctx context.Context, txHash string) (r Receipt, found bool, err error)
}

// recentRevert is how far back Reconcile looks for a transaction that reverted and was settled before it was final. A settled item whose
// revert block is above the pinned height has its fee in the books but not yet in the chain's balance at that height; the window only has to
// be longer than the confirmation depth, and a longer one costs one receipt read per reverted item.
const recentRevert = "24 hours"

// reconcileEVM compares the books with the chain for an EVM cell, in flight or not.
//
// The chain is read at one pinned safe height h. The books are the books at the moment of the read. They differ from the chain at h only by
// things that rows we hold explain:
//
//   - a transaction of ours that mined at or below h and is not settled yet: the chain has its effect, the books get it at settlement;
//   - a transaction booked at broadcast that has not mined at or below h: the books have its effect, the chain does not yet;
//   - a transaction that reverted above h and was settled already: the books have its fee, the chain at h does not.
//
// For every open item the cell's own records (evm_tx_attempts through evm_nonce_allocations, and the refill's hash) say which attempt, if any,
// has a receipt at or below h. From it the books are put in the terms of the chain at h: the ledger legs the item's settlement books are added
// to the posted amounts, exactly as the settlement code books them (so the same legs, for the same cases: success, revert, cancel), and the
// broadcast bookings of the items without a mined transaction are taken out, so every clearing account must then be exactly zero. What is left is a real
// difference and raises the ALERT, in flight or not.
//
// Reading balances and receipts at one height is consistent on EVM; the books can change during the read. The stamp of the books is taken
// before the height and after the last read, and the read is repeated when it changed (3 reads); only then is the comparison skipped, and
// the report says so and is not Clean.
func (s *Service) reconcileEVM(ctx context.Context, rep *Report) error {
	rr, ok := s.Reader.(ReceiptReader)
	if !ok {
		s.skipChainChecks(rep, "this chain reader cannot read receipts")
		return nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		// The stamp first, then the height: a settlement in the books at the stamp was decided against a safe height no higher than the one read
		// after it, so no settled item has its transaction above h (except the early revert, which is accounted for).
		st0, err := s.reconcileStampEVM(ctx)
		if err != nil {
			return err
		}
		h, err := s.Reader.SafeHead(ctx)
		if err != nil {
			return err
		}
		cur, err := s.Cursor(ctx)
		if err != nil {
			return err
		}
		checks, open, unsupported, err := s.evmChecks(ctx, rr, h, cur)
		if err != nil {
			return err
		}
		st1, err := s.reconcileStampEVM(ctx)
		if err != nil {
			return err
		}
		if st0 != st1 {
			continue
		}
		rep.Height, rep.ScanCursor, rep.InFlight = h, cur, open
		for _, ck := range checks {
			rep.add(ck)
		}
		if unsupported {
			s.skipChainChecks(rep, "this chain cell cannot read balances yet")
			return nil
		}
		s.reconSkipSince.Store(0)
		return nil
	}
	s.skipChainChecks(rep, "a change in the books arrived during each of 3 reads")
	return nil
}

// reconcileStampEVM changes whenever the books change in a way that matters to the comparison: any ledger entry, any row that moves money, and
// the attempts and allocations that say what was sent.
func (s *Service) reconcileStampEVM(ctx context.Context) (string, error) {
	var st string
	err := s.Pool.QueryRow(ctx, `SELECT concat_ws('|',
		(SELECT COALESCE(max(id),0)::text FROM ledger_entries),
		(SELECT max(updated_at)::text FROM sweeps WHERE chain=$1), (SELECT max(updated_at)::text FROM withdrawals WHERE chain=$1),
		(SELECT max(updated_at)::text FROM cold_moves WHERE chain=$1), (SELECT max(updated_at)::text FROM rebalance_moves WHERE chain=$1),
		(SELECT max(updated_at)::text FROM refills WHERE chain=$1),
		(SELECT count(*)::text FROM evm_tx_attempts WHERE chain=$1), (SELECT max(updated_at)::text FROM evm_nonce_allocations WHERE chain=$1),
		(SELECT count(*)::text FROM deposit_addresses WHERE chain=$1),
		(SELECT next_height::text FROM chain_cursors WHERE chain=$1))`, s.Cfg.Chain).Scan(&st)
	return st, err
}

// evmAdj is the books put in the terms of the chain at the pinned height.
type evmAdj struct {
	delta map[string]*big.Int // ledger account -> change of its posted amount that puts the books in the terms of the chain at h
	mined int                 // open items whose transaction has mined at or below h
}

func newEVMAdj() *evmAdj {
	return &evmAdj{delta: map[string]*big.Int{}}
}

func addTo(m map[string]*big.Int, acct string, amt *big.Int) {
	if amt == nil || amt.Sign() == 0 {
		return
	}
	if m[acct] == nil {
		m[acct] = new(big.Int)
	}
	m[acct].Add(m[acct], amt)
}

// move is a ledger transfer: from goes down by amt, to goes up.
func (a *evmAdj) move(from, to string, amt *big.Int) {
	if amt == nil || amt.Sign() == 0 {
		return
	}
	addTo(a.delta, from, new(big.Int).Neg(amt))
	addTo(a.delta, to, amt)
}

func (a *evmAdj) of(acct string) *big.Int {
	if d := a.delta[acct]; d != nil {
		return d
	}
	return new(big.Int)
}

// evmAttempt is one transaction of ours at an owner's nonce, with its receipt if the node has one.
type evmAttempt struct {
	hash   string
	cancel bool
	rc     Receipt
	found  bool
}

// attemptsOf reads every transaction of ours at the nonce of an owner and its receipt.
func (s *Service) attemptsOf(ctx context.Context, rr ReceiptReader, kind, id string) ([]evmAttempt, error) {
	rows, err := s.Pool.Query(ctx, `SELECT at.tx_hash, at.kind FROM evm_tx_attempts at
		JOIN evm_nonce_allocations al ON al.chain=at.chain AND al.address=at.address AND al.nonce=at.nonce
		WHERE al.chain=$1 AND al.owner_kind=$2 AND al.owner_id=$3 ORDER BY at.created_at`, s.Cfg.Chain, kind, id)
	if err != nil {
		return nil, err
	}
	var out []evmAttempt
	for rows.Next() {
		var a evmAttempt
		var k string
		if err := rows.Scan(&a.hash, &k); err != nil {
			rows.Close()
			return nil, err
		}
		a.cancel = k == "cancel"
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].rc, out[i].found, err = rr.Receipt(ctx, out[i].hash); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// minedAt is the attempt that has a receipt at or below h (only one attempt per nonce can mine), or nil. above is the attempt whose receipt is
// above h.
func minedAt(atts []evmAttempt, h uint64) (at, above *evmAttempt) {
	for i := range atts {
		a := &atts[i]
		switch {
		case !a.found:
		case a.rc.Block <= h:
			if at == nil {
				at = a
			}
		case above == nil:
			above = a
		}
	}
	return at, above
}

// nativeHot is the account that pays the gas of a transaction signed by the shard of partitionID.
func (s *Service) nativeHot(partitionID string) (string, error) {
	p, err := s.nativePartitionOf(partitionID)
	return hotAcct(p), err
}

// fee puts fee -> hot (native) of the shard.
func (s *Service) adjFee(a *evmAdj, partitionID string, fee *big.Int) error {
	hot, err := s.nativeHot(partitionID)
	if err != nil {
		return err
	}
	a.move(feeAcct(s.Cfg.Chain, s.Cfg.Native), hot, fee)
	return nil
}

// unFee takes back a fee the books recorded for a transaction that has not reached the pinned height.
func (s *Service) adjUnFee(a *evmAdj, partitionID string, fee *big.Int) error {
	hot, err := s.nativeHot(partitionID)
	if err != nil {
		return err
	}
	a.move(hot, feeAcct(s.Cfg.Chain, s.Cfg.Native), fee)
	return nil
}

// evmPending works out what the books lack, or have too early, for every open item (and every item that reverted too early to be final).
func (s *Service) evmPending(ctx context.Context, rr ReceiptReader, h uint64) (*evmAdj, error) {
	c := s.Cfg
	a := newEVMAdj()

	// Sweeps. Booked at broadcast (sweep -> dep); at settlement what moved goes to the sink shard, the excess or shortfall is booked against dep,
	// and the fee comes out of the receiving shard. A cancel that mined books nothing (the sweep ends failed): see the report.
	sweeps, err := s.Pool.Query(ctx, `SELECT `+sweepCols+` FROM sweeps WHERE chain=$1 AND (status NOT IN ('confirmed','failed')
		OR (status='failed' AND failure_reason='transaction reverted' AND updated_at > now() - interval '`+recentRevert+`')) ORDER BY created_at`, c.Chain)
	if err != nil {
		return nil, err
	}
	var sw []Sweep
	for sweeps.Next() {
		x, err := scanSweep(sweeps)
		if err != nil {
			sweeps.Close()
			return nil, err
		}
		sw = append(sw, x)
	}
	sweeps.Close()
	for _, x := range sw {
		atts, err := s.attemptsOf(ctx, rr, "sweep", x.ID)
		if err != nil {
			return nil, err
		}
		at, above := minedAt(atts, h)
		if x.Status == "failed" { // settled as reverted: its fee is in the books; if the revert is above h it is not on the chain yet
			if above != nil && !above.cancel && above.rc.Fee != nil {
				if err := s.adjUnFee(a, x.PartitionID, above.rc.Fee); err != nil {
					return nil, err
				}
			}
			continue
		}
		if at == nil || at.cancel {
			if x.Status == "broadcast" && at == nil {
				a.move(depAcct(c.Chain, x.Asset), sweepAcct(c.Chain, x.Asset), x.Amount) // booked at broadcast, not on the chain yet: take it out
			}
			continue
		}
		a.mined++
		if x.Status != "broadcast" { // a crash between the broadcast and its record: settlement books it first
			a.move(sweepAcct(c.Chain, x.Asset), depAcct(c.Chain, x.Asset), x.Amount)
		}
		movedMain := new(big.Int)
		if at.rc.Success {
			moved, err := s.Chain.MovedAssets(ctx, at.hash)
			if err != nil {
				return nil, err
			}
			byAsset := map[string]*big.Int{}
			for _, m := range moved {
				if m.Address != x.From {
					continue
				}
				addTo(byAsset, m.Asset, m.Amount)
			}
			for _, asset := range sortedKeys(byAsset) {
				amt := byAsset[asset]
				a.move(hotAcct(c.SinkPartition(asset)), sweepAcct(c.Chain, asset), amt)
				if asset != x.Asset { // rode along: all of it is excess
					a.move(sweepAcct(c.Chain, asset), depAcct(c.Chain, asset), amt)
				}
			}
			if m := byAsset[x.Asset]; m != nil {
				movedMain = m
			}
		}
		switch cmp := movedMain.Cmp(x.Amount); {
		case cmp > 0:
			a.move(sweepAcct(c.Chain, x.Asset), depAcct(c.Chain, x.Asset), new(big.Int).Sub(movedMain, x.Amount))
		case cmp < 0:
			a.move(depAcct(c.Chain, x.Asset), sweepAcct(c.Chain, x.Asset), new(big.Int).Sub(x.Amount, movedMain))
		}
		if err := s.adjFee(a, x.PartitionID, at.rc.Fee); err != nil {
			return nil, err
		}
	}

	// Withdrawals. Nothing is booked until settlement: a mined withdrawal books the hold and the payout (wd -> hot) and the fee; a reverted one or a
	// cancel releases the hold and books only the fee.
	wrows, err := s.Pool.Query(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE chain=$1 AND status NOT IN ('confirmed','failed') ORDER BY created_at`, c.Chain)
	if err != nil {
		return nil, err
	}
	var wds []Withdrawal
	for wrows.Next() {
		w, err := scanWd(wrows)
		if err != nil {
			wrows.Close()
			return nil, err
		}
		wds = append(wds, w)
	}
	wrows.Close()
	for _, w := range wds {
		atts, err := s.attemptsOf(ctx, rr, "withdrawal", w.ID)
		if err != nil {
			return nil, err
		}
		at, _ := minedAt(atts, h)
		if at == nil {
			continue
		}
		a.mined++
		if !at.cancel && at.rc.Success {
			addTo(a.delta, hotAcct(w.PartitionID), w.Amount)
		}
		if err := s.adjFee(a, w.PartitionID, at.rc.Fee); err != nil {
			return nil, err
		}
	}

	// Hot-to-cold moves: tocold -> hot at broadcast; cold -> tocold when it mined, hot -> tocold when it reverted; the fee in both cases.
	type move struct {
		kind, id, status, partition, toPartition, asset string
		amount                                          *big.Int
	}
	loadMoves := func(table, kind string) ([]move, error) {
		to := "partition_id"
		if kind == OwnerKindRebalance {
			to = "to_partition_id"
		}
		rows, err := s.Pool.Query(ctx, `SELECT id, status, partition_id, `+to+`, asset, amount::text FROM `+table+` WHERE chain=$1 AND (status NOT IN ('confirmed','failed')
			OR (status='failed' AND failure_reason='transaction reverted' AND updated_at > now() - interval '`+recentRevert+`')) ORDER BY created_at`, c.Chain)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []move
		for rows.Next() {
			m := move{kind: kind}
			var amt string
			if err := rows.Scan(&m.id, &m.status, &m.partition, &m.toPartition, &m.asset, &amt); err != nil {
				return nil, err
			}
			m.amount = parseBig(amt)
			out = append(out, m)
		}
		return out, rows.Err()
	}
	for _, kind := range []string{OwnerKindToCold, OwnerKindRebalance} {
		table, clearAcct := "cold_moves", toColdAcct
		if kind == OwnerKindRebalance {
			table, clearAcct = "rebalance_moves", rebalAcct
		}
		ms, err := loadMoves(table, kind)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			atts, err := s.attemptsOf(ctx, rr, kind, m.id)
			if err != nil {
				return nil, err
			}
			at, above := minedAt(atts, h)
			if m.status == "failed" {
				if above != nil && !above.cancel && above.rc.Fee != nil {
					if err := s.adjUnFee(a, m.partition, above.rc.Fee); err != nil {
						return nil, err
					}
				}
				continue
			}
			if at == nil || at.cancel {
				if m.status == "broadcast" && at == nil {
					a.move(hotAcct(m.partition), clearAcct(c.Chain, m.asset), m.amount) // booked at broadcast, not on the chain yet: take it out
				}
				continue
			}
			a.mined++
			if m.status != "broadcast" {
				a.move(clearAcct(c.Chain, m.asset), hotAcct(m.partition), m.amount) // booked at broadcast: clearing -> hot
			}
			switch {
			case kind == OwnerKindToCold && at.rc.Success:
				a.move(coldAcct(m.partition), clearAcct(c.Chain, m.asset), m.amount)
			case kind == OwnerKindRebalance && at.rc.Success:
				a.move(hotAcct(m.toPartition), clearAcct(c.Chain, m.asset), m.amount)
			default:
				a.move(hotAcct(m.partition), clearAcct(c.Chain, m.asset), m.amount)
			}
			if err := s.adjFee(a, m.partition, at.rc.Fee); err != nil {
				return nil, err
			}
		}
	}

	// Refills: the cold ceremony's transaction is not one of our allocations; its hash is on the row from the moment it is imported.
	rrows, err := s.Pool.Query(ctx, `SELECT `+refillCols+` FROM refills WHERE chain=$1 AND COALESCE(tx_hash,'') <> '' AND (status IN ('signed','broadcast')
		OR (status='failed' AND failure_reason='transaction reverted' AND updated_at > now() - interval '`+recentRevert+`')) ORDER BY created_at`, c.Chain)
	if err != nil {
		return nil, err
	}
	var rfs []Refill
	for rrows.Next() {
		r, err := scanRefill(rrows)
		if err != nil {
			rrows.Close()
			return nil, err
		}
		rfs = append(rfs, r)
	}
	rrows.Close()
	for _, r := range rfs {
		rc, found, err := rr.Receipt(ctx, r.TxHash)
		if err != nil {
			return nil, err
		}
		if r.Status == RefillFailed { // settled as reverted: the fee is in the books
			if found && rc.Block > h && rc.Fee != nil {
				if err := s.adjRefillFee(a, r, new(big.Int).Neg(rc.Fee)); err != nil {
					return nil, err
				}
			}
			continue
		}
		if !found || rc.Block > h {
			if r.Status == RefillBroadcast {
				a.move(coldAcct(r.PartitionID), refillAcct(c.Chain, r.Asset), r.Amount) // booked at broadcast, not on the chain yet: take it out
			}
			continue
		}
		a.mined++
		if r.Status == RefillSigned {
			a.move(refillAcct(c.Chain, r.Asset), coldAcct(r.PartitionID), r.Amount)
		}
		if rc.Success {
			a.move(hotAcct(r.PartitionID), refillAcct(c.Chain, r.Asset), r.Amount)
		} else {
			a.move(coldAcct(r.PartitionID), refillAcct(c.Chain, r.Asset), r.Amount)
		}
		if err := s.adjRefillFee(a, r, rc.Fee); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// adjRefillFee books (or with a negative fee takes back) the fee of a cold transaction as bookColdSignerFee does: out of the cold address when it
// signed, else an operator expense.
func (s *Service) adjRefillFee(a *evmAdj, r Refill, fee *big.Int) error {
	if fee == nil || fee.Sign() == 0 {
		return nil
	}
	c := s.Cfg
	nativePart, err := s.nativePartitionOf(r.PartitionID)
	if err != nil {
		return err
	}
	to := opFundAcct(c.Chain, c.Native)
	if cold, cerr := c.EVM.ColdAddress(nativePart, c.Native); cerr == nil && strings.EqualFold(cold.Hex(), r.ColdAddress) {
		to = coldAcct(nativePart)
	}
	a.move(feeAcct(c.Chain, c.Native), to, fee)
	return nil
}

// evmChecks makes every chain comparison of an EVM cell at height h. unsupported is true when the reader cannot read balances.
func (s *Service) evmChecks(ctx context.Context, rr ReceiptReader, h, cur uint64) (checks []Check, open int, unsupported bool, err error) {
	c := s.Cfg
	checks = append(checks, Check{Name: "scan_caught_up", Ledger: fmt.Sprint(cur), Chain: fmt.Sprint(h + 1), OK: cur > h,
		Detail: "the scan cursor must be past the pinned height"})
	adj, err := s.evmPending(ctx, rr, h)
	if err != nil {
		return nil, 0, false, err
	}
	// The books' open items, as before: what the report shows as in flight.
	if err := s.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM withdrawals WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM cold_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM rebalance_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM refills WHERE chain=$1 AND status IN ('signed','broadcast'))`, c.Chain).Scan(&open); err != nil {
		return nil, 0, false, err
	}
	note := func(_ string, d *big.Int) string {
		if d == nil || d.Sign() == 0 {
			return ""
		}
		return fmt.Sprintf("the ledger side is adjusted by %s for transactions mined at or below the pinned height and not settled yet, for bookings made at broadcast of transactions not mined yet, and for reverts settled before they were final", d)
	}
	adjusted := func(acct string) (*big.Int, *big.Int, error) {
		p, err := s.posted(ctx, acct)
		if err != nil {
			return nil, nil, err
		}
		d := adj.of(acct)
		return new(big.Int).Add(p, d), d, nil
	}
	balance := func(addr, sym string) (*big.Int, bool, error) {
		b, err := s.Reader.Balance(ctx, addr, sym, h)
		if errors.Is(err, chain.ErrNotSupported) {
			return nil, true, nil
		}
		return b, false, err
	}

	// Hot wallets.
	for _, sym := range c.AssetList {
		for i, addr := range c.HotShards {
			p := c.PartitionKey(sym, i).String()
			posted, d, err := adjusted(hotAcct(p))
			if err != nil {
				return nil, 0, false, err
			}
			bal, no, err := balance(addr.Hex(), sym)
			if err != nil {
				return nil, 0, false, err
			}
			if no {
				unsupported = true
				checks = append(checks, Check{Name: "hot", Asset: sym, Subject: addr.Hex(), OK: true, Skipped: true, Detail: "this chain cell cannot read balances yet"})
				continue
			}
			want := new(big.Int).Neg(posted)
			checks = append(checks, Check{Name: "hot", Asset: sym, Subject: addr.Hex(), Ledger: want.String(), Chain: bal.String(), OK: want.Cmp(bal) == 0,
				Detail: note("", new(big.Int).Neg(d))})
		}
	}

	// Cold addresses: several hot partitions (shards) may share one cold address, so their cold accounts are summed.
	if len(c.EVM.ColdAddresses) > 0 {
		type coldKey struct{ addr, asset string }
		sums := map[coldKey]*big.Int{}
		adjs := map[coldKey]*big.Int{}
		var keys []coldKey
		for _, sym := range c.AssetList {
			for i := range c.HotShards {
				p := c.PartitionKey(sym, i).String()
				ca, err := c.EVM.ColdAddress(p, sym)
				if err != nil {
					continue // no cold address configured for this pool and asset class
				}
				posted, d, err := adjusted(coldAcct(p))
				if err != nil {
					return nil, 0, false, err
				}
				k := coldKey{ca.Hex(), sym}
				if sums[k] == nil {
					sums[k], adjs[k] = new(big.Int), new(big.Int)
					keys = append(keys, k)
				}
				sums[k].Sub(sums[k], posted)
				adjs[k].Sub(adjs[k], d)
			}
		}
		for _, k := range keys {
			bal, no, err := balance(k.addr, k.asset)
			if err != nil {
				return nil, 0, false, err
			}
			if no {
				unsupported = true
				checks = append(checks, Check{Name: "cold", Asset: k.asset, Subject: k.addr, OK: true, Skipped: true, Detail: "this chain cell cannot read balances yet"})
				continue
			}
			checks = append(checks, Check{Name: "cold", Asset: k.asset, Subject: k.addr, Ledger: sums[k].String(), Chain: bal.String(), OK: sums[k].Cmp(bal) == 0,
				Detail: note("", adjs[k])})
		}
	}

	// Deposit addresses.
	rows, err := s.Pool.Query(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 ORDER BY address`, c.Chain)
	if err != nil {
		return nil, 0, false, err
	}
	var addrs []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return nil, 0, false, err
		}
		addrs = append(addrs, a)
	}
	rows.Close()
	for _, sym := range c.AssetList {
		sum := new(big.Int)
		no := false
		for _, a := range addrs {
			b, skip, err := balance(a, sym)
			if err != nil {
				return nil, 0, false, err
			}
			if skip {
				no = true
				break
			}
			sum.Add(sum, b)
		}
		if no {
			unsupported = true
			checks = append(checks, Check{Name: "deposit_addresses", Asset: sym, OK: true, Skipped: true, Detail: "this chain cell cannot read balances yet"})
			continue
		}
		posted, d, err := adjusted(depAcct(c.Chain, sym))
		if err != nil {
			return nil, 0, false, err
		}
		want := new(big.Int).Neg(posted)
		checks = append(checks, Check{Name: "deposit_addresses", Asset: sym, Ledger: want.String(), Chain: sum.String(), OK: want.Cmp(sum) == 0,
			Detail: note("", new(big.Int).Neg(d))})
	}

	// Clearing residuals: zero, once the broadcast bookings of the items not mined yet are out and the mined ones are settled.
	for _, sym := range c.AssetList {
		for _, id := range []string{sweepAcct(c.Chain, sym), wdAcct(c.Chain, sym), toColdAcct(c.Chain, sym), rebalAcct(c.Chain, sym), refillAcct(c.Chain, sym)} {
			posted, _, err := adjusted(id)
			if err != nil {
				return nil, 0, false, err
			}
			checks = append(checks, Check{Name: "clearing_residual", Asset: sym, Subject: id, Ledger: posted.String(), Chain: "0", OK: posted.Sign() == 0,
				Detail: "after taking out the broadcast bookings of the transactions not mined yet and settling the ones that are"})
		}
	}
	return checks, open, unsupported, nil
}
