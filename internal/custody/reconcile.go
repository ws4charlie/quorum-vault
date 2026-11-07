package custody

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
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
	Chain      string `json:"chain"`
	Height     uint64 `json:"height"`      // the pinned safe block height
	ScanCursor uint64 `json:"scan_cursor"` // next height Scan will read
	// ChainHeight is the tip a chain-read balance was taken at (Bitcoin reads the node's UTXO set at its tip); 0 if the chain is read at Height.
	ChainHeight uint64 `json:"chain_height,omitempty"`
	// SkippedChainChecks counts chain comparisons that could not be made (a block kept arriving during the read, or the cell cannot produce the
	// view). A report with any is not Clean: it must not show green when the control did not run.
	SkippedChainChecks int     `json:"skipped_chain_checks"`
	InFlight           int     `json:"in_flight"` // open sweeps and withdrawals
	Checks             []Check `json:"checks"`
	Clean              bool    `json:"clean"`
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
//   - sweep, wd, tocold and rebal residuals are zero when nothing is in flight (otherwise
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

	if c.Family == FamilyBTC {
		if err := s.reconcileBTC(ctx, &rep); err != nil {
			return rep, err
		}
	}

	// Hot wallets.
	for _, sym := range c.AssetList {
		for i, addr := range c.HotShards {
			p := c.PartitionKey(sym, i).String()
			posted, err := s.posted(ctx, hotAcct(p))
			if err != nil {
				return rep, err
			}
			bal, err := s.Reader.Balance(ctx, addr.Hex(), sym, h)
			if errors.Is(err, chain.ErrNotSupported) {
				rep.add(Check{Name: "hot", Asset: sym, Subject: addr.Hex(), OK: true, Skipped: true, Detail: "this chain cell cannot read balances yet"})
				continue
			}
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
		if c.Family == FamilyBTC {
			break // reconcileBTC compared the deposit addresses
		}
		sum := new(big.Int)
		unsupported := false
		for _, a := range addrs {
			b, err := s.Reader.Balance(ctx, a, sym, h)
			if errors.Is(err, chain.ErrNotSupported) {
				unsupported = true
				break
			}
			if err != nil {
				return rep, err
			}
			sum.Add(sum, b)
		}
		if unsupported {
			rep.add(Check{Name: "deposit_addresses", Asset: sym, OK: true, Skipped: true, Detail: "this chain cell cannot read balances yet"})
			continue
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
		+ (SELECT count(*) FROM cold_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM consolidations WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM rebalance_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM refills WHERE chain=$1 AND status IN ('signed','broadcast'))`, c.Chain).Scan(&open); err != nil {
		return rep, err
	}
	rep.InFlight = open
	for _, sym := range c.AssetList {
		for _, id := range []string{sweepAcct(c.Chain, sym), wdAcct(c.Chain, sym), toColdAcct(c.Chain, sym), rebalAcct(c.Chain, sym), refillAcct(c.Chain, sym)} {
			p, err := s.posted(ctx, id)
			if err != nil {
				return rep, err
			}
			ck := Check{Name: "clearing_residual", Asset: sym, Subject: id, Ledger: p.String(), Chain: "0", OK: p.Sign() == 0}
			if c.Family == FamilyBTC {
				// Bitcoin books a sweep and a move at broadcast, so the clearing accounts hold exactly what is broadcast and not settled.
				want, err := s.btcClearing(ctx, id)
				if err != nil {
					return rep, err
				}
				ck.Chain, ck.OK = want.String(), p.Cmp(want) == 0
			} else if open > 0 {
				ck.Skipped, ck.Detail = true, fmt.Sprintf("%d sweeps or withdrawals in flight", open)
			}
			rep.add(ck)
		}
	}
	rep.Clean = len(rep.Failures()) == 0 && rep.SkippedChainChecks == 0
	for _, f := range rep.Failures() {
		slog.Error("ALERT: the books and the chain disagree", "chain", c.Chain, "check", f.Name, "subject", f.Subject, "ledger", f.Ledger, "on_chain", f.Chain, "height", rep.Height, "chain_height", rep.ChainHeight, "detail", f.Detail)
	}
	return rep, nil
}

// btcClearing is what a clearing account must hold on Bitcoin: a sweep is booked at broadcast (sweep -> dep) and a move to cold too (tocold -> hot), and
// both are undone or finished at settlement, so the sweep account holds minus the sweeps in broadcast and the to-cold account minus the moves in
// broadcast; a withdrawal is posted and paid out in one transaction, so the others hold nothing.
func (s *Service) btcClearing(ctx context.Context, acct string) (*big.Int, error) {
	c := s.Cfg
	var q string
	switch acct {
	case sweepAcct(c.Chain, btc.Native):
		q = `SELECT COALESCE(SUM(amount),0)::text FROM sweeps WHERE chain=$1 AND status='broadcast'`
	case toColdAcct(c.Chain, btc.Native):
		q = `SELECT COALESCE(SUM(amount),0)::text FROM cold_moves WHERE chain=$1 AND status='broadcast'`
	case refillAcct(c.Chain, btc.Native):
		q = `SELECT COALESCE(SUM(amount),0)::text FROM refills WHERE chain=$1 AND kind='refill' AND status='broadcast'`
	default:
		return new(big.Int), nil
	}
	var sum string
	if err := s.Pool.QueryRow(ctx, q, c.Chain).Scan(&sum); err != nil {
		return nil, err
	}
	return new(big.Int).Neg(parseBig(sum)), nil
}

// reconcileStamp changes whenever the books change in a way that matters to the chain comparison: a read of the books and of the chain that
// straddles a change is not a consistent pair.
func (s *Service) reconcileStamp(ctx context.Context) (string, error) {
	var st string
	err := s.Pool.QueryRow(ctx, `SELECT concat_ws('|',
		(SELECT max(updated_at)::text FROM btc_utxos WHERE chain=$1), (SELECT max(updated_at)::text FROM sweeps WHERE chain=$1),
		(SELECT max(updated_at)::text FROM withdrawals WHERE chain=$1), (SELECT max(updated_at)::text FROM cold_moves WHERE chain=$1), (SELECT max(updated_at)::text FROM consolidations WHERE chain=$1), (SELECT max(updated_at)::text FROM refills WHERE chain=$1),
		(SELECT count(*)::text FROM deposits WHERE chain=$1), (SELECT count(*)::text FROM btc_attempts WHERE chain=$1 AND broadcast_at IS NOT NULL),
		(SELECT next_height::text FROM chain_cursors WHERE chain=$1))`, s.Cfg.Chain).Scan(&st)
	return st, err
}

// reconcileBTC compares the ledger, the output table and the chain for a Bitcoin cell, in flight or not. The chain is read from the node (the cell's
// ChainView) and put in the terms of the books: what the cell sent but the books have not settled is computed from its own records of those
// transactions (rows spent by a confirmed transaction of ours, outputs of ours not recorded yet, payments not yet deep enough to credit), and the
// books' bookings made at broadcast are undone for the comparison. What is left is a real difference. The read is repeated when a block, or a change in
// the books, arrives during it; only if that keeps happening (3 reads) is the comparison skipped, and then the report says so and is not Clean.
func (s *Service) reconcileBTC(ctx context.Context, rep *Report) error {
	c := s.Cfg
	cv, ok := s.Chain.(chain.ChainViewer)
	if !ok {
		s.skipChainChecks(rep, "this chain cell cannot produce a view of the chain")
		return nil
	}
	hots := make([]string, 0, len(c.BTC.HotShards))
	for _, h := range c.BTC.HotShards {
		hots = append(hots, h.Address)
	}
	var colds []string
	for _, a := range c.BTC.ColdAddresses {
		colds = append(colds, a)
	}
	rows, err := s.Pool.Query(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 ORDER BY address`, c.Chain)
	if err != nil {
		return err
	}
	var deps []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return err
		}
		deps = append(deps, a)
	}
	rows.Close()
	all := append(append(append([]string{}, hots...), colds...), deps...)

	for attempt := 0; attempt < 3; attempt++ {
		h0, err := s.Reader.SafeHead(ctx)
		if err != nil {
			return err
		}
		st0, err := s.reconcileStamp(ctx)
		if err != nil {
			return err
		}
		view, err := cv.ChainView(ctx, all)
		if err != nil {
			return err
		}
		checks, err := s.btcChecks(ctx, view, hots, colds, deps)
		if err != nil {
			return err
		}
		h1, err := s.Reader.SafeHead(ctx)
		if err != nil {
			return err
		}
		st1, err := s.reconcileStamp(ctx)
		if err != nil {
			return err
		}
		if h0 == h1 && st0 == st1 {
			for _, ck := range checks {
				rep.add(ck)
			}
			rep.ChainHeight = view.Height
			s.reconSkipSince.Store(0)
			return nil
		}
	}
	s.skipChainChecks(rep, "a block or a change in the books arrived during each of 3 reads")
	return nil
}

// skipChainChecks records that the chain comparisons could not be made: the report says so and is not Clean, and a run of skips longer than
// reconcile.max_skip raises an ALERT.
func (s *Service) skipChainChecks(rep *Report, why string) {
	rep.SkippedChainChecks++
	rep.add(Check{Name: "chain_comparison", OK: true, Skipped: true, Detail: why})
	now := s.Now().Unix()
	if !s.reconSkipSince.CompareAndSwap(0, now) {
		since := s.reconSkipSince.Load()
		if time.Duration(now-since)*time.Second >= s.Cfg.ReconcileMaxSkip {
			slog.Error("ALERT: the chain comparisons of Reconcile have been skipped for too long; the books are not being checked against the chain",
				"chain", s.Cfg.Chain, "since", time.Unix(since, 0).UTC().Format(time.RFC3339), "max_skip", s.Cfg.ReconcileMaxSkip.String(), "reason", why)
		}
	}
}

func (s *Service) btcChecks(ctx context.Context, v chain.ChainView, hots, colds, deps []string) ([]Check, error) {
	c := s.Cfg
	canon := func(a string) string {
		if n, ok := s.Chain.(chain.AddressNormalizer); ok {
			if x, err := n.NormalizeAddress(a); err == nil {
				return x
			}
		}
		return a
	}
	bal := func(a string) *big.Int {
		if b := v.Balance[canon(a)]; b != nil {
			return b
		}
		return new(big.Int)
	}
	spent := func(a string) *big.Int {
		if b := v.SpentInFlight[canon(a)]; b != nil {
			return b
		}
		return new(big.Int)
	}
	var out []Check
	note := func(base string, inflight *big.Int) string {
		if inflight.Sign() == 0 {
			return base
		}
		return fmt.Sprintf("%s; %s sats of rows already spent on chain and not settled are taken out of the ledger side", base, inflight)
	}
	// What was booked at broadcast and is undone for the comparison (a move's amount leaves hot at broadcast, a sweep's enters the clearing account).
	moves := map[string]*big.Int{}
	mrows, err := s.Pool.Query(ctx, `SELECT partition_id, SUM(amount)::text FROM cold_moves WHERE chain=$1 AND status='broadcast' GROUP BY partition_id`, c.Chain)
	if err != nil {
		return nil, err
	}
	for mrows.Next() {
		var p, amt string
		if err := mrows.Scan(&p, &amt); err != nil {
			mrows.Close()
			return nil, err
		}
		moves[p] = parseBig(amt)
	}
	mrows.Close()
	var sweeping string
	if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0)::text FROM sweeps WHERE chain=$1 AND status='broadcast'`, c.Chain).Scan(&sweeping); err != nil {
		return nil, err
	}

	for i, h := range c.BTC.HotShards {
		p := c.PartitionKey(btc.Native, i).String()
		posted, err := s.posted(ctx, hotAcct(p))
		if err != nil {
			return nil, err
		}
		booked := new(big.Int).Neg(posted)
		if m := moves[p]; m != nil {
			booked.Add(booked, m)
		}
		want := new(big.Int).Sub(booked, spent(h.Address))
		out = append(out, Check{Name: "hot", Asset: btc.Native, Subject: h.Address, Ledger: want.String(), Chain: bal(h.Address).String(), OK: want.Cmp(bal(h.Address)) == 0,
			Detail: note(fmt.Sprintf("read at chain height %d", v.Height), spent(h.Address))})
		var rows string
		if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(value),0)::text FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND NOT deposit AND status IN ('available','reserved')`,
			c.Chain, p).Scan(&rows); err != nil {
			return nil, err
		}
		out = append(out, Check{Name: "hot_outputs", Asset: btc.Native, Subject: p, Ledger: booked.String(), Chain: rows, OK: booked.Cmp(parseBig(rows)) == 0,
			Detail: "the output table against the ledger"})
	}

	// What a refill booked at broadcast (refill -> cold) is undone for the comparison, per partition, as a move's is on the hot side.
	refilling := map[string]*big.Int{}
	rrows, err := s.Pool.Query(ctx, `SELECT partition_id, SUM(amount)::text FROM refills WHERE chain=$1 AND kind='refill' AND status='broadcast' GROUP BY partition_id`, c.Chain)
	if err != nil {
		return nil, err
	}
	for rrows.Next() {
		var p, amt string
		if err := rrows.Scan(&p, &amt); err != nil {
			rrows.Close()
			return nil, err
		}
		refilling[p] = parseBig(amt)
	}
	rrows.Close()
	sums := map[string]*big.Int{}
	var keys []string
	for i := 0; i < c.shardCount(); i++ {
		p := c.PartitionKey(btc.Native, i).String()
		ca, err := c.ColdAddressOf(p, btc.Native)
		if err != nil {
			continue
		}
		posted, err := s.posted(ctx, coldAcct(p))
		if err != nil {
			return nil, err
		}
		if sums[ca] == nil {
			sums[ca] = new(big.Int)
			keys = append(keys, ca)
		}
		sums[ca].Sub(sums[ca], posted)
		if m := refilling[p]; m != nil {
			sums[ca].Add(sums[ca], m)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		want := new(big.Int).Sub(sums[k], spent(k))
		out = append(out, Check{Name: "cold", Asset: btc.Native, Subject: k, Ledger: want.String(), Chain: bal(k).String(), OK: want.Cmp(bal(k)) == 0,
			Detail: note(fmt.Sprintf("read at chain height %d", v.Height), spent(k))})
		var rows string
		if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(value),0)::text FROM btc_utxos WHERE chain=$1 AND cold AND address=$2 AND status IN ('available','reserved')`,
			c.Chain, canon(k)).Scan(&rows); err != nil {
			return nil, err
		}
		out = append(out, Check{Name: "cold_outputs", Asset: btc.Native, Subject: k, Ledger: sums[k].String(), Chain: rows, OK: sums[k].Cmp(parseBig(rows)) == 0,
			Detail: "the cold outputs in the table against the ledger"})
	}

	dep, err := s.posted(ctx, depAcct(c.Chain, btc.Native))
	if err != nil {
		return nil, err
	}
	susp, err := s.posted(ctx, suspenseAcct(c.Chain, btc.Native))
	if err != nil {
		return nil, err
	}
	booked := new(big.Int).Neg(dep)
	booked.Add(booked, parseBig(sweeping))
	onDeposit, spentDeposit := new(big.Int), new(big.Int)
	for _, a := range deps {
		onDeposit.Add(onDeposit, bal(a))
		spentDeposit.Add(spentDeposit, spent(a))
	}
	want := new(big.Int).Sub(booked, spentDeposit)
	out = append(out, Check{Name: "deposit_addresses", Asset: btc.Native, Ledger: want.String(), Chain: onDeposit.String(), OK: want.Cmp(onDeposit) == 0,
		Detail: note(fmt.Sprintf("suspense deposits stay on their address, so they are part of what the chain holds; read at chain height %d", v.Height), spentDeposit)})
	var rows string
	if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(value),0)::text FROM btc_utxos WHERE chain=$1 AND deposit AND status IN ('available','reserved')`, c.Chain).Scan(&rows); err != nil {
		return nil, err
	}
	wantRows := new(big.Int).Sub(booked, susp) // suspense stays on its address but is not an output the cell sweeps
	out = append(out, Check{Name: "deposit_outputs", Asset: btc.Native, Ledger: wantRows.String(), Chain: rows, OK: wantRows.Cmp(parseBig(rows)) == 0,
		Detail: "the deposit outputs in the table against the ledger, without suspense"})

	if len(v.Diffs) == 0 {
		out = append(out, Check{Name: "outputs_on_chain", Asset: btc.Native, OK: true, Ledger: "table", Chain: fmt.Sprintf("chain at %d", v.Height),
			Detail: fmt.Sprintf("%d outputs explained as not settled yet", v.Unsettled)})
	}
	for _, d := range v.Diffs {
		out = append(out, Check{Name: "outputs_on_chain", Asset: btc.Native, Subject: d.Address, Ledger: "table", Chain: fmt.Sprintf("chain at %d", v.Height), Detail: d.Output + ": " + d.Detail})
	}
	return out, nil
}
