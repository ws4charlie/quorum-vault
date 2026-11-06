package custody

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"

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
	// ChainHeight is the tip a chain-read balance was taken at (Bitcoin reads the node's UTXO set at its tip), 0 if the chain is read at Height.
	ChainHeight uint64  `json:"chain_height,omitempty"`
	InFlight    int     `json:"in_flight"` // open sweeps and withdrawals
	Checks      []Check `json:"checks"`
	Clean       bool    `json:"clean"`
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

	var open int
	if err := s.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM withdrawals WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM cold_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM rebalance_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed'))
		+ (SELECT count(*) FROM refills WHERE chain=$1 AND status IN ('signed','broadcast'))`, c.Chain).Scan(&open); err != nil {
		return rep, err
	}
	rep.InFlight = open

	// The chain side. A chain whose balance read is expensive (Bitcoin: the node is busy during it) is read for all the addresses at once.
	hots := s.hotAddresses()
	chainBal, err := s.batchBalances(ctx, &rep, hots)
	if err != nil {
		return rep, err
	}
	// A chain that settles outputs on its own schedule (Bitcoin) has outputs in flight that the books and the chain see at different times: with
	// anything in flight its chain comparisons are skipped, as the clearing residuals are.
	btcInFlight := c.Family == FamilyBTC && open > 0
	addChain := func(ck Check) {
		if btcInFlight {
			ck.Skipped, ck.Detail = true, fmt.Sprintf("%d sweeps, withdrawals or moves in flight", open)
		}
		rep.add(ck)
	}
	balance := func(addr, sym string) (*big.Int, error) {
		if chainBal != nil {
			if b, ok := chainBal[s.canonAddr(addr)]; ok {
				return b, nil
			}
		}
		return s.Reader.Balance(ctx, addr, sym, h)
	}

	// Hot wallets.
	for _, sym := range c.AssetList {
		for _, hs := range hots {
			posted, err := s.posted(ctx, hotAcct(hs.partition(sym)))
			if err != nil {
				return rep, err
			}
			bal, err := balance(hs.addr, sym)
			if errors.Is(err, chain.ErrNotSupported) {
				rep.add(Check{Name: "hot", Asset: sym, Subject: hs.addr, OK: true, Skipped: true, Detail: "this chain cell cannot read balances yet"})
				continue
			}
			if err != nil {
				return rep, err
			}
			want := new(big.Int).Neg(posted)
			addChain(Check{Name: "hot", Asset: sym, Subject: hs.addr, Ledger: want.String(), Chain: bal.String(), OK: want.Cmp(bal) == 0})
		}
	}

	// Cold addresses: what hot-to-cold moves delivered, per cold address and asset, against the chain. Several hot partitions
	// (shards) may share one cold address, so their cold accounts are summed.
	if len(c.EVM.ColdAddresses) > 0 || len(c.BTC.ColdAddresses) > 0 {
		type coldKey struct{ addr, asset string }
		sums := map[coldKey]*big.Int{}
		var keys []coldKey
		for _, sym := range c.AssetList {
			for i := 0; i < c.shardCount(); i++ {
				p := c.PartitionKey(sym, i).String()
				ca, err := c.ColdAddressOf(p, sym)
				if err != nil {
					continue // no cold address configured for this pool and asset class
				}
				posted, err := s.posted(ctx, coldAcct(p))
				if err != nil {
					return rep, err
				}
				k := coldKey{ca, sym}
				if sums[k] == nil {
					sums[k] = new(big.Int)
					keys = append(keys, k)
				}
				sums[k].Sub(sums[k], posted)
			}
		}
		for _, k := range keys {
			bal, err := balance(k.addr, k.asset)
			if err != nil {
				return rep, err
			}
			addChain(Check{Name: "cold", Asset: k.asset, Subject: k.addr, Ledger: sums[k].String(), Chain: bal.String(), OK: sums[k].Cmp(bal) == 0})
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
	if err := s.batchDeposits(ctx, &rep, addrs, &chainBal); err != nil {
		return rep, err
	}
	for _, sym := range c.AssetList {
		sum := new(big.Int)
		unsupported := false
		for _, a := range addrs {
			b, err := balance(a, sym)
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
		addChain(Check{Name: "deposit_addresses", Asset: sym, Ledger: want.String(), Chain: sum.String(), OK: want.Cmp(sum) == 0,
			Detail: "suspense deposits stay on their address, so they are part of what the chain holds"})
	}

	if c.Family == FamilyBTC {
		if err := s.reconcileOutputs(ctx, &rep, btcInFlight, open); err != nil {
			return rep, err
		}
	}

	// Ledger invariants.
	if err := ledger.CheckInvariants(ctx, s.Pool); err != nil {
		rep.add(Check{Name: "ledger_invariants", OK: false, Detail: err.Error()})
	} else {
		rep.add(Check{Name: "ledger_invariants", OK: true})
	}

	// Clearing residuals.
	for _, sym := range c.AssetList {
		for _, id := range []string{sweepAcct(c.Chain, sym), wdAcct(c.Chain, sym), toColdAcct(c.Chain, sym), rebalAcct(c.Chain, sym), refillAcct(c.Chain, sym)} {
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
	for _, f := range rep.Failures() {
		slog.Error("ALERT: the books and the chain disagree", "chain", c.Chain, "check", f.Name, "subject", f.Subject, "ledger", f.Ledger, "on_chain", f.Chain, "height", rep.Height, "detail", f.Detail)
	}
	return rep, nil
}

// hotAddress is a hot shard's address, with its partition index.
type hotAddress struct {
	addr  string
	shard int
	cfg   *Config
}

func (h hotAddress) partition(asset string) string {
	return h.cfg.PartitionKey(asset, h.shard).String()
}

func (s *Service) hotAddresses() []hotAddress {
	c := s.Cfg
	var out []hotAddress
	if c.Family == FamilyBTC {
		for i, h := range c.BTC.HotShards {
			out = append(out, hotAddress{addr: h.Address, shard: i, cfg: c})
		}
		return out
	}
	for i, a := range c.HotShards {
		out = append(out, hotAddress{addr: a.Hex(), shard: i, cfg: c})
	}
	return out
}

// canonAddr is the chain cell's canonical form of an address, when it has one.
func (s *Service) canonAddr(a string) string {
	if n, ok := s.Chain.(chain.AddressNormalizer); ok {
		if c, err := n.NormalizeAddress(a); err == nil {
			return c
		}
	}
	return a
}

// batchBalances reads the balances of the hot shards and the cold addresses in one call for a chain that offers it; nil otherwise.
func (s *Service) batchBalances(ctx context.Context, rep *Report, hots []hotAddress) (map[string]*big.Int, error) {
	bb, ok := s.Chain.(chain.BatchBalancer)
	if !ok {
		return nil, nil
	}
	set := map[string]bool{}
	for _, h := range hots {
		set[s.canonAddr(h.addr)] = true
	}
	for _, a := range s.Cfg.BTC.ColdAddresses {
		set[s.canonAddr(a)] = true
	}
	addrs := make([]string, 0, len(set))
	for a := range set {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	m, height, err := bb.BalanceBatch(ctx, addrs)
	if err != nil {
		return nil, err
	}
	rep.ChainHeight = height
	return m, nil
}

// batchDeposits adds the deposit addresses to the chain read (a second batch: there can be many of them).
func (s *Service) batchDeposits(ctx context.Context, rep *Report, addrs []string, bal *map[string]*big.Int) error {
	bb, ok := s.Chain.(chain.BatchBalancer)
	if !ok || len(addrs) == 0 {
		return nil
	}
	m, height, err := bb.BalanceBatch(ctx, addrs)
	if err != nil {
		return err
	}
	rep.ChainHeight = height
	if *bal == nil {
		*bal = map[string]*big.Int{}
	}
	for k, v := range m {
		(*bal)[k] = v
	}
	return nil
}

// reconcileOutputs is the third source for a chain that keeps its own outputs (Bitcoin): the output table must agree with the ledger and with the
// chain. Every disagreement is a failed check naming the address, both figures and the height read; nothing is changed.
func (s *Service) reconcileOutputs(ctx context.Context, rep *Report, skip bool, open int) error {
	c := s.Cfg
	add := func(ck Check) {
		if skip {
			ck.Skipped, ck.Detail = true, fmt.Sprintf("%d sweeps, withdrawals or moves in flight", open)
		}
		rep.add(ck)
	}
	for i := range c.BTC.HotShards {
		p := c.PartitionKey(btc.Native, i).String()
		var rows string
		if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(value),0)::text FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND NOT deposit AND status IN ('available','reserved')`,
			c.Chain, p).Scan(&rows); err != nil {
			return err
		}
		posted, err := s.posted(ctx, hotAcct(p))
		if err != nil {
			return err
		}
		want := new(big.Int).Neg(posted)
		add(Check{Name: "hot_outputs", Asset: btc.Native, Subject: p, Ledger: want.String(), Chain: rows, OK: want.Cmp(parseBig(rows)) == 0,
			Detail: "the output table against the ledger"})
	}
	var rows string
	if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(value),0)::text FROM btc_utxos WHERE chain=$1 AND deposit AND status IN ('available','reserved')`, c.Chain).Scan(&rows); err != nil {
		return err
	}
	dep, err := s.posted(ctx, depAcct(c.Chain, btc.Native))
	if err != nil {
		return err
	}
	susp, err := s.posted(ctx, suspenseAcct(c.Chain, btc.Native))
	if err != nil {
		return err
	}
	want := new(big.Int).Neg(dep)
	want.Sub(want, susp) // suspense stays on its address but is not an output the cell sweeps
	add(Check{Name: "deposit_outputs", Asset: btc.Native, Ledger: want.String(), Chain: rows, OK: want.Cmp(parseBig(rows)) == 0,
		Detail: "the deposit outputs in the table against the ledger, without suspense"})

	au, ok := s.Chain.(chain.OutputAuditor)
	if !ok {
		return nil
	}
	diffs, height, err := au.AuditOutputs(ctx)
	if err != nil {
		return err
	}
	if len(diffs) == 0 {
		add(Check{Name: "outputs_on_chain", Asset: btc.Native, OK: true, Ledger: "table", Chain: fmt.Sprintf("chain at %d", height)})
		return nil
	}
	for _, d := range diffs {
		add(Check{Name: "outputs_on_chain", Asset: btc.Native, Subject: d.Address, Ledger: "table", Chain: fmt.Sprintf("chain at %d", height),
			Detail: d.Output + ": " + d.Detail})
	}
	return nil
}
