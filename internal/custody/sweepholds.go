package custody

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Credited deposits that are not swept, and why (docs/runbooks/unswept-deposits.md).
//
// The sweep rule leaves an address alone while its funds are worth less than max(min_sweep, k x the fee of sweeping it). The planner runs every
// plan_interval and looks at every such address again, so the state clears by itself: the fee falls, or the address receives more. What it saw is written to
// sweep_holds at each pass, so an operator can tell this state from a sweep that is stuck. Nothing here moves money or changes the rule.
const (
	ReasonBelowThreshold = "below_sweep_threshold" // waiting: worth less than max(min_sweep, k x fee) now
	ReasonSweepPending   = "sweep_pending"         // a sweep is planned, signing or broadcast
	ReasonSweepFailed    = "sweep_failed"          // the last sweep failed; the planner tries again after its backoff
	ReasonParked         = "parked"                // a sweep needs a person
)

// holdSweep records that the address was left alone at this pass. fee is nil when the funds were under min_sweep and no estimate was asked.
func (s *Service) holdSweep(ctx context.Context, addr, asset string, amount, value, fee, threshold *big.Int) error {
	var fs *string
	if fee != nil {
		v := fee.String()
		fs = &v
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO sweep_holds (chain, address, asset, amount, value, fee, threshold, by_fee)
		VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7::numeric,$8)
		ON CONFLICT (chain, address, asset) DO UPDATE SET amount=EXCLUDED.amount, value=EXCLUDED.value, fee=EXCLUDED.fee, threshold=EXCLUDED.threshold,
			by_fee=EXCLUDED.by_fee, updated_at=now()
			WHERE (sweep_holds.amount, sweep_holds.value, sweep_holds.fee, sweep_holds.threshold, sweep_holds.by_fee) IS DISTINCT FROM (EXCLUDED.amount, EXCLUDED.value, EXCLUDED.fee, EXCLUDED.threshold, EXCLUDED.by_fee)
				OR sweep_holds.updated_at < now() - interval '1 minute'`,
		s.Cfg.Chain, addr, asset, amount.String(), value.String(), fs, threshold.String(), fee != nil)
	return err
}

// releaseHold removes the record of an address: a sweep is planned, or one is open.
func (s *Service) releaseHold(ctx context.Context, addr, asset string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sweep_holds WHERE chain=$1 AND address=$2 AND asset=$3`, s.Cfg.Chain, addr, asset)
	return err
}

// pruneHolds removes the records of addresses that no longer have unswept funds (swept, or emptied).
func (s *Service) pruneHolds(ctx context.Context, un map[[2]string]*big.Int) error {
	var addrs, assets []string
	for k, v := range un {
		if v.Sign() > 0 {
			addrs, assets = append(addrs, k[0]), append(assets, k[1])
		}
	}
	_, err := s.Pool.Exec(ctx, `DELETE FROM sweep_holds h WHERE h.chain=$1 AND NOT EXISTS (
		SELECT 1 FROM unnest($2::text[], $3::text[]) AS u(address, asset) WHERE u.address=h.address AND u.asset=h.asset)`, s.Cfg.Chain, addrs, assets)
	return err
}

// UnsweptDeposit is one credited deposit address whose funds are still there, and why.
type UnsweptDeposit struct {
	Address string `json:"address"`
	Asset   string `json:"asset"`
	Reason  string `json:"reason"`
	Amount  string `json:"amount"` // unswept credited funds, in the asset's base units
	// Below the threshold only: the value in the rule's common unit (wei; Bitcoin: satoshi), the fee estimate of the last pass, and the line the value must reach.
	Value     string     `json:"value,omitempty"`
	Fee       string     `json:"fee,omitempty"`
	Threshold string     `json:"threshold,omitempty"`
	ByFee     *bool      `json:"by_fee,omitempty"` // true: the fee alone holds it; false: it is under min_sweep
	Since     *time.Time `json:"since,omitempty"`  // below the threshold: held since this pass
	SweepID   string     `json:"sweep_id,omitempty"`
	Detail    string     `json:"detail,omitempty"` // sweep status or failure reason
}

// UnsweptGroup counts the addresses of one (asset, reason).
type UnsweptGroup struct {
	Asset  string `json:"asset"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
	Amount string `json:"amount"`
}

// UnsweptReport is the operator's view of credited funds that sit on deposit addresses.
type UnsweptReport struct {
	Groups    []UnsweptGroup   `json:"groups"`
	Items     []UnsweptDeposit `json:"items"`
	Truncated bool             `json:"truncated,omitempty"` // Items holds the first unsweptListLimit
}

const unsweptListLimit = 200

// UnsweptDeposits says, for every deposit address that still holds credited funds and that the sweeper has looked at, which of the four reasons applies.
// An address not yet looked at (credited since the last pass) is not listed: it is neither waiting nor stuck, only new.
func (s *Service) UnsweptDeposits(ctx context.Context) (UnsweptReport, error) {
	rep := UnsweptReport{Groups: []UnsweptGroup{}, Items: []UnsweptDeposit{}}
	un, err := s.unswept(ctx)
	if err != nil {
		return rep, err
	}
	type key = [2]string
	items := map[key]*UnsweptDeposit{}
	// Open sweeps (a Solana sweep lists its addresses in sweep_items).
	rows, err := s.Pool.Query(ctx, `SELECT w.from_address, w.asset, w.id, w.status, COALESCE(w.failure_reason,'') FROM sweeps w WHERE w.chain=$1 AND w.status NOT IN ('confirmed','failed')
		UNION ALL SELECT i.address, w.asset, w.id, w.status, COALESCE(w.failure_reason,'') FROM sweep_items i JOIN sweeps w ON w.id=i.sweep_id WHERE w.chain=$1 AND w.status NOT IN ('confirmed','failed')`, s.Cfg.Chain)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var addr, asset, id, st, reason string
		if err := rows.Scan(&addr, &asset, &id, &st, &reason); err != nil {
			rows.Close()
			return rep, err
		}
		k := key{addr, asset}
		if v := un[k]; v == nil || v.Sign() <= 0 {
			continue
		}
		d := &UnsweptDeposit{Address: addr, Asset: asset, Reason: ReasonSweepPending, SweepID: id, Detail: st, Amount: un[k].String()}
		if strings.HasPrefix(reason, ParkedPrefix) {
			d.Reason, d.Detail = ReasonParked, reason
		}
		items[k] = d
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}
	// The last sweep of each address, when it failed; it counts only if no pass has looked at the address since.
	type failed struct {
		id, reason string
		at         time.Time
	}
	last := map[key]failed{}
	frows, err := s.Pool.Query(ctx, `SELECT DISTINCT ON (from_address, asset) from_address, asset, id, status, COALESCE(failure_reason,''), updated_at FROM sweeps WHERE chain=$1
		ORDER BY from_address, asset, created_at DESC`, s.Cfg.Chain)
	if err != nil {
		return rep, err
	}
	for frows.Next() {
		var addr, asset, id, st, reason string
		var at time.Time
		if err := frows.Scan(&addr, &asset, &id, &st, &reason, &at); err != nil {
			frows.Close()
			return rep, err
		}
		if st == "failed" {
			last[key{addr, asset}] = failed{id, reason, at}
		}
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return rep, err
	}
	holds := map[key]UnsweptDeposit{}
	var heldAt = map[key]time.Time{}
	hrows, err := s.Pool.Query(ctx, `SELECT address, asset, value::text, COALESCE(fee::text,''), threshold::text, by_fee, since, updated_at FROM sweep_holds WHERE chain=$1`, s.Cfg.Chain)
	if err != nil {
		return rep, err
	}
	for hrows.Next() {
		var d UnsweptDeposit
		var by bool
		var since, upd time.Time
		if err := hrows.Scan(&d.Address, &d.Asset, &d.Value, &d.Fee, &d.Threshold, &by, &since, &upd); err != nil {
			hrows.Close()
			return rep, err
		}
		d.Reason, d.ByFee, d.Since = ReasonBelowThreshold, &by, &since
		holds[key{d.Address, d.Asset}], heldAt[key{d.Address, d.Asset}] = d, upd
	}
	hrows.Close()
	if err := hrows.Err(); err != nil {
		return rep, err
	}
	for k, v := range un {
		if v.Sign() <= 0 || items[k] != nil {
			continue
		}
		f, wasFailed := last[k]
		h, held := holds[k]
		switch {
		case held && !(wasFailed && f.at.After(heldAt[k])):
			h.Amount = v.String()
			items[k] = &h
		case wasFailed:
			items[k] = &UnsweptDeposit{Address: k[0], Asset: k[1], Reason: ReasonSweepFailed, Amount: v.String(), SweepID: f.id, Detail: f.reason}
		}
	}
	keys := make([]key, 0, len(items))
	groups := map[key]*UnsweptGroup{}
	sums := map[key]*big.Int{}
	for k, d := range items {
		keys = append(keys, k)
		gk := key{d.Asset, d.Reason}
		if groups[gk] == nil {
			groups[gk], sums[gk] = &UnsweptGroup{Asset: d.Asset, Reason: d.Reason}, new(big.Int)
		}
		groups[gk].Count++
		sums[gk].Add(sums[gk], parseBig(d.Amount))
	}
	for gk, g := range groups {
		g.Amount = sums[gk].String()
		rep.Groups = append(rep.Groups, *g)
	}
	sort.Slice(rep.Groups, func(i, j int) bool {
		if rep.Groups[i].Asset != rep.Groups[j].Asset {
			return rep.Groups[i].Asset < rep.Groups[j].Asset
		}
		return rep.Groups[i].Reason < rep.Groups[j].Reason
	})
	sort.Slice(keys, func(i, j int) bool {
		return keys[i][0] < keys[j][0] || (keys[i][0] == keys[j][0] && keys[i][1] < keys[j][1])
	})
	for i, k := range keys {
		if i == unsweptListLimit {
			rep.Truncated = true
			break
		}
		rep.Items = append(rep.Items, *items[k])
	}
	return rep, nil
}

// SweepHoldMetrics serves the held-deposit metrics, read from sweep_holds at each scrape (the worker's metrics endpoint serves it: cmd/qv-worker,
// workermetrics.Registry.AddWriter(m.Write)):
//
//	qv_sweep_held_addresses{chain,asset,cause}       deposit addresses left alone because their funds are under the sweep threshold
//	qv_sweep_held_amount{chain,asset,cause}          their total, in the asset's base units
//	qv_sweep_held_oldest_seconds{chain,asset,cause}  the age of the oldest
//
// cause is "fee" (the value reached min_sweep: only the fee holds it, and it clears when the fee falls) or "min_sweep" (under the floor: it clears only when more
// arrives). A scrape that cannot read says so with qv_sweep_held_metrics_error 1 and no series. The metrics endpoint starts before the database is open: until Use,
// Write says nothing.
type SweepHoldMetrics struct{ pool atomic.Pointer[pgxpool.Pool] }

// Use gives the metrics their database.
func (m *SweepHoldMetrics) Use(pool *pgxpool.Pool) { m.pool.Store(pool) }

// Write writes the metrics in the Prometheus text format.
func (m *SweepHoldMetrics) Write(w io.Writer) {
	pool := m.pool.Load()
	if pool == nil {
		return
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rows, err := pool.Query(ctx, `SELECT chain, asset, CASE WHEN by_fee THEN 'fee' ELSE 'min_sweep' END, count(*), COALESCE(sum(amount),0)::text,
			COALESCE(max(extract(epoch FROM now() - since)),0)::bigint FROM sweep_holds GROUP BY 1,2,3 ORDER BY 1,2,3`)
		if err != nil {
			fmt.Fprint(w, "# HELP qv_sweep_held_metrics_error 1 when the held-deposit metrics could not be read from the database.\n# TYPE qv_sweep_held_metrics_error gauge\nqv_sweep_held_metrics_error 1\n")
			return
		}
		defer rows.Close()
		var n, a, o strings.Builder
		for rows.Next() {
			var chain, asset, cause, amount string
			var count, age int64
			if err := rows.Scan(&chain, &asset, &cause, &count, &amount, &age); err != nil {
				fmt.Fprint(w, "qv_sweep_held_metrics_error 1\n")
				return
			}
			l := fmt.Sprintf("{chain=%q,asset=%q,cause=%q}", chain, asset, cause)
			fmt.Fprintf(&n, "qv_sweep_held_addresses%s %d\n", l, count)
			fmt.Fprintf(&a, "qv_sweep_held_amount%s %s\n", l, amount)
			fmt.Fprintf(&o, "qv_sweep_held_oldest_seconds%s %d\n", l, age)
		}
		if rows.Err() != nil {
			fmt.Fprint(w, "qv_sweep_held_metrics_error 1\n")
			return
		}
		fmt.Fprint(w, "# HELP qv_sweep_held_metrics_error 1 when the held-deposit metrics could not be read from the database.\n# TYPE qv_sweep_held_metrics_error gauge\nqv_sweep_held_metrics_error 0\n")
		fmt.Fprint(w, "# HELP qv_sweep_held_addresses Credited deposit addresses left unswept because their funds are under the sweep threshold, by cause (fee or min_sweep).\n# TYPE qv_sweep_held_addresses gauge\n"+n.String())
		fmt.Fprint(w, "# HELP qv_sweep_held_amount Total held below the sweep threshold, in the asset's base units.\n# TYPE qv_sweep_held_amount gauge\n"+a.String())
		fmt.Fprint(w, "# HELP qv_sweep_held_oldest_seconds Seconds since the oldest held address was first left below the sweep threshold.\n# TYPE qv_sweep_held_oldest_seconds gauge\n"+o.String())
	}
}
