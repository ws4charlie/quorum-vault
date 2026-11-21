package custody

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// The deposit scan reads the chain a little behind the safe head: a block arrives, the scan reads it a few seconds later. In between, the chain holds
// deposits the books do not. Reconcile must not call that a difference, and must not stop calling a real one a difference. So:
//
//   - the lag is measured in blocks (safe head + 1 - scan cursor) and is a status: Report.ScanLag, the metric qv_scan_lag_blocks;
//   - it becomes an ALERT (check "scan_caught_up") only when it is above reconcile.max_scan_lag_blocks, or when the cursor has not moved for
//     reconcile.scan_stuck_after while the safe head is ahead of it (a stuck scan);
//   - inside those bounds the deposits (and, on Bitcoin, the operator funding) in the blocks the scan has not read are put on the books' side of the
//     comparison, taken from a read-only Scan of the same range the next scan will credit. So the books and the chain are compared as at the height the
//     scan has reached; anything else (a missing credit at a height the scan has finished, a wrong amount, an unexpected balance) is still a difference
//     and alerts at once.

// scanWatch remembers where the scan cursor was last seen and since when.
type scanWatch struct {
	mu    sync.Mutex
	set   bool
	cur   uint64
	since time.Time
}

// observe records the cursor and returns how long it has been where it is, as far as Reconcile has watched.
func (w *scanWatch) observe(cur uint64, now time.Time) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.set || w.cur != cur {
		w.set, w.cur, w.since = true, cur, now
	}
	return now.Sub(w.since)
}

// stuckFor is how long the cursor has been where it is, without recording a new look (0 if it was never seen there).
func (w *scanWatch) stuckFor(cur uint64, now time.Time) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.set || w.cur != cur {
		return 0
	}
	return now.Sub(w.since)
}

// scanLag is how many blocks of the chain up to the safe head h the scan has not read: 0 when its cursor is past h.
func scanLag(cur, h uint64) uint64 {
	if cur > h {
		return 0
	}
	return h + 1 - cur
}

// scanCheck makes the "scan_caught_up" check and records the lag. It fails (and so alerts) when the scan is behind by more than the bound or
// its cursor has not moved for too long while it is behind. When it is OK the books and the chain may be compared with the lag accounted for.
func (s *Service) scanCheck(cur, h uint64) (Check, uint64) {
	c := s.Cfg
	now := s.Now()
	still := s.scanSeen.observe(cur, now)
	lag := scanLag(cur, h)
	setScanLag(c.Chain, lag, now)
	chk := Check{Name: "scan_caught_up", Ledger: fmt.Sprint(cur), Chain: fmt.Sprint(h + 1), OK: true}
	switch {
	case lag == 0:
		chk.Detail = "the scan cursor is past the pinned height"
	case lag > c.ReconcileMaxScanLag:
		chk.OK = false
		chk.Detail = fmt.Sprintf("the scan is behind by %d blocks, more than the %d allowed (reconcile.max_scan_lag_blocks)", lag, c.ReconcileMaxScanLag)
	case still >= c.ReconcileScanStuckAfter:
		chk.OK = false
		chk.Detail = fmt.Sprintf("the scan is behind by %d blocks and its cursor has not moved for %s (reconcile.scan_stuck_after is %s): the scan is stuck",
			lag, still.Truncate(time.Second), c.ReconcileScanStuckAfter)
	default:
		chk.Detail = fmt.Sprintf("the scan is behind by %d blocks (at most %d allowed); the deposits in those blocks are accounted for in this comparison", lag, c.ReconcileMaxScanLag)
	}
	return chk, lag
}

// pendingScan is what the scan has not booked yet in the blocks it has not read: the result of reading the range from the cursor, without applying it.
type pendingScan struct {
	deposits []chain.ObservedDeposit
	funding  []chain.FundingOutput
	covered  uint64 // the highest height the read covers
	err      error
}

// readPendingScan reads, without applying anything, what the scan will credit next. It is only called when the scan is behind within the bound.
func (s *Service) readPendingScan(ctx context.Context, cur uint64) pendingScan {
	res, err := s.Chain.Scan(ctx, cur)
	if err != nil {
		return pendingScan{err: err}
	}
	return pendingScan{deposits: res.Deposits, funding: res.Funding, covered: res.SafeHeadHeight}
}

// joinNotes joins the non-empty parts of a check's detail.
func joinNotes(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}

// sumDeposits adds up the pending deposits by asset, up to height h (inclusive; 0 = all).
func (p pendingScan) sumDeposits(h uint64) map[string]*big.Int {
	out := map[string]*big.Int{}
	for _, d := range p.deposits {
		if h != 0 && d.BlockHeight > h {
			continue
		}
		addTo(out, d.Asset, d.Amount)
	}
	return out
}

// --- the metric ---------------------------------------------------------------------------------------------------------------------------

type scanLagSample struct {
	lag uint64
	at  time.Time
}

var scanLagGauge sync.Map // chain -> scanLagSample

func setScanLag(chainName string, lag uint64, at time.Time) {
	scanLagGauge.Store(chainName, scanLagSample{lag: lag, at: at})
}

// WriteScanLagMetrics writes the scan lag of every chain this process has run Reconcile for, in the Prometheus text format:
//
//	qv_scan_lag_blocks{chain}                 blocks between the safe head and the scan cursor at the last Reconcile (0: caught up)
//	qv_scan_lag_observed_timestamp_seconds{chain}   when that was measured (an alert on a stale value covers a Reconcile that stopped being called)
func WriteScanLagMetrics(w io.Writer) {
	var chains []string
	scanLagGauge.Range(func(k, _ any) bool { chains = append(chains, k.(string)); return true })
	sort.Strings(chains)
	fmt.Fprintln(w, "# HELP qv_scan_lag_blocks Blocks between the safe head and the deposit scan cursor at the last Reconcile.")
	fmt.Fprintln(w, "# TYPE qv_scan_lag_blocks gauge")
	for _, c := range chains {
		v, _ := scanLagGauge.Load(c)
		fmt.Fprintf(w, "qv_scan_lag_blocks{chain=%q} %d\n", c, v.(scanLagSample).lag)
	}
	fmt.Fprintln(w, "# HELP qv_scan_lag_observed_timestamp_seconds Unix time of the last Reconcile that measured the scan lag.")
	fmt.Fprintln(w, "# TYPE qv_scan_lag_observed_timestamp_seconds gauge")
	for _, c := range chains {
		v, _ := scanLagGauge.Load(c)
		fmt.Fprintf(w, "qv_scan_lag_observed_timestamp_seconds{chain=%q} %d\n", c, v.(scanLagSample).at.Unix())
	}
}

// ScanLagMetrics serves the scan lag metrics, then what next serves (the core's /metrics: cmd/qv-core).
func ScanLagMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		WriteScanLagMetrics(w)
		next.ServeHTTP(w, r)
	})
}
