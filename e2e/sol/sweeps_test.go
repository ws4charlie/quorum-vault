package sole2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// ---- helpers ----

// watchReconcile asks for Reconcile every few hundred milliseconds while a sweep runs and collects every check that FAILED (a report that skipped a
// comparison because the chain was moving is not a failure): the comparisons at every stage of the flow, not only before and after.
func (s *wdSys) watchReconcile() (stop func() []string) {
	done := make(chan struct{})
	var mu sync.Mutex
	var bad []string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case <-time.After(400 * time.Millisecond):
			}
			resp, err := http.Get(s.apiURL + "/v2/reconcile")
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var rep struct {
				Checks []struct {
					Name, Asset, Subject, Ledger, Chain string
					OK, Skipped                         bool
				} `json:"checks"`
			}
			if json.Unmarshal(b, &rep) != nil {
				continue
			}
			for _, c := range rep.Checks {
				if !c.OK && !c.Skipped {
					mu.Lock()
					bad = append(bad, fmt.Sprintf("%s %s %s: books %s chain %s", c.Name, c.Asset, c.Subject, c.Ledger, c.Chain))
					mu.Unlock()
				}
			}
		}
	}()
	return func() []string {
		close(done)
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bad...)
	}
}

type swRow struct {
	ID, Asset, Status, Reason, Hash string
	Amount, Moved                   string
	Items                           int
}

func (s *wdSys) sweeps() []swRow {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT w.id, w.asset, w.status, COALESCE(w.failure_reason,''), COALESCE(w.tx_hash,''), w.amount::text, COALESCE(w.moved::text,''),
		(SELECT count(*) FROM sweep_items i WHERE i.sweep_id=w.id) FROM sweeps w WHERE w.chain=$1 ORDER BY w.created_at`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []swRow
	for rows.Next() {
		var r swRow
		if err := rows.Scan(&r.ID, &r.Asset, &r.Status, &r.Reason, &r.Hash, &r.Amount, &r.Moved, &r.Items); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (s *wdSys) confirmedSweeps() int {
	return s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND status='confirmed'`, s.chain)
}

func (s *wdSys) openSweeps() int {
	return s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed')`, s.chain)
}

// waitSwept waits until nothing is open and the given addresses hold nothing of the asset ("SOL" or the token).
func (s *wdSys) waitSwept(what string, asset string, addrs ...string) {
	s.t.Helper()
	s.waitFor(180*time.Second, what, func() bool {
		if s.openSweeps() > 0 {
			return false
		}
		for _, a := range addrs {
			if asset == "SOL" && s.lamports(a) != 0 {
				return false
			}
			if asset != "SOL" && s.tokensOf(a) != 0 {
				return false
			}
		}
		return true
	})
}

// rawOfAttempt is the transaction of one attempt: the signatures of all its jobs (the hot shard first, then each deposit key) and the message.
func rawOfAttempt(t testing.TB, s *wdSys, attempt string) []byte {
	t.Helper()
	var sigs [][]byte
	var msg []byte
	for i := 0; ; i++ {
		id := attempt
		if i > 0 {
			id = fmt.Sprintf("%s.%d", attempt, i)
		}
		j, err := signjob.Get(s.ctx, s.pool, id)
		if err != nil {
			break
		}
		if j.Status != signjob.StatusDone {
			t.Fatalf("job %s is %s", id, j.Status)
		}
		sigs = append(sigs, j.Signature)
		var p sol.Payload
		if err := json.Unmarshal(j.Payload, &p); err != nil {
			t.Fatal(err)
		}
		msg = p.Message
	}
	raw := []byte{byte(len(sigs))}
	for _, sg := range sigs {
		raw = append(raw, sg...)
	}
	return append(raw, msg...)
}

func (s *wdSys) attemptsOfSweep(id string) []string {
	rows, err := s.pool.Query(s.ctx, `SELECT id FROM sign_jobs WHERE starts_with(id, $1) AND position('.' in substr(id, $2)) = 0 AND status='done' ORDER BY created_at, id`,
		"sweep:"+id+":", len("sweep:"+id+":")+1)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		rows.Scan(&a)
		out = append(out, a)
	}
	return out
}

func (s *wdSys) restartWorkerWithConfig(mod func()) {
	s.t.Helper()
	s.worker.stop()
	mod()
	writeJSONFile(s.t, s.cfgPath, s.cf)
	s.startWorker("")
}

// depositAddr creates a customer and returns its deposit address.
func (s *wdSys) depositAddr(customer string) string { return s.newCustomer(customer) }

// ---- the flows ----

// dumpScan says where the deposit scan and the sweeps stand, for a test that waited for a credit that never came.
func (s *wdSys) dumpScan() {
	slot, _ := s.c.rpc.Slot(s.ctx, sol.Finalized)
	s.t.Logf("finalized slot %d, scan cursor %d", slot, s.cursor())
	t0 := time.Now()
	r, err := s.adapter.Scan(s.ctx, uint64(s.cursor()))
	s.t.Logf("a scan from the cursor takes %s, finds %d deposits, error %v", time.Since(t0), len(r.Deposits), err)
	rows, err := s.pool.Query(s.ctx, `SELECT customer_id, d.address, d.amount::text, d.status, COALESCE(d.block_height,0) FROM deposits d LEFT JOIN deposit_addresses a ON a.address=d.address ORDER BY d.created_at DESC LIMIT 8`)
	if err == nil {
		for rows.Next() {
			var c, a, amt, st string
			var h int64
			rows.Scan(&c, &a, &amt, &st, &h)
			s.t.Logf("deposit customer=%s address=%s amount=%s status=%s height=%d", c, a, amt, st, h)
		}
		rows.Close()
	}
	for _, r := range s.sweeps() {
		s.t.Logf("sweep %+v", r)
	}
	for _, id := range []string{"scan:" + s.chain, "sweep-planner:" + s.chain} {
		d, err := s.tc.DescribeWorkflowExecution(s.ctx, id, "")
		if err != nil {
			s.t.Logf("workflow %s: %v", id, err)
			continue
		}
		s.t.Logf("workflow %s: %s, history %d, %d pending activities", id, d.WorkflowExecutionInfo.Status, d.WorkflowExecutionInfo.HistoryLength, len(d.PendingActivities))
		for _, pa := range d.PendingActivities {
			s.t.Logf("  pending %s attempt %d state %s last failure %v", pa.ActivityType.Name, pa.Attempt, pa.State, pa.LastFailure.GetMessage())
		}
	}
	s.t.Logf("worker log:\n%s", tail(readLog(s.worker.log)))
}

func TestSwFlows(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 4, minSweep: "5000000", batch: 3})
	t.Cleanup(func() {
		if t.Failed() {
			s.dumpScan()
		}
	})
	s.reconcileClean("a shard that sweeps nothing yet")
	hotBefore := s.lamports(s.hotAddr())
	_ = hotBefore

	s.sub(t, "one_sol_address_is_swept_to_the_hot_shard", func(t *testing.T) {
		stop := s.watchReconcile()
		addr := s.depositAddr("s-one")
		hot0 := s.lamports(s.hotAddr())
		s.paySOL(addr, 2*oneSOL)
		s.waitDeposits("s-one", 2*oneSOL, 0)
		s.waitSwept("the address swept", "SOL", addr)
		if bad := stop(); len(bad) > 0 {
			t.Fatalf("Reconcile failed while the sweep ran: %v", bad)
		}
		sw := s.sweeps()
		last := sw[len(sw)-1]
		if last.Status != "confirmed" || last.Moved != fmt.Sprint(2*oneSOL) || last.Items != 1 {
			t.Fatalf("sweep %+v", last)
		}
		gain := s.lamports(s.hotAddr()) - hot0
		if gain < 2*oneSOL-100_000 || gain > 2*oneSOL {
			t.Fatalf("the hot shard gained %d, want 2 SOL less the fee", gain)
		}
		s.reconcileClean("after the sweep")
		// the customer keeps the balance and the same address
		if a := s.available("s-one", "SOL"); a.Cmp(bigU(2*oneSOL)) != 0 {
			t.Fatalf("available %s", a)
		}
		// a second deposit to the same address is credited and swept again
		s.paySOL(addr, 3*oneSOL)
		s.waitAvailable("s-one", "SOL", 5*oneSOL, 90*time.Second)
		s.waitSwept("the second deposit swept", "SOL", addr)
		s.reconcileClean("after the second sweep")
	})

	s.sub(t, "below_the_threshold_stays", func(t *testing.T) {
		addr := s.depositAddr("s-dust")
		s.paySOL(addr, 1_000_000) // above the rent minimum, worth 0.001 SOL: below min_sweep (0.005)
		s.waitDeposits("s-dust", 1_000_000, 0)
		s.waitScanned()
		s.holds(4*time.Second, "nothing is swept", func() bool { return s.openSweeps() == 0 && s.lamports(addr) == 1_000_000 })
		s.reconcileClean("with dust on a deposit address")
	})

	s.sub(t, "a_batch_of_addresses_is_one_transaction", func(t *testing.T) {
		stop := s.watchReconcile()
		const n = 6
		var addrs []string
		before := len(s.sweeps())
		hot0 := s.lamports(s.hotAddr())
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			a := s.depositAddr(fmt.Sprintf("s-b%d", i))
			addrs = append(addrs, a)
		}
		for i, a := range addrs {
			wg.Add(1)
			go func(i int, a string) {
				defer wg.Done()
				s.paySOL(a, uint64(i+1)*oneSOL)
			}(i, a)
		}
		wg.Wait()
		for i := 0; i < n; i++ {
			s.waitDeposits(fmt.Sprintf("s-b%d", i), uint64(i+1)*oneSOL, 0)
		}
		s.waitSwept("every address swept", "SOL", addrs...)
		if bad := stop(); len(bad) > 0 {
			t.Fatalf("Reconcile failed while the batch ran: %v", bad)
		}
		var total, maxItems int
		for _, r := range s.sweeps()[before:] {
			if r.Items > 3 {
				t.Fatalf("sweep %+v", r)
			}
			if r.Status == "failed" {
				// A sweep that found every nonce account busy or not yet advanced at finalized fails to build and its addresses are planned again.
				if !strings.Contains(r.Reason, "no free nonce account") {
					t.Fatalf("sweep failed for another reason: %+v", r)
				}
				continue
			}
			if r.Status != "confirmed" {
				t.Fatalf("sweep %+v", r)
			}
			total += r.Items
			maxItems = max(maxItems, r.Items)
		}
		if total < n || maxItems < 2 {
			t.Fatalf("%d addresses swept in sweeps of at most %d: the addresses were not batched", total, maxItems)
		}
		want := uint64(n*(n+1)/2) * oneSOL
		if gain := s.lamports(s.hotAddr()) - hot0; gain > want || gain < want-n*100_000 {
			t.Fatalf("the hot shard gained %d, want %d less fees", gain, want)
		}
		s.reconcileClean("after the batches")
	})

	s.sub(t, "token_sweep_without_close_and_with_close", func(t *testing.T) {
		stop := s.watchReconcile()
		addr := s.depositAddr("s-tok")
		src := s.funderTokens(s.mint, 10_000*tknUnit)
		s.payToken(src, s.mint, addr, 1_000*tknUnit)
		s.waitDeposits("s-tok", 0, 1_000*tknUnit)
		s.waitSwept("the token swept", "TKN", addr)
		ata := s.c.ata(addrBytes(t, addr), s.mint.pub)
		if _, err := s.c.rpc.GetAccount(s.ctx, sol.Address(ata), sol.Finalized); err != nil {
			t.Fatalf("the deposit token account is gone without a close: %v", err)
		}
		if bad := stop(); len(bad) > 0 {
			t.Fatalf("Reconcile failed: %v", bad)
		}
		s.reconcileClean("after a token sweep without close")

		// now the address counts as quiet at once: the next token sweep also closes the deposit account, rent to the hot shard
		s.restartWorkerWithConfig(func() { s.cf.Chain.SOL.CloseQuietAfter = "1ms" })
		stop = s.watchReconcile()
		hotRent0 := s.lamports(s.hotAddr())
		s.payToken(src, s.mint, addr, 500*tknUnit)
		s.waitAvailable("s-tok", "TKN", 1_500*tknUnit, 90*time.Second)
		s.waitSwept("the token swept and the account closed", "TKN", addr)
		s.waitFor(60*time.Second, "the deposit token account to be gone", func() bool {
			_, err := s.c.rpc.GetAccount(s.ctx, sol.Address(ata), sol.Finalized)
			return err != nil
		})
		if gain := s.lamports(s.hotAddr()) - hotRent0; gain < s.c.rent(165)-100_000 {
			t.Fatalf("the hot shard got %d lamports, want the rent %d of the closed account less fees", gain, s.c.rent(165))
		}
		if bad := stop(); len(bad) > 0 {
			t.Fatalf("Reconcile failed: %v", bad)
		}
		s.reconcileClean("after a sweep that closed the account")
		// a deposit after the close is credited again: the sender creates the account anew
		s.payToken(src, s.mint, addr, 250*tknUnit)
		s.waitAvailable("s-tok", "TKN", 1_750*tknUnit, 90*time.Second)
		s.waitSwept("swept again after the close", "TKN", addr)
		s.reconcileClean("after the deposit that followed the close")
		s.restartWorkerWithConfig(func() { s.cf.Chain.SOL.CloseQuietAfter = "" })
	})

	s.sub(t, "a_stuck_sweep_is_raised_and_exactly_one_version_lands", func(t *testing.T) {
		addr := s.depositAddr("s-stuck")
		s.proxy.hold.Store(true)
		hot0 := s.lamports(s.hotAddr())
		s.paySOL(addr, 2*oneSOL)
		s.waitDeposits("s-stuck", 2*oneSOL, 0)
		var sw swRow
		s.waitFor(60*time.Second, "two versions broadcast", func() bool {
			for _, r := range s.sweeps() {
				if r.Status == "broadcast" && s.attempts(r.ID) >= 2 {
					sw = r
					return true
				}
			}
			return false
		})
		if s.lamports(addr) != 2*oneSOL {
			t.Fatal("moved while its sends were held")
		}
		s.reconcileClean("broadcast and stuck")
		s.proxy.hold.Store(false)
		s.waitSwept("the sweep landed", "SOL", addr)
		atts := s.attemptsOfSweep(sw.ID)
		if len(atts) < 3 {
			t.Fatalf("%d versions signed, want at least 3", len(atts))
		}
		var prev uint64
		landed := 0
		for _, a := range atts {
			raw := rawOfAttempt(t, s, a)
			if p := priceOf(t, raw); p <= prev {
				t.Fatalf("version %s has price %d after %d", a, p, prev)
			} else {
				prev = p
			}
			if s.statusOf(sigOf(raw)) != nil {
				landed++
			}
		}
		if landed != 1 {
			t.Fatalf("%d of %d versions landed", landed, len(atts))
		}
		for _, a := range atts {
			s.sendDirect(rawOfAttempt(t, s, a))
		}
		time.Sleep(3 * time.Second)
		landed = 0
		for _, a := range atts {
			if s.statusOf(sigOf(rawOfAttempt(t, s, a))) != nil {
				landed++
			}
		}
		if gain := s.lamports(s.hotAddr()) - hot0; landed != 1 || gain > 2*oneSOL || gain < 2*oneSOL-100_000 {
			t.Fatalf("after sending every version again: %d landed, the hot shard gained %d", landed, gain)
		}
		s.reconcileClean("after the fee raise")
	})

	s.sub(t, "a_sweep_that_lands_and_fails_is_voided_and_swept_again", func(t *testing.T) {
		addr := s.depositAddr("s-fail")
		s.proxy.hold.Store(true)
		hot0 := s.lamports(s.hotAddr())
		s.paySOL(addr, 2*oneSOL)
		s.waitDeposits("s-fail", 2*oneSOL, 0)
		s.waitFor(60*time.Second, "the sweep to be broadcast", func() bool {
			for _, r := range s.sweeps() {
				if r.Status == "broadcast" && r.Amount == fmt.Sprint(2*oneSOL) && s.attempts(r.ID) >= 1 {
					return true
				}
			}
			return false
		})
		// 1000 lamports more arrive, not credited yet: the sweep takes the credited 2 SOL and would leave 1000, below the rent minimum, so it fails
		s.paySOL(addr, 1000)
		failedBefore := s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND status='failed'`, s.chain)
		s.proxy.hold.Store(false)
		s.waitFor(90*time.Second, "the sweep to fail on the chain", func() bool {
			return s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND status='failed' AND failure_reason LIKE '%reverted%'`, s.chain) > 0 ||
				s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND status='failed'`, s.chain) > failedBefore
		})
		if s.lamports(addr) != 2*oneSOL+1000 {
			t.Fatalf("the failed sweep moved something: %d", s.lamports(addr))
		}
		s.reconcileClean("after a failed sweep")
		// the dust is credited, the planner sweeps everything once, and nothing is counted twice
		s.waitDeposits("s-fail", 2*oneSOL+1000, 0)
		s.waitSwept("the address swept in the end", "SOL", addr)
		if gain := s.lamports(s.hotAddr()) - hot0; gain > 2*oneSOL+1000 || gain < 2*oneSOL+1000-200_000 {
			t.Fatalf("the hot shard gained %d, want %d less fees (once)", gain, 2*oneSOL+1000)
		}
		s.reconcileClean("after the retry")
	})

	// An uncredited deposit is never swept: every item was credited when its sweep was planned.
	s.sub(t, "only_credited_money_was_ever_planned", func(t *testing.T) {
		n := s.count(`SELECT count(*) FROM sweep_items i JOIN sweeps w ON w.id=i.sweep_id WHERE w.chain=$1 AND i.amount >
			(SELECT COALESCE(sum(d.amount),0) FROM deposits d WHERE d.chain=w.chain AND d.address=i.address AND d.asset=w.asset AND d.status='credited' AND d.updated_at <= w.created_at)`, s.chain)
		if n != 0 {
			t.Fatalf("%d sweep items were larger than what was credited when they were planned", n)
		}
	})

	// What a scan pass costs with this many deposit addresses (the work per pass grows with them, not with the sweeps): a pass over the last 600 slots.
	s.sub(t, "the_cost_of_a_scan_pass", func(t *testing.T) {
		n := s.count(`SELECT count(*) FROM deposit_addresses WHERE chain=$1`, s.chain)
		from := uint64(max(int64(0), s.cursor()-600))
		t0 := time.Now()
		r, err := s.adapter.Scan(s.ctx, from)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("scan pass over 600 slots with %d deposit addresses (%d accounts watched with the token accounts): %s, %d deposits found", n, 2*n, time.Since(t0).Round(time.Millisecond), len(r.Deposits))
	})
}
