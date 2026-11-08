package mpcsign_test

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// raiseCaps lifts the daily caps of the test policy so thousands of 1-wei signatures are not refused by a rule the soak is
// not about. Both the gateway and the cosigner get the same change.
func raiseCaps(f gateway.File) gateway.File {
	for name, cf := range f.Chains {
		for sym, a := range cf.Assets {
			a.DailyCap = "1000000000000000000000"
			a.PerTxCap = "1000000000000000000"
			cf.Assets[sym] = a
		}
		f.Chains[name] = cf
	}
	return f
}

type sample struct {
	at           time.Duration
	rss, threads map[string]int
}

// TestSoakWholePath signs at a steady rate through the whole path (jobs table -> gateway workers -> party A -> party B ->
// cosigner -> Postgres guards) and watches the memory and threads of every process. Off by default:
//
//	QV_MPC_SOAK=1 [QV_MPC_SOAK_MINUTES=10] [QV_MPC_SOAK_RATE=50] make test-mpc-soak
func TestSoakWholePath(t *testing.T) {
	if os.Getenv("QV_MPC_SOAK") != "1" {
		t.Skip("soak: set QV_MPC_SOAK=1")
	}
	minutes, rate := 10, 50
	if v, _ := strconv.Atoi(os.Getenv("QV_MPC_SOAK_MINUTES")); v > 0 {
		minutes = v
	}
	if v, _ := strconv.Atoi(os.Getenv("QV_MPC_SOAK_RATE")); v > 0 {
		rate = v
	}
	s := newStack(t, stackOpts{})
	s.cosignerTweak = raiseCaps
	s.provision(t, false)
	s.h.File = raiseCaps(s.h.File)

	const workers = 8
	var gws []*proc
	for i := 0; i < workers; i++ {
		gws = append(gws, s.startGateway(fmt.Sprintf("w%d", i)))
	}
	time.Sleep(time.Second)

	pids := func() map[string]int {
		m := map[string]int{"party-A": s.a.cmd.Process.Pid, "party-B": s.b.cmd.Process.Pid, "party-C": s.c.cmd.Process.Pid, "cosigner": s.cosigner.cmd.Process.Pid, "cosigner-C": s.cosignerC.cmd.Process.Pid}
		for i, g := range gws {
			m[fmt.Sprintf("gateway-%d", i)] = g.cmd.Process.Pid
		}
		return m
	}
	take := func(at time.Duration) sample {
		sm := sample{at: at, rss: map[string]int{}, threads: map[string]int{}}
		for name, pid := range pids() {
			rss, th, err := mpcstack.RSSAndThreads(pid)
			if err != nil {
				t.Errorf("sample %s: %v", name, err)
				continue
			}
			sm.rss[name], sm.threads[name] = rss, th
		}
		return sm
	}

	total := minutes * 60 * rate
	t.Logf("SOAK: %d signatures at %d/s for %d minutes through %d gateway workers", total, rate, minutes, workers)
	start := time.Now()
	samples := []sample{take(0)}

	// Producer: one job every 1/rate second, on a ticker so a slow enqueue does not shift the whole schedule.
	var enq sync.WaitGroup
	enq.Add(1)
	go func() {
		defer enq.Done()
		tick := time.NewTicker(time.Second / time.Duration(rate))
		defer tick.Stop()
		for i := 0; i < total; i++ {
			<-tick.C
			s.enqueue(s.h.Withdrawal(fmt.Sprintf("soak-%d", i), gatewaytest.AddrUser, 1, uint64(i), "alice"))
		}
	}()

	// Watcher: every 30 s, memory, threads and how many jobs are finished.
	countBy := func() (done, bad, open int) {
		rows, err := s.biz.Query(context.Background(), `SELECT status, count(*) FROM sign_jobs GROUP BY status`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var st string
			var n int
			rows.Scan(&st, &n)
			switch st {
			case signjob.StatusDone:
				done += n
			case signjob.StatusPending, signjob.StatusSigning:
				open += n
			default:
				bad += n
			}
		}
		return
	}
	stop := make(chan struct{})
	var watch sync.WaitGroup
	watch.Add(1)
	go func() {
		defer watch.Done()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				sm := take(time.Since(start))
				samples = append(samples, sm)
				done, bad, open := countBy()
				t.Logf("SOAK t=%4.0fs done=%d failed/rejected=%d open=%d  A: rss=%dMB thr=%d  B: rss=%dMB thr=%d  cosigner: rss=%dMB thr=%d",
					sm.at.Seconds(), done, bad, open, sm.rss["party-A"]/1024, sm.threads["party-A"], sm.rss["party-B"]/1024, sm.threads["party-B"],
					sm.rss["cosigner"]/1024, sm.threads["cosigner"])
			}
		}
	}()

	enq.Wait()
	// Drain: everything enqueued must finish.
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if _, _, open := countBy(); open == 0 {
			break
		}
		time.Sleep(time.Second)
	}
	el := time.Since(start)
	close(stop)
	watch.Wait()
	samples = append(samples, take(el))
	done, bad, open := countBy()

	t.Logf("SOAK RESULT: %d done, %d failed or rejected, %d still open after %v = %.1f sig/s", done, bad, open, el.Round(time.Second), float64(done)/el.Seconds())
	report := func(name string) {
		first, last := samples[0], samples[len(samples)-1]
		// "start" for memory is the first sample after the warm-up minute: the first signatures grow caches and thread pools.
		warm := samples[0]
		for _, sm := range samples {
			if sm.at >= time.Minute {
				warm = sm
				break
			}
		}
		t.Logf("SOAK %-9s RSS at start %d MB, after 1 min %d MB, at end %d MB (peak %d MB); threads at start %d, after 1 min %d, at end %d (peak %d)",
			name, first.rss[name]/1024, warm.rss[name]/1024, last.rss[name]/1024, peak(samples, func(s sample) int { return s.rss[name] })/1024,
			first.threads[name], warm.threads[name], last.threads[name], peak(samples, func(s sample) int { return s.threads[name] }))
	}
	for _, n := range []string{"party-A", "party-B", "cosigner", "gateway-0"} {
		report(n)
	}

	if bad != 0 || open != 0 || done != total {
		t.Errorf("not every job signed: done %d of %d, failed/rejected %d, open %d", done, total, bad, open)
	}
	if got := float64(done) / el.Seconds(); got < float64(rate)*0.95 {
		t.Errorf("sustained %.1f sig/s, want about %d", got, rate)
	}
	// Memory and threads of the long-lived mpc-party processes must be flat once warm: allow 25% + 20 MB, and 25% + 8 threads.
	warmIdx := 0
	for i, sm := range samples {
		if sm.at >= time.Minute {
			warmIdx = i
			break
		}
	}
	for _, n := range []string{"party-A", "party-B"} {
		w, l := samples[warmIdx], samples[len(samples)-1]
		if l.rss[n] > w.rss[n]*125/100+20*1024 {
			t.Errorf("%s memory grew: %d MB after 1 min -> %d MB at the end", n, w.rss[n]/1024, l.rss[n]/1024)
		}
		if l.threads[n] > w.threads[n]*125/100+8 {
			t.Errorf("%s threads grew: %d after 1 min -> %d at the end", n, w.threads[n], l.threads[n])
		}
		// A steady climb is a leak even when it stays under the limit: compare the median of the first and last quarter.
		var rs []int
		for _, sm := range samples[warmIdx:] {
			rs = append(rs, sm.rss[n])
		}
		if len(rs) >= 8 {
			q := len(rs) / 4
			a, b := median(rs[:q]), median(rs[len(rs)-q:])
			t.Logf("SOAK %s RSS median of the first quarter %d MB, last quarter %d MB", n, a/1024, b/1024)
		}
	}
}

func peak(ss []sample, f func(sample) int) int {
	m := 0
	for _, s := range ss {
		if v := f(s); v > m {
			m = v
		}
	}
	return m
}

func median(v []int) int {
	c := append([]int(nil), v...)
	sort.Ints(c)
	return c[len(c)/2]
}
