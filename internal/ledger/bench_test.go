package ledger_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// TestMeasure prints the throughput table for docs/measurements/ledger.md.
// Run: QV_LEDGER_BENCH=1 go test -run TestMeasure -v -timeout 20m ./internal/ledger/
// Each transfer is one transaction (BEGIN, savepoint, txn insert, two row
// locks, entries, two updates, commit) from the Go client over loopback.
func TestMeasure(t *testing.T) {
	if os.Getenv("QV_LEDGER_BENCH") != "1" {
		t.Skip("set QV_LEDGER_BENCH=1 to run the ledger benchmark")
	}
	dur := 10 * time.Second
	const accounts = 1000
	fmt.Println("| workload | conns | transfers/s | p50 ms | p99 ms | errors |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, workload := range []string{"uniform", "skewed"} {
		for _, conns := range []int{1, 8, 32} {
			base := newDB(t)
			cfg := base.Config().Copy()
			cfg.MaxConns = int32(conns)
			cfg.MinConns = int32(conns)
			pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			l := ledger.New()
			names := make([]string, accounts)
			for i := range names {
				names[i] = fmt.Sprintf("acct-%04d", i)
			}
			seed(t, base, l, 1_000_000_000, names...)

			var mu sync.Mutex
			var lats []time.Duration
			var errs int
			var wg sync.WaitGroup
			start := time.Now()
			deadline := start.Add(dur)
			for w := 0; w < conns; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					rng := rand.New(rand.NewSource(int64(w) + 1))
					var local []time.Duration
					var lerr, n int
					for time.Now().Before(deadline) {
						from := names[rng.Intn(accounts)]
						to := names[rng.Intn(accounts)]
						if workload == "skewed" {
							// 90% of transfers credit one hot account.
							if rng.Intn(10) < 9 {
								to = names[0]
							}
						}
						if from == to {
							continue
						}
						n++
						id := fmt.Sprintf("b-%s-%d-%d-%d", workload, conns, w, n)
						t0 := time.Now()
						err := withTx(pool, func(tx pgx.Tx) error {
							return l.Transfer(ctx, tx, ledger.TransferReq{ID: id, From: from, To: to, Amount: bi(1)})
						})
						local = append(local, time.Since(t0))
						if err != nil {
							lerr++
						}
					}
					mu.Lock()
					lats = append(lats, local...)
					errs += lerr
					mu.Unlock()
				}()
			}
			wg.Wait()
			elapsed := time.Since(start)
			sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
			pct := func(p float64) float64 {
				return float64(lats[int(float64(len(lats)-1)*p)].Microseconds()) / 1000
			}
			fmt.Printf("| %s | %d | %.0f | %.2f | %.2f | %d |\n", workload, conns,
				float64(len(lats))/elapsed.Seconds(), pct(0.50), pct(0.99), errs)
			invariants(t, base, l)
			pool.Close()
		}
	}
}
