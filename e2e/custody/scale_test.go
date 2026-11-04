package custody_test

import (
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// 50 customers, mixed ETH and token deposits, concurrent withdrawals from two
// hot shards. Afterwards the books equal the chain, every outbox row is
// published, and every event is consumed once after de-duplication.
func TestFiftyCustomersConcurrent(t *testing.T) {
	s := newSystem(t, opts{shards: 2})
	const n = 50
	addrs := make([]common.Address, n)
	for i := 0; i < n; i++ {
		addrs[i] = s.newCustomer(fmt.Sprintf("m%02d", i))
	}
	for i := 0; i < n; i++ {
		switch {
		case i == 3: // dust: credited, never worth sweeping
			s.sendETH(addrs[i], big.NewInt(200_000_000_000_000)) // 0.0002 ETH
		case i%2 == 0:
			s.sendETH(addrs[i], eth(2))
		default:
			s.sendETH(addrs[i], eth(1))
			s.mintUSDT(addrs[i], 500_000_000)
		}
	}
	// A token deposit below min_deposit goes to suspense instead of the customer.
	s.mintUSDT(addrs[1], 500)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("m%02d", i)
		switch {
		case i == 3:
			s.waitAvailable(id, "ETH", big.NewInt(200_000_000_000_000), 60*time.Second)
		case i%2 == 0:
			s.waitAvailable(id, "ETH", eth(2), 60*time.Second)
		default:
			s.waitAvailable(id, "USDT", big.NewInt(500_000_000), 60*time.Second)
		}
	}
	s.waitFor(180*time.Second, "every forwarder swept clean (except the dust one)", func() bool {
		if s.openWork() != 0 {
			return false
		}
		for i, a := range addrs {
			if i != 3 && (s.ethBalance(a).Sign() != 0 || s.usdtBalance(a).Sign() != 0) {
				return false
			}
		}
		return true
	})
	if got := s.posted("suspense:" + s.chainName + ":USDT"); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("suspense USDT = %s, want 500", got)
	}
	s.reconcileClean()

	// Concurrent withdrawals: ETH from the even customers, USDT from the odd.
	type job struct {
		id, asset string
		dest      common.Address
		amount    *big.Int
	}
	var jobs []job
	for i := 0; i < n; i++ {
		switch {
		case i == 3:
		case i%2 == 0:
			jobs = append(jobs, job{fmt.Sprintf("m%02d", i), "ETH", randAddr(), new(big.Int).Div(eth(3), big.NewInt(10))})
		default:
			jobs = append(jobs, job{fmt.Sprintf("m%02d", i), "USDT", randAddr(), big.NewInt(100_000_000)})
		}
	}
	ids := make([]string, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			w := s.withdraw("initiator", "k-"+j.id, j.id, j.asset, j.dest, j.amount)
			if w.Code != 201 {
				t.Errorf("withdraw %s: %d %v", j.id, w.Code, w.Raw)
			}
			ids[i] = w.ID
		}()
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	for _, id := range ids {
		s.waitWd(id, "confirmed", 240*time.Second)
	}
	for _, j := range jobs {
		if got := s.chainBalance(j.asset, j.dest); got.Cmp(j.amount) != 0 {
			t.Fatalf("%s: destination holds %s, want %s", j.id, got, j.amount)
		}
	}
	s.waitIdle(60 * time.Second)
	rep := s.reconcileClean()
	used := map[string]int{}
	rows, _ := s.pool.Query(s.ctx, `SELECT partition_id, count(*) FROM withdrawals GROUP BY 1`)
	for rows.Next() {
		var p string
		var c int
		rows.Scan(&p, &c)
		used[p] = c
	}
	rows.Close()
	t.Logf("%d withdrawals over partitions %v; reconcile clean at %d", len(jobs), used, rep.Height)
	s.checkKafka(90 * time.Second)
}
