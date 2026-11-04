package ledger_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

func TestConcurrentOverdraw(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 0, "a", "b")
	inTx(t, pool, func(tx pgx.Tx) error {
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "f", From: "src", To: "a", Amount: bi(300)})
	})
	// 50 x 10 = 500 against a balance of 300: exactly 30 succeed.
	var ok, insufficient atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := withTx(pool, func(tx pgx.Tx) error {
				return l.Transfer(ctx, tx, ledger.TransferReq{ID: fmt.Sprintf("c%d", i), From: "a", To: "b", Amount: bi(10)})
			})
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ledger.ErrInsufficientFunds):
				insufficient.Add(1)
			default:
				t.Errorf("transfer %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 30 || insufficient.Load() != 20 {
		t.Fatalf("ok=%d insufficient=%d", ok.Load(), insufficient.Load())
	}
	if p, _ := bal(t, pool, l, "a"); p != 0 {
		t.Fatalf("a=%d", p)
	}
	if p, _ := bal(t, pool, l, "b"); p != 300 {
		t.Fatalf("b=%d", p)
	}
	invariants(t, pool, l)
}

func TestOpposingTransfersNoDeadlock(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 1_000_000, "a", "b")
	const workers, iters = 8, 100
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			from, to := "a", "b"
			if w%2 == 1 {
				from, to = "b", "a"
			}
			for i := 0; i < iters; i++ {
				err := withTx(pool, func(tx pgx.Tx) error {
					return l.Transfer(ctx, tx, ledger.TransferReq{ID: fmt.Sprintf("o-%d-%d", w, i), From: from, To: to, Amount: bi(1)})
				})
				if err != nil {
					t.Errorf("worker %d iter %d: %v", w, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	pa, _ := bal(t, pool, l, "a")
	pb, _ := bal(t, pool, l, "b")
	if pa != 1_000_000 || pb != 1_000_000 {
		t.Fatalf("a=%d b=%d", pa, pb)
	}
	invariants(t, pool, l)
}

func TestConcurrentSameID(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	for round := 0; round < 5; round++ {
		id := fmt.Sprintf("dup%d", round)
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := withTx(pool, func(tx pgx.Tx) error {
					return l.Transfer(ctx, tx, ledger.TransferReq{ID: id, From: "a", To: "b", Amount: bi(5)})
				}); err != nil {
					t.Errorf("%s: %v", id, err)
				}
			}()
		}
		wg.Wait()
	}
	if p, _ := bal(t, pool, l, "a"); p != 75 {
		t.Fatalf("a=%d, want 75 (each ID applied once)", p)
	}
	invariants(t, pool, l)
}

func TestConcurrentDuplicateHoldAndSettle(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	run := func(fn func(tx pgx.Tx) error) {
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := withTx(pool, fn); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
	}
	run(func(tx pgx.Tx) error {
		return l.Hold(ctx, tx, ledger.HoldReq{ID: "h", Account: "a", CounterAccount: "b", Amount: bi(30)})
	})
	if _, h := bal(t, pool, l, "a"); h != 30 {
		t.Fatalf("held=%d", h)
	}
	run(func(tx pgx.Tx) error { return l.Post(ctx, tx, "h", "p") })
	if p, h := bal(t, pool, l, "a"); p != 70 || h != 0 {
		t.Fatalf("a=%d/%d", p, h)
	}
	invariants(t, pool, l)
}

// Racing Post and Void on one hold: exactly one wins, the other gets ErrHoldNotPending.
func TestPostVoidRace(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	for i := 0; i < 20; i++ {
		h := fmt.Sprintf("h%d", i)
		inTx(t, pool, func(tx pgx.Tx) error {
			return l.Hold(ctx, tx, ledger.HoldReq{ID: h, Account: "a", CounterAccount: "b", Amount: bi(1)})
		})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs[0] = withTx(pool, func(tx pgx.Tx) error { return l.Post(ctx, tx, h, "p-"+h) })
		}()
		go func() {
			defer wg.Done()
			errs[1] = withTx(pool, func(tx pgx.Tx) error { return l.Void(ctx, tx, h, "v-"+h) })
		}()
		wg.Wait()
		wins := 0
		for _, e := range errs {
			if e == nil {
				wins++
			} else if !errors.Is(e, ledger.ErrHoldNotPending) {
				t.Fatalf("%s: %v", h, e)
			}
		}
		if wins != 1 {
			t.Fatalf("%s: %d winners", h, wins)
		}
	}
	invariants(t, pool, l)
}
