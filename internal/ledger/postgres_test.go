package ledger_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

var ctx = context.Background()

func TestEnsureAccount(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	a := acct("a", false)
	inTx(t, pool, func(tx pgx.Tx) error { return l.EnsureAccount(ctx, tx, a) })
	inTx(t, pool, func(tx pgx.Tx) error { return l.EnsureAccount(ctx, tx, a) }) // identical: no-op

	for name, mod := range map[string]func(*ledger.Account){
		"kind":  func(x *ledger.Account) { x.Kind = ledger.KindHot },
		"asset": func(x *ledger.Account) { x.Asset = "USDC" },
		"neg":   func(x *ledger.Account) { x.AllowNegative = true },
	} {
		b := a
		mod(&b)
		err := withTx(pool, func(tx pgx.Tx) error { return l.EnsureAccount(ctx, tx, b) })
		if !errors.Is(err, ledger.ErrAccountMismatch) {
			t.Errorf("%s: got %v, want ErrAccountMismatch", name, err)
		}
	}
	if err := withTx(pool, func(tx pgx.Tx) error { return l.EnsureAccount(ctx, tx, ledger.Account{}) }); !errors.Is(err, ledger.ErrInvalidRequest) {
		t.Errorf("empty id: %v", err)
	}
}

func TestBalanceUnknown(t *testing.T) {
	pool := newDB(t)
	_, err := ledger.New().Balance(ctx, pool, "nope")
	if !errors.Is(err, ledger.ErrAccountNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestTransfer(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	inTx(t, pool, func(tx pgx.Tx) error {
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "t1", From: "a", To: "b", Amount: bi(30), Metadata: map[string]any{"memo": "x"}})
	})
	if p, _ := bal(t, pool, l, "a"); p != 70 {
		t.Fatalf("a=%d", p)
	}
	if p, _ := bal(t, pool, l, "b"); p != 130 {
		t.Fatalf("b=%d", p)
	}
	var memo string
	if err := pool.QueryRow(ctx, `SELECT metadata->>'memo' FROM ledger_txns WHERE id='t1'`).Scan(&memo); err != nil || memo != "x" {
		t.Fatalf("memo %q %v", memo, err)
	}
	invariants(t, pool, l)
}

func TestTransferErrors(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	inTx(t, pool, func(tx pgx.Tx) error {
		u := acct("u", false)
		u.Asset = "USDC"
		return l.EnsureAccount(ctx, tx, u)
	})
	cases := []struct {
		name string
		req  ledger.TransferReq
		want error
	}{
		{"same", ledger.TransferReq{ID: "e1", From: "a", To: "a", Amount: bi(1)}, ledger.ErrInvalidRequest},
		{"zero", ledger.TransferReq{ID: "e2", From: "a", To: "b", Amount: bi(0)}, ledger.ErrInvalidRequest},
		{"negative", ledger.TransferReq{ID: "e3", From: "a", To: "b", Amount: bi(-5)}, ledger.ErrInvalidRequest},
		{"nil", ledger.TransferReq{ID: "e4", From: "a", To: "b"}, ledger.ErrInvalidRequest},
		{"asset mismatch", ledger.TransferReq{ID: "e5", From: "a", To: "u", Amount: bi(1)}, ledger.ErrInvalidRequest},
		{"unknown from", ledger.TransferReq{ID: "e6", From: "zz", To: "b", Amount: bi(1)}, ledger.ErrAccountNotFound},
		{"unknown to", ledger.TransferReq{ID: "e7", From: "a", To: "zz", Amount: bi(1)}, ledger.ErrAccountNotFound},
		{"insufficient", ledger.TransferReq{ID: "e8", From: "a", To: "b", Amount: bi(101)}, ledger.ErrInsufficientFunds},
		{"empty id", ledger.TransferReq{From: "a", To: "b", Amount: bi(1)}, ledger.ErrInvalidRequest},
		{"reserved key", ledger.TransferReq{ID: "e9", From: "a", To: "b", Amount: bi(1), Metadata: map[string]any{"_qv_body_hash": "x"}}, ledger.ErrInvalidRequest},
	}
	for _, c := range cases {
		err := withTx(pool, func(tx pgx.Tx) error { return l.Transfer(ctx, tx, c.req) })
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	// Failures leave no trace, not even a txn row.
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM ledger_txns WHERE id LIKE 'e%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d txn rows left behind", n)
	}
	invariants(t, pool, l)
}

// A failed op inside a caller tx that keeps going must not leave a txn row
// that would make a later retry look like a replay.
func TestFailedOpDoesNotPoisonTx(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 10, "a", "b")
	inTx(t, pool, func(tx pgx.Tx) error {
		if err := l.Transfer(ctx, tx, ledger.TransferReq{ID: "x", From: "a", To: "b", Amount: bi(50)}); !errors.Is(err, ledger.ErrInsufficientFunds) {
			t.Fatalf("got %v", err)
		}
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "x", From: "a", To: "b", Amount: bi(5)})
	})
	if p, _ := bal(t, pool, l, "b"); p != 15 {
		t.Fatalf("b=%d", p)
	}
}

func TestAllowNegativeSource(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 0, "a")
	inTx(t, pool, func(tx pgx.Tx) error {
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "n", From: "src", To: "a", Amount: bi(7)})
	})
	if p, _ := bal(t, pool, l, "src"); p != -7 {
		t.Fatalf("src=%d", p)
	}
	invariants(t, pool, l)
}

func TestTransferIdempotency(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	req := ledger.TransferReq{ID: "t", From: "a", To: "b", Amount: bi(10), Metadata: map[string]any{"k": "v"}}
	for i := 0; i < 3; i++ {
		inTx(t, pool, func(tx pgx.Tx) error { return l.Transfer(ctx, tx, req) })
	}
	if p, _ := bal(t, pool, l, "a"); p != 90 {
		t.Fatalf("a=%d", p)
	}
	// numerically equal amount built differently is still identical
	same := req
	same.Amount, _ = new(big.Int).SetString("0010", 10)
	inTx(t, pool, func(tx pgx.Tx) error { return l.Transfer(ctx, tx, same) })

	for name, mod := range map[string]func(*ledger.TransferReq){
		"amount": func(r *ledger.TransferReq) { r.Amount = bi(11) },
		"from":   func(r *ledger.TransferReq) { r.From = "b"; r.To = "a" },
		"meta":   func(r *ledger.TransferReq) { r.Metadata = map[string]any{"k": "other"} },
		"nometa": func(r *ledger.TransferReq) { r.Metadata = nil },
	} {
		r := req
		mod(&r)
		err := withTx(pool, func(tx pgx.Tx) error { return l.Transfer(ctx, tx, r) })
		if !errors.Is(err, ledger.ErrIdempotencyConflict) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if p, _ := bal(t, pool, l, "a"); p != 90 {
		t.Fatalf("a=%d after conflicts", p)
	}
	// A replay of a transfer that would no longer be affordable is still nil.
	inTx(t, pool, func(tx pgx.Tx) error {
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "drain", From: "a", To: "b", Amount: bi(90)})
	})
	inTx(t, pool, func(tx pgx.Tx) error { return l.Transfer(ctx, tx, req) })
	invariants(t, pool, l)
}

func TestHoldPostVoid(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	exp := time.Now().Add(time.Hour)
	inTx(t, pool, func(tx pgx.Tx) error {
		if err := l.Hold(ctx, tx, ledger.HoldReq{ID: "h1", Account: "a", CounterAccount: "b", Amount: bi(40), ExpiresAt: &exp}); err != nil {
			return err
		}
		return l.Hold(ctx, tx, ledger.HoldReq{ID: "h2", Account: "a", CounterAccount: "b", Amount: bi(50)})
	})
	if p, h := bal(t, pool, l, "a"); p != 100 || h != 90 {
		t.Fatalf("a=%d/%d", p, h)
	}
	var entries int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM ledger_entries WHERE txn_id IN ('h1','h2')`).Scan(&entries)
	if entries != 0 {
		t.Fatal("hold wrote entries")
	}
	// Available is only 10.
	err := withTx(pool, func(tx pgx.Tx) error {
		return l.Hold(ctx, tx, ledger.HoldReq{ID: "h3", Account: "a", CounterAccount: "b", Amount: bi(11)})
	})
	if !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("got %v", err)
	}
	err = withTx(pool, func(tx pgx.Tx) error {
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "t", From: "a", To: "b", Amount: bi(11)})
	})
	if !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("transfer over held: %v", err)
	}

	inTx(t, pool, func(tx pgx.Tx) error { return l.Post(ctx, tx, "h1", "p1") })
	inTx(t, pool, func(tx pgx.Tx) error { return l.Void(ctx, tx, "h2", "v2") })
	if p, h := bal(t, pool, l, "a"); p != 60 || h != 0 {
		t.Fatalf("a=%d/%d", p, h)
	}
	if p, _ := bal(t, pool, l, "b"); p != 140 {
		t.Fatalf("b=%d", p)
	}
	var st string
	var settled *time.Time
	_ = pool.QueryRow(ctx, `SELECT status, settled_at FROM ledger_holds WHERE id='h2'`).Scan(&st, &settled)
	if st != "voided" || settled == nil {
		t.Fatalf("h2 %s %v", st, settled)
	}
	var kind string
	_ = pool.QueryRow(ctx, `SELECT kind FROM ledger_txns WHERE id='v2'`).Scan(&kind)
	if kind != "void" {
		t.Fatalf("kind %s", kind)
	}
	invariants(t, pool, l)
}

func TestHoldErrors(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	inTx(t, pool, func(tx pgx.Tx) error {
		u := acct("u", false)
		u.Asset = "USDC"
		return l.EnsureAccount(ctx, tx, u)
	})
	cases := []struct {
		name string
		req  ledger.HoldReq
		want error
	}{
		{"same", ledger.HoldReq{ID: "x1", Account: "a", CounterAccount: "a", Amount: bi(1)}, ledger.ErrInvalidRequest},
		{"zero", ledger.HoldReq{ID: "x2", Account: "a", CounterAccount: "b", Amount: bi(0)}, ledger.ErrInvalidRequest},
		{"asset", ledger.HoldReq{ID: "x3", Account: "a", CounterAccount: "u", Amount: bi(1)}, ledger.ErrInvalidRequest},
		{"unknown", ledger.HoldReq{ID: "x4", Account: "a", CounterAccount: "zz", Amount: bi(1)}, ledger.ErrAccountNotFound},
		{"insufficient", ledger.HoldReq{ID: "x5", Account: "a", CounterAccount: "b", Amount: bi(101)}, ledger.ErrInsufficientFunds},
	}
	for _, c := range cases {
		err := withTx(pool, func(tx pgx.Tx) error { return l.Hold(ctx, tx, c.req) })
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	invariants(t, pool, l)
}

func TestHoldIdempotency(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	req := ledger.HoldReq{ID: "h", Account: "a", CounterAccount: "b", Amount: bi(40)}
	inTx(t, pool, func(tx pgx.Tx) error { return l.Hold(ctx, tx, req) })
	inTx(t, pool, func(tx pgx.Tx) error { return l.Hold(ctx, tx, req) })
	if _, h := bal(t, pool, l, "a"); h != 40 {
		t.Fatalf("held=%d", h)
	}
	diff := req
	diff.Amount = bi(41)
	if err := withTx(pool, func(tx pgx.Tx) error { return l.Hold(ctx, tx, diff) }); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("got %v", err)
	}
	// replay still nil after settlement
	inTx(t, pool, func(tx pgx.Tx) error { return l.Post(ctx, tx, "h", "p") })
	inTx(t, pool, func(tx pgx.Tx) error { return l.Hold(ctx, tx, req) })
	invariants(t, pool, l)
}

func TestSettleErrors(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	for _, id := range []string{"h1", "h2", "h3"} {
		inTx(t, pool, func(tx pgx.Tx) error {
			return l.Hold(ctx, tx, ledger.HoldReq{ID: id, Account: "a", CounterAccount: "b", Amount: bi(10)})
		})
	}
	// unknown hold
	if err := withTx(pool, func(tx pgx.Tx) error { return l.Post(ctx, tx, "nope", "p") }); !errors.Is(err, ledger.ErrHoldNotFound) {
		t.Fatalf("got %v", err)
	}
	// txnID already used by something else while the hold is pending
	if err := withTx(pool, func(tx pgx.Tx) error { return l.Post(ctx, tx, "h1", "h2") }); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("got %v", err)
	}
	inTx(t, pool, func(tx pgx.Tx) error { return l.Post(ctx, tx, "h1", "p1") })
	inTx(t, pool, func(tx pgx.Tx) error { return l.Post(ctx, tx, "h1", "p1") }) // replay
	inTx(t, pool, func(tx pgx.Tx) error { return l.Void(ctx, tx, "h2", "v2") })
	inTx(t, pool, func(tx pgx.Tx) error { return l.Void(ctx, tx, "h2", "v2") }) // replay

	for name, fn := range map[string]func(tx pgx.Tx) error{
		"post other txn":    func(tx pgx.Tx) error { return l.Post(ctx, tx, "h1", "p-other") },
		"void after post":   func(tx pgx.Tx) error { return l.Void(ctx, tx, "h1", "v1") },
		"void with post id": func(tx pgx.Tx) error { return l.Void(ctx, tx, "h1", "p1") },
		"post after void":   func(tx pgx.Tx) error { return l.Post(ctx, tx, "h2", "p2") },
		"post with void id": func(tx pgx.Tx) error { return l.Post(ctx, tx, "h2", "v2") },
		"post other hold":   func(tx pgx.Tx) error { return l.Post(ctx, tx, "h2", "p1") },
	} {
		if err := withTx(pool, fn); !errors.Is(err, ledger.ErrHoldNotPending) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if p, h := bal(t, pool, l, "a"); p != 90 || h != 10 {
		t.Fatalf("a=%d/%d", p, h)
	}
	invariants(t, pool, l)
}

func TestRollbackLeavesNoTrace(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a", "b")
	boom := errors.New("boom")
	err := withTx(pool, func(tx pgx.Tx) error {
		if err := l.Transfer(ctx, tx, ledger.TransferReq{ID: "r", From: "a", To: "b", Amount: bi(60)}); err != nil {
			return err
		}
		if err := l.Hold(ctx, tx, ledger.HoldReq{ID: "rh", Account: "b", CounterAccount: "a", Amount: bi(5)}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ledger_txns WHERE id IN ('r','rh')) + (SELECT count(*) FROM ledger_holds)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows survived rollback", n)
	}
	if p, h := bal(t, pool, l, "a"); p != 100 || h != 0 {
		t.Fatalf("a=%d/%d", p, h)
	}
	inTx(t, pool, func(tx pgx.Tx) error {
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "r", From: "a", To: "b", Amount: bi(60)})
	})
	if p, _ := bal(t, pool, l, "a"); p != 40 {
		t.Fatalf("a=%d", p)
	}
	invariants(t, pool, l)
}

func TestInvariantsDetectCorruption(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a")
	invariants(t, pool, l)
	// Break posted without an entry; the zero-sum and posted-vs-entries checks must fire.
	if _, err := pool.Exec(ctx, `UPDATE ledger_accounts SET posted = posted + 1 WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckInvariants(ctx, pool); err == nil {
		t.Fatal("corruption not detected")
	}
	if _, err := pool.Exec(ctx, `UPDATE ledger_accounts SET posted = posted - 1 WHERE id='a'; UPDATE ledger_accounts SET held = 1 WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckInvariants(ctx, pool); err == nil {
		t.Fatal("held corruption not detected")
	}
}

func TestClearingResidual(t *testing.T) {
	pool := newDB(t)
	l := ledger.New()
	seed(t, pool, l, 100, "a")
	inTx(t, pool, func(tx pgx.Tx) error {
		c := acct("deposits_pending", true)
		c.Kind = ledger.KindClearing
		if err := l.EnsureAccount(ctx, tx, c); err != nil {
			return err
		}
		return l.Transfer(ctx, tx, ledger.TransferReq{ID: "c1", From: "deposits_pending", To: "a", Amount: bi(25)})
	})
	got, err := ledger.ClearingResidual(ctx, pool)
	if err != nil || len(got) != 1 || got["deposits_pending"].Int64() != -25 {
		t.Fatalf("%v %v", got, err)
	}
	got, err = l.ClearingResidual(ctx, pool, "a", "src")
	if err != nil || got["a"].Int64() != 125 || got["src"].Int64() != -100 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ledger.ClearingResidual(ctx, pool, "zz"); !errors.Is(err, ledger.ErrAccountNotFound) {
		t.Fatalf("got %v", err)
	}
}
