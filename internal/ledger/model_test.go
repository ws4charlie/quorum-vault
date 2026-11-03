package ledger_test

import (
	"errors"
	"flag"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"pgregory.net/rapid"

	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

type mHold struct {
	acct, counter string
	amount        int64
	status        string // pending | posted | voided
}

type mTransfer struct {
	from, to string
	amount   int64
}

type model struct {
	posted    map[string]int64
	held      map[string]int64
	holds     map[string]*mHold
	transfers map[string]mTransfer
}

func (m *model) avail(a string) int64 { return m.posted[a] - m.held[a] }

func requireErr(rt *rapid.T, got, want error) {
	rt.Helper()
	if !errors.Is(got, want) {
		rt.Fatalf("got %v, want %v", got, want)
	}
}

// TestModel runs random Transfer, Hold, Post, Void and replayed IDs against
// Postgres and an in-memory model, then checks balances and CheckInvariants.
func TestModel(t *testing.T) {
	// Bound the number of checks unless the caller chose one.
	if f := flag.Lookup("rapid.checks"); f != nil && f.Value.String() == f.DefValue {
		n := "40"
		if testing.Short() {
			n = "60" // rapid divides the count by 5 under -short: 12 checks
		}
		_ = f.Value.Set(n)
	}
	pool := newDB(t)
	l := ledger.New()
	names := []string{"a", "b", "c", "d"}
	seed(t, pool, l, 0, names...)

	var run int
	rapid.Check(t, func(rt *rapid.T) {
		run++
		p := fmt.Sprintf("r%d-", run) // IDs are unique per run: the database persists across runs
		m := &model{posted: map[string]int64{}, held: map[string]int64{},
			holds: map[string]*mHold{}, transfers: map[string]mTransfer{}}
		all := append([]string{"src"}, names...)
		for _, n := range all {
			m.posted[n], m.held[n] = bal(rt, pool, l, n)
		}
		transfer := func(id, from, to string, amt int64) {
			err := withTx(pool, func(tx pgx.Tx) error {
				return l.Transfer(ctx, tx, ledger.TransferReq{ID: id, From: from, To: to, Amount: bi(amt)})
			})
			if from != "src" && m.avail(from) < amt {
				requireErr(rt, err, ledger.ErrInsufficientFunds)
				return
			}
			if err != nil {
				rt.Fatalf("transfer: %v", err)
			}
			m.posted[from] -= amt
			m.posted[to] += amt
			m.transfers[id] = mTransfer{from, to, amt}
		}
		transfer(p+"topup", "src", "a", rapid.Int64Range(1, 100).Draw(rt, "topup"))

		acct := rapid.SampledFrom(names)
		var ids, holdIDs []string
		n := rapid.IntRange(5, 40).Draw(rt, "ops")
		for i := 0; i < n; i++ {
			switch rapid.IntRange(0, 5).Draw(rt, "op") {
			case 0, 1:
				from, to := acct.Draw(rt, "from"), acct.Draw(rt, "to")
				amt := rapid.Int64Range(1, 60).Draw(rt, "amt")
				if from == to {
					continue
				}
				id := fmt.Sprintf("%st%d", p, i)
				transfer(id, from, to, amt)
				if _, ok := m.transfers[id]; ok {
					ids = append(ids, id)
				}
			case 2:
				from, to := acct.Draw(rt, "hfrom"), acct.Draw(rt, "hto")
				amt := rapid.Int64Range(1, 60).Draw(rt, "hamt")
				if from == to {
					continue
				}
				id := fmt.Sprintf("%sh%d", p, i)
				err := withTx(pool, func(tx pgx.Tx) error {
					return l.Hold(ctx, tx, ledger.HoldReq{ID: id, Account: from, CounterAccount: to, Amount: bi(amt)})
				})
				if m.avail(from) < amt {
					requireErr(rt, err, ledger.ErrInsufficientFunds)
					continue
				}
				if err != nil {
					rt.Fatalf("hold: %v", err)
				}
				m.held[from] += amt
				m.holds[id] = &mHold{from, to, amt, "pending"}
				holdIDs = append(holdIDs, id)
			case 3, 4:
				if len(holdIDs) == 0 {
					continue
				}
				h := rapid.SampledFrom(holdIDs).Draw(rt, "hold")
				post := rapid.Bool().Draw(rt, "post")
				id := fmt.Sprintf("%sv%d", p, i)
				if post {
					id = fmt.Sprintf("%sp%d", p, i)
				}
				hd := m.holds[h]
				err := withTx(pool, func(tx pgx.Tx) error {
					if post {
						return l.Post(ctx, tx, h, id)
					}
					return l.Void(ctx, tx, h, id)
				})
				if hd.status != "pending" {
					requireErr(rt, err, ledger.ErrHoldNotPending)
					continue
				}
				if err != nil {
					rt.Fatalf("settle: %v", err)
				}
				m.held[hd.acct] -= hd.amount
				hd.status = "voided"
				if post {
					m.posted[hd.acct] -= hd.amount
					m.posted[hd.counter] += hd.amount
					hd.status = "posted"
				}
			case 5: // replay an earlier ID: no-op; same ID with another amount: conflict
				if len(ids)+len(holdIDs) == 0 {
					continue
				}
				id := rapid.SampledFrom(append(append([]string(nil), ids...), holdIDs...)).Draw(rt, "replay")
				if hd, ok := m.holds[id]; ok {
					err := withTx(pool, func(tx pgx.Tx) error {
						return l.Hold(ctx, tx, ledger.HoldReq{ID: id, Account: hd.acct, CounterAccount: hd.counter, Amount: bi(hd.amount)})
					})
					if err != nil {
						rt.Fatalf("hold replay: %v", err)
					}
					continue
				}
				tr := m.transfers[id]
				err := withTx(pool, func(tx pgx.Tx) error {
					return l.Transfer(ctx, tx, ledger.TransferReq{ID: id, From: tr.from, To: tr.to, Amount: bi(tr.amount)})
				})
				if err != nil {
					rt.Fatalf("transfer replay: %v", err)
				}
				err = withTx(pool, func(tx pgx.Tx) error {
					return l.Transfer(ctx, tx, ledger.TransferReq{ID: id, From: tr.from, To: tr.to, Amount: bi(tr.amount + 1)})
				})
				requireErr(rt, err, ledger.ErrIdempotencyConflict)
			}
		}
		for _, n := range all {
			po, he := bal(rt, pool, l, n)
			if po != m.posted[n] || he != m.held[n] {
				rt.Fatalf("%s: db %d/%d, model %d/%d", n, po, he, m.posted[n], m.held[n])
			}
		}
		invariants(rt, pool, l)
	})
}
