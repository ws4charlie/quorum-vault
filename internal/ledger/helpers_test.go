package ledger_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// fataler is satisfied by *testing.T and *rapid.T.
type fataler interface {
	Helper()
	Fatal(args ...any)
}

func bi(n int64) *big.Int { return big.NewInt(n) }

// newDB returns a migrated database with assets evm/ETH and evm/USDC.
func newDB(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.New(t)
	_, err := pool.Exec(context.Background(),
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('evm','ETH',18), ('evm','USDC',6)`)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

// inTx runs fn in a transaction and commits it, failing the test on error.
func inTx(t testing.TB, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) {
	t.Helper()
	if err := withTx(pool, fn); err != nil {
		t.Fatal(err)
	}
}

// withTx runs fn in a transaction: commit on nil, rollback otherwise.
func withTx(pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func acct(id string, allowNeg bool) ledger.Account {
	return ledger.Account{ID: id, Kind: ledger.KindCustomer, Chain: "evm", Asset: "ETH", AllowNegative: allowNeg}
}

// seed creates a negative-allowed "src" account and the named accounts, and
// funds each named account with `fund`.
func seed(t testing.TB, pool *pgxpool.Pool, l *ledger.Postgres, fund int64, names ...string) {
	t.Helper()
	ctx := context.Background()
	inTx(t, pool, func(tx pgx.Tx) error {
		src := acct("src", true)
		src.Kind = ledger.KindSuspense
		if err := l.EnsureAccount(ctx, tx, src); err != nil {
			return err
		}
		for _, n := range names {
			if err := l.EnsureAccount(ctx, tx, acct(n, false)); err != nil {
				return err
			}
			if fund > 0 {
				if err := l.Transfer(ctx, tx, ledger.TransferReq{ID: "fund-" + n, From: "src", To: n, Amount: bi(fund)}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func bal(t fataler, pool *pgxpool.Pool, l *ledger.Postgres, id string) (posted, held int64) {
	t.Helper()
	b, err := l.Balance(context.Background(), pool, id)
	if err != nil {
		t.Fatal(err)
	}
	return b.Posted.Int64(), b.Held.Int64()
}

func invariants(t fataler, pool *pgxpool.Pool, l *ledger.Postgres) {
	t.Helper()
	if err := l.CheckInvariants(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
}
