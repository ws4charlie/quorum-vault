package sol

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// A close of a nonce account is pinned to the key that built it: when the other generation is activated between build and record, and between record and
// finish, the rows of the old key's pool are the ones recorded and marked, and the new key's pool is untouched.
func TestNonceCloseStaysWithTheKeyThatBuiltIt(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	oldK, newK := pub(t), pub(t)
	part := "qv-us/sol-t/SOL/hot/omnibus/0"
	shard, _ := partition.NewShardID("qv-us", "sol-t", "omnibus", 0)
	a := &Adapter{cfg: &validatedConfig{Config: Config{Chain: "sol-t", NoncePool: 2}, hot: map[string][32]byte{part: oldK}}, pool: pool}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := partition.RegisterInitial(ctx, tx, "t", shard, Address(oldK), "", nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, h := range [][32]byte{oldK, newK} {
		if _, err := pool.Exec(ctx, `INSERT INTO sol_nonce_accounts (chain, address, hot_address, idx, retired_at) VALUES ('sol-t',$1,$2,0,now())`, Address(NonceAddress(h, 0)), Address(h)); err != nil {
			t.Fatal(err)
		}
	}
	step := func(f func(tx pgx.Tx) error) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := f(tx); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	activate := func() { // candidate, draining, active: the new key serves the shard
		step(func(tx pgx.Tx) error {
			if _, err := partition.RegisterCandidate(ctx, tx, "t", shard, Address(newK), "ref", nil); err != nil {
				return err
			}
			if _, err := partition.StartDraining(ctx, tx, "t", shard, 1); err != nil {
				return err
			}
			_, err := partition.Activate(ctx, tx, "t", shard, 2)
			return err
		})
	}
	old := Address(oldK)
	// the close of the old key's account is built (hot pinned = old), then generation 2 is activated
	activate()
	if err := a.RecordNonceCloseTx(ctx, part, old, 0, "sigA"); err != nil {
		t.Fatal(err)
	}
	sigOf := func(h [32]byte) string {
		var s *string
		if err := pool.QueryRow(ctx, `SELECT close_tx FROM sol_nonce_accounts WHERE chain='sol-t' AND address=$1`, Address(NonceAddress(h, 0))).Scan(&s); err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return *s
	}
	if sigOf(oldK) != "sigA" || sigOf(newK) != "" {
		t.Fatalf("recorded on the wrong pool: old %q new %q", sigOf(oldK), sigOf(newK))
	}
	// after the record, still pinned: the lookup and the mark follow the old key
	if got, err := a.NonceCloseTx(ctx, part, old, 0); err != nil || got != "sigA" {
		t.Fatalf("recorded signature %q %v", got, err)
	}
	if err := a.MarkNonceClosed(ctx, part, old, 0); err != nil {
		t.Fatal(err)
	}
	var closedOld, closedNew bool
	_ = pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM sol_nonce_accounts WHERE address=$1`, Address(NonceAddress(oldK, 0))).Scan(&closedOld)
	_ = pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM sol_nonce_accounts WHERE address=$1`, Address(NonceAddress(newK, 0))).Scan(&closedNew)
	if !closedOld || closedNew {
		t.Fatalf("closed: old %v new %v", closedOld, closedNew)
	}
	// a key that is no generation of the shard cannot be pinned
	if err := a.RecordNonceCloseTx(ctx, part, Address(pub(t)), 0, "x"); err == nil {
		t.Fatal("a stranger's key was pinned")
	}
}
