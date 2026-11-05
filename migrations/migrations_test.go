package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

func seed(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('eth', 'ETH', 18), ('eth', 'USDC', 6)`,
		`INSERT INTO ledger_accounts (id, kind, chain, asset, allow_negative) VALUES
			('a', 'customer', 'eth', 'ETH', false),
			('b', 'customer', 'eth', 'ETH', false),
			('u', 'customer', 'eth', 'USDC', false)`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func TestApplyOnTopOfInit(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t) // applies 0001 then 0002
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE name IN ('0001_init.sql', '0002_custody_core.sql')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("applied migrations = %d, err %v; want 2", n, err)
	}
	if err := db.Migrate(ctx, pool); err != nil { // idempotent
		t.Fatalf("second Migrate: %v", err)
	}
	for _, tbl := range []string{"assets", "partitions", "customers", "ledger_accounts", "ledger_txns",
		"ledger_entries", "ledger_holds", "deposit_addresses", "deposits", "withdrawals", "sweeps",
		"evm_nonces", "evm_nonce_allocations", "sign_jobs", "outbox"} {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, tbl).Scan(&ok); err != nil || !ok {
			t.Errorf("table %s missing (err %v)", tbl, err)
		}
	}
}

func TestNoApproverKeysInBusinessDB(t *testing.T) {
	pool := dbtest.New(t)
	var ok bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('approver_keys') IS NOT NULL`).Scan(&ok); err != nil || ok {
		t.Errorf("approver_keys exists (err %v): approver keys must live in signing-zone config", err)
	}
}

func TestLedgerEntriesMustBalanceAtCommit(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	seed(t, ctx, pool)

	insert := func(txn string, amounts map[string]string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `INSERT INTO ledger_txns (id, kind) VALUES ($1, 'transfer')`, txn); err != nil {
			return err
		}
		for acct, amt := range amounts {
			if _, err := tx.Exec(ctx, `INSERT INTO ledger_entries (txn_id, account_id, amount) VALUES ($1, $2, $3::numeric)`, txn, acct, amt); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}

	if err := insert("bad1", map[string]string{"a": "10", "b": "-5"}); err == nil || !strings.Contains(err.Error(), "unbalanced") {
		t.Errorf("unbalanced txn: err = %v, want unbalanced", err)
	}
	// Sums to zero across assets, but not per (chain, asset): must fail.
	if err := insert("bad2", map[string]string{"a": "10", "u": "-10"}); err == nil {
		t.Error("cross-asset txn summing to zero overall was accepted")
	}
	if err := insert("ok1", map[string]string{"a": "10", "b": "-10"}); err != nil {
		t.Errorf("balanced txn: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ledger_entries`).Scan(&n); err != nil || n != 2 {
		t.Errorf("entries = %d, err %v; want only the balanced txn's 2", n, err)
	}
}

func TestLedgerEntriesAppendOnly(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	seed(t, ctx, pool)
	if _, err := pool.Exec(ctx, `WITH t AS (INSERT INTO ledger_txns (id, kind) VALUES ('t1', 'transfer'))
		INSERT INTO ledger_entries (txn_id, account_id, amount) VALUES ('t1', 'a', 0)`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE ledger_entries SET amount = 1`,
		`DELETE FROM ledger_entries`,
		`TRUNCATE ledger_entries`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want append-only", q, err)
		}
	}
}

func TestNonNegativeAccount(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	seed(t, ctx, pool)
	if _, err := pool.Exec(ctx, `UPDATE ledger_accounts SET posted = 100 WHERE id = 'a'`); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"below zero":          `UPDATE ledger_accounts SET posted = -1 WHERE id = 'a'`,
		"hold exceeds posted": `UPDATE ledger_accounts SET held = 101 WHERE id = 'a'`,
		"negative hold":       `UPDATE ledger_accounts SET held = -1 WHERE id = 'a'`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE ledger_accounts SET held = 100 WHERE id = 'a'`); err != nil {
		t.Errorf("held == posted should be allowed: %v", err)
	}
	// allow_negative accounts (e.g. clearing) may go below zero.
	if _, err := pool.Exec(ctx, `INSERT INTO ledger_accounts (id, kind, chain, asset, allow_negative, posted)
		VALUES ('c', 'clearing', 'eth', 'ETH', true, -50)`); err != nil {
		t.Errorf("allow_negative account: %v", err)
	}
}

func TestDepositDedupKeyUnique(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	ins := `INSERT INTO deposits (id, chain, asset, address, amount, dedup_key, status)
		VALUES ($1, 'eth', 'ETH', '0xabc', 1, 'eth:0xdead:0', 'seen')`
	if _, err := pool.Exec(ctx, ins, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, ins, "d2"); err == nil || !strings.Contains(err.Error(), "dedup_key") {
		t.Errorf("duplicate dedup_key: err = %v, want unique violation", err)
	}
}

// At most one open rebalance leaves a shard, and at most one open rebalance feeds a shard (per asset); a finished one frees both.
func TestRebalanceOneOpenPerSourceAndPerDestination(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('eth', 'ETH', 18)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES
			('p0','qv-us','eth','ETH','hot','omnibus',0), ('p1','qv-us','eth','ETH','hot','omnibus',1), ('p2','qv-us','eth','ETH','hot','omnibus',2)`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	ins := func(id, from, to, status string) error {
		_, err := pool.Exec(ctx, `INSERT INTO rebalance_moves (id, chain, asset, partition_id, to_partition_id, to_address, amount, status)
			VALUES ($1,'eth','ETH',$2,$3,'0xaa',5,$4)`, id, from, to, status)
		return err
	}
	if err := ins("r1", "p0", "p1", "planned"); err != nil {
		t.Fatal(err)
	}
	if err := ins("r2", "p0", "p2", "planned"); err == nil {
		t.Error("two open rebalances from one shard were accepted")
	}
	if err := ins("r3", "p2", "p1", "planned"); err == nil {
		t.Error("two open rebalances to one shard were accepted")
	}
	if err := ins("r4", "p1", "p1", "planned"); err == nil {
		t.Error("a rebalance from a shard to itself was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE rebalance_moves SET status='confirmed' WHERE id='r1'`); err != nil {
		t.Fatal(err)
	}
	if err := ins("r5", "p0", "p2", "planned"); err != nil {
		t.Errorf("a finished rebalance still blocks the shard: %v", err)
	}
}
