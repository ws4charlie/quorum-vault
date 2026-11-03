package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

func TestMigrateIdempotent(t *testing.T) {
	pool := dbtest.New(t) // already migrated once
	ctx := context.Background()
	var before int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before == 0 {
		t.Fatal("no migrations recorded")
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var after int
	pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&after)
	if after != before {
		t.Fatalf("migrations recorded: %d -> %d", before, after)
	}
}

func TestAuditLogAppendOnly(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log (at, actor, type, payload, prev_hash, hash)
		VALUES (now(), 'test', 'wallet.created', '{}', '\x00', '\x01')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	for _, stmt := range []string{
		`UPDATE audit_log SET actor = 'evil'`,
		`DELETE FROM audit_log`,
		`TRUNCATE audit_log`,
	} {
		_, err := pool.Exec(ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "audit_log is append-only") {
			t.Errorf("%s: err = %v, want append-only error", stmt, err)
		}
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE actor = 'test'`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

func TestOneActiveKeyPerWallet(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	var wid string
	if err := pool.QueryRow(ctx, `INSERT INTO wallets (name, tier, backend) VALUES ('w1', 'hot', 'hsm') RETURNING id`).Scan(&wid); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO keys (wallet_id, version, curve, backend, state, public_key, address)
		VALUES ($1, $2, 'secp256k1', 'hsm', $3, '\x04', '0x0')`
	if _, err := pool.Exec(ctx, ins, wid, 1, "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, ins, wid, 2, "active"); err == nil || !strings.Contains(err.Error(), "keys_one_active_per_wallet") {
		t.Fatalf("second active key: err = %v, want unique violation", err)
	}
	if _, err := pool.Exec(ctx, ins, wid, 2, "sign_only"); err != nil {
		t.Fatalf("sign_only key should be allowed: %v", err)
	}
}

func TestSignRequestStatusCheck(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	var wid, kid string
	pool.QueryRow(ctx, `INSERT INTO wallets (name, tier, backend) VALUES ('w', 'cold', 'mpc') RETURNING id`).Scan(&wid)
	if err := pool.QueryRow(ctx, `INSERT INTO keys (wallet_id, version, curve, backend, state, public_key, address)
		VALUES ($1, 1, 'secp256k1', 'mpc', 'active', '\x04', '0x0') RETURNING id`, wid).Scan(&kid); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO sign_requests (wallet_id, key_id, chain_id, to_address, value_wei, nonce, gas_limit,
		max_fee_per_gas, max_priority_fee_per_gas, requester, status)
		VALUES ($1, $2, 11155111, '0xabc', 1, 0, 21000, 1, 1, 'alice', $3)`
	if _, err := pool.Exec(ctx, ins, wid, kid, "pending_approval"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, ins, wid, kid, "bogus"); err == nil {
		t.Fatal("bogus status accepted")
	}
}
