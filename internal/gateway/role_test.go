package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/migrations"
)

// The role qv_gateway reaches sign_jobs and nothing else.
func TestGatewayRoleIsConfinedToSignJobs(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET ROLE qv_gateway`); err != nil {
		t.Fatalf("set role: %v", err)
	}
	defer conn.Exec(ctx, `RESET ROLE`)

	ok := []string{
		`SELECT count(*) FROM sign_jobs`,
		`UPDATE sign_jobs SET status = status`,
	}
	for _, q := range ok {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	denied := []string{
		`INSERT INTO sign_jobs (id, partition_id, key_ref, chain, intent, digest, payload) VALUES ('x','p','k','c','{}','\x01','{}')`,
		`DELETE FROM sign_jobs`,
		`TRUNCATE sign_jobs`,
		`SELECT * FROM outbox`,
		`UPDATE outbox SET published_at = now()`,
		`INSERT INTO outbox (id, topic, key, payload) VALUES (gen_random_uuid(), 't', 'k', '{}')`,
		`SELECT * FROM partitions`,
		`SELECT * FROM assets`,
		`SELECT * FROM evm_nonces`,
		`SELECT * FROM schema_migrations`,
		`CREATE TABLE approvers (a text)`,
	}
	for _, q := range denied {
		_, err := conn.Exec(ctx, q)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: err = %v, want permission denied", q, err)
		}
		// A failed statement aborts nothing outside a transaction, but keep the session clean.
	}
	// Every table of the business schema other than sign_jobs is out of reach.
	conn.Exec(ctx, `RESET ROLE`)
	rows, err := conn.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	conn.Exec(ctx, `SET ROLE qv_gateway`)
	for _, n := range tables {
		if n == "sign_jobs" {
			continue
		}
		if _, err := conn.Exec(ctx, `SELECT 1 FROM `+n+` LIMIT 1`); err == nil {
			t.Errorf("role can read %s", n)
		}
	}
}

// Roles are cluster-global: the migration must be repeatable, including on a
// server where another database already created the role.
func TestGatewayRoleMigrationIsRepeatable(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t) // already ran 0004
	sql, err := migrations.FS.ReadFile("0004_gateway_role.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

// The replay guard is a different database from the job queue.
func TestGuardLivesInItsOwnDatabase(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var n int
	h.guardDB.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('sign_jobs','outbox','accounts')`).Scan(&n)
	if n != 0 {
		t.Fatal("guard database contains business tables")
	}
	h.biz.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('signed_intents','signed_digests','nonce_claims')`).Scan(&n)
	if n != 0 {
		t.Fatal("business database contains guard tables")
	}
}
