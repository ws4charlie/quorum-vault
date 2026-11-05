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
