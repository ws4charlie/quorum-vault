// Package dbtest gives each test its own freshly migrated Postgres database,
// so tests (and parallel hands) never share state.
//
// If DATABASE_URL is unset or unreachable the test is skipped, unless
// QV_REQUIRE_DB=1 (CI and every hand's verification), then it fails.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db"
)

// New creates database qv_test_<random> on the DATABASE_URL server, migrates
// it and returns a pool. Cleanup closes the pool and drops the database.
func New(t testing.TB) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		unavailable(t, "DATABASE_URL is not set (see .env.example; `make db-up`)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		unavailable(t, "connect %s: %v", redact(url), err)
	}
	defer admin.Close(ctx)

	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	name := "qv_test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("dbtest: create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, url)
		if err != nil {
			t.Errorf("dbtest: drop %s: %v", name, err)
			return
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("dbtest: drop %s: %v", name, err)
		}
	})

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("dbtest: parse DATABASE_URL: %v", err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("dbtest: open %s: %v", name, err)
	}
	t.Cleanup(pool.Close) // registered last, runs before the drop
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("dbtest: migrate: %v", err)
	}
	return pool
}

func unavailable(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_DB") == "1" {
		t.Fatalf("dbtest (QV_REQUIRE_DB=1): "+format, args...)
	}
	t.Skipf("dbtest: "+format, args...)
}

func redact(url string) string {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return "<DATABASE_URL>"
	}
	return cfg.Host + "/" + cfg.Database
}
