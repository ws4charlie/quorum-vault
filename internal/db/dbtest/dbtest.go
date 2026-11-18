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
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
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

// DSN is a DSN of the pool's database, made from DATABASE_URL so that the TLS settings (sslmode, certificate files) carry over. Build a DSN
// for a spawned program from it, never with a format string.
func DSN(pool *pgxpool.Pool) string {
	return db.Rewrite(os.Getenv("DATABASE_URL"), "", pool.Config().ConnConfig.Database)
}

// SigningURL is the admin DSN of the signing zone's Postgres (QV_SIGNING_DB_URL): the server that holds the replay-guard databases, with its own
// certificate authority. Without it the test is skipped, or fails under QV_REQUIRE_DB=1.
func SigningURL(t testing.TB) string {
	t.Helper()
	u := os.Getenv("QV_SIGNING_DB_URL")
	if u == "" {
		unavailable(t, "QV_SIGNING_DB_URL is not set (the signing zone's Postgres; `make db-up`)")
	}
	return u
}

// CreateGuardDB creates a database for a replay guard on the signing zone's Postgres and returns its DSN. Cleanup drops it. The guard databases
// of the gateway and of the cosigner are made by two calls: they must never be the same database.
func CreateGuardDB(t testing.TB, prefix string) string {
	t.Helper()
	admin := SigningURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("dbtest: connect to the signing zone's Postgres: %v", err)
	}
	defer c.Close(ctx)
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	name := prefix + hex.EncodeToString(b[:])
	if _, err := c.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("dbtest: create %s: %v", name, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c, err := pgx.Connect(ctx, admin); err == nil {
			c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(ctx)
		}
	})
	return db.Rewrite(admin, "", name)
}

// GatewayLogin lets role qv_gateway log in for the test (the migration creates it NOLOGIN) and takes it away at cleanup. The role is
// cluster-global, so tests that use it run one after another, as the e2e packages do.
func GatewayLogin(t testing.TB) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, `ALTER ROLE qv_gateway LOGIN`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c, err := pgx.Connect(ctx, url); err == nil {
			c.Exec(ctx, `ALTER ROLE qv_gateway NOLOGIN`)
			c.Close(ctx)
		}
	})
}

// GatewayJobsDSN is the DSN the gateway reads the job queue with: the restricted role qv_gateway, and the certificate the BUSINESS authority
// issued to the gateway for this one link (name business/gateway-link), which the business Postgres maps to that role and to no other.
func GatewayJobsDSN(bizDSN string) string {
	return pkitest.WithCert(db.Rewrite(bizDSN, "qv_gateway", ""), pki.ZoneBusiness, "gateway-link", pki.ZoneBusiness)
}
