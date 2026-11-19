package db_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// These tests connect the way the services do: a login as the service's own role, with the service's own certificate, against the real
// Postgres server whose pg_ident map is in deploy/postgres. SET ROLE from the owner would not test the map.

type service struct{ cert, role string }

var (
	core    = service{"core", dbtest.RoleCore}
	worker  = service{"worker", dbtest.RoleWorker}
	relay   = service{"relay", dbtest.RoleRelay}
	archive = service{"archiver", dbtest.RoleArchive}
	gateway = service{"gateway-link", "qv_gateway"}
	all     = []service{core, worker, relay, archive, gateway}
)

func connect(t *testing.T, pool *pgxpool.Pool, s service) (*pgx.Conn, error) {
	t.Helper()
	var dsn string
	if s == gateway {
		dbtest.GatewayLogin(t)
		dsn = dbtest.GatewayJobsDSN(dbtest.DSN(pool))
	} else {
		dsn = pkitest.WithCert(dbtest.ServiceDSN(t, dbtest.DSN(pool), s.role), pki.ZoneBusiness, s.cert, pki.ZoneBusiness)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, dsn)
	if err == nil {
		t.Cleanup(func() { c.Close(context.Background()) })
	}
	return c, err
}

func as(t *testing.T, pool *pgxpool.Pool, s service) *pgx.Conn {
	t.Helper()
	c, err := connect(t, pool, s)
	if err != nil {
		t.Fatalf("connect as %s with certificate %s: %v", s.role, s.cert, err)
	}
	return c
}

// denied runs q and wants SQLSTATE 42501 (insufficient_privilege).
func denied(t *testing.T, c *pgx.Conn, who, q string) {
	t.Helper()
	_, err := c.Exec(context.Background(), q)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" {
		t.Errorf("%s: %s: err = %v, want permission denied", who, q, err)
	}
}

func allowed(t *testing.T, c *pgx.Conn, who, q string) {
	t.Helper()
	if _, err := c.Exec(context.Background(), q); err != nil {
		t.Errorf("%s: %s: %v", who, q, err)
	}
}

// A certificate opens its own role and no other.
func TestCertificateMapsToOwnRoleOnly(t *testing.T) {
	pool := dbtest.New(t)
	for _, s := range all {
		as(t, pool, s).Close(context.Background())
	}
	for _, role := range []string{"qv", dbtest.RoleCore, dbtest.RoleWorker, dbtest.RoleRelay, "qv_gateway"} {
		// the relay's certificate may not become any role but its own
		if role == dbtest.RoleRelay {
			continue
		}
		dsn := pkitest.WithCert(dbtest.ServiceDSN(t, dbtest.DSN(pool), dbtest.RoleCore), pki.ZoneBusiness, "relay", pki.ZoneBusiness)
		dsn = db.Rewrite(dsn, role, "")
		if role == "qv_gateway" {
			dbtest.GatewayLogin(t)
		}
		if c, err := pgx.Connect(context.Background(), dsn); err == nil {
			c.Close(context.Background())
			t.Errorf("the relay certificate logged in as %s", role)
		}
	}
	// the owner role is the admin certificate's alone
	dsn := pkitest.WithCert(db.Rewrite(dbtest.DSN(pool), "qv", ""), pki.ZoneBusiness, "worker", pki.ZoneBusiness)
	if c, err := pgx.Connect(context.Background(), dsn); err == nil {
		c.Close(context.Background())
		t.Error("the worker certificate logged in as the owner role")
	}
}

// No service role can change the schema or the cluster, whatever it may read or write.
func TestServiceRolesCannotCreateAlterOrDrop(t *testing.T) {
	pool := dbtest.New(t)
	stmts := []string{
		`CREATE TABLE evil (a int)`,
		`CREATE TEMP TABLE evil (a int)`,
		`CREATE SCHEMA evil`,
		`CREATE FUNCTION evil() RETURNS int LANGUAGE sql AS 'SELECT 1'`,
		`CREATE INDEX evil ON ledger_entries (id)`,
		`CREATE TRIGGER evil BEFORE INSERT ON ledger_entries FOR EACH ROW EXECUTE FUNCTION ledger_entries_zero_sum()`,
		`ALTER TABLE withdrawals ADD COLUMN evil int`,
		`ALTER TABLE ledger_entries DISABLE TRIGGER ALL`,
		`ALTER TABLE ledger_entries OWNER TO qv_relay`,
		`DROP TABLE withdrawals`,
		`DROP TABLE schema_migrations`,
		`DROP TRIGGER ledger_entries_no_update_delete ON ledger_entries`,
		`DROP FUNCTION outbox_prune(interval, int)`,
		`TRUNCATE ledger_entries`,
		`CREATE ROLE evil LOGIN`,
		`ALTER ROLE qv_relay SUPERUSER`,
		`ALTER ROLE qv_core NOLOGIN`,
		`GRANT qv TO qv_core`,
		`SET ROLE qv`,
		`CREATE DATABASE evil`,
	}
	for _, s := range all {
		c := as(t, pool, s)
		for _, q := range stmts {
			_, err := c.Exec(context.Background(), q)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || (pe.Code != "42501" && !strings.Contains(pe.Message, "must be owner") && !strings.Contains(pe.Message, "permission denied")) {
				t.Errorf("%s: %s: err = %v, want permission denied", s.role, q, err)
			}
		}
	}
}

// The relay moves the outbox and the audit chain and cannot touch a ledger, a withdrawal or a job.
func TestRelayCannotRewriteTheLedger(t *testing.T) {
	pool := dbtest.New(t)
	c := as(t, pool, relay)
	for _, q := range []string{
		`UPDATE ledger_accounts SET id = id`,
		`UPDATE ledger_holds SET amount = amount`,
		`UPDATE withdrawals SET amount = amount`,
		`INSERT INTO ledger_entries (txn_id, account_id, amount) VALUES ('t', 'a', 1)`,
		`DELETE FROM ledger_entries`,
		`DELETE FROM withdrawals`,
		`SELECT * FROM withdrawals`,
		`SELECT * FROM ledger_entries`,
		`SELECT * FROM sign_jobs`,
		`UPDATE sign_jobs SET chain = chain`,
		`SELECT * FROM evm_nonces`,
		`UPDATE evm_nonces SET next_nonce = 0`,
		`INSERT INTO sign_jobs (id, partition_id, key_ref, chain, intent, digest, payload) VALUES ('x','p','k','c','{}','\x01','{}')`,
		// an outbox row is immutable apart from its two timestamps, and nobody deletes one by hand
		`UPDATE outbox SET payload = '{}'`,
		`UPDATE outbox SET topic = 'x'`,
		`DELETE FROM outbox`,
		`INSERT INTO outbox (id, topic, key, payload) VALUES (gen_random_uuid(), 't', 'k', '{}')`,
		`UPDATE audit_log SET actor = 'x'`,
		`DELETE FROM audit_log`,
		`TRUNCATE audit_log`,
	} {
		_, err := c.Exec(context.Background(), q)
		var pe *pgconn.PgError
		// the audit trigger may answer before the privilege check only for statements the relay may start; the rest must be a privilege error
		if !errors.As(err, &pe) || pe.Code != "42501" {
			if strings.HasPrefix(q, "UPDATE audit_log") || strings.HasPrefix(q, "DELETE FROM audit_log") || strings.HasPrefix(q, "TRUNCATE audit_log") {
				// not allowed either way: UPDATE/DELETE/TRUNCATE are not granted
				t.Errorf("relay: %s: err = %v, want permission denied", q, err)
				continue
			}
			t.Errorf("relay: %s: err = %v, want permission denied", q, err)
		}
	}
	// what it does need
	allowed(t, c, "relay", `SELECT count(*) FROM outbox`)
	allowed(t, c, "relay", `UPDATE outbox SET published_at = now() WHERE false`)
	allowed(t, c, "relay", `UPDATE outbox SET chained_at = now() WHERE false`)
	allowed(t, c, "relay", `SELECT count(*) FROM audit_log`)
	allowed(t, c, "relay", `SELECT outbox_prune(interval '8 days', 10)`)
}

// The worker cannot prune the outbox, rewrite the audit chain, or take another role.
func TestWorkerCannotPruneOrChangeRoles(t *testing.T) {
	pool := dbtest.New(t)
	for _, s := range []service{core, worker, archive, gateway} {
		c := as(t, pool, s)
		denied(t, c, s.role, `SELECT outbox_prune(interval '8 days', 10)`)
	}
	for _, s := range []service{core, worker} {
		c := as(t, pool, s)
		for _, q := range []string{
			`SET ROLE qv_relay`, `SET ROLE qv`, `CREATE ROLE evil`, `DROP ROLE qv_relay`,
			`UPDATE outbox SET published_at = now()`, `SELECT * FROM outbox`, `DELETE FROM outbox`,
			`SELECT * FROM audit_log`, `INSERT INTO audit_log (at, actor, type, payload, prev_hash, hash) VALUES (now(), 'x', 't', '{}', '\x00', '\x01')`,
			`UPDATE ledger_entries SET amount = 0`, `DELETE FROM ledger_entries`, `TRUNCATE ledger_entries`, `UPDATE ledger_txns SET id = id`, `DELETE FROM ledger_txns`,
		} {
			_, err := c.Exec(context.Background(), q)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || (pe.Code != "42501" && !strings.Contains(pe.Message, "permission denied") && !strings.Contains(pe.Message, "must be")) {
				t.Errorf("%s: %s: err = %v, want permission denied", s.role, q, err)
			}
		}
		// what it does need
		allowed(t, c, s.role, `SELECT count(*) FROM schema_migrations`)
		allowed(t, c, s.role, `SELECT count(*) FROM ledger_entries`)
		allowed(t, c, s.role, `SELECT count(*) FROM withdrawals`)
		allowed(t, c, s.role, `INSERT INTO outbox (id, topic, key, payload) VALUES (gen_random_uuid(), 't', 'k', '{}')`)
		allowed(t, c, s.role, `INSERT INTO outbox (id, topic, key, payload) VALUES (gen_random_uuid(), 't', 'k', '{}') ON CONFLICT (id) DO NOTHING`)
	}
}

// The gateway's link role still sees the job queue and nothing else; the archiver's certificate opens nothing.
func TestGatewayLinkAndArchiverReachOnlyTheirOwn(t *testing.T) {
	pool := dbtest.New(t)
	g := as(t, pool, gateway)
	allowed(t, g, "gateway", `SELECT count(*) FROM sign_jobs`)
	allowed(t, g, "gateway", `UPDATE sign_jobs SET status = status`)
	for _, tbl := range tables(t, pool) {
		if tbl == "sign_jobs" {
			continue
		}
		denied(t, g, "gateway", `SELECT * FROM `+pgx.Identifier{tbl}.Sanitize())
	}
	a := as(t, pool, archive)
	for _, tbl := range tables(t, pool) {
		denied(t, a, "archiver", `SELECT * FROM `+pgx.Identifier{tbl}.Sanitize())
	}
}

// Every table is out of reach of every service role except where the matrix grants it: a table added later is closed until a migration opens it.
func TestNewTableIsClosedUntilGranted(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TABLE later_table (id serial PRIMARY KEY, v text)`,
		`CREATE FUNCTION later_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'`,
		`CREATE SEQUENCE later_seq`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range all {
		c := as(t, pool, s)
		denied(t, c, s.role, `SELECT * FROM later_table`)
		denied(t, c, s.role, `INSERT INTO later_table (v) VALUES ('x')`)
		denied(t, c, s.role, `SELECT later_fn()`)
		denied(t, c, s.role, `SELECT nextval('later_seq')`)
	}
	// and once a migration grants it, it opens
	if _, err := pool.Exec(ctx, `GRANT SELECT ON later_table TO qv_core`); err != nil {
		t.Fatal(err)
	}
	allowed(t, as(t, pool, core), "core", `SELECT * FROM later_table`)
	denied(t, as(t, pool, worker), "worker", `SELECT * FROM later_table`)
}

// Migrations are applied by the owner only; a service only checks.
func TestServicesCheckMigrationsButCannotApplyThem(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	for _, s := range []service{core, worker} {
		c := as(t, pool, s)
		sp := serviceConnPool(t, pool, s)
		if err := db.Check(ctx, sp); err != nil {
			t.Errorf("%s: Check on a migrated database: %v", s.role, err)
		}
		if err := db.Migrate(ctx, sp); err == nil {
			t.Errorf("%s: Migrate must fail for a role that cannot create", s.role)
		}
		_ = c
	}
	// a pending migration: the service refuses and names the file and the command
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE name = '0030_service_roles.sql'`); err != nil {
		t.Fatal(err)
	}
	err := db.Check(ctx, serviceConnPool(t, pool, core))
	if err == nil || !strings.Contains(err.Error(), "0030_service_roles.sql") || !strings.Contains(err.Error(), "qv-migrate") {
		t.Fatalf("Check with a pending migration: err = %v, want it to name the file and qv-migrate", err)
	}
	// a database ahead of the binary
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ('0030_service_roles.sql'), ('9999_future.sql')`); err != nil {
		t.Fatal(err)
	}
	err = db.Check(ctx, serviceConnPool(t, pool, core))
	if err == nil || !strings.Contains(err.Error(), "9999_future.sql") {
		t.Fatalf("Check with an unknown migration: err = %v", err)
	}
}

func serviceConnPool(t *testing.T, pool *pgxpool.Pool, s service) *pgxpool.Pool {
	t.Helper()
	dsn := pkitest.WithCert(dbtest.ServiceDSN(t, dbtest.DSN(pool), s.role), pki.ZoneBusiness, s.cert, pki.ZoneBusiness)
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func tables(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		out = append(out, n)
	}
	return out
}
