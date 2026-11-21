package dbtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	postgresdeploy "github.com/ws4charlie/quorum-vault/deploy/postgres"
	"github.com/ws4charlie/quorum-vault/internal/db"
)

// Service roles. The Postgres map (deploy/postgres/*.pg_ident.conf) sends each certificate name to the role of the same service, and a login role
// must equal the DSN user, so a spawned service gets a DSN naming its own role. The certificate it presents is its own (it loads it itself).
const (
	RoleCore    = "qv_core"
	RoleWorker  = "qv_worker"
	RoleRelay   = "qv_relay"
	RoleArchive = "qv_archiver"

	RoleGatewayGuard   = "qv_gateway_guard"
	RoleCosignerBGuard = "qv_cosigner_b_guard"
	RoleCosignerCGuard = "qv_cosigner_c_guard"
)

var loginMu sync.Mutex

// ServiceDSN is bizDSN with the user of the service's own role (core, worker, relay), after making sure that role can log in (the migration
// creates it NOLOGIN; the owner switches it on, as `qv-migrate -enable-login` does). bizDSN is a DSN of a migrated database of the business server.
func ServiceDSN(t testing.TB, bizDSN, role string) string {
	t.Helper()
	enableLogin(t, databaseURL(), role)
	return db.Rewrite(bizDSN, role, "")
}

// GuardDSN prepares guardDSN (a replay-guard database of the signing zone's server made by CreateGuardDB) for a spawned gateway or cosigner and
// returns the DSN it connects with: the database gets the service's own role as owner (the service applies its schema at start and may alter
// only this database), CONNECT is taken from PUBLIC, and the user of the DSN is the role. Call it once per database, before the service starts.
func GuardDSN(t testing.TB, guardDSN, role string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin := SigningURL(t)
	pool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("dbtest: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, postgresdeploy.SigningRoles); err != nil {
		t.Fatalf("dbtest: signing roles: %v", err)
	}
	enableLoginOn(t, pool, role)
	cfg, err := pgx.ParseConfig(guardDSN)
	if err != nil {
		t.Fatal(err)
	}
	name := pgx.Identifier{cfg.Database}.Sanitize()
	for _, stmt := range []string{
		`ALTER DATABASE ` + name + ` OWNER TO ` + role,
		`REVOKE CONNECT ON DATABASE ` + name + ` FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE ` + name + ` TO ` + role,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("dbtest: %s: %v", stmt, err)
		}
	}
	// a schema the test (as the owner) already applied belongs to the role too, so the service's own start-up migration can alter it
	c, err := pgx.Connect(ctx, guardDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, `DO $$ DECLARE o record; BEGIN
		FOR o IN SELECT c.oid::regclass AS n, c.relkind FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'S', 'v') LOOP
			EXECUTE format('ALTER %s %s OWNER TO `+role+`', CASE o.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW' ELSE 'TABLE' END, o.n);
		END LOOP;
		FOR o IN SELECT p.oid::regprocedure AS n FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace LOOP
			EXECUTE format('ALTER FUNCTION %s OWNER TO `+role+`', o.n);
		END LOOP;
	END $$`); err != nil {
		t.Fatalf("dbtest: hand the schema to %s: %v", role, err)
	}
	return db.Rewrite(guardDSN, role, "")
}

func enableLogin(t testing.TB, url, role string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("dbtest: %v", err)
	}
	defer pool.Close()
	enableLoginOn(t, pool, role)
}

func enableLoginOn(t testing.TB, pool *pgxpool.Pool, role string) {
	t.Helper()
	loginMu.Lock()
	defer loginMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.EnableLogin(ctx, pool, role); err != nil {
		t.Fatalf("dbtest: %v", err)
	}
}

// RoleArgs rewrites the database flags of a spawned QuorumVault binary so it connects as its own role instead of the owner: qv-core, qv-worker
// and qv-relay get their role in -dsn; qv-gateway and qv-cosigner get a guard database owned by their role in -guard-dsn (the gateway's -jobs-dsn
// already names qv_gateway). Other binaries and flags are left alone (operator tools such as qv-sol-nonces and `qv-relay verify` run as the owner).
func RoleArgs(t testing.TB, binary string, args []string) []string {
	t.Helper()
	if filepath.Base(binary) == "qv-cosigner" {
		t.Fatalf("dbtest: qv-cosigner needs its role: use RoleArgsFor(t, binary, \"b\" or \"c\", args); B and C are different identities")
	}
	return RoleArgsFor(t, binary, "", args)
}

// RoleArgsFor is RoleArgs for a qv-cosigner that is cosigner "b" or "c": the binary is the same, the role is the one of the certificate it is started with
// (pkitest.CosignerEnv). Other binaries ignore cosigner.
func RoleArgsFor(t testing.TB, binary, cosigner string, args []string) []string {
	t.Helper()
	name := filepath.Base(binary)
	out := append([]string(nil), args...)
	set := func(flag string, f func(string) string) {
		for i := 0; i+1 < len(out); i++ {
			if out[i] == flag {
				out[i+1] = f(out[i+1])
			}
		}
	}
	switch {
	case name == "qv-core":
		set("-dsn", func(d string) string { return ServiceDSN(t, d, RoleCore) })
	case name == "qv-worker":
		set("-dsn", func(d string) string { return ServiceDSN(t, d, RoleWorker) })
	case name == "qv-relay" && !(len(out) > 0 && out[0] == "verify"):
		set("-dsn", func(d string) string { return ServiceDSN(t, d, RoleRelay) })
	case name == "qv-gateway":
		set("-guard-dsn", func(d string) string { return GuardDSN(t, d, RoleGatewayGuard) })
	case name == "qv-cosigner":
		var role string
		switch cosigner {
		case "b":
			role = RoleCosignerBGuard
		case "c":
			role = RoleCosignerCGuard
		default:
			t.Fatalf("dbtest: qv-cosigner role %q: want \"b\" or \"c\"", cosigner)
		}
		set("-guard-dsn", func(d string) string { return GuardDSN(t, d, role) })
	}
	return out
}

func databaseURL() string { return strings.TrimSpace(os.Getenv("DATABASE_URL")) }
