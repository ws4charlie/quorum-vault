package db_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// Needs the two Postgres servers (make db-up): the business one (DATABASE_URL) and the signing zone's (QV_SIGNING_DB_URL).

// refused expects err and logs its reason, so a run shows WHY each case was refused (the server's rule, not a broken test).
func refused(t *testing.T, what string, dsn string) {
	t.Helper()
	err := tryConnect(dsn)
	if err == nil {
		t.Errorf("%s was accepted", what)
		return
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg) > 160 {
		msg = msg[strings.LastIndex(msg[:i], "\n")+1:]
	}
	t.Logf("refused, as it must be: %s: %.200s", what, msg)
}

func tryConnect(dsn string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	var one int
	return c.QueryRow(ctx, "select 1").Scan(&one)
}

// base is a server's DSN with its own admin certificate; the tests change one thing at a time.
func serverCases(t *testing.T, zone, other, base string, admin string, unmapped string) {
	t.Helper()
	only := func(d string) string { // the server's CA to verify it, and no client certificate at all
		_, _, ca := pkitest.Files(zone, "admin")
		return db.WithClientCert(d, "", "", ca)
	}
	if err := tryConnect(base); err != nil {
		t.Fatalf("the right client was refused: %v", err)
	}
	// no certificate
	refused(t, "a client without a certificate", only(base))
	// a plain connection
	refused(t, "a connection without TLS", strings.Replace(base, "sslmode=verify-full", "sslmode=disable", 1))
	// the other zone's certificate (it still checks the server against the right CA, so the refusal is the server's)
	refused(t, other+"-zone certificate on the "+zone+"-zone server", pkitest.WithCert(base, other, "admin", zone))
	// the right authority, a name the server does not map to a role
	refused(t, "a "+zone+" certificate named "+unmapped+", which the server does not map", pkitest.WithCert(base, zone, unmapped, zone))
	// the client refuses a server of the other zone's authority
	refused(t, "a server certificate that the other zone's CA did not sign", pkitest.WithCert(base, zone, "admin", other))
}

func TestBusinessPostgresMatrix(t *testing.T) {
	_ = dbtest.New(t) // skips (or fails under QV_REQUIRE_DB) when there is no server
	base := os.Getenv("DATABASE_URL")
	serverCases(t, pki.ZoneBusiness, pki.ZoneSigning, base, "admin", "guardian")
}

func TestSigningPostgresMatrix(t *testing.T) {
	base := dbtest.SigningURL(t)
	serverCases(t, pki.ZoneSigning, pki.ZoneBusiness, base, "admin", "mpc-party-a")
}

// The one link between the zones: the gateway's certificate from the BUSINESS authority maps to role qv_gateway and to no other.
func TestGatewayLinkCertificateIsTheRestrictedRole(t *testing.T) {
	pool := dbtest.New(t)
	dbtest.GatewayLogin(t)
	good := dbtest.GatewayJobsDSN(dbtest.DSN(pool))
	if err := tryConnect(good); err != nil {
		t.Fatalf("the gateway's link certificate was refused as qv_gateway: %v", err)
	}
	if err := tryConnect(db.Rewrite(good, "qv", "")); err == nil {
		t.Error("the gateway's link certificate was accepted as the full role qv")
	}
	// the signing zone's own certificate of the gateway is not accepted by the business server at all
	own := pkitest.WithCert(db.Rewrite(good, "qv_gateway", ""), pki.ZoneSigning, "gateway", pki.ZoneBusiness)
	if err := tryConnect(own); err == nil {
		t.Error("the gateway's signing-zone certificate was accepted by the business database")
	}
	// the role may read the job queue and nothing else
	ctx := context.Background()
	c, err := pgx.Connect(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, "select count(*) from sign_jobs"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, "select count(*) from withdrawals"); err == nil {
		t.Error("qv_gateway read a table that is not the job queue")
	}
}

func TestDSNPolicy(t *testing.T) {
	t.Setenv("QV_ENV", "")
	t.Setenv("QV_ALLOW_PLAINTEXT", "")
	for _, bad := range []string{
		"postgres://qv@localhost:5432/x?sslmode=disable",
		"postgres://qv@localhost:5432/x?sslmode=prefer",
		"postgres://qv@localhost:5432/x?sslmode=require",
		"postgres://qv@localhost:5432/x?sslmode=verify-ca",
		"postgres://qv@localhost:5432/x",
	} {
		if _, err := db.PoolConfig(bad, nil, nil); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if _, err := db.PoolConfig("postgres://qv@localhost:5432/x?sslmode=verify-full", nil, nil); err != nil {
		t.Errorf("verify-full refused: %v", err)
	}
	// the development switch needs both parts
	t.Setenv("QV_ALLOW_PLAINTEXT", "1")
	if _, err := db.PoolConfig("postgres://qv@localhost:5432/x?sslmode=disable", nil, nil); err == nil {
		t.Error("plain text accepted without QV_ENV=dev")
	}
	t.Setenv("QV_ENV", "dev")
	if _, err := db.PoolConfig("postgres://qv@localhost:5432/x?sslmode=disable", nil, nil); err != nil {
		t.Errorf("plain text refused with the dev switch: %v", err)
	}
	// a parse error does not repeat the DSN (it may hold a password)
	if _, err := db.PoolConfig("postgres://qv:secret-pw@localhost:bad/x", nil, nil); err == nil || strings.Contains(err.Error(), "secret-pw") {
		t.Errorf("a parse error leaked the DSN: %v", err)
	}
}

// Rotation: a new connection of a running pool presents the certificate in the file now, without a restart.
func TestPoolFollowsRotatedCertificate(t *testing.T) {
	pool := dbtest.New(t)
	base := db.Rewrite(dbtest.DSN(pool), "", "")
	_, _, ca := pkitest.Files(pki.ZoneBusiness, "admin")
	dsn := db.WithClientCert(base, "", "", ca) // the DSN has no client certificate: it comes from the source
	src, rotate := pkitest.CopyIdentity(t, pki.ZoneBusiness, "admin")
	ctx := context.Background()
	p, err := db.OpenTLS(ctx, dsn, src, pki.Allow{pki.ID(pki.ZoneBusiness, "postgres")})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	serial := func() string {
		var s string
		if err := p.QueryRow(ctx, `select client_serial::text from pg_stat_ssl where pid = pg_backend_pid()`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := serial()
	rotate()
	p.Reset() // what the pool does by itself when a connection ages out: the next one is dialled with the new certificate
	if after := serial(); after == before {
		t.Fatalf("a new connection still used the old certificate (serial %s)", after)
	}
	// and a server whose name is not the allowed one is refused
	if _, err := db.OpenTLS(ctx, dsn, src, pki.Allow{pki.ID(pki.ZoneBusiness, "kafka")}); err == nil {
		t.Error("a server with another name was accepted")
	}
}

// A signing-zone service reaches the signing zone's Postgres through its own Source (the cosigner and the gateway do this), as the business ones do.
func TestSigningServiceUsesItsSourceForTheGuardDatabase(t *testing.T) {
	_, _, ca := pkitest.Files(pki.ZoneSigning, "admin")
	// each service is its own role (deploy/postgres/signing.pg_ident.conf) and reaches the guard database that role owns
	for who, role := range map[string]string{"gateway": dbtest.RoleGatewayGuard, "cosigner": dbtest.RoleCosignerGuard} {
		dsn := db.WithClientCert(dbtest.GuardDSN(t, dbtest.CreateGuardDB(t, "qv_guard_"), role), "", "", ca)
		src, _ := pkitest.CopyIdentity(t, pki.ZoneSigning, who)
		p, err := db.OpenTLS(context.Background(), dsn, src, pki.Allow{pki.ID(pki.ZoneSigning, "signing-db")})
		if err != nil {
			t.Fatalf("%s: %v", who, err)
		}
		p.Close()
	}
}
