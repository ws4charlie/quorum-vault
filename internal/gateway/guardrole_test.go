package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// The signing zone's Postgres maps the gateway's certificate to qv_gateway_guard and the cosigner's to qv_cosigner_guard (deploy/postgres/
// signing.pg_ident.conf). Each role owns its own guard database and cannot connect to the other's.
func TestGuardRolesAreSeparated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	gwDB := dbtest.CreateGuardDB(t, "qv_guard_")
	csDB := dbtest.CreateGuardDB(t, "qv_guard_")
	gwAs := dbtest.GuardDSN(t, gwDB, dbtest.RoleGatewayGuard)
	csAs := dbtest.GuardDSN(t, csDB, dbtest.RoleCosignerGuard)
	_, _, ca := pkitest.Files(pki.ZoneSigning, "admin")
	with := func(dsn, cert string) string {
		c, k, _ := pkitest.Files(pki.ZoneSigning, cert)
		return db.WithClientCert(dsn, c, k, ca)
	}
	gw, cs := with(gwAs, "gateway"), with(csAs, "cosigner")

	// each applies the real replay-guard schema to its own database, with its own certificate
	for name, dsn := range map[string]string{"gateway": gw, "cosigner": cs} {
		p, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenGuard(ctx, p); err != nil {
			t.Fatalf("%s: OpenGuard under its own role: %v", name, err)
		}
		if _, err := OpenGuard(ctx, p); err != nil { // a second start: CREATE IF NOT EXISTS and ALTER on tables it owns
			t.Fatalf("%s: second OpenGuard: %v", name, err)
		}
		// the approver registry's append-only table (I4): readable and appendable in its own database, and immutable
		var n int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM approver_changes`).Scan(&n); err != nil {
			t.Fatalf("%s: read approver_changes: %v", name, err)
		}
		if _, err := p.Exec(ctx, `INSERT INTO approver_changes (seq, action, name, signed_at, signatures) VALUES (1, 'add', 'zed', 1, '[]')`); err != nil {
			t.Fatalf("%s: append approver_changes: %v", name, err)
		}
		if _, err := p.Exec(ctx, `UPDATE approver_changes SET name = 'x'`); err == nil {
			t.Errorf("%s: approver_changes was updated", name)
		}
		if _, err := p.Exec(ctx, `DELETE FROM approver_changes`); err == nil {
			t.Errorf("%s: approver_changes rows were deleted", name)
		}
		p.Close()
	}
	// neither can open the other's guard database, nor the bootstrap database, with the right certificate or the wrong one
	refused := func(label, dsn string) {
		t.Helper()
		if c, err := pgx.Connect(ctx, dsn); err == nil {
			c.Close(ctx)
			t.Errorf("%s: connected, want refused", label)
		}
	}
	refused("gateway -> cosigner's guard", with(db.Rewrite(csAs, dbtest.RoleGatewayGuard, ""), "gateway"))
	refused("cosigner -> gateway's guard", with(db.Rewrite(gwAs, dbtest.RoleCosignerGuard, ""), "cosigner"))
	refused("gateway cert as the cosigner role", with(db.Rewrite(csAs, dbtest.RoleCosignerGuard, ""), "gateway"))
	refused("cosigner cert as the gateway role", with(db.Rewrite(gwAs, dbtest.RoleGatewayGuard, ""), "cosigner"))
	refused("gateway cert as the owner", with(db.Rewrite(gwAs, "qv", ""), "gateway"))
	refused("gateway -> bootstrap database", with(db.Rewrite(gwAs, "", "qv_signing"), "gateway"))
	refused("cosigner -> bootstrap database", with(db.Rewrite(csAs, "", "qv_signing"), "cosigner"))

	// the right to alter stops at its own database: no cluster-level or other-role change
	for name, dsn := range map[string]string{"gateway": gw, "cosigner": cs} {
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{`CREATE ROLE evil`, `ALTER ROLE qv_gateway_guard SUPERUSER`, `CREATE DATABASE evil`, `DROP DATABASE ` + pgx.Identifier{c.Config().Database}.Sanitize(), `SET ROLE qv`} {
			if _, err := c.Exec(ctx, q); err == nil {
				t.Errorf("%s: %s succeeded", name, q)
			}
		}
		c.Close(ctx)
	}
}
