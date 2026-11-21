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

// The signing zone's Postgres maps the gateway's certificate to qv_gateway_guard and each cosigner's own certificate name to its own role,
// cosigner-b to qv_cosigner_b_guard and cosigner-c to qv_cosigner_c_guard (deploy/postgres/signing.pg_ident.conf). Each role owns its own guard
// database and cannot connect to the other's; C's certificate at B's database is refused, with C's role name or B's.
func TestGuardRolesAreSeparated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	gwDB := dbtest.CreateGuardDB(t, "qv_guard_")
	csDB := dbtest.CreateGuardDB(t, "qv_guard_")
	ccDB := dbtest.CreateGuardDB(t, "qv_guard_")
	gwAs := dbtest.GuardDSN(t, gwDB, dbtest.RoleGatewayGuard)
	csAs := dbtest.GuardDSN(t, csDB, dbtest.RoleCosignerBGuard)
	ccAs := dbtest.GuardDSN(t, ccDB, dbtest.RoleCosignerCGuard)
	_, _, ca := pkitest.Files(pki.ZoneSigning, "admin")
	with := func(dsn, cert string) string {
		c, k, _ := pkitest.Files(pki.ZoneSigning, cert)
		return db.WithClientCert(dsn, c, k, ca)
	}
	gw, cs, cc := with(gwAs, "gateway"), with(csAs, "cosigner-b"), with(ccAs, "cosigner-c")

	// each applies the real replay-guard schema to its own database, with its own certificate
	for name, dsn := range map[string]string{"gateway": gw, "cosigner-b": cs, "cosigner-c": cc} {
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
		// the keyset log (keysets.go) is a table in the same database, so the role needs no extra grant: readable, appendable, immutable
		if err := p.QueryRow(ctx, `SELECT count(*) FROM keyset_changes`).Scan(&n); err != nil {
			t.Fatalf("%s: read keyset_changes: %v", name, err)
		}
		if _, err := p.Exec(ctx, `INSERT INTO keyset_changes (seq, action, shard, generation, signed_at, signatures) VALUES (1, 'activate', 'e/c/omnibus/0', 2, 1, '[]')`); err != nil {
			t.Fatalf("%s: append keyset_changes: %v", name, err)
		}
		if _, err := p.Exec(ctx, `UPDATE keyset_changes SET shard = 'x'`); err == nil {
			t.Errorf("%s: keyset_changes was updated", name)
		}
		if _, err := p.Exec(ctx, `DELETE FROM keyset_changes`); err == nil {
			t.Errorf("%s: keyset_changes rows were deleted", name)
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
	refused("cosigner B -> gateway's guard", with(db.Rewrite(gwAs, dbtest.RoleCosignerBGuard, ""), "cosigner-b"))
	refused("gateway cert as the cosigner B role", with(db.Rewrite(csAs, dbtest.RoleCosignerBGuard, ""), "gateway"))
	refused("cosigner B cert as the gateway role", with(db.Rewrite(gwAs, dbtest.RoleGatewayGuard, ""), "cosigner-b"))
	// the two cosigners are apart: neither role's name opens the other's database with its own certificate, and a certificate of one does not pass as the other
	refused("cosigner C cert at B's database, as B's role", with(csAs, "cosigner-c"))
	refused("cosigner B cert at C's database, as C's role", with(ccAs, "cosigner-b"))
	refused("cosigner C -> B's guard, as C's role", with(db.Rewrite(csAs, dbtest.RoleCosignerCGuard, ""), "cosigner-c"))
	refused("cosigner B -> C's guard, as B's role", with(db.Rewrite(ccAs, dbtest.RoleCosignerBGuard, ""), "cosigner-b"))
	refused("gateway cert as the owner", with(db.Rewrite(gwAs, "qv", ""), "gateway"))
	refused("gateway -> bootstrap database", with(db.Rewrite(gwAs, "", "qv_signing"), "gateway"))
	refused("cosigner B -> bootstrap database", with(db.Rewrite(csAs, "", "qv_signing"), "cosigner-b"))
	refused("cosigner C -> bootstrap database", with(db.Rewrite(ccAs, "", "qv_signing"), "cosigner-c"))

	// the right to alter stops at its own database: no cluster-level or other-role change
	for name, dsn := range map[string]string{"gateway": gw, "cosigner-b": cs, "cosigner-c": cc} {
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
