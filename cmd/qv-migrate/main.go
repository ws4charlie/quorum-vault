// Command qv-migrate applies the database migrations as the OWNER role. qv-core and qv-worker only check that the migrations are applied
// (db.Check); they run under roles that cannot CREATE, ALTER or DROP, so this is the one explicit step that changes the schema. Run it before
// a release, with the admin certificate (the one the Postgres map sends to the owner role qv).
//
//	qv-migrate [-dsn $DATABASE_URL]                  business zone: apply pending migrations (creates the service roles, grants their rights)
//	qv-migrate -zone signing [-dsn $QV_SIGNING_DB_URL]   signing zone: create the guard roles (the databases are made by the operator, see signing_roles.sql)
//	qv-migrate -enable-login ...                     also let the roles of the zone log in (development, CI and tests; production enables login itself)
//
// It is a separate binary, not a mode of qv-core: the services that run all day carry no code that changes the schema.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	postgresdeploy "github.com/ws4charlie/quorum-vault/deploy/postgres"
	"github.com/ws4charlie/quorum-vault/internal/db"
)

// ServiceRoles are the login roles of each zone that -enable-login switches on (migration 0030 and signing_roles.sql create them).
var serviceRoles = map[string][]string{
	"business": {"qv_core", "qv_worker", "qv_relay", "qv_archiver", "qv_gateway"},
	"signing":  {"qv_gateway_guard", "qv_cosigner_b_guard", "qv_cosigner_c_guard"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qv-migrate:", err)
		os.Exit(1)
	}
}

func run() error {
	zone := flag.String("zone", "business", "business or signing")
	dsn := flag.String("dsn", "", "owner DSN (default: DATABASE_URL for business, QV_SIGNING_DB_URL for signing)")
	login := flag.Bool("enable-login", false, "ALTER ROLE ... LOGIN for the zone's service roles (development, CI, tests)")
	flag.Parse()
	roles, ok := serviceRoles[*zone]
	if !ok {
		return fmt.Errorf("-zone must be business or signing")
	}
	if *dsn == "" {
		if *zone == "signing" {
			*dsn = os.Getenv("QV_SIGNING_DB_URL")
		} else {
			*dsn = os.Getenv("DATABASE_URL")
		}
	}
	if *dsn == "" {
		return fmt.Errorf("-dsn (or DATABASE_URL / QV_SIGNING_DB_URL) is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pool, err := db.OpenTLS(ctx, *dsn, nil, nil)
	if err != nil {
		return err
	}
	defer pool.Close()
	if *zone == "business" {
		if err := db.Migrate(ctx, pool); err != nil {
			return err
		}
	} else if _, err := pool.Exec(ctx, postgresdeploy.SigningRoles); err != nil {
		return fmt.Errorf("signing roles: %w", err)
	}
	if *login {
		for _, r := range roles {
			if err := db.EnableLogin(ctx, pool, r); err != nil {
				return err
			}
		}
	}
	fmt.Printf("qv-migrate: %s zone up to date\n", *zone)
	return nil
}
