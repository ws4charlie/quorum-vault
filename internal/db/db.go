// Package db opens the Postgres pool and applies the embedded migrations.
package db

import (
	"context"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/migrations"
)

// migrateLockID serializes concurrent Migrate calls on one database.
const migrateLockID = 0x71760001

// Migrate applies every migrations/*.sql file not yet recorded in
// schema_migrations, in name order, each in its own transaction. Safe to call
// repeatedly and concurrently.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return MigrateFS(ctx, pool, migrations.FS)
}

// MigrateFS is Migrate with an explicit file system of *.sql files.
func MigrateFS(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("db: create schema_migrations: %w", err)
	}
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		if err := applyOne(ctx, pool, fsys, name); err != nil {
			return err
		}
	}
	return nil
}

// Check is the read-only counterpart of Migrate, for the services (qv-core, qv-worker): they run under roles that cannot CREATE, ALTER or DROP,
// so they never apply a migration. Check needs SELECT on schema_migrations and nothing else. It fails when an embedded migration is not
// recorded (the message names the files and the command to run, as the owner) or when the database has a migration this binary does not know
// (the binary is older than the database).
func Check(ctx context.Context, pool *pgxpool.Pool) error {
	return CheckFS(ctx, pool, migrations.FS)
}

// CheckFS is Check with an explicit file system of *.sql files.
func CheckFS(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) error {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("db: read schema_migrations (has `qv-migrate` run on this database?): %w", err)
	}
	defer rows.Close()
	recorded := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		recorded[n] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	known := map[string]bool{}
	var pending []string
	for _, n := range names {
		known[n] = true
		if !recorded[n] {
			pending = append(pending, n)
		}
	}
	var ahead []string
	for n := range recorded {
		if !known[n] {
			ahead = append(ahead, n)
		}
	}
	sort.Strings(pending)
	sort.Strings(ahead)
	if len(pending) > 0 {
		return fmt.Errorf("db: %d migration(s) not applied: %v; run `qv-migrate` as the owner role (DATABASE_URL with the admin certificate) before starting this service", len(pending), pending)
	}
	if len(ahead) > 0 {
		return fmt.Errorf("db: the database has migration(s) this binary does not know: %v; the binary is older than the database", ahead)
	}
	return nil
}

func applyOne(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS, name string) error {
	sql, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrateLockID); err != nil {
		return fmt.Errorf("db: migration lock: %w", err)
	}
	var done bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&done); err != nil {
		return err
	}
	if done {
		return nil
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return fmt.Errorf("db: migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// EnableLogin lets a service role log in. The migrations create the roles NOLOGIN (as 0004 does for qv_gateway); a deployment decides when
// they may connect, and development, CI and the tests switch them on with this (qv-migrate -enable-login, dbtest). It does nothing when the role
// can already log in, so concurrent callers do not collide on the catalog row. Needs the owner role.
func EnableLogin(ctx context.Context, pool *pgxpool.Pool, role string) error {
	var can, exists bool
	if err := pool.QueryRow(ctx, `SELECT COALESCE(bool_or(rolcanlogin), false), count(*) > 0 FROM pg_roles WHERE rolname = $1`, role).Scan(&can, &exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("db: role %s does not exist (is the zone migrated?)", role)
	}
	if can {
		return nil
	}
	if _, err := pool.Exec(ctx, `ALTER ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN`); err != nil {
		return fmt.Errorf("db: enable login for %s: %w", role, err)
	}
	return nil
}
