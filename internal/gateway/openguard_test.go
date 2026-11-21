package gateway

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// An operator's tool opens the guard of a zone that is deciding. Opening must run no DDL when the schema is current: DDL takes table locks even when it changes
// nothing, and would block (or deadlock with) a decision at the moment the tool is used.
func TestOpenGuardOfACurrentSchemaTakesNoTableLock(t *testing.T) {
	pool := newGuardDB(t)
	if _, err := OpenGuard(t.Context(), pool); err != nil { // the service's own start: applies the schema and records its version
		t.Fatal(err)
	}
	var v string
	if err := pool.QueryRow(t.Context(), `SELECT version FROM guard_schema WHERE id=1`).Scan(&v); err != nil || v != storeVersion {
		t.Fatalf("the schema version was not recorded: %q %v", v, err)
	}
	// A decision in progress: a transaction holding the locks a guard decision takes on its tables (ROW EXCLUSIVE; the DDL of store.sql needs ACCESS EXCLUSIVE and
	// would wait for it).
	ctx := t.Context()
	dec, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Rollback(context.Background())
	if _, err := dec.Exec(ctx, `LOCK TABLE signed_digests, signed_intents, exclusive_claims IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	// Eight tools open the guard at once, none may wait for the decision.
	octx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	start := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := OpenGuard(octx, pool)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("open under a decision: %v (after %s)", err, time.Since(start))
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("opening waited %s for a decision: it ran DDL", time.Since(start))
	}
	// While the opens ran, no lock stronger than the decision's was held by anybody else.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE mode='AccessExclusiveLock' AND granted AND relation IN ('signed_digests'::regclass, 'signed_intents'::regclass, 'exclusive_claims'::regclass)`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d access-exclusive locks on the guard tables: %v", n, err)
	}
}

// A database behind the schema (no marker, or another version) is brought to it, by one opener at a time, also when several start together; and a second
// open then runs no DDL.
func TestOpenGuardAppliesAMissingOrOldSchemaOnceUnderALock(t *testing.T) {
	// A small pool: an opener that waits for the schema lock holds a connection, so the one that holds the lock must never need another (CI's pool is small).
	big := newGuardDB(t)
	cfg := big.Config().Copy()
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	big.Close() // the pool the helper made is not used again; the database stays until the helper's cleanup
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := OpenGuard(t.Context(), pool)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !schemaCurrent(t.Context(), pool) {
		t.Fatal("the schema is not recorded as current after the opens")
	}
	// An older version: the marker is changed, the next open applies the schema again and records the version.
	if _, err := pool.Exec(t.Context(), `UPDATE guard_schema SET version='old'`); err != nil {
		t.Fatal(err)
	}
	if schemaCurrent(t.Context(), pool) {
		t.Fatal("a marker of another version counted as current")
	}
	if _, err := OpenGuard(t.Context(), pool); err != nil || !schemaCurrent(t.Context(), pool) {
		t.Fatalf("an old schema was not brought up to date: %v", err)
	}
}
