package partition_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

const shard = partition.ShardID("acme/eth/omnibus/0")

func inTx(t *testing.T, pool *pgxpool.Pool, f func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f(tx); err != nil {
		tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func auditTypes(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT payload->>'type' FROM outbox WHERE topic = 'qv.audit' ORDER BY created_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestRegisterInitialIsIdempotentAndPinsTheAddress(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := inTx(t, pool, func(tx pgx.Tx) error {
			k, err := partition.RegisterInitial(ctx, tx, "system", shard, "0xAbC", "", nil)
			if err == nil && (k.Generation != 1 || k.State != partition.StateActive) {
				t.Errorf("got generation %d state %s", k.Generation, k.State)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := auditTypes(t, pool); len(got) != 1 || got[0] != "keyset.registered" {
		t.Errorf("audit events %v, want one keyset.registered", got)
	}
	// the same address in another case is the same address; another address is refused
	if err := inTx(t, pool, func(tx pgx.Tx) error {
		_, err := partition.RegisterInitial(ctx, tx, "system", shard, "0xabc", "", nil)
		return err
	}); err != nil {
		t.Errorf("same address, other case: %v", err)
	}
	err := inTx(t, pool, func(tx pgx.Tx) error {
		_, err := partition.RegisterInitial(ctx, tx, "system", shard, "0xdef", "", nil)
		return err
	})
	if !errors.Is(err, partition.ErrKeysetAddressChange) {
		t.Errorf("another address: %v, want ErrKeysetAddressChange", err)
	}
	k, err := partition.Active(ctx, pool, shard)
	if err != nil || k.Address != "0xAbC" {
		t.Errorf("Active = %+v, %v", k, err)
	}
}

func TestLifecycleAndGuards(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	run := func(f func(tx pgx.Tx) error) error { return inTx(t, pool, f) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(run(func(tx pgx.Tx) error { _, err := partition.RegisterInitial(ctx, tx, "system", shard, "a1", "", nil); return err }))

	var g2 int
	must(run(func(tx pgx.Tx) error {
		k, err := partition.RegisterCandidate(ctx, tx, "op", shard, "a2", "ks2", nil)
		g2 = k.Generation
		return err
	}))
	if g2 != 2 {
		t.Fatalf("candidate generation %d, want 2", g2)
	}

	refused := func(name string, want error, f func(tx pgx.Tx) error) {
		t.Helper()
		if err := run(f); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	refused("two active", partition.ErrActiveExists, func(tx pgx.Tx) error { _, err := partition.Activate(ctx, tx, "op", shard, g2); return err })
	refused("retire an active", partition.ErrIllegalTransition, func(tx pgx.Tx) error { _, err := partition.Retire(ctx, tx, "op", shard, 1); return err })
	refused("drain a candidate", partition.ErrIllegalTransition, func(tx pgx.Tx) error { _, err := partition.StartDraining(ctx, tx, "op", shard, g2); return err })
	refused("unknown generation", partition.ErrKeysetNotFound, func(tx pgx.Tx) error { _, err := partition.Activate(ctx, tx, "op", shard, 9); return err })
	if err := run(func(tx pgx.Tx) error { _, err := partition.StartDraining(ctx, tx, "", shard, 1); return err }); err == nil {
		t.Error("a change without an actor was accepted")
	}

	must(run(func(tx pgx.Tx) error { _, err := partition.StartDraining(ctx, tx, "op", shard, 1); return err }))
	refused("activate again an active", partition.ErrIllegalTransition, func(tx pgx.Tx) error { _, err := partition.Activate(ctx, tx, "op", shard, 1); return err })
	must(run(func(tx pgx.Tx) error { _, err := partition.Activate(ctx, tx, "op", shard, g2); return err }))
	if k, err := partition.Active(ctx, pool, shard); err != nil || k.Generation != g2 || k.Address != "a2" {
		t.Errorf("Active = %+v, %v", k, err)
	}
	must(run(func(tx pgx.Tx) error { _, err := partition.Retire(ctx, tx, "op", shard, 1); return err }))
	refused("retired back to anything", partition.ErrIllegalTransition, func(tx pgx.Tx) error { _, err := partition.Activate(ctx, tx, "op", shard, 1); return err })
	refused("retired compromised", partition.ErrIllegalTransition, func(tx pgx.Tx) error { _, err := partition.MarkCompromised(ctx, tx, "op", shard, 1); return err })

	must(run(func(tx pgx.Tx) error { _, err := partition.MarkCompromised(ctx, tx, "op", shard, g2); return err }))
	refused("compromised never leaves", partition.ErrIllegalTransition, func(tx pgx.Tx) error { _, err := partition.StartDraining(ctx, tx, "op", shard, g2); return err })
	refused("compromised twice", partition.ErrIllegalTransition, func(tx pgx.Tx) error { _, err := partition.MarkCompromised(ctx, tx, "op", shard, g2); return err })
	if _, err := partition.Active(ctx, pool, shard); !errors.Is(err, partition.ErrKeysetNotFound) {
		t.Errorf("a compromised keyset is not active: %v", err)
	}

	want := []string{"keyset.registered", "keyset.candidate", "keyset.draining", "keyset.activated", "keyset.retired", "keyset.compromised"}
	got := auditTypes(t, pool)
	if len(got) != len(want) {
		t.Fatalf("audit events %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("audit event %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestDatabaseRefusesTwoActive(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	for _, g := range []int{1, 2} {
		_, err := pool.Exec(ctx, `INSERT INTO keysets (shard_id, generation, address, state) VALUES ($1, $2, $3, 'active')`, string(shard), g, "a"+string(rune('0'+g)))
		if g == 2 && err == nil {
			t.Error("the database accepted a second active keyset for one shard")
		}
		if g == 1 && err != nil {
			t.Fatal(err)
		}
	}
}
