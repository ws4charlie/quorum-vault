package signjob_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

func testJob(id string) signjob.Job {
	return signjob.Job{
		ID: id, PartitionID: "p1", KeyRef: "k", Chain: "evm-test",
		Intent: []byte(`{"Kind":"withdrawal"}`), Digest: []byte{1, 2, 3}, Payload: []byte(`{"a":1}`),
		Approvals: []signjob.Approval{{Actor: "alice", Signature: []byte{9}}},
	}
}

func TestQueue(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	if _, err := pool.Exec(ctx, `INSERT INTO assets (chain, symbol, decimals) VALUES ('evm-test','ETH',18)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('p1','qv-us','evm-test','ETH','hot','omnibus',0)`); err != nil {
		t.Fatal(err)
	}
	put := func(j signjob.Job) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := signjob.Enqueue(ctx, tx, j); err != nil {
			tx.Rollback(ctx)
			return err
		}
		return tx.Commit(ctx)
	}

	t.Run("enqueue idempotent and conflicting", func(t *testing.T) {
		if err := put(testJob("j-idem")); err != nil {
			t.Fatal(err)
		}
		if err := put(testJob("j-idem")); err != nil {
			t.Fatalf("identical repeat: %v", err)
		}
		other := testJob("j-idem")
		other.Digest = []byte{4}
		if err := put(other); !errors.Is(err, signjob.ErrConflict) {
			t.Fatalf("different body: %v, want ErrConflict", err)
		}
		other = testJob("j-idem")
		other.Approvals = nil
		if err := put(other); !errors.Is(err, signjob.ErrConflict) {
			t.Fatalf("different approvals: %v, want ErrConflict", err)
		}
		// A rolled-back enqueue leaves nothing.
		tx, _ := pool.Begin(ctx)
		signjob.Enqueue(ctx, tx, testJob("j-rb"))
		tx.Rollback(ctx)
		if _, err := signjob.Get(ctx, pool, "j-rb"); !errors.Is(err, signjob.ErrNotFound) {
			t.Fatalf("rolled back job: %v", err)
		}
	})

	t.Run("claim order, lease reclaim, ownership", func(t *testing.T) {
		pool.Exec(ctx, `DELETE FROM sign_jobs`)
		for _, id := range []string{"a", "b", "c"} {
			if err := put(testJob(id)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		a, err := signjob.Claim(ctx, pool, "w1", time.Minute)
		if err != nil || a.ID != "a" || a.Status != signjob.StatusSigning || a.LockedBy != "w1" || len(a.Approvals) != 1 {
			t.Fatalf("claim = %+v, %v", a, err)
		}
		b, _ := signjob.Claim(ctx, pool, "w2", time.Minute)
		if b.ID != "b" {
			t.Fatalf("second claim = %s, want b", b.ID)
		}
		// w2 cannot finish w1's job.
		if err := signjob.Complete(ctx, pool, "a", "w2", []byte{1}); !errors.Is(err, signjob.ErrNotHeld) {
			t.Fatalf("complete by non-holder: %v", err)
		}
		// Expire w1's lease: the job is reclaimed by w3, and w1 may no longer complete it.
		pool.Exec(ctx, `UPDATE sign_jobs SET locked_at = now() - interval '2 minutes' WHERE id='a'`)
		got, err := signjob.Claim(ctx, pool, "w3", time.Minute)
		if err != nil || got.ID != "a" || got.LockedBy != "w3" {
			t.Fatalf("reclaim = %+v, %v", got, err)
		}
		if err := signjob.Complete(ctx, pool, "a", "w1", []byte{1}); !errors.Is(err, signjob.ErrNotHeld) {
			t.Fatalf("stale worker completed: %v", err)
		}
		if err := signjob.Complete(ctx, pool, "a", "w3", []byte{7}); err != nil {
			t.Fatal(err)
		}
		if err := signjob.Complete(ctx, pool, "a", "w3", []byte{7}); !errors.Is(err, signjob.ErrNotHeld) {
			t.Fatalf("double complete: %v", err)
		}
		j, _ := signjob.Get(ctx, pool, "a")
		if j.Status != signjob.StatusDone || string(j.Signature) != "\x07" || j.LockedBy != "" {
			t.Fatalf("done job = %+v", j)
		}
		if err := signjob.Reject(ctx, pool, "b", "w2", "no"); err != nil {
			t.Fatal(err)
		}
		if j, _ := signjob.Get(ctx, pool, "b"); j.Status != signjob.StatusRejected || j.RejectReason != "no" {
			t.Fatalf("rejected job = %+v", j)
		}
		c, _ := signjob.Claim(ctx, pool, "w2", time.Minute)
		if err := signjob.Fail(ctx, pool, c.ID, "w2", "boom"); err != nil {
			t.Fatal(err)
		}
		if _, err := signjob.Claim(ctx, pool, "w2", time.Minute); !errors.Is(err, signjob.ErrNoJob) {
			t.Fatalf("empty queue: %v", err)
		}
	})

	t.Run("concurrent claims never share a job", func(t *testing.T) {
		pool.Exec(ctx, `DELETE FROM sign_jobs`)
		const n = 20
		for i := 0; i < n; i++ {
			if err := put(testJob("c" + string(rune('a'+i)))); err != nil {
				t.Fatal(err)
			}
		}
		var mu sync.Mutex
		seen := map[string]int{}
		var wg sync.WaitGroup
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					j, err := signjob.Claim(ctx, pool, "w"+string(rune('0'+w)), time.Minute)
					if err != nil {
						return
					}
					mu.Lock()
					seen[j.ID]++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(seen) != n {
			t.Fatalf("claimed %d distinct jobs, want %d", len(seen), n)
		}
		for id, c := range seen {
			if c != 1 {
				t.Fatalf("job %s claimed %d times", id, c)
			}
		}
	})
}
