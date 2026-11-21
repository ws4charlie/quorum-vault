package custody

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The state table of docs/runbooks/stolen-hot-key.md, "Work in flight": for each state a transaction of the old address can be in when its generation is
// marked compromised, what the core does and what the drain planner sees. The zone refuses everything but the drain, the cancel included, so a refused
// transaction must not hold its nonce.
func TestCompromisedGenerationInFlightStates(t *testing.T) {
	ctx := context.Background()
	s, m := drainWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	m.add(gen1, "USDT", 50)
	a := WithActor(ctx, "a")
	if _, err := s.RegisterKeysetCandidate(a, shard0(s), gen2Addr, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkKeysetCompromised(a, shard0(s), 1, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateKeyset(a, shard0(s), 2); err != nil {
		t.Fatal(err)
	}
	part := s.Cfg.PartitionKey("ETH", 0).String()
	intent, _ := json.Marshal(signjob.Intent{Kind: "sweep", ID: "x", PartitionID: part, Chain: testChain})
	// owner makes an allocation at the old address and one sign job in the given state ("" for none).
	owner := func(kind, id string, nonce int, alloc, job string) Owner {
		o := Owner{Kind: kind, ID: id, PartitionID: part}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO evm_nonce_allocations (chain, address, nonce, owner_kind, owner_id, status) VALUES ($1,$2,$3,$4,$5,$6)`,
			testChain, gen1, nonce, kind, id, alloc); err != nil {
			t.Fatal(err)
		}
		if job != "" {
			InTx(ctx, s.Pool, func(tx pgx.Tx) error {
				if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: OwnerTrack(o).FirstJob(), PartitionID: part, KeyRef: "k", Chain: testChain, Intent: intent, Digest: []byte{byte(nonce), 1}, Payload: []byte(`{}`)}); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE sign_jobs SET status=$2 WHERE id=$1`, OwnerTrack(o).FirstJob(), job)
				return err
			})
		}
		return o
	}
	waits := func(want string) {
		t.Helper()
		if mv := plan(t, s); len(mv) != 0 {
			t.Fatalf("the drain started with work in flight: %+v", mv)
		}
		if st, why := drainState(t, s); st != "waiting" || !strings.Contains(why, want) {
			t.Fatalf("state %s, reason %q; want it to name %q", st, why, want)
		}
	}

	// real transactions: the drain waits and names them.
	owner("withdrawal", "w-signed", 3, "allocated", "done")     // signed, not broadcast
	owner("withdrawal", "w-signing", 4, "allocated", "signing") // being signed
	owner("withdrawal", "w-sent", 5, "broadcast", "done")       // broadcast, not confirmed
	waits("withdrawal w-signed at nonce 3 is allocated (sign jobs: wd:w-signed:a1=done)")
	if _, why := drainState(t, s); !strings.Contains(why, "w-sent at nonce 5 is broadcast") || !strings.Contains(why, "3 transactions") {
		t.Fatalf("%q", why)
	}
	s.Pool.Exec(ctx, `DELETE FROM evm_nonce_allocations`)
	s.Pool.Exec(ctx, `DELETE FROM sign_jobs`)

	// built or queued for signing (pending), and refused with no signature: both end as holes at once; nothing waits.
	queued := owner("sweep", "sw-queued", 3, "allocated", "pending")
	refused := owner("sweep", "sw-refused", 4, "allocated", "rejected")
	built := owner("withdrawal", "w-built", 5, "allocated", "")
	_ = built
	mv := plan(t, s)
	if len(mv) != 1 {
		t.Fatalf("the drain did not start: %+v", mv)
	}
	var st string
	s.Pool.QueryRow(ctx, `SELECT status FROM sign_jobs WHERE id=$1`, OwnerTrack(queued).FirstJob()).Scan(&st)
	if st != "rejected" {
		t.Fatalf("the queued job is %s: a gateway could still claim it", st)
	}
	var holes int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM evm_nonce_allocations WHERE owner_kind='hole'`).Scan(&holes)
	if holes != 3 {
		t.Fatalf("%d holes", holes)
	}
	// A refused owner whose workflow asks for the cancel gets "nothing to free", not a job the zone would refuse.
	for _, o := range []Owner{queued, refused} {
		if id, err := s.EnqueueCancel(ctx, o); err != nil || id != "" {
			t.Fatalf("cancel for %s: %q %v", o.ID, id, err)
		}
		if open, _ := s.ReservationOpen(ctx, s.Pool, o); open {
			t.Fatalf("%s still holds a reservation", o.ID)
		}
	}
	// The drain move takes the lowest hole for its own transfer.
	if _, err := s.BuildDrainJob(ctx, mv[0].ID); err != nil {
		t.Fatal(err)
	}
	// (the fake chain of this file also allocates its own nonce 1; the real cell finds the adopted one)
	var owners string
	s.Pool.QueryRow(ctx, `SELECT string_agg(owner_kind, ',' ORDER BY nonce) FROM evm_nonce_allocations WHERE nonce >= 3`).Scan(&owners)
	if owners != "drain,hole,hole" {
		t.Fatalf("the drain did not take the first hole: %s", owners)
	}
	// An owner whose nonce a drain took still gets "nothing to free".
	if id, err := s.EnqueueCancel(ctx, queued); err != nil || id != "" {
		t.Fatalf("cancel after the drain took the nonce: %q %v", id, err)
	}
}

// A planned drain (the generation is draining) keeps its cancel: the zone allows it there, so nothing is handed over and the wait is the old one.
func TestDrainingGenerationKeepsItsCancel(t *testing.T) {
	ctx := context.Background()
	s, _ := drainWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	a := WithActor(ctx, "a")
	if _, err := s.RegisterKeysetCandidate(a, shard0(s), gen2Addr, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDrainingKeyset(a, shard0(s), 1, 2); err != nil {
		t.Fatal(err)
	}
	s.Pool.Exec(ctx, `INSERT INTO evm_nonce_allocations (chain, address, nonce, owner_kind, owner_id, status) VALUES ($1,$2,3,'sweep','sw-1','allocated')`, testChain, gen1)
	if _, err := s.ActivateKeyset(a, shard0(s), 2); err != nil {
		t.Fatal(err)
	}
	plan(t, s)
	if _, why := drainState(t, s); !strings.Contains(why, "sweep sw-1 at nonce 3 is allocated") {
		t.Fatalf("%q", why)
	}
	var kind string
	s.Pool.QueryRow(ctx, `SELECT owner_kind FROM evm_nonce_allocations WHERE nonce=3`).Scan(&kind)
	if kind != "sweep" {
		t.Fatalf("a draining generation's nonce was handed over: %s", kind)
	}
}
