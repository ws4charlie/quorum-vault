package custody

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"

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

// compromisedWorld is a shard whose generation 1 is compromised, generation 2 active, and a helper that leaves an owner's allocation and jobs at the old address.
func compromisedWorld(t *testing.T) (*Service, string, func(kind, id string, nonce int, alloc string, jobs ...string)) {
	t.Helper()
	ctx := context.Background()
	s, _ := drainWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
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
	put := func(kind, id string, nonce int, alloc string, jobs ...string) {
		t.Helper()
		o := Owner{Kind: kind, ID: id, PartitionID: part}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO evm_nonce_allocations (chain, address, nonce, owner_kind, owner_id, status) VALUES ($1,$2,$3,$4,$5,$6)`,
			testChain, gen1, nonce, kind, id, alloc); err != nil {
			t.Fatal(err)
		}
		// jobs: "own=<status>" for the owner's transfer, "cancel=<status>" for its cancel
		for i, j := range jobs {
			track, st, _ := strings.Cut(j, "=")
			jid := OwnerTrack(o).FirstJob()
			if track == "cancel" {
				jid = CancelTrack(o).FirstJob()
			}
			if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
				if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: jid, PartitionID: part, KeyRef: "k", Chain: testChain, Intent: intent, Digest: []byte{byte(nonce), byte(i), 7}, Payload: []byte(`{}`)}); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE sign_jobs SET status=$2 WHERE id=$1`, jid, st)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return s, gen1, put
}

// A hole below a live transaction is filled first: the transaction above cannot confirm while the nonce under it is empty. The fill is the smallest drain
// (one wei of the native asset); the live transaction is left alone.
func TestHoleBelowALiveTransactionIsFilledFirst(t *testing.T) {
	for _, live := range []struct{ name, alloc, job string }{{"signed, not broadcast", "allocated", "own=done"}, {"broadcast", "broadcast", "own=done"}} {
		t.Run(live.name, func(t *testing.T) {
			ctx := context.Background()
			s, _, put := compromisedWorld(t)
			put("sweep", "sw-refused", 3, "allocated", "own=rejected")
			put("withdrawal", "w-live", 4, live.alloc, live.job)
			mv := plan(t, s)
			if len(mv) != 1 || mv[0].Asset != "ETH" || mv[0].Amount.Cmp(big.NewInt(1)) != 0 {
				t.Fatalf("the hole was not filled with a one-wei drain: %+v", mv)
			}
			if _, err := s.BuildDrainJob(ctx, mv[0].ID); err != nil {
				t.Fatal(err)
			}
			var k string
			s.Pool.QueryRow(ctx, `SELECT owner_kind FROM evm_nonce_allocations WHERE nonce=3`).Scan(&k)
			if k != "drain" {
				t.Fatalf("nonce 3 belongs to %s, not the drain", k)
			}
			s.Pool.QueryRow(ctx, `SELECT owner_kind FROM evm_nonce_allocations WHERE nonce=4`).Scan(&k)
			if k != "withdrawal" {
				t.Fatalf("the live transaction's nonce was taken: %s", k)
			}
		})
	}
}

// Two holes with a live transaction between them: the lower is filled now; the upper waits for the live one (nothing above it needs it).
func TestTwoHolesAroundALiveTransaction(t *testing.T) {
	ctx := context.Background()
	s, _, put := compromisedWorld(t)
	put("sweep", "sw-a", 3, "allocated", "own=rejected")
	put("withdrawal", "w-live", 4, "broadcast", "own=done")
	put("sweep", "sw-b", 5, "allocated", "own=rejected")
	mv := plan(t, s)
	if len(mv) != 1 {
		t.Fatalf("%+v", mv)
	}
	if _, err := s.BuildDrainJob(ctx, mv[0].ID); err != nil {
		t.Fatal(err)
	}
	// the filler is final; the live transaction is still not
	s.Pool.Exec(ctx, `UPDATE drain_moves SET status='confirmed'`)
	s.Pool.Exec(ctx, `UPDATE evm_nonce_allocations SET status='confirmed' WHERE owner_kind='drain'`)
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("a second filler for a hole that is above the live transaction: %+v", mv)
	}
	if _, why := drainState(t, s); !strings.Contains(why, "w-live at nonce 4 is broadcast") {
		t.Fatalf("%q", why)
	}
}

// A refused transfer whose CANCEL was signed (before the mark) and not yet broadcast keeps its nonce: the cancel can still reach the chain, and a drain on the
// same nonce would make two valid signatures for it. A cancel still queued is rejected with the rest.
func TestSignedCancelKeepsItsNonce(t *testing.T) {
	ctx := context.Background()
	s, _, put := compromisedWorld(t)
	put("sweep", "sw-cancel-signed", 3, "allocated", "own=rejected", "cancel=done")
	put("sweep", "sw-cancel-queued", 4, "allocated", "own=rejected", "cancel=pending")
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("the drain started over a signed cancel: %+v", mv)
	}
	if _, why := drainState(t, s); !strings.Contains(why, "sw-cancel-signed at nonce 3 is allocated") || !strings.Contains(why, "cancel:sweep:sw-cancel-signed:a1=done") || strings.Contains(why, "sw-cancel-queued") {
		t.Fatalf("%q", why)
	}
	var st, kind string
	s.Pool.QueryRow(ctx, `SELECT status FROM sign_jobs WHERE id='cancel:sweep:sw-cancel-queued:a1'`).Scan(&st)
	s.Pool.QueryRow(ctx, `SELECT owner_kind FROM evm_nonce_allocations WHERE nonce=4`).Scan(&kind)
	if st != "rejected" || kind != "hole" {
		t.Fatalf("queued cancel %s, nonce 4 owner %s", st, kind)
	}
	s.Pool.QueryRow(ctx, `SELECT owner_kind FROM evm_nonce_allocations WHERE nonce=3`).Scan(&kind)
	if kind != "sweep" {
		t.Fatalf("a nonce with a signed cancel was handed over: %s", kind)
	}
}

// A refusal by a cosigner AFTER the gateway reserved ("signer_refused") leaves the zone's claim on the nonce: a drain there is refused for ever, so the core
// does not make a hole of it. It asks for the cancel (which the zone signs for a compromised generation), with a not_after so the zone can wait for the
// successor to be active. A refusal by a rule (nothing claimed) still becomes a hole.
func TestClaimedRefusalGetsACancelNotAHole(t *testing.T) {
	ctx := context.Background()
	s, _, put := compromisedWorld(t)
	put("sweep", "sw-claimed", 3, "allocated", "own=rejected")
	s.Pool.Exec(ctx, `UPDATE sign_jobs SET reject_reason='signer_refused: authorizer on B refused: keyset_state: compromised' WHERE id='sweep:sw-claimed:a1'`)
	put("sweep", "sw-rule", 4, "allocated", "own=rejected")
	s.Pool.Exec(ctx, `UPDATE sign_jobs SET reject_reason='keyset_state: compromised' WHERE id='sweep:sw-rule:a1'`)
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("the drain started under a claimed nonce: %+v", mv)
	}
	if _, why := drainState(t, s); !strings.Contains(why, "sw-claimed at nonce 3") || strings.Contains(why, "sw-rule") {
		t.Fatalf("%q", why)
	}
	var kind string
	s.Pool.QueryRow(ctx, `SELECT owner_kind FROM evm_nonce_allocations WHERE nonce=4`).Scan(&kind)
	if kind != "hole" {
		t.Fatalf("a refusal by a rule is a hole, got %s", kind)
	}
	o := Owner{Kind: "sweep", ID: "sw-claimed", PartitionID: s.Cfg.PartitionKey("ETH", 0).String()}
	s.Chain = &evmCancelChain{drainChain: s.Chain.(*drainChain)}
	id, err := s.EnqueueCancel(ctx, o)
	if err != nil || id == "" {
		t.Fatalf("the cancel of a claimed nonce was not asked for: %q %v", id, err)
	}
	var intent []byte
	s.Pool.QueryRow(ctx, `SELECT intent FROM sign_jobs WHERE id=$1`, id).Scan(&intent)
	var in signjob.Intent
	json.Unmarshal(intent, &in)
	if in.NotAfter <= s.Now().Unix() {
		t.Fatalf("the cancel intent has no not_after: %+v", in)
	}
}

// evmCancelChain builds a cancel as the EVM cell does (no Releaser: the nonce is cancelled, never released).
type evmCancelChain struct{ *drainChain }

func (c *evmCancelChain) BuildCancel(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{Chain: testChain, Digest: []byte{9, 9}, Payload: []byte(`{}`), KeyRef: chain.KeyRef{Path: "k"}}, nil
}
func (c *evmCancelChain) Reservation(context.Context, chain.Querier, string, string) (chain.Reservation, error) {
	return chain.Reservation{Open: true, Account: "0xold"}, nil
}
