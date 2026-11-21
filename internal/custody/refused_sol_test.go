package custody

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A Solana attempt the zone refused: what is left behind is decided from every job of the attempt (refused_sol.go). The attempt has one sign job per
// signer; the core calls it refused as soon as one is rejected.

func solRefusalWorld(t *testing.T) (*Service, *cancelChain, func(id string, jobs ...string) Owner) {
	t.Helper()
	ctx := context.Background()
	s, fc := newSvc(t)
	cc := &cancelChain{releaseChain: &releaseChain{fakeChain: fc}}
	s.Chain = cc
	s.Cfg.Family = FamilySOL
	part := s.Cfg.PartitionKey("ETH", 0).String()
	intent, _ := json.Marshal(signjob.Intent{Kind: "sweep", ID: "x", PartitionID: part, Chain: testChain})
	// jobs are "status" or "status:reason"
	return s, cc, func(id string, jobs ...string) Owner {
		o := Owner{Kind: "sweep", ID: id, PartitionID: part}
		if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			for i, j := range jobs {
				st, why, _ := strings.Cut(j, ":")
				jid := JobAt(OwnerTrack(o).FirstJob(), i)
				if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: jid, PartitionID: part, KeyRef: "k", Chain: testChain, Intent: intent, Digest: []byte{byte(i), 3, byte(len(id))}, Payload: []byte(`{}`)}); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE sign_jobs SET status=$2, reject_reason=NULLIF($3,'') WHERE id=$1`, jid, st, why); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return o
	}
}

func setSolJob(t *testing.T, s *Service, o Owner, i int, status, why string) {
	t.Helper()
	if _, err := s.Pool.Exec(context.Background(), `UPDATE sign_jobs SET status=$2, reject_reason=NULLIF($3,''), updated_at=now() WHERE id=$1`, JobAt(OwnerTrack(o).FirstJob(), i), status, why); err != nil {
		t.Fatal(err)
	}
}

// The race behind the parked sweep: the first job is refused by a rule while a sibling is still being signed. The sibling is refused a moment later (same
// message, same rule). Before the fix a cancel was built at once (a signature "may exist"), the zone refused it because nothing was claimed, and the sweep
// was parked for an operator; now the core waits for the sibling and releases the nonce account.
func TestSolRefusedSweepWithASiblingStillBeingSignedIsReleased(t *testing.T) {
	ctx := context.Background()
	s, cc, mk := solRefusalWorld(t)
	o := mk("w", "rejected:tx_mismatch: sol: deposit generation 1 is written as no generation", "signing", "signing")
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		time.Sleep(400 * time.Millisecond)
		setSolJob(t, s, o, 1, "rejected", "tx_mismatch: sol: deposit generation 1 is written as no generation")
		time.Sleep(200 * time.Millisecond)
		setSolJob(t, s, o, 2, "rejected", "tx_mismatch: sol: deposit generation 1 is written as no generation")
	}()
	id, err := s.EnqueueCancel(ctx, o)
	if err != nil || id != "" || cc.built != 0 {
		t.Fatalf("a cancel was built for an attempt that was refused by a rule and never signed: id=%q built=%d err=%v", id, cc.built, err)
	}
	if ok, err := s.ReleaseIfUnsigned(ctx, o); err != nil || !ok || len(cc.released) != 1 {
		t.Fatalf("the nonce account was not released: %v %v %v", ok, err, cc.released)
	}
}

// Everything that may be signed keeps its nonce: a sibling that ended done or failed, a sibling that is still being signed when the wait ends, and a
// refusal by a cosigner after the gateway reserved (a claim without a signature: released, it would be refused for ever as taken). Each gets the cancel and
// nothing is released.
func TestSolRefusedAttemptThatMayBeSignedOrClaimedKeepsItsNonce(t *testing.T) {
	ctx := context.Background()
	old := solSettleWait
	solSettleWait = 600 * time.Millisecond
	defer func() { solSettleWait = old }()
	for _, tc := range []struct {
		name string
		jobs []string
	}{
		{"sibling done", []string{"rejected:tx_mismatch", "done"}},
		{"sibling failed", []string{"rejected:tx_mismatch", "failed"}},
		{"sibling signing past the wait", []string{"rejected:tx_mismatch", "signing"}},
		{"cosigner refused after the reservation", []string{"rejected:signer_refused: authorizer on B refused: keyset_state: candidate", "pending"}},
		{"cosigner refused, sibling refused by a rule", []string{"rejected:tx_mismatch", "rejected:signer_refused: authorizer on B refused"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cc, mk := solRefusalWorld(t)
			o := mk("w", tc.jobs...)
			id, err := s.EnqueueCancel(ctx, o)
			if err != nil || id == "" || cc.built != 1 {
				t.Fatalf("no cancel for an attempt that may be signed or claimed: id=%q built=%d err=%v", id, cc.built, err)
			}
			if ok, err := s.ReleaseIfUnsigned(ctx, o); err != nil || ok || len(cc.released) != 0 {
				t.Fatalf("released a nonce that may be signed or claimed: %v %v %v", ok, err, cc.released)
			}
		})
	}
}

// A pending sibling of a rule refusal is rejected by the core in the release, so no gateway claims it afterwards.
func TestSolRefusedByARuleRejectsPendingSiblingsAndReleases(t *testing.T) {
	ctx := context.Background()
	s, cc, mk := solRefusalWorld(t)
	o := mk("w", "rejected:tx_mismatch", "pending", "pending")
	if id, err := s.EnqueueCancel(ctx, o); err != nil || id != "" {
		t.Fatalf("cancel %q %v", id, err)
	}
	if ok, err := s.ReleaseIfUnsigned(ctx, o); err != nil || !ok || len(cc.released) != 1 {
		t.Fatalf("%v %v %v", ok, err, cc.released)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM sign_jobs WHERE starts_with(id,$1) AND status='rejected'`, string(OwnerTrack(o))+":").Scan(&n)
	if n != 3 {
		t.Fatalf("%d of 3 jobs rejected", n)
	}
}

// A refusal that does not go away is not replanned for ever: after solRefusedBound failures in a row the address is left alone, with one ALERT, and is
// tried again after a day. A failure of another kind, or a confirmed sweep, ends the streak.
func TestSolRefusedSweepsAreReplannedAtMostSixTimesThenOncePerDay(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	s.Cfg.Family = FamilySOL
	add := func(i int, status, why string, age time.Duration) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, `INSERT INTO sweeps (id, chain, asset, from_address, to_partition_id, amount, status, failure_reason, created_at, updated_at)
			VALUES ($1,$2,'SOL','addr',$3,1,$4,$5, now() - $6::interval, now() - $6::interval)`,
			fmt.Sprintf("sw-%d", i), s.Cfg.Chain, s.Cfg.PartitionKey("ETH", 0).String(), status, why, fmt.Sprintf("%d seconds", int(age.Seconds()))); err != nil {
			t.Fatal(err)
		}
	}
	left := func() bool {
		t.Helper()
		b, err := s.solRefusedLeftAlone(ctx, "addr", "SOL")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for i := 0; i < solRefusedBound-1; i++ {
		add(i, "failed", "gateway refused: tx_mismatch", time.Duration(10-i)*time.Hour)
	}
	if left() {
		t.Fatal("left alone after five refusals")
	}
	add(10, "failed", "gateway refused: tx_mismatch", time.Hour)
	if !left() {
		t.Fatal("not left alone after six refusals in a row")
	}
	// the probe: the last failure is older than a day
	s.Pool.Exec(ctx, `UPDATE sweeps SET updated_at = now() - interval '25 hours'`)
	if left() {
		t.Fatal("no probe after a day")
	}
	// another kind of failure in the streak ends it
	s.Pool.Exec(ctx, `UPDATE sweeps SET updated_at = now() - interval '1 hour'`)
	s.Pool.Exec(ctx, `UPDATE sweeps SET failure_reason='could not build: x' WHERE id='sw-2'`)
	if left() {
		t.Fatal("a streak that is not all refusals")
	}
}

// A compromised generation cannot cancel, and its drain takes a claimed nonce account's lamports all the same (gateway test
// TestSolCompromisedDrainTakesAClaimedNonceAccount): a refusal by a cosigner is released there, not held for a cancel that would be refused and park the
// owner, which would keep the drain waiting for ever on "transactions still in flight".
func TestSolClaimedRefusalOfACompromisedGenerationIsReleased(t *testing.T) {
	ctx := context.Background()
	for _, compromised := range []bool{false, true} {
		s, gen1, _ := compromisedWorld(t)
		if !compromised {
			if _, err := s.Pool.Exec(ctx, `UPDATE keysets SET state='draining' WHERE lower(address)=lower($1)`, gen1); err != nil {
				t.Fatal(err)
			}
		}
		fc := s.Chain.(*drainChain).fakeChain
		cc := &cancelChain{releaseChain: &releaseChain{fakeChain: fc}}
		s.Chain = cc
		s.Cfg.Family = FamilySOL
		part := s.Cfg.PartitionKey("ETH", 0).String()
		intent, _ := json.Marshal(signjob.Intent{Kind: "sweep", ID: "x", PartitionID: part, Chain: testChain})
		o := Owner{Kind: "sweep", ID: "w", PartitionID: part}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO sol_nonce_accounts (chain, address, hot_address, idx) VALUES ($1,'nonce-0',$2,0)`, s.Cfg.Chain, gen1); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO sol_nonce_allocations (chain, address, hot_address, nonce_value, owner_kind, owner_id, status, payload, price) VALUES ($1,'nonce-0',$2,'v','sweep','w','allocated','{}',0)`, s.Cfg.Chain, gen1); err != nil {
			t.Fatal(err)
		}
		if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: OwnerTrack(o).FirstJob(), PartitionID: part, KeyRef: "k", Chain: testChain, Intent: intent, Digest: []byte{1, 2, 3}, Payload: []byte(`{}`)}); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE sign_jobs SET status='rejected', reject_reason='signer_refused: authorizer on B refused' WHERE id=$1`, OwnerTrack(o).FirstJob())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		id, err := s.EnqueueCancel(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		if compromised && (id != "" || cc.built != 0) {
			t.Fatalf("a cancel was asked for at a compromised generation: %q", id)
		}
		if !compromised && (id == "" || cc.built != 1) {
			t.Fatalf("no cancel for a claimed refusal at a draining generation")
		}
	}
}
