package approval_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/approval"
	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
)

type fixture struct {
	pool *pgxpool.Pool
	q    *approval.Queue
	log  *audit.Log
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := dbtest.New(t)
	log := audit.New(pool)
	return &fixture{pool: pool, q: approval.New(pool, log), log: log}
}

// pending inserts a pending_approval request by alice needing `required` approvals.
func (f *fixture) pending(t *testing.T, required int) domain.SignRequest {
	t.Helper()
	ctx := context.Background()
	r := domain.SignRequest{To: "0x1111111111111111111111111111111111111111", ValueWei: big.NewInt(1),
		Requester: "alice", Status: domain.StatusPendingApproval,
		Decision: &domain.Decision{Outcome: domain.OutcomeNeedsApproval, Reasons: []string{"cold wallet requires approval"}, RequiredApprovals: required}}
	if err := f.pool.QueryRow(ctx, `INSERT INTO wallets (name, tier, backend) VALUES (gen_random_uuid()::text, 'cold', 'mpc') RETURNING id::text`).Scan(&r.WalletID); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `INSERT INTO keys (wallet_id, version, curve, backend, state, public_key, address)
		VALUES ($1, 1, 'secp256k1', 'mpc', 'active', '\x04', '0x0') RETURNING id::text`, r.WalletID).Scan(&r.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `INSERT INTO sign_requests (wallet_id, key_id, chain_id, to_address, value_wei, nonce,
		gas_limit, max_fee_per_gas, max_priority_fee_per_gas, requester, status)
		VALUES ($1, $2, 11155111, $3, 1, 0, 21000, 1, 1, 'alice', 'pending_approval') RETURNING id::text`,
		r.WalletID, r.KeyID, r.To).Scan(&r.ID); err != nil {
		t.Fatal(err)
	}
	return r
}

func vote(t *testing.T, f *fixture, r domain.SignRequest, who string, approve bool) approval.Tally {
	t.Helper()
	tl, err := f.q.Vote(context.Background(), r, who, approve, "")
	if err != nil {
		t.Fatalf("Vote(%s): %v", who, err)
	}
	return tl
}

func TestTwoApprovalsCompleteRequest(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 2)
	if tl := vote(t, f, r, "bob", true); tl != (approval.Tally{Approvals: 1, Required: 2}) {
		t.Fatalf("after bob: %+v", tl)
	}
	if tl := vote(t, f, r, "carol", true); tl != (approval.Tally{Approvals: 2, Required: 2, Done: true}) {
		t.Fatalf("after carol: %+v", tl)
	}
}

func TestSingleApprovalHotDefault(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 1)
	if tl := vote(t, f, r, "bob", true); !tl.Done || tl.Rejected || tl.Approvals != 1 {
		t.Fatalf("tally %+v", tl)
	}
	// Missing decision falls back to one required approval.
	r2 := f.pending(t, 1)
	r2.Decision = nil
	if tl := vote(t, f, r2, "bob", true); !tl.Done || tl.Required != 1 {
		t.Fatalf("nil decision tally %+v", tl)
	}
}

func TestAnyRejectRejects(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 2)
	vote(t, f, r, "bob", true)
	if tl := vote(t, f, r, "carol", false); !tl.Rejected || !tl.Done || tl.Approvals != 1 {
		t.Fatalf("tally %+v", tl)
	}
}

func TestSelfApprovalRejected(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 1)
	if _, err := f.q.Vote(context.Background(), r, "alice", true, ""); !errors.Is(err, approval.ErrSelfApproval) {
		t.Fatalf("err = %v, want ErrSelfApproval", err)
	}
	var n int
	f.pool.QueryRow(context.Background(), `SELECT count(*) FROM approvals`).Scan(&n)
	if n != 0 {
		t.Fatalf("self vote stored: %d rows", n)
	}
}

func TestDuplicateVoteRejected(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 2)
	vote(t, f, r, "bob", true)
	for _, approve := range []bool{true, false} {
		if _, err := f.q.Vote(context.Background(), r, "bob", approve, "again"); !errors.Is(err, approval.ErrDuplicateVote) {
			t.Fatalf("err = %v, want ErrDuplicateVote", err)
		}
	}
}

func TestNotPendingRejected(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 1)
	for _, s := range []domain.RequestStatus{domain.StatusApproved, domain.StatusRejected, domain.StatusDenied, domain.StatusSigned, ""} {
		r.Status = s
		if _, err := f.q.Vote(context.Background(), r, "bob", true, ""); !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("status %q: err = %v, want ErrNotPending", s, err)
		}
	}
}

func TestVoteAudited(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 2)
	if _, err := f.q.Vote(context.Background(), r, "bob", true, "looks fine"); err != nil {
		t.Fatal(err)
	}
	evs, err := f.log.List(context.Background(), audit.Filter{RequestID: r.ID})
	if err != nil || len(evs) != 1 {
		t.Fatalf("events = %+v, %v", evs, err)
	}
	ev := evs[0]
	if ev.Type != domain.EventApprovalVoted || ev.Actor != "bob" || ev.WalletID != r.WalletID || ev.KeyID != r.KeyID {
		t.Fatalf("event = %+v", ev)
	}
	var p struct {
		Approver string
		Approve  bool
		Comment  string
		Tally    approval.Tally
	}
	if err := json.Unmarshal(ev.Payload, &p); err != nil || p.Approver != "bob" || !p.Approve || p.Comment != "looks fine" || p.Tally.Approvals != 1 {
		t.Fatalf("payload %s (%v)", ev.Payload, err)
	}
}

func TestConcurrentDistinctApproversBothCount(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 2)
	var wg sync.WaitGroup
	tallies := make([]approval.Tally, 2)
	errs := make([]error, 2)
	for i, who := range []string{"bob", "carol"} {
		wg.Add(1)
		go func(i int, who string) {
			defer wg.Done()
			tallies[i], errs[i] = f.q.Vote(context.Background(), r, who, true, "")
		}(i, who)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// The later tally is read after both commits, so at least one sees both votes.
	if !(tallies[0].Done || tallies[1].Done) || max(tallies[0].Approvals, tallies[1].Approvals) != 2 {
		t.Fatalf("tallies %+v", tallies)
	}
}

func TestConcurrentSameApproverOnlyOnce(t *testing.T) {
	f := newFixture(t)
	r := f.pending(t, 3)
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.q.Vote(context.Background(), r, "bob", true, "")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	var ok, dup int
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, approval.ErrDuplicateVote):
			dup++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || dup != n-1 {
		t.Fatalf("ok %d dup %d", ok, dup)
	}
}
