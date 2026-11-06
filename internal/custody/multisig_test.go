package custody

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// multiChain is a fake chain, in test code only, whose transactions need two signatures under two different keys and which has no
// cancel (like Bitcoin will): it records what Assemble and Broadcast were given.
type multiChain struct {
	*fakeChain
	outcome   chain.Outcome
	assembled [][]chain.Signature
	moreSeen  []int
	sent      int
	nonce     int // makes each built transaction different
}

func (m *multiChain) tx() chain.UnsignedTx {
	m.nonce++
	d := func(s string) []byte {
		return []byte{byte(m.nonce), s[0], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}
	return chain.UnsignedTx{Chain: testChain, Digest: d("a"), Payload: []byte(`{"tx":true}`), KeyRef: chain.KeyRef{Path: "k/0"},
		More: []chain.SigInput{{Digest: d("b"), KeyRef: chain.KeyRef{Path: "k/1"}}}}
}
func (m *multiChain) BuildReplacement(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return m.tx(), nil
}
func (m *multiChain) BuildCancel(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, chain.ErrNotSupported
}
func (m *multiChain) Assemble(u chain.UnsignedTx, sigs []chain.Signature) (chain.SignedTx, error) {
	m.assembled = append(m.assembled, sigs)
	m.moreSeen = append(m.moreSeen, len(u.More))
	return chain.SignedTx{Chain: testChain, Raw: []byte("raw")}, nil
}
func (m *multiChain) Broadcast(context.Context, chain.SignedTx) (string, error) {
	m.sent++
	return "0xhash", nil
}
func (m *multiChain) Outcome(context.Context, string, string) (chain.Outcome, error) {
	if m.outcome.State == "" {
		return chain.Outcome{State: chain.OutcomeOpen}, nil
	}
	return m.outcome, nil
}
func (m *multiChain) Reservation(context.Context, chain.Querier, string, string) (chain.Reservation, error) {
	return chain.Reservation{}, nil
}

func newMultiSvc(t *testing.T) (*Service, *multiChain, string) {
	t.Helper()
	s, fc := newSvc(t)
	mc := &multiChain{fakeChain: fc}
	s.Chain = mc
	return s, mc, s.Cfg.PartitionKey("ETH", 0).String()
}

func setJob(t *testing.T, s *Service, id, status string, sig []byte) {
	t.Helper()
	if _, err := s.Pool.Exec(context.Background(), `UPDATE sign_jobs SET status=$2, signature=$3 WHERE id=$1`, id, status, sig); err != nil {
		t.Fatal(err)
	}
}

func enqueue(t *testing.T, s *Service, mc *multiChain, id, part string) {
	t.Helper()
	intent, _ := json.Marshal(signjob.Intent{Kind: "sweep", ID: "s1", PartitionID: part, Chain: testChain})
	if err := InTx(context.Background(), s.Pool, func(tx pgx.Tx) error {
		return EnqueueUnsigned(context.Background(), tx, id, part, mc.tx(), intent, nil)
	}); err != nil {
		t.Fatal(err)
	}
}

// One attempt, two jobs: both must finish, a refusal of either refuses the attempt, and the transaction is assembled from
// both signatures in input order, once.
func TestAttemptWithTwoSignatures(t *testing.T) {
	ctx := context.Background()
	s, mc, part := newMultiSvc(t)
	enqueue(t, s, mc, "sweep:s1:a1", part)

	// The first job keeps the ID a one-signature attempt always had; the second is "<id>.1" under another key.
	j0, err := signjob.Get(ctx, s.Pool, "sweep:s1:a1")
	if err != nil {
		t.Fatal(err)
	}
	j1, err := signjob.Get(ctx, s.Pool, "sweep:s1:a1.1")
	if err != nil {
		t.Fatal(err)
	}
	if j0.KeyRef != "k/0" || j1.KeyRef != "k/1" || j0.PartitionID != j1.PartitionID || string(j0.Payload) != string(j1.Payload) || string(j0.Digest) == string(j1.Digest) {
		t.Fatalf("jobs: %+v %+v", j0, j1)
	}

	status := func() string {
		st, _, err := s.JobStatus(ctx, "sweep:s1:a1")
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if status() != JobPending {
		t.Fatalf("nothing signed: %s", status())
	}
	setJob(t, s, "sweep:s1:a1", signjob.StatusDone, []byte("sig0"))
	if status() != JobPending {
		t.Fatalf("one of two signed: %s", status())
	}
	if _, err := s.SubmitJob(ctx, "sweep:s1:a1", Owner{Kind: "sweep", ID: "s1"}); err == nil || mc.sent != 0 {
		t.Fatalf("submitted with one signature missing: %v, sent %d", err, mc.sent)
	}
	setJob(t, s, "sweep:s1:a1.1", signjob.StatusDone, []byte("sig1"))
	if status() != JobDone {
		t.Fatalf("both signed: %s", status())
	}
	h, err := s.SubmitJob(ctx, "sweep:s1:a1", Owner{Kind: "sweep", ID: "s1"})
	if err != nil || h != "0xhash" || mc.sent != 1 {
		t.Fatalf("submit: %q %v sent %d", h, err, mc.sent)
	}
	if len(mc.assembled) != 1 || len(mc.assembled[0]) != 2 || string(mc.assembled[0][0].Bytes) != "sig0" || string(mc.assembled[0][1].Bytes) != "sig1" || mc.moreSeen[0] != 1 {
		t.Fatalf("assembled from %v (more %v), want [sig0 sig1]", mc.assembled, mc.moreSeen)
	}

	// Once the outcome is decided, nothing is sent again.
	mc.outcome = chain.Outcome{State: chain.OutcomeConfirmed, Hash: "0xhash", Kind: chain.AttemptSend}
	if h, err := s.SubmitJob(ctx, "sweep:s1:a1", Owner{Kind: "sweep", ID: "s1"}); err != nil || h != "" || mc.sent != 1 {
		t.Fatalf("submit after the outcome: %q %v sent %d", h, err, mc.sent)
	}
}

func TestRefusalOfOneJobRefusesTheAttempt(t *testing.T) {
	ctx := context.Background()
	s, mc, part := newMultiSvc(t)
	enqueue(t, s, mc, "sweep:s1:a1", part)
	setJob(t, s, "sweep:s1:a1", signjob.StatusDone, []byte("sig0"))
	if _, err := s.Pool.Exec(ctx, `UPDATE sign_jobs SET status='rejected', reject_reason='policy_x: no' WHERE id='sweep:s1:a1.1'`); err != nil {
		t.Fatal(err)
	}
	if st, why, _ := s.JobStatus(ctx, "sweep:s1:a1"); st != JobRejected || why != "policy_x: no" {
		t.Fatalf("one rejected: %s %q", st, why)
	}
	// ... at once, even while the other job is still pending.
	setJob(t, s, "sweep:s1:a1", signjob.StatusPending, nil)
	if st, _, _ := s.JobStatus(ctx, "sweep:s1:a1"); st != JobRejected {
		t.Fatalf("rejected beside a pending job: %s", st)
	}
}

// A failed attempt is asked for again as a whole: the same digests, so a job that was signed comes back as the same signature.
func TestRetryOfAFailedAttemptCopiesEveryJob(t *testing.T) {
	ctx := context.Background()
	s, mc, part := newMultiSvc(t)
	enqueue(t, s, mc, "sweep:s1:a1", part)
	setJob(t, s, "sweep:s1:a1", signjob.StatusDone, []byte("sig0"))
	setJob(t, s, "sweep:s1:a1.1", signjob.StatusFailed, nil)
	if st, _, _ := s.JobStatus(ctx, "sweep:s1:a1"); st != JobFailed {
		t.Fatalf("one failed: %s", st)
	}
	if err := s.RequeueJob(ctx, "sweep:s1:a1", "sweep:s1:a2"); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"sweep:s1:a2", "sweep:s1:a2.1"} {
		old, _ := signjob.Get(ctx, s.Pool, JobAt("sweep:s1:a1", i))
		cp, err := signjob.Get(ctx, s.Pool, id)
		if err != nil || cp.Status != signjob.StatusPending || string(cp.Digest) != string(old.Digest) || old.KeyRef != cp.KeyRef {
			t.Fatalf("copy %s: %+v %v", id, cp, err)
		}
	}
	// Repeating it, after the copy failed too, revives the failed one (as before).
	setJob(t, s, "sweep:s1:a2.1", signjob.StatusFailed, nil)
	if err := s.RequeueJob(ctx, "sweep:s1:a1", "sweep:s1:a2"); err != nil {
		t.Fatal(err)
	}
	if cp, _ := signjob.Get(ctx, s.Pool, "sweep:s1:a2.1"); cp.Status != signjob.StatusPending {
		t.Fatalf("revived copy: %s", cp.Status)
	}
}

// A replacement of a transaction with two inputs is two jobs again, with the intent of the first attempt.
func TestReplacementHasOneJobPerInput(t *testing.T) {
	ctx := context.Background()
	s, mc, part := newMultiSvc(t)
	enqueue(t, s, mc, "sweep:s1:a1", part)
	id, err := s.EnqueueReplacement(ctx, Owner{Kind: "sweep", ID: "s1", PartitionID: part}, Track("sweep:s1"), 1)
	if err != nil || id != "sweep:s1:r1" {
		t.Fatalf("%q %v", id, err)
	}
	first, _ := signjob.Get(ctx, s.Pool, "sweep:s1:a1")
	for i := 0; i < 2; i++ {
		j, err := signjob.Get(ctx, s.Pool, JobAt(id, i))
		if err != nil || string(j.Intent) != string(first.Intent) || j.PartitionID != first.PartitionID {
			t.Fatalf("replacement job %d: %+v %v", i, j, err)
		}
	}
}

// A chain without cancel has nothing to free after a refusal: EnqueueCancel says so with no job.
func TestChainWithoutCancelEnqueuesNoCancel(t *testing.T) {
	ctx := context.Background()
	s, _, part := newMultiSvc(t)
	id, err := s.EnqueueCancel(ctx, Owner{Kind: "sweep", ID: "s1", PartitionID: part})
	if err != nil || id != "" {
		t.Fatalf("cancel on a chain without cancel: %q %v", id, err)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM sign_jobs WHERE id LIKE 'cancel:%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d cancel jobs", n)
	}
}
