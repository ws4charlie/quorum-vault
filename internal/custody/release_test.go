package custody

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

type releaseChain struct {
	*fakeChain
	released []string
}

func (r *releaseChain) ReleaseUnsigned(_ context.Context, _ pgx.Tx, kind, id string) error {
	r.released = append(r.released, kind+":"+id)
	return nil
}

// A refused attempt gives back what it reserved only when no signature can exist: every job is rejected, or still pending (and then it is rejected
// in the same transaction, so no gateway claims it afterwards). A job being signed, done or failed means a signature may exist: nothing is released.
func TestReleaseIfUnsignedOnlyWhenNoSignatureCanExist(t *testing.T) {
	ctx := context.Background()
	s, fc := newSvc(t)
	rc := &releaseChain{fakeChain: fc}
	s.Chain = rc
	part := s.Cfg.PartitionKey("ETH", 0).String()
	intent, _ := json.Marshal(signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: part, Chain: testChain})
	mk := func(owner string, statuses ...string) Owner {
		o := Owner{Kind: "withdrawal", ID: owner, PartitionID: part}
		if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			for i, st := range statuses {
				id := JobAt(OwnerTrack(o).FirstJob(), i)
				if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: id, PartitionID: part, KeyRef: "k", Chain: testChain, Intent: intent, Digest: []byte{byte(i), 1}, Payload: []byte(`{}`)}); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE sign_jobs SET status=$2 WHERE id=$1`, id, st); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return o
	}
	status := func(o Owner, i int) string {
		var st string
		s.Pool.QueryRow(ctx, `SELECT status FROM sign_jobs WHERE id=$1`, JobAt(OwnerTrack(o).FirstJob(), i)).Scan(&st)
		return st
	}
	// All rejected: released.
	if ok, err := s.ReleaseIfUnsigned(ctx, mk("a", "rejected")); err != nil || !ok {
		t.Fatalf("one rejected job: %v %v", ok, err)
	}
	// One rejected, one still pending: released, and the pending one is rejected so no gateway claims it later.
	o := mk("b", "rejected", "pending")
	if ok, err := s.ReleaseIfUnsigned(ctx, o); err != nil || !ok {
		t.Fatalf("rejected and pending: %v %v", ok, err)
	}
	if status(o, 1) != "rejected" {
		t.Fatalf("the pending sibling is %s", status(o, 1))
	}
	// A signature may exist: nothing is released and nothing is touched.
	for _, st := range []string{"signing", "done", "failed"} {
		o := mk("c-"+st, "rejected", st, "pending")
		before := len(rc.released)
		if ok, err := s.ReleaseIfUnsigned(ctx, o); err != nil || ok || len(rc.released) != before {
			t.Fatalf("a %s sibling: released=%v err=%v", st, ok, err)
		}
		if status(o, 2) != "pending" {
			t.Fatalf("a %s sibling: the pending job was changed to %s", st, status(o, 2))
		}
	}
	if len(rc.released) != 2 {
		t.Fatalf("released %v", rc.released)
	}
	// A chain without a Releaser (EVM) releases nothing.
	s.Chain = fc
	if ok, err := s.ReleaseIfUnsigned(ctx, mk("d", "rejected")); err != nil || ok {
		t.Fatalf("no releaser: %v %v", ok, err)
	}
}

type cancelChain struct {
	*releaseChain
	built int
}

func (c *cancelChain) BuildCancel(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	c.built++
	return chain.UnsignedTx{Chain: testChain, Digest: []byte{9, 9}, Payload: []byte(`{}`), KeyRef: chain.KeyRef{Path: "k"}}, nil
}
func (c *cancelChain) Reservation(context.Context, chain.Querier, string, string) (chain.Reservation, error) {
	return chain.Reservation{Open: true, Account: "shard"}, nil
}

// On a chain whose attempts can be released, a cancel is built only when a signature may exist; otherwise EnqueueCancel says there is nothing to free
// and the caller releases the reservation. Refusals that the node makes of a broadcast are not retried for ever.
func TestEnqueueCancelOnlyWhenASignatureMayExist(t *testing.T) {
	ctx := context.Background()
	s, fc := newSvc(t)
	cc := &cancelChain{releaseChain: &releaseChain{fakeChain: fc}}
	s.Chain = cc
	part := s.Cfg.PartitionKey("ETH", 0).String()
	intent, _ := json.Marshal(signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: part, Chain: testChain})
	mk := func(id string, statuses ...string) Owner {
		o := Owner{Kind: "withdrawal", ID: id, PartitionID: part}
		InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			for i, st := range statuses {
				jid := JobAt(OwnerTrack(o).FirstJob(), i)
				if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: jid, PartitionID: part, KeyRef: "k", Chain: testChain, Intent: intent, Digest: []byte{byte(i), 2}, Payload: []byte(`{}`)}); err != nil {
					return err
				}
				tx.Exec(ctx, `UPDATE sign_jobs SET status=$2 WHERE id=$1`, jid, st)
			}
			return nil
		})
		return o
	}
	if id, err := s.EnqueueCancel(ctx, mk("a", "rejected")); err != nil || id != "" || cc.built != 0 {
		t.Fatalf("all refused: id %q err %v built %d", id, err, cc.built)
	}
	if id, err := s.EnqueueCancel(ctx, mk("b", "done", "rejected")); err != nil || id == "" || cc.built != 1 {
		t.Fatalf("a signature exists: id %q err %v built %d", id, err, cc.built)
	}
	// SubmitJob does not return the node's judgement as an error that would be retried for ever.
	s.Chain = &sendChain{fakeChain: fc, err: chain.ErrBroadcastStuck}
	o := mk("c", "done")
	if h, err := s.SubmitJob(ctx, OwnerTrack(o).FirstJob(), o); err != nil || h != "" {
		t.Fatalf("stuck: %q %v", h, err)
	}
	s.Chain = &sendChain{fakeChain: fc, err: chain.ErrInputsSpent}
	if h, err := s.SubmitJob(ctx, OwnerTrack(o).FirstJob(), o); err != nil || h != "" {
		t.Fatalf("inputs spent: %q %v", h, err)
	}
}

type sendChain struct {
	*fakeChain
	err error
}

func (c *sendChain) Outcome(context.Context, string, string) (chain.Outcome, error) {
	return chain.Outcome{State: chain.OutcomeOpen}, nil
}
func (c *sendChain) Assemble(chain.UnsignedTx, []chain.Signature) (chain.SignedTx, error) {
	return chain.SignedTx{Raw: []byte{1}}, nil
}
func (c *sendChain) Broadcast(context.Context, chain.SignedTx) (string, error) { return "", c.err }
