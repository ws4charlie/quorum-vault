package custody

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Owner is the business object a transaction belongs to: a withdrawal or a
// sweep. The chain cell keys what it reserves for the owner (EVM: a nonce) by (Kind, ID).
type Owner struct {
	Kind        string // "withdrawal" | "sweep" | "to-cold" | "rebalance"
	ID          string
	PartitionID string // partition whose key signs
}

// Track is the sign jobs of one purpose for an owner. The first attempt of a
// track is "<prefix>:a1"; a retry of a failed attempt is "<prefix>:a2"; fee-bumped
// replacements are "<prefix>:r1", "<prefix>:r2", ...
//
// An attempt is one transaction and has one sign job per signature it needs. The
// ID of an attempt is the ID of its first job, and the ID of input i > 0 is
// "<attempt>.<i>". A transaction with one signature (every EVM transaction)
// has the job IDs it always had.
type Track string

// JobAt is the ID of the sign job of input i of the attempt with ID attempt.
func JobAt(attempt string, i int) string {
	if i == 0 {
		return attempt
	}
	return attempt + "." + strconv.Itoa(i)
}

// OwnerTrack is the track of the owner's own transaction.
func OwnerTrack(o Owner) Track {
	switch o.Kind {
	case "withdrawal":
		return Track("wd:" + o.ID)
	case OwnerKindToCold:
		return Track("tocold:" + o.ID)
	case OwnerKindRebalance:
		return Track("rebal:" + o.ID)
	}
	return Track("sweep:" + o.ID)
}

// CancelTrack is the track of the cancel that frees the owner's nonce.
func CancelTrack(o Owner) Track { return Track("cancel:" + o.Kind + ":" + o.ID) }

// FirstJob is the ID of the track's first job.
func (t Track) FirstJob() string { return string(t) + ":a1" }

// Retry is the ID of the second attempt (same digest, after a failed job).
func (t Track) Retry() string { return string(t) + ":a2" }

// Replacement is the ID of the n-th fee-bumped replacement.
func (t Track) Replacement(n int) string { return string(t) + ":r" + strconv.Itoa(n) }

// Job states as the workflows see them.
const (
	JobPending  = "pending" // pending or signing in the queue
	JobDone     = signjob.StatusDone
	JobRejected = signjob.StatusRejected
	JobFailed   = signjob.StatusFailed
)

// jobGroup reads every sign job of an attempt, input 0 first. The jobs of one attempt are enqueued in one
// transaction, so the group is complete as soon as the first job exists.
func jobGroup(ctx context.Context, q signjob.Querier, attempt string) ([]signjob.Job, error) {
	first, err := signjob.Get(ctx, q, attempt)
	if err != nil {
		return nil, err
	}
	out := []signjob.Job{first}
	for i := 1; ; i++ {
		j, err := signjob.Get(ctx, q, JobAt(attempt, i))
		if errors.Is(err, signjob.ErrNotFound) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
}

// JobStatus reads an attempt: the state of all its sign jobs together. A refusal of any job refuses the attempt, at
// once, whatever the others do. Otherwise it is pending until every job is done, and failed if one failed (the
// signatures of the others stay valid, and a retry asks for them again).
func (s *Service) JobStatus(ctx context.Context, attempt string) (status, reason string, err error) {
	jobs, err := jobGroup(ctx, s.Pool, attempt)
	if err != nil {
		return "", "", err
	}
	return groupStatus(jobs)
}

func groupStatus(jobs []signjob.Job) (status, reason string, err error) {
	pending, failed, failedReason := false, false, ""
	for _, j := range jobs {
		switch j.Status {
		case signjob.StatusRejected:
			return signjob.StatusRejected, j.RejectReason, nil
		case signjob.StatusFailed:
			if !failed {
				failed, failedReason = true, j.RejectReason
			}
		case signjob.StatusDone:
		default:
			pending = true
		}
	}
	switch {
	case pending:
		return JobPending, "", nil
	case failed:
		return signjob.StatusFailed, failedReason, nil
	}
	return signjob.StatusDone, "", nil
}

// JobExists reports whether the job row exists.
func (s *Service) JobExists(ctx context.Context, jobID string) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sign_jobs WHERE id=$1)`, jobID).Scan(&ok)
	return ok, err
}

func unsignedOf(j signjob.Job) chain.UnsignedTx {
	return chain.UnsignedTx{Chain: j.Chain, Digest: j.Digest, Payload: j.Payload, KeyRef: chain.KeyRef{PartitionID: j.PartitionID, Path: j.KeyRef}}
}

// EnqueueUnsigned enqueues one sign job per input of u, as attempt's input jobs (see JobAt), with the intent and
// approvals the gateway checks. Every job carries the intent's partition, and the key of its own input in KeyRef.
// All of them go in the caller's transaction, so the attempt exists whole or not at all.
func EnqueueUnsigned(ctx context.Context, tx pgx.Tx, attempt, partitionID string, u chain.UnsignedTx, intent []byte, approvals []signjob.Approval) error {
	for i, in := range u.Inputs() {
		if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: JobAt(attempt, i), PartitionID: partitionID, KeyRef: in.KeyRef.Path, Chain: u.Chain,
			Intent: intent, Digest: in.Digest, Payload: u.Payload, Approvals: approvals}); err != nil {
			return err
		}
	}
	return nil
}

// SubmitJob assembles a done attempt's signatures into a transaction and broadcasts
// it. Rebroadcasting a transaction the node already knows is not an error, so
// this is safe to repeat after a crash. It returns "" and sends nothing when the
// owner's attempts are already decided.
func (s *Service) SubmitJob(ctx context.Context, attempt string, o Owner) (string, error) {
	jobs, err := jobGroup(ctx, s.Pool, attempt)
	if err != nil {
		return "", err
	}
	sigs := make([]chain.Signature, len(jobs))
	for i, j := range jobs {
		if j.Status != signjob.StatusDone {
			return "", fmt.Errorf("custody: job %s is %s, not done", j.ID, j.Status)
		}
		sigs[i] = chain.Signature{Bytes: j.Signature}
	}
	// A restarted workflow may submit an old attempt whose transaction was replaced
	// and the replacement mined: sending it would fail for ever (EVM: "nonce too
	// low"). If the outcome is already decided, send nothing; the wait loop reports it.
	n, err := s.AttemptState(ctx, o)
	if err != nil {
		return "", err
	}
	switch n.State {
	case AttemptMined, AttemptReverted, AttemptCancelled, AttemptConsumed:
		return "", nil
	}
	u := unsignedOf(jobs[0])
	for _, j := range jobs[1:] {
		u.More = append(u.More, chain.SigInput{Digest: j.Digest, KeyRef: chain.KeyRef{PartitionID: j.PartitionID, Path: j.KeyRef}})
	}
	st, err := s.Chain.Assemble(u, sigs)
	if err != nil {
		return "", fmt.Errorf("custody: assemble %s: %w", attempt, err)
	}
	return s.Chain.Broadcast(ctx, st)
}

// RequeueJob enqueues the attempt newID as an exact copy (intent, digest, payload,
// approvals) of a failed attempt, job by job. The gateway keeps its reservation for each digest,
// so every copy gets the same signature, not a second one: signatures already made come back as replays.
func (s *Service) RequeueJob(ctx context.Context, failedID, newID string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		jobs, err := jobGroup(ctx, tx, failedID)
		if err != nil {
			return err
		}
		for i, j := range jobs {
			j.ID = JobAt(newID, i)
			if err := signjob.Enqueue(ctx, tx, j); err != nil {
				return err
			}
			// A restarted workflow (an operator cleared a parked row after fixing the cause, e.g. unfreezing a keyset) meets a
			// retry job that already exists and already failed. Failed means the signer had an operational problem, not that
			// the request was refused, and the gateway keeps its reservation for the digest, so signing it again can only give
			// the same signature. Without this the second failure would be final and the row would park again at once.
			if _, err := tx.Exec(ctx, `UPDATE sign_jobs SET status='pending', locked_by=NULL, locked_at=NULL, updated_at=now() WHERE id=$1 AND status='failed'`, j.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnqueueReplacement builds a fee-bumped replacement of the owner's pending
// transaction (EVM: at the same nonce) and enqueues it as the track's n-th
// replacement, with the intent and approvals of the track's first job. It does
// nothing if that attempt already exists (a repeat after a crash).
func (s *Service) EnqueueReplacement(ctx context.Context, o Owner, t Track, n int) (string, error) {
	id := t.Replacement(n)
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		var have bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sign_jobs WHERE id=$1)`, id).Scan(&have); err != nil {
			return err
		}
		if have {
			return nil
		}
		first, err := signjob.Get(ctx, tx, t.FirstJob())
		if err != nil {
			return err
		}
		u, err := s.Chain.BuildReplacement(ctx, tx, o.Kind, o.ID)
		if err != nil {
			return err
		}
		// The adapter names the first partition that shares the hot address; the
		// intent (what approvers signed) names the owner's own partition.
		return EnqueueUnsigned(ctx, tx, id, first.PartitionID, u, first.Intent, first.Approvals)
	})
	return id, err
}

// EnqueueCancel builds a cancel (EVM: a zero-value self-send at the owner's nonce)
// and enqueues it as the first attempt of the cancel track. Repeating it returns
// the same job. A chain without cancel (chain.ErrNotSupported) has nothing to free
// after a refusal: it returns "" and the caller goes on.
func (s *Service) EnqueueCancel(ctx context.Context, o Owner) (string, error) {
	t := CancelTrack(o)
	id := t.FirstJob()
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		var have bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sign_jobs WHERE id=$1)`, id).Scan(&have); err != nil {
			return err
		}
		if have {
			return nil
		}
		u, err := s.Chain.BuildCancel(ctx, tx, o.Kind, o.ID)
		if err != nil {
			return err
		}
		res, err := s.Chain.Reservation(ctx, tx, o.Kind, o.ID)
		if err != nil {
			return err
		}
		if !res.Open {
			return fmt.Errorf("custody: nothing reserved for %s %s to cancel", o.Kind, o.ID)
		}
		intent := signjob.Intent{Kind: "cancel", ID: string(t), PartitionID: o.PartitionID, Chain: s.Cfg.Chain,
			Asset: s.Cfg.Native, To: res.Account, Amount: "0"}
		ib, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		return EnqueueUnsigned(ctx, tx, id, o.PartitionID, u, ib, nil)
	})
	if errors.Is(err, chain.ErrNotSupported) {
		return "", nil
	}
	return id, err
}

// Attempt states, as the workflows see them. The values are recorded in workflow histories: never change them.
const (
	AttemptNone      = "none"      // nothing was ever broadcast for the owner
	AttemptPending   = "pending"   // at least one attempt may still confirm
	AttemptMined     = "mined"     // the owner's own transaction confirmed and succeeded
	AttemptReverted  = "reverted"  // the owner's own transaction confirmed and failed (it paid its fee)
	AttemptCancelled = "cancelled" // a cancel confirmed: what the owner reserved is free and its own transaction never will
	AttemptConsumed  = "consumed"  // what the owner reserved was used by something we did not make, and no attempt of ours confirmed
)

// AttemptOutcome is the combined state of every attempt of an owner.
type AttemptOutcome struct {
	State string
	Hash  string // the attempt that decided it (mined, reverted, cancelled)
	Kind  string
	// Detail says what was consumed, for the alert (consumed only).
	Detail string
}

// AttemptState looks at all attempts through the chain cell (chain.Adapter.Outcome) and names the result as the
// workflows know it. A confirmed attempt decides it, and which one it was matters: the withdrawal itself, or the cancel.
func (s *Service) AttemptState(ctx context.Context, o Owner) (AttemptOutcome, error) {
	oc, err := s.Chain.Outcome(ctx, o.Kind, o.ID)
	if err != nil {
		return AttemptOutcome{}, err
	}
	switch oc.State {
	case chain.OutcomeConsumed:
		return AttemptOutcome{State: AttemptConsumed, Detail: oc.Detail}, nil
	case chain.OutcomeConfirmed:
		switch {
		case oc.Kind == chain.AttemptCancel:
			return AttemptOutcome{State: AttemptCancelled, Hash: oc.Hash, Kind: "cancel"}, nil
		case oc.Failed:
			return AttemptOutcome{State: AttemptReverted, Hash: oc.Hash, Kind: "send"}, nil
		}
		return AttemptOutcome{State: AttemptMined, Hash: oc.Hash, Kind: "send"}, nil
	}
	if oc.Attempts == 0 {
		return AttemptOutcome{State: AttemptNone}, nil
	}
	return AttemptOutcome{State: AttemptPending}, nil
}

// ReservationOpen reports whether the owner still holds something on the chain side that is not final. While it
// does, some signature for it may yet be broadcast by someone, so the owner's funds must not be released.
func (s *Service) ReservationOpen(ctx context.Context, q chain.Querier, o Owner) (bool, error) {
	r, err := s.Chain.Reservation(ctx, q, o.Kind, o.ID)
	return r.Open, err
}

// WaitJob polls a job until it is no longer pending or max elapses, and returns
// its state. It is the body of the workflows' polling activity.
func (s *Service) WaitJob(ctx context.Context, jobID string, max time.Duration, beat func()) (status, reason string, err error) {
	deadline := time.Now().Add(max)
	for {
		status, reason, err = s.JobStatus(ctx, jobID)
		if err != nil || status != JobPending || time.Now().After(deadline) {
			return status, reason, err
		}
		if beat != nil {
			beat()
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ReleaseIfUnsigned gives back what an owner reserved when its attempt was refused and no signature of it can exist, so the money may be
// released. A signature can exist when any job of the owner is being signed, is done or failed (the gateway keeps its reservation for a failed
// one). Jobs still pending are marked rejected in the same transaction, so no gateway claims one afterwards. Without a Releaser (EVM) or with a
// signature that may exist, it does nothing and reports false.
func (s *Service) ReleaseIfUnsigned(ctx context.Context, o Owner) (bool, error) {
	rel, ok := s.Chain.(chain.Releaser)
	if !ok {
		return false, nil
	}
	released := false
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		released = false
		prefix := string(OwnerTrack(o)) + ":"
		rows, err := tx.Query(ctx, `SELECT id, status FROM sign_jobs WHERE starts_with(id, $1) FOR UPDATE`, prefix)
		if err != nil {
			return err
		}
		var pending []string
		for rows.Next() {
			var id, st string
			if err := rows.Scan(&id, &st); err != nil {
				rows.Close()
				return err
			}
			switch st {
			case signjob.StatusPending:
				pending = append(pending, id)
			case signjob.StatusRejected:
			default: // signing, done, failed: a signature may exist
				rows.Close()
				return nil
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range pending {
			if _, err := tx.Exec(ctx, `UPDATE sign_jobs SET status='rejected', reject_reason='sibling_refused: another job of the attempt was refused', updated_at=now() WHERE id=$1 AND status='pending'`, id); err != nil {
				return err
			}
		}
		if err := rel.ReleaseUnsigned(ctx, tx, o.Kind, o.ID); err != nil {
			return err
		}
		released = true
		return nil
	})
	return released, err
}
