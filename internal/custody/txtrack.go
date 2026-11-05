package custody

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Owner is the business object a transaction belongs to: a withdrawal or a
// sweep. The EVM nonce manager keys its allocations by (Kind, ID).
type Owner struct {
	Kind        string // "withdrawal" | "sweep" | "to-cold"
	ID          string
	PartitionID string // partition whose key signs
}

// Track is the sign jobs of one purpose for an owner. The first job of a track
// is "<prefix>:a1"; a retry of a failed job is "<prefix>:a2"; fee-bumped
// replacements are "<prefix>:r1", "<prefix>:r2", ...
type Track string

// OwnerTrack is the track of the owner's own transaction.
func OwnerTrack(o Owner) Track {
	switch o.Kind {
	case "withdrawal":
		return Track("wd:" + o.ID)
	case OwnerKindToCold:
		return Track("tocold:" + o.ID)
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

// JobStatus reads a sign job.
func (s *Service) JobStatus(ctx context.Context, jobID string) (status, reason string, err error) {
	j, err := signjob.Get(ctx, s.Pool, jobID)
	if err != nil {
		return "", "", err
	}
	switch j.Status {
	case signjob.StatusDone, signjob.StatusRejected, signjob.StatusFailed:
		return j.Status, j.RejectReason, nil
	}
	return JobPending, "", nil
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

// SubmitJob assembles a done job's signature into a transaction and broadcasts
// it. Rebroadcasting a transaction the node already knows is not an error, so
// this is safe to repeat after a crash. It returns "" and sends nothing when the
// owner's nonce is already decided.
func (s *Service) SubmitJob(ctx context.Context, jobID string, o Owner) (string, error) {
	j, err := signjob.Get(ctx, s.Pool, jobID)
	if err != nil {
		return "", err
	}
	if j.Status != signjob.StatusDone {
		return "", fmt.Errorf("custody: job %s is %s, not done", jobID, j.Status)
	}
	// A restarted workflow may submit an old job whose transaction was replaced
	// and the replacement mined: sending it would fail with "nonce too low" for
	// ever. If the nonce is already decided, send nothing; the wait loop reports it.
	n, err := s.NonceState(ctx, o)
	if err != nil {
		return "", err
	}
	switch n.State {
	case NonceMined, NonceReverted, NonceCancelled, NonceConsumed:
		return "", nil
	}
	st, err := s.Chain.Assemble(unsignedOf(j), chain.Signature{Bytes: j.Signature})
	if err != nil {
		return "", fmt.Errorf("custody: assemble %s: %w", jobID, err)
	}
	return s.Chain.Broadcast(ctx, st)
}

// RequeueJob enqueues newID as an exact copy (intent, digest, payload,
// approvals) of a failed job. The gateway keeps its reservation for the digest,
// so the copy gets the same signature, not a second one.
func (s *Service) RequeueJob(ctx context.Context, failedID, newID string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		j, err := signjob.Get(ctx, tx, failedID)
		if err != nil {
			return err
		}
		j.ID = newID
		if err := signjob.Enqueue(ctx, tx, j); err != nil {
			return err
		}
		// A restarted workflow (an operator cleared a parked row after fixing the cause, e.g. unfreezing a keyset) meets a
		// retry job that already exists and already failed. Failed means the signer had an operational problem, not that
		// the request was refused, and the gateway keeps its reservation for the digest, so signing it again can only give
		// the same signature. Without this the second failure would be final and the row would park again at once.
		_, err = tx.Exec(ctx, `UPDATE sign_jobs SET status='pending', locked_by=NULL, locked_at=NULL, updated_at=now() WHERE id=$1 AND status='failed'`, newID)
		return err
	})
}

// EnqueueReplacement builds a fee-bumped replacement of the owner's pending
// transaction at the same nonce and enqueues it as the track's n-th
// replacement, with the intent and approvals of the track's first job. It does
// nothing if that job already exists (a repeat after a crash).
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
		u.KeyRef.PartitionID = first.PartitionID
		return signjob.Enqueue(ctx, tx, signjob.Job{ID: id, PartitionID: first.PartitionID, KeyRef: u.KeyRef.Path, Chain: u.Chain,
			Intent: first.Intent, Digest: u.Digest, Payload: u.Payload, Approvals: first.Approvals})
	})
	return id, err
}

// EnqueueCancel builds a cancel (a zero-value self-send at the owner's nonce)
// and enqueues it as the first job of the cancel track. Repeating it returns
// the same job.
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
		var addr string
		err := tx.QueryRow(ctx, `SELECT address FROM evm_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3
			AND status IN ('allocated','broadcast') ORDER BY nonce DESC LIMIT 1`, s.Cfg.Chain, o.Kind, o.ID).Scan(&addr)
		if err != nil {
			return fmt.Errorf("custody: no open nonce for %s %s to cancel: %w", o.Kind, o.ID, err)
		}
		u, err := s.Chain.BuildCancel(ctx, tx, o.Kind, o.ID)
		if err != nil {
			return err
		}
		u.KeyRef.PartitionID = o.PartitionID
		intent := signjob.Intent{Kind: "cancel", ID: string(t), PartitionID: o.PartitionID, Chain: s.Cfg.Chain,
			Asset: s.Cfg.Native, To: addr, Amount: "0"}
		ib, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		return signjob.Enqueue(ctx, tx, signjob.Job{ID: id, PartitionID: o.PartitionID, KeyRef: u.KeyRef.Path, Chain: u.Chain,
			Intent: ib, Digest: u.Digest, Payload: u.Payload})
	})
	return id, err
}

// Attempt is one broadcast transaction at the owner's nonce.
type Attempt struct {
	Hash string
	Kind string // "send" | "cancel"
}

// Attempts lists every transaction ever broadcast at the nonce of the owner:
// the original, its replacements and any cancel. Any of them may be the one
// that mined, so every decision looks at all of them.
func (s *Service) Attempts(ctx context.Context, o Owner) ([]Attempt, error) {
	rows, err := s.Pool.Query(ctx, `SELECT at.tx_hash, at.kind FROM evm_tx_attempts at
		JOIN evm_nonce_allocations al ON al.chain=at.chain AND al.address=at.address AND al.nonce=at.nonce
		WHERE al.chain=$1 AND al.owner_kind=$2 AND al.owner_id=$3 ORDER BY at.created_at`, s.Cfg.Chain, o.Kind, o.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attempt
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.Hash, &a.Kind); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Nonce states.
const (
	NonceNone      = "none"      // nothing was ever broadcast at this nonce
	NoncePending   = "pending"   // at least one attempt may still mine
	NonceMined     = "mined"     // the owner's own transaction mined and succeeded
	NonceReverted  = "reverted"  // the owner's own transaction mined and reverted
	NonceCancelled = "cancelled" // a cancel mined: the nonce is free and the owner's transaction never will
	NonceConsumed  = "consumed"  // the chain's nonce passed ours but none of our attempts mined: someone else used it
)

// NonceOutcome is the combined state of every attempt at an owner's nonce.
type NonceOutcome struct {
	State string
	Hash  string // the attempt that decided it (mined, reverted, cancelled)
	Kind  string
	Fee   string // decimal wei of the deciding attempt; empty unless decided
}

// NonceState looks at all attempts. A final mined transaction decides it, and
// which one it was matters: the withdrawal itself, or the cancel.
func (s *Service) NonceState(ctx context.Context, o Owner) (NonceOutcome, error) {
	return s.nonceState(ctx, o)
}

func (s *Service) nonceState(ctx context.Context, o Owner) (NonceOutcome, error) {
	atts, err := s.Attempts(ctx, o)
	if err != nil {
		return NonceOutcome{}, err
	}
	if len(atts) == 0 {
		return NonceOutcome{State: NonceNone}, nil
	}
	dropped := 0
	for _, a := range atts {
		st, err := s.Chain.Status(ctx, a.Hash)
		if err != nil {
			return NonceOutcome{}, err
		}
		switch st {
		case chain.TxConfirmed:
			if a.Kind == "cancel" {
				return NonceOutcome{State: NonceCancelled, Hash: a.Hash, Kind: a.Kind}, nil
			}
			return NonceOutcome{State: NonceMined, Hash: a.Hash, Kind: a.Kind}, nil
		case chain.TxFailed:
			if a.Kind == "cancel" {
				return NonceOutcome{State: NonceCancelled, Hash: a.Hash, Kind: a.Kind}, nil
			}
			return NonceOutcome{State: NonceReverted, Hash: a.Hash, Kind: a.Kind}, nil
		case chain.TxDropped:
			dropped++
		}
	}
	if dropped == len(atts) {
		// Status reports dropped only when the sender's nonce has already passed
		// the attempt's and the attempt has no receipt: a transaction we did not
		// make used our nonce. A merely forgotten transaction stays pending.
		return NonceOutcome{State: NonceConsumed}, nil
	}
	return NonceOutcome{State: NoncePending}, nil
}

// NonceOpen reports whether the owner still has a nonce allocation that is not
// final. While it is, some signature at that nonce may yet be broadcast by
// someone, so the owner's funds must not be released.
func (s *Service) NonceOpen(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, o Owner) (bool, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM evm_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3
		AND status IN ('allocated','broadcast')`, s.Cfg.Chain, o.Kind, o.ID).Scan(&n)
	return n > 0, err
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
