package signjob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Errors returned by the queue.
var (
	ErrConflict = errors.New("signjob: job id exists with a different body")
	ErrNotFound = errors.New("signjob: job not found")
	ErrNotHeld  = errors.New("signjob: job is not held by this worker")
	ErrNoJob    = errors.New("signjob: no job available")
)

// Querier is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Enqueue inserts job as pending inside the caller's transaction, so the job
// exists iff the business change commits. Repeating an identical job is a
// no-op; the same ID with a different body returns ErrConflict. Status,
// signature and lock fields of job are ignored.
func Enqueue(ctx context.Context, tx pgx.Tx, job Job) error {
	approvals := job.Approvals
	if approvals == nil {
		approvals = []Approval{}
	}
	ab, err := json.Marshal(approvals)
	if err != nil {
		return fmt.Errorf("signjob: marshal approvals: %w", err)
	}
	if !json.Valid(job.Intent) || !json.Valid(job.Payload) {
		return errors.New("signjob: intent and payload must be valid JSON")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO sign_jobs (id, partition_id, key_ref, chain, intent, digest, payload, approvals)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7::jsonb,$8::jsonb) ON CONFLICT (id) DO NOTHING`,
		job.ID, job.PartitionID, job.KeyRef, job.Chain, string(job.Intent), job.Digest, string(job.Payload), string(ab))
	if err != nil {
		return fmt.Errorf("signjob: enqueue %s: %w", job.ID, err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var same bool
	err = tx.QueryRow(ctx, `SELECT partition_id=$2 AND key_ref=$3 AND chain=$4 AND intent=$5::jsonb
			AND digest=$6 AND payload=$7::jsonb AND approvals=$8::jsonb
		FROM sign_jobs WHERE id=$1`,
		job.ID, job.PartitionID, job.KeyRef, job.Chain, string(job.Intent), job.Digest, string(job.Payload), string(ab)).Scan(&same)
	if err != nil {
		return fmt.Errorf("signjob: compare %s: %w", job.ID, err)
	}
	if !same {
		return fmt.Errorf("%w: %s", ErrConflict, job.ID)
	}
	return nil
}

const jobCols = `id, partition_id, key_ref, chain, intent, digest, payload, approvals, status,
	signature, reject_reason, locked_by, locked_at, created_at, updated_at`

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var intent, payload, approvals []byte
	var reason, lockedBy *string
	err := row.Scan(&j.ID, &j.PartitionID, &j.KeyRef, &j.Chain, &intent, &j.Digest, &payload, &approvals, &j.Status,
		&j.Signature, &reason, &lockedBy, &j.LockedAt, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		return Job{}, err
	}
	j.Intent, j.Payload = bytes.Clone(intent), bytes.Clone(payload)
	if reason != nil {
		j.RejectReason = *reason
	}
	if lockedBy != nil {
		j.LockedBy = *lockedBy
	}
	if err := json.Unmarshal(approvals, &j.Approvals); err != nil {
		return Job{}, fmt.Errorf("signjob: decode approvals of %s: %w", j.ID, err)
	}
	return j, nil
}

// Claim takes the oldest pending job, or a signing job whose lease (time since
// locked_at) has expired, and marks it signing for workerID. It uses
// FOR UPDATE SKIP LOCKED, so concurrent workers never get the same job.
// Returns ErrNoJob when nothing is available.
func Claim(ctx context.Context, q Querier, workerID string, lease time.Duration) (Job, error) {
	j, err := scanJob(q.QueryRow(ctx, `UPDATE sign_jobs SET status='signing', locked_by=$1, locked_at=now(), updated_at=now()
		WHERE id = (SELECT id FROM sign_jobs
			WHERE status='pending' OR (status='signing' AND locked_at < now() - $2::interval)
			ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+jobCols, workerID, fmt.Sprintf("%d microseconds", lease.Microseconds())))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNoJob
	}
	if err != nil {
		return Job{}, fmt.Errorf("signjob: claim: %w", err)
	}
	return j, nil
}

func finish(ctx context.Context, q Querier, id, workerID, status string, sig []byte, reason string) error {
	var r *string
	if reason != "" {
		r = &reason
	}
	tag, err := q.Exec(ctx, `UPDATE sign_jobs SET status=$3, signature=$4, reject_reason=$5, locked_by=NULL, locked_at=NULL, updated_at=now()
		WHERE id=$1 AND status='signing' AND locked_by=$2`, id, workerID, status, sig, r)
	if err != nil {
		return fmt.Errorf("signjob: %s %s: %w", status, id, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: %s", ErrNotHeld, id)
	}
	return nil
}

// Complete stores sig and marks the job done. Only the worker that still holds
// the job (status signing, locked_by = workerID) may complete it.
func Complete(ctx context.Context, q Querier, id, workerID string, sig []byte) error {
	if len(sig) == 0 {
		return errors.New("signjob: complete without a signature")
	}
	return finish(ctx, q, id, workerID, StatusDone, sig, "")
}

// Reject marks the job rejected with reason (a policy or verification refusal).
func Reject(ctx context.Context, q Querier, id, workerID, reason string) error {
	return finish(ctx, q, id, workerID, StatusRejected, nil, reason)
}

// Fail marks the job failed (an operational error, not a refusal).
func Fail(ctx context.Context, q Querier, id, workerID, reason string) error {
	return finish(ctx, q, id, workerID, StatusFailed, nil, reason)
}

// Get reads one job.
func Get(ctx context.Context, q Querier, id string) (Job, error) {
	j, err := scanJob(q.QueryRow(ctx, `SELECT `+jobCols+` FROM sign_jobs WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return j, err
}
