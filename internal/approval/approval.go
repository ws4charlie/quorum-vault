// Package approval records approver votes on sign requests that need approval
// and tallies them (dual control). It writes only the approvals table plus an
// approval.voted audit event; moving sign_requests.status to approved/rejected
// is the caller's job, driven by the returned Tally.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

var (
	ErrSelfApproval  = errors.New("approval: requester cannot vote on own request")
	ErrDuplicateVote = errors.New("approval: approver already voted on this request")
	ErrNotPending    = errors.New("approval: request is not pending approval")
)

// Tally is the vote state of one request after a vote.
type Tally struct {
	Approvals int  `json:"approvals"` // distinct approve votes
	Rejected  bool `json:"rejected"`  // any reject vote
	Required  int  `json:"required"`
	Done      bool `json:"done"` // approved (Approvals >= Required) or rejected
}

// Queue records votes.
type Queue struct {
	pool *pgxpool.Pool
	aud  domain.Auditor
}

// New returns a Queue.
func New(pool *pgxpool.Pool, aud domain.Auditor) *Queue { return &Queue{pool: pool, aud: aud} }

// Vote records approver's vote on req and returns the tally read back from the
// DB. Required = req.Decision.RequiredApprovals (at least 1). The approver must
// differ from the requester and may vote once per request (enforced by the
// unique (request_id, approver) constraint, so it holds under concurrency).
func (q *Queue) Vote(ctx context.Context, req domain.SignRequest, approver string, approve bool, comment string) (Tally, error) {
	if req.Status != domain.StatusPendingApproval {
		return Tally{}, fmt.Errorf("%w (status %q)", ErrNotPending, req.Status)
	}
	if approver == "" {
		return Tally{}, errors.New("approval: approver is required")
	}
	if approver == req.Requester {
		return Tally{}, ErrSelfApproval
	}
	required := 1
	if req.Decision != nil && req.Decision.RequiredApprovals > required {
		required = req.Decision.RequiredApprovals
	}

	if _, err := q.pool.Exec(ctx, `INSERT INTO approvals (request_id, approver, approve, comment) VALUES ($1, $2, $3, $4)`,
		req.ID, approver, approve, comment); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Tally{}, ErrDuplicateVote
		}
		return Tally{}, fmt.Errorf("approval: insert vote: %w", err)
	}

	t := Tally{Required: required}
	if err := q.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE approve), bool_or(NOT approve) IS TRUE
		FROM approvals WHERE request_id = $1`, req.ID).Scan(&t.Approvals, &t.Rejected); err != nil {
		return Tally{}, fmt.Errorf("approval: tally: %w", err)
	}
	t.Done = t.Rejected || t.Approvals >= t.Required

	payload, err := json.Marshal(struct {
		Approver string `json:"approver"`
		Approve  bool   `json:"approve"`
		Comment  string `json:"comment"`
		Tally    Tally  `json:"tally"`
	}{approver, approve, comment, t})
	if err != nil {
		return Tally{}, err
	}
	if _, err := q.aud.Append(ctx, domain.AuditEvent{Actor: approver, Type: domain.EventApprovalVoted,
		RequestID: req.ID, WalletID: req.WalletID, KeyID: req.KeyID, Payload: payload}); err != nil {
		return Tally{}, fmt.Errorf("approval: audit: %w", err)
	}
	return t, nil
}
