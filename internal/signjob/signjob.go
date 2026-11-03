// Package signjob defines the sign-job types stored in the sign_jobs table.
// Types only; the queue and the signing gateway are P3. Frozen after P0.
package signjob

import "time"

// Status values, matching sign_jobs.status.
const (
	StatusPending  = "pending"
	StatusSigning  = "signing"
	StatusDone     = "done"
	StatusRejected = "rejected"
	StatusFailed   = "failed"
)

// Approval is one approver's Ed25519 signature over the job digest.
type Approval struct {
	Actor     string `json:"actor"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
}

// Job is a row of sign_jobs. ID is the idempotency key.
type Job struct {
	ID           string
	PartitionID  string
	KeyRef       string
	Chain        string
	Digest       []byte
	Payload      []byte // JSON
	Approvals    []Approval
	Status       string
	Signature    []byte
	RejectReason string
	LockedBy     string
	LockedAt     *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
