// Package signjob defines the sign-job types stored in the sign_jobs table.
// Types only; the queue and the signing gateway are P3. Frozen after P0.
package signjob

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"time"
)

// Status values, matching sign_jobs.status.
const (
	StatusPending  = "pending"
	StatusSigning  = "signing"
	StatusDone     = "done"
	StatusRejected = "rejected"
	StatusFailed   = "failed"
)

// Approval is one approver's Ed25519 signature over Intent.Hash().
//
// It deliberately carries no public key: approver public keys and signing
// policy come only from signing-zone configuration, never from the business
// database, which an attacker may be able to write.
type Approval struct {
	Actor     string `json:"actor"`
	Signature []byte `json:"signature"`
}

// Job is a row of sign_jobs. ID is the idempotency key.
type Job struct {
	ID           string
	PartitionID  string
	KeyRef       string
	Chain        string
	Intent       []byte // JSON of Intent; approvals sign Intent.Hash()
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

// Intent is the human-readable statement approvers sign: what moves, from
// where, to where. It exists before the transaction does (nonce and fees are
// set at build time), and the built transaction must prove it matches the
// intent (chain.TxVerifier).
type Intent struct {
	Kind        string // "withdrawal" or "sweep"
	ID          string // withdrawal or sweep ID
	PartitionID string
	Chain       string
	Asset       string
	From        string // sweep source address; empty for a withdrawal
	To          string
	Amount      string // decimal base units
	// NotAfter is the Unix time (seconds) after which the approvals lapse. The
	// gateway refuses to start signing a withdrawal whose NotAfter is zero, past,
	// or too far ahead, so an old approval cannot be replayed.
	NotAfter int64
}

const intentDomain = "qv-intent-v1\n"

// Canonical returns the domain prefix followed by every field, in struct
// order, each (NotAfter as a decimal string) prefixed by its 4-byte big-endian length so that field
// boundaries are unambiguous.
func (i Intent) Canonical() []byte {
	b := []byte(intentDomain)
	for _, f := range []string{i.Kind, i.ID, i.PartitionID, i.Chain, i.Asset, i.From, i.To, i.Amount, strconv.FormatInt(i.NotAfter, 10)} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

// Hash is SHA-256 of Canonical; approvers sign this.
func (i Intent) Hash() [32]byte { return sha256.Sum256(i.Canonical()) }
