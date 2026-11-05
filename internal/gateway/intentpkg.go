package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// IntentPackageVersion is the only package version this code reads and writes.
const IntentPackageVersion = "qv-intentpkg-v1"

// intentPackage is the canonical, versioned encoding of everything party B's cosigner needs to repeat the gateway's
// decision: the intent as the approvers signed it, the unsigned payload, the digest, chain and partition, and the
// approvals. The mpc-party service passes it through opaquely. Encoding is encoding/json of this struct: fixed field
// order, base64 for byte fields, no extra whitespace, unknown fields refused on decode.
type intentPackage struct {
	V           string             `json:"v"`
	JobID       string             `json:"job_id"`
	Chain       string             `json:"chain"`
	PartitionID string             `json:"partition_id"`
	KeyRef      string             `json:"key_ref"`
	Intent      []byte             `json:"intent"`
	Payload     []byte             `json:"payload"`
	Digest      []byte             `json:"digest"`
	Approvals   []signjob.Approval `json:"approvals"`
}

// MaxIntentPackage bounds the encoded size.
const MaxIntentPackage = 192 << 10

// EncodePackage encodes the parts of job that a cosigner needs.
func EncodePackage(job signjob.Job) ([]byte, error) {
	p := intentPackage{V: IntentPackageVersion, JobID: job.ID, Chain: job.Chain, PartitionID: job.PartitionID, KeyRef: job.KeyRef,
		Intent: job.Intent, Payload: job.Payload, Digest: job.Digest, Approvals: job.Approvals}
	if p.Approvals == nil {
		p.Approvals = []signjob.Approval{}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxIntentPackage {
		return nil, fmt.Errorf("intent package is %d bytes, limit %d", len(b), MaxIntentPackage)
	}
	return b, nil
}

// DecodePackage is the strict inverse of EncodePackage.
func DecodePackage(b []byte) (signjob.Job, error) {
	var j signjob.Job
	if len(b) == 0 || len(b) > MaxIntentPackage {
		return j, errors.New("intent package: empty or too large")
	}
	var p intentPackage
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return j, fmt.Errorf("intent package: %w", err)
	}
	if dec.More() {
		return j, errors.New("intent package: trailing data")
	}
	if p.V != IntentPackageVersion {
		return j, fmt.Errorf("intent package: version %q, want %q", p.V, IntentPackageVersion)
	}
	if len(p.Digest) != 32 {
		return j, errors.New("intent package: digest must be 32 bytes")
	}
	return signjob.Job{ID: p.JobID, Chain: p.Chain, PartitionID: p.PartitionID, KeyRef: p.KeyRef, Intent: p.Intent,
		Payload: p.Payload, Digest: p.Digest, Approvals: p.Approvals}, nil
}
