// Package domain holds the few types shared by the signing and audit
// packages: curves, backends, keys, audit events, and the two small
// interfaces (Auditor, KeyGenerator) that let those packages talk to each
// other without importing each other.
package domain

import (
	"context"
	"encoding/json"
	"time"
)

type Curve string   // "secp256k1", "P-256"
type Backend string // "hsm", "mpc"

const (
	CurveSecp256k1 Curve = "secp256k1"
	CurveP256      Curve = "P-256"
)

const (
	BackendHSM Backend = "hsm"
	BackendMPC Backend = "mpc"
)

// Audit event types still written by internal/audit callers.
const (
	EventWalletCreated    = "wallet.created"
	EventPolicyUpdated    = "policy.updated"
	EventAllowlistUpdated = "allowlist.updated"
	EventRequestCreated   = "request.created"
	EventSignStarted      = "sign.started"
	EventSignCompleted    = "sign.completed" // payload: backend, participant set, signature, tx hash
)

type Key struct {
	ID        string    `json:"id"`
	WalletID  string    `json:"wallet_id"`
	Version   int       `json:"version"`
	Curve     Curve     `json:"curve"`
	Backend   Backend   `json:"backend"`
	Purpose   string    `json:"purpose"`
	HSMLabel  string    `json:"hsm_label,omitempty"`   // CKA_LABEL, HSM backend only
	HSMKeyID  []byte    `json:"hsm_key_id,omitempty"`  // CKA_ID, HSM backend only
	MPCKeyRef string    `json:"mpc_key_ref,omitempty"` // directory key under the MPC data dir, MPC backend only
	PublicKey []byte    `json:"public_key"`            // SEC1 uncompressed, 65 bytes
	Address   string    `json:"address"`               // 0x-prefixed EIP-55 Ethereum address
	CreatedAt time.Time `json:"created_at"`
}

type AuditEvent struct {
	Seq       int64           `json:"seq"`
	At        time.Time       `json:"at"`
	Actor     string          `json:"actor"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"` // "" = NULL
	WalletID  string          `json:"wallet_id,omitempty"`  // "" = NULL
	KeyID     string          `json:"key_id,omitempty"`     // "" = NULL
	Payload   json.RawMessage `json:"payload,omitempty"`
	PrevHash  []byte          `json:"prev_hash,omitempty"`
	Hash      []byte          `json:"hash,omitempty"`
}

// Auditor lets other packages emit audit events without importing internal/audit.
type Auditor interface {
	Append(ctx context.Context, ev AuditEvent) (AuditEvent, error)
}

// KeyGenerator creates a new key for a wallet on one backend.
type KeyGenerator interface {
	Backend() Backend
	Generate(ctx context.Context, walletID string, version int) (Key, error)
}
