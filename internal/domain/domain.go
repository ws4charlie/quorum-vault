// Package domain holds the types shared by every other package: wallets,
// keys, policies, sign requests, decisions and audit events, plus the two
// small interfaces (Auditor, KeyGenerator) that let tasks built in parallel
// talk to each other without importing each other.
//
// JSON: every struct uses snake_case tags. []byte fields use encoding/json's
// default (base64). *big.Int fields marshal as decimal strings (e.g.
// "1000000000000000000") rather than JSON numbers, because wei values exceed
// the 2^53 precision of JavaScript/float64 numbers; see json.go.
package domain

import (
	"context"
	"encoding/json"
	"math/big"
	"time"
)

type Curve string    // "secp256k1", "P-256"
type Backend string  // "hsm", "mpc"
type KeyState string // "active", "sign_only", "retired"
type Tier string     // "hot", "cold"
type RequestStatus string
type Outcome string // "allow","deny","needs_approval"

const (
	CurveSecp256k1 Curve = "secp256k1"
	CurveP256      Curve = "P-256"
)

const (
	BackendHSM Backend = "hsm"
	BackendMPC Backend = "mpc"
)

const (
	KeyStateActive   KeyState = "active"
	KeyStateSignOnly KeyState = "sign_only"
	KeyStateRetired  KeyState = "retired"
)

const (
	TierHot  Tier = "hot"
	TierCold Tier = "cold"
)

const (
	StatusPendingApproval RequestStatus = "pending_approval"
	StatusApproved        RequestStatus = "approved"
	StatusRejected        RequestStatus = "rejected"
	StatusDenied          RequestStatus = "denied"
	StatusSigning         RequestStatus = "signing"
	StatusSigned          RequestStatus = "signed"
	StatusFailed          RequestStatus = "failed"
)

const (
	OutcomeAllow         Outcome = "allow"
	OutcomeDeny          Outcome = "deny"
	OutcomeNeedsApproval Outcome = "needs_approval"
)

// Audit event types (AuditEvent.Type).
const (
	EventKeyGenerated     = "key.generated"
	EventKeyStateChanged  = "key.state_changed"
	EventKeyRotated       = "key.rotated"
	EventKeyDestroyed     = "key.destroyed"
	EventWalletCreated    = "wallet.created"
	EventPolicyUpdated    = "policy.updated"
	EventAllowlistUpdated = "allowlist.updated"
	EventRequestCreated   = "request.created"
	EventPolicyDecision   = "policy.decision"
	EventApprovalVoted    = "approval.voted"
	EventRequestApproved  = "request.approved"
	EventRequestRejected  = "request.rejected"
	EventSignStarted      = "sign.started"
	EventSignCompleted    = "sign.completed" // payload: backend, participant set, signature, tx hash
	EventSignFailed       = "sign.failed"
	EventTxBroadcast      = "tx.broadcast"
	EventMPCKeygen        = "mpc.keygen"
)

type Wallet struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Tier      Tier      `json:"tier"`
	Backend   Backend   `json:"backend"`
	CreatedAt time.Time `json:"created_at"`
}

type Key struct {
	ID          string     `json:"id"`
	WalletID    string     `json:"wallet_id"`
	Version     int        `json:"version"`
	Curve       Curve      `json:"curve"`
	Backend     Backend    `json:"backend"`
	Purpose     string     `json:"purpose"`
	State       KeyState   `json:"state"`
	HSMLabel    string     `json:"hsm_label,omitempty"`   // CKA_LABEL, HSM backend only
	HSMKeyID    []byte     `json:"hsm_key_id,omitempty"`  // CKA_ID, HSM backend only
	MPCKeyRef   string     `json:"mpc_key_ref,omitempty"` // directory key under the MPC data dir, MPC backend only
	PublicKey   []byte     `json:"public_key"`            // SEC1 uncompressed, 65 bytes
	Address     string     `json:"address"`               // 0x-prefixed EIP-55 Ethereum address
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	SignOnlyAt  *time.Time `json:"sign_only_at,omitempty"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

type Policy struct {
	WalletID              string    `json:"wallet_id"`
	DailyLimitWei         *big.Int  `json:"daily_limit_wei"`
	PerTxLimitWei         *big.Int  `json:"per_tx_limit_wei"`
	ApprovalThresholdWei  *big.Int  `json:"approval_threshold_wei"`
	VelocityMaxTx         int       `json:"velocity_max_tx"`
	VelocityWindowSeconds int       `json:"velocity_window_seconds"`
	RequiredApprovals     int       `json:"required_approvals"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type SignRequest struct {
	ID                   string        `json:"id"`
	WalletID             string        `json:"wallet_id"`
	KeyID                string        `json:"key_id"`
	ChainID              int64         `json:"chain_id"`
	To                   string        `json:"to"`
	ValueWei             *big.Int      `json:"value_wei"`
	Data                 []byte        `json:"data,omitempty"`
	Nonce                uint64        `json:"nonce"`
	GasLimit             uint64        `json:"gas_limit"`
	MaxFeePerGas         *big.Int      `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas *big.Int      `json:"max_priority_fee_per_gas"`
	Requester            string        `json:"requester"`
	Status               RequestStatus `json:"status"`
	Decision             *Decision     `json:"decision,omitempty"`
	Signature            []byte        `json:"signature,omitempty"`
	RawTx                []byte        `json:"raw_tx,omitempty"`
	TxHash               string        `json:"tx_hash,omitempty"`
	CreatedAt            time.Time     `json:"created_at"`
	UpdatedAt            time.Time     `json:"updated_at"`
}

type Decision struct {
	Outcome           Outcome  `json:"outcome"`
	Reasons           []string `json:"reasons"`
	RequiredApprovals int      `json:"required_approvals"`
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

// Auditor lets T1/T3 emit events without importing internal/audit (built in parallel by T2).
type Auditor interface {
	Append(ctx context.Context, ev AuditEvent) (AuditEvent, error)
}

// KeyGenerator creates a new key for a wallet on one backend (HSM by T1, MPC by T3).
// It returns a Key with State "" ; the registry sets state and persists it.
type KeyGenerator interface {
	Backend() Backend
	Generate(ctx context.Context, walletID string, version int) (Key, error)
}
