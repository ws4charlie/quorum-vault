// Package chain defines the chain-neutral interface every chain cell
// implements (EVM, BTC, Solana). Frozen after P0; changes go through the lead.
// The demo's Ethereum signing helpers live in internal/chain/eth and are unrelated.
package chain

import (
	"context"
	"errors"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// ErrNotSupported is returned by BuildReplacement and BuildCancel on chains without them.
var ErrNotSupported = errors.New("chain: operation not supported")

// Adapter is one chain cell: address derivation, deposit scanning, and
// building, assembling, broadcasting and tracking transactions. It never signs;
// signatures come back through the sign-job path.
type Adapter interface {
	Chain() string
	DeriveDepositAddress(ctx context.Context, customerID string, index uint64) (DepositAddress, error)
	// Scan returns deposits observed from fromHeight up to the chain's safe head.
	Scan(ctx context.Context, fromHeight uint64) (ScanResult, error)
	// BuildWithdrawal and BuildSweep run inside the caller's transaction, so
	// resources they reserve (EVM nonces, BTC UTXOs) commit or roll back with
	// the withdrawal or sweep row.
	BuildWithdrawal(ctx context.Context, tx pgx.Tx, w WithdrawalIntent) (UnsignedTx, error)
	BuildSweep(ctx context.Context, tx pgx.Tx, s SweepIntent) (UnsignedTx, error)
	// BuildReplacement builds a fee-bumped replacement of a stuck transaction
	// owned by (ownerKind, ownerID). Chains without replacement return ErrNotSupported.
	BuildReplacement(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (UnsignedTx, error)
	// BuildCancel builds a transaction that frees what was reserved for
	// (ownerKind, ownerID) when its job was refused (EVM: the nonce, so later
	// transactions of the same sender can proceed). It is optional: a chain
	// that has nothing to free after a refusal returns ErrNotSupported, and the
	// workflows then go on without a cancel.
	BuildCancel(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (UnsignedTx, error)
	// Assemble joins the payload of u with one signature per input of u, in the
	// order of u.Inputs().
	Assemble(u UnsignedTx, sigs []Signature) (SignedTx, error)
	Broadcast(ctx context.Context, s SignedTx) (txHash string, err error)
	Status(ctx context.Context, txHash string) (TxStatus, error)
	EstimateSweepFee(ctx context.Context, s SweepIntent) (*big.Int, error)
	// TxFee is the fee a mined transaction paid, in the chain's native base
	// units (EVM: gas used x effective gas price). A reverted transaction paid
	// it too. Errors if the transaction has no receipt yet.
	TxFee(ctx context.Context, txHash string) (*big.Int, error)
	// MovedAssets lists what a mined sweep transaction actually moved out of
	// deposit addresses, as reported by the chain itself (EVM: Forwarder Swept
	// events from known forwarders; one entry per address and asset). A sweep
	// can move more than it expected (a deposit landed meanwhile, or ETH rides
	// along with a token sweep), so accounting uses this, not the intent.
	MovedAssets(ctx context.Context, txHash string) ([]MovedAsset, error)
	// Outcome decides what became of every attempt (the original transaction,
	// its fee-bumped replacements and any cancel) that was ever broadcast for
	// the owner. Any attempt may be the one that confirms, so it looks at all.
	Outcome(ctx context.Context, ownerKind, ownerID string) (Outcome, error)
	// Reservation reports what the owner's transaction still holds on the chain
	// side (EVM: a nonce). While Open is true some signature for it may yet be
	// broadcast, so the owner's funds must not be released.
	Reservation(ctx context.Context, q Querier, ownerKind, ownerID string) (Reservation, error)
}

// Querier is the read side of a database handle (a pgx.Tx or a pool).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Attempt kinds of Outcome.Kind.
const (
	AttemptSend   = "send"   // the owner's own transaction or a fee-bumped replacement of it
	AttemptCancel = "cancel" // a transaction that frees what the owner reserved
)

// OutcomeState says whether the attempts of an owner are decided.
type OutcomeState string

const (
	// OutcomeOpen: nothing is decided; some attempt may still confirm (or none was ever broadcast).
	OutcomeOpen OutcomeState = "open"
	// OutcomeConfirmed: one attempt confirmed. Hash and Kind say which; Failed says it ran and failed.
	OutcomeConfirmed OutcomeState = "confirmed"
	// OutcomeConsumed: what the owner reserved was used by a transaction this system did not make, and none of the owner's attempts confirmed.
	OutcomeConsumed OutcomeState = "consumed"
)

// Outcome is the combined state of an owner's attempts.
type Outcome struct {
	State    OutcomeState
	Hash     string // the attempt that decided it (OutcomeConfirmed)
	Kind     string // AttemptSend or AttemptCancel, of that attempt
	Failed   bool   // the deciding attempt confirmed but failed (EVM: reverted); it still paid its fee
	Attempts int    // how many attempts were ever broadcast
	Detail   string // for OutcomeConsumed: what was used, for the operator's alert
}

// Reservation is what an owner's transaction holds on the chain side.
type Reservation struct {
	Open bool
	// Account is the sender the reservation belongs to (EVM: the hot address whose nonce it is).
	Account string
	// Detail describes the reservation for an alert.
	Detail string
}

// MovedAsset is an amount a sweep moved out of one deposit address.
type MovedAsset struct {
	Address string
	Asset   string   // configured symbol, e.g. "ETH", "USDT"
	Amount  *big.Int // base units, > 0
}

// DepositAddress kinds, matching deposit_addresses.kind.
const (
	KindForwarder = "forwarder"
	KindXpub      = "xpub"
	KindEd25519   = "ed25519"
)

// DepositAddress is a per-customer deposit address.
type DepositAddress struct {
	Chain           string
	Address         string
	Kind            string
	DerivationIndex uint64
	Asset           string // empty = any asset on the chain
}

// ObservedDeposit is one incoming transfer seen on chain.
type ObservedDeposit struct {
	Chain       string
	Asset       string
	Address     string
	Amount      *big.Int // base units
	BlockHeight uint64
	TxHash      string
	// DedupKey is unique per transfer: chain:tx_hash:log_index (EVM),
	// chain:txid:vout (BTC), chain:sig:ix:inner_ix (Solana).
	DedupKey string
}

// ScanResult is what Scan found, plus the highest height that is safe to
// resume from (past the confirmation or finality depth).
type ScanResult struct {
	Deposits       []ObservedDeposit
	SafeHeadHeight uint64
}

// WithdrawalIntent asks for a transfer out of a partition's wallet.
type WithdrawalIntent struct {
	// OwnerKind names the owner of the nonce this transfer takes: "withdrawal" (the default when empty), "to-cold" for a
	// hot-to-cold move or "rebalance" for a move between hot shards. The kind decides how the transaction is found again for replacement and cancel.
	OwnerKind   string
	ID          string // withdrawal ID (idempotency)
	PartitionID string
	Asset       string
	To          string
	Amount      *big.Int
}

// SweepIntent asks for a transfer from a deposit address into a partition.
type SweepIntent struct {
	ID          string // sweep ID (idempotency)
	Asset       string
	From        string
	ToPartition string
	Amount      *big.Int
}

// KeyRef names the key that must sign: the partition and, where the chain
// needs it, the derivation path or child index.
type KeyRef struct {
	PartitionID string
	Path        string
}

// SigInput is one digest to sign and the key that signs it.
type SigInput struct {
	Digest []byte
	KeyRef KeyRef
}

// UnsignedTx is a built transaction waiting for signatures. It needs one
// signature per input: Digest and KeyRef are the first input, More the others
// (Bitcoin: one per spent output, often under different keys; EVM: always
// just the first). All inputs share Payload, which Assemble consumes and which
// is opaque and chain-specific. Each input becomes one sign job.
type UnsignedTx struct {
	Chain   string
	Digest  []byte // what the signer signs, for the first input
	Payload []byte
	KeyRef  KeyRef // the key that signs the first input
	More    []SigInput
}

// Inputs lists every input to sign, first one first.
func (u UnsignedTx) Inputs() []SigInput {
	out := make([]SigInput, 0, 1+len(u.More))
	out = append(out, SigInput{Digest: u.Digest, KeyRef: u.KeyRef})
	return append(out, u.More...)
}

// Input is input i seen as a transaction of its own (what one sign job carries, and what TxVerifier checks).
func (u UnsignedTx) Input(i int) UnsignedTx {
	in := u.Inputs()[i]
	return UnsignedTx{Chain: u.Chain, Digest: in.Digest, Payload: u.Payload, KeyRef: in.KeyRef}
}

// Signature is a raw signature over one input's digest.
type Signature struct {
	Bytes []byte
}

// SignedTx is a transaction ready to broadcast.
type SignedTx struct {
	Chain string
	Raw   []byte
}

// TxStatus is a transaction's state on chain.
type TxStatus string

const (
	TxPending   TxStatus = "pending"
	TxConfirmed TxStatus = "confirmed"
	TxFailed    TxStatus = "failed"
	TxDropped   TxStatus = "dropped"
)

// TxVerifier checks one input of a built transaction offline (u is one sign
// job: Digest and KeyRef of that input, the shared Payload). It recomputes the
// digest from Payload, compares it to u.Digest, decodes Payload, and returns an error
// unless destination, asset and amount match the intent. The signing gateway
// runs it in the signing zone, with no chain access.
type TxVerifier interface {
	Verify(u UnsignedTx, i signjob.Intent) error
}
