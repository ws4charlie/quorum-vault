// Package chain defines the chain-neutral interface every chain cell
// implements (EVM, BTC, Solana). Frozen after P0; changes go through the lead.
// The demo's Ethereum signing helpers live in internal/chain/eth and are unrelated.
package chain

import (
	"context"
	"errors"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
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
	Deposits []ObservedDeposit
	// SafeHeadHeight is the highest height this result covers: the caller continues at SafeHeadHeight+1.
	SafeHeadHeight uint64
	// Blocks lists the blocks this result read, for chains that detect reorgs by comparing hashes (Bitcoin). The caller
	// stores them in the same transaction as the deposits and the cursor, and gives the last one back as the check of
	// the next scan (see ScanCheck).
	Blocks []ScannedBlock
	// Deferred are deposits seen in a block that is final but whose funds are not yet spendable (a Bitcoin coinbase
	// output). The caller stores them and credits each when its ReleaseAt is covered by a later scan.
	Deferred []DeferredDeposit
	// Funding lists payments to the cell's own hot addresses that did not come from a transaction of ours (operator funding). The
	// caller records each in the same transaction (FundingRecorder) and books it as operator funding.
	Funding []FundingOutput
}

// FundingOutput is an output paying one of the cell's hot addresses, seen at safe depth.
type FundingOutput struct {
	Chain       string
	Asset       string
	PartitionID string // the hot partition whose address was paid
	Address     string
	TxHash      string
	Vout        uint32
	Amount      *big.Int
	BlockHeight uint64
	// Cold: the output pays a cold address (PartitionID is then the first hot partition of its pool, whose cold account the books use).
	Cold bool
}

// FundingRecorder is implemented by a chain cell that keeps its own outputs (Bitcoin's UTXO table). RecordFunding stores the output once
// and reports whether it was new: only a new one is booked, so a rescan books nothing twice.
type FundingRecorder interface {
	RecordFunding(ctx context.Context, tx pgx.Tx, f FundingOutput) (inserted bool, err error)
}

// DepositRecorder is implemented by a chain cell that keeps its own outputs and must know the credited outputs of deposit addresses (Bitcoin:
// they are what a sweep spends). It is called in the transaction that credits the deposit, once per credited deposit, never for suspense.
type DepositRecorder interface {
	RecordDeposit(ctx context.Context, tx pgx.Tx, d ObservedDeposit) error
}

// SweepCandidate is what one deposit address could send in one sweep right now: the amount is exactly what the sweep would move.
type SweepCandidate struct {
	Address string
	Asset   string
	Amount  *big.Int
}

// SweepSource is implemented by a chain cell that knows which funds of a deposit address a sweep can take (Bitcoin: its available outputs,
// up to the input cap, leaving out any that cost more to spend than they carry). A chain without it is planned from the credited deposits.
type SweepSource interface {
	SweepCandidates(ctx context.Context) ([]SweepCandidate, error)
}

// MoveCapacity is implemented by a chain cell where one transaction can spend only so many inputs (Bitcoin): MaxMove is the most one hot-to-cold
// move from the partition can carry now, from the outputs that are available (a reserved output is not counted), after the fee. The planner caps
// a move at it, so a shard of many small outputs is emptied in rounds instead of waiting for a move that cannot be built.
type MoveCapacity interface {
	MaxMove(ctx context.Context, partitionID string) (*big.Int, error)
}

// OutputDiff is one disagreement between a chain cell's own output table and the chain.
type OutputDiff struct {
	Address string
	Output  string // txid:vout
	Detail  string
}

// ChainView is what the chain says, put in the terms of the books at this moment, for a chain cell that keeps its own outputs (Bitcoin). The
// books and the chain differ by things the cell can name from its own records of the transactions it sent; the view leaves those out of the
// chain side and lists them, so that what is left is a real difference.
type ChainView struct {
	Height uint64 // the tip the UTXO set was read at
	// Balance of each address as the books should see it: unspent outputs that are in the output table, or that nothing explains away. Left out:
	// outputs of our own transactions that are not settled yet, and outputs of others younger than the credit depth (not credited yet).
	Balance map[string]*big.Int
	// SpentInFlight is, per address, the value of table rows that a confirmed transaction of ours has already spent but the books have not settled.
	SpentInFlight map[string]*big.Int
	// Unsettled counts the outputs left out of Balance for those reasons.
	Unsettled int
	// Diffs are the disagreements nothing explains.
	Diffs []OutputDiff
}

// ChainViewer is implemented by a chain cell that can produce a ChainView for a set of addresses. The read is of the node's UTXO set at its tip and
// keeps the node busy: callers batch and run it on their own cadence, never on a request path.
type ChainViewer interface {
	ChainView(ctx context.Context, addrs []string) (ChainView, error)
}

// RefillBuild asks a chain cell for the request of a refill: Need is what the hot partition should receive.
type RefillBuild struct {
	ID          string
	PartitionID string
	Need        *big.Int
	Revision    int
}

// ColdRefiller is implemented by a chain cell that builds refill requests from its own outputs (Bitcoin). BuildRefill picks the cold address's oldest
// available outputs (at most max_inputs) and returns the request; it reserves nothing, so a request that is never signed leaves nothing behind. The
// payment may be less than Need when the inputs a transaction can carry are fewer than the need: the caller books what the request pays. AdoptRefill
// runs in the transaction that imports the signed file: it checks the request's inputs are still available cold outputs, reserves them and records
// the transaction as an attempt of the refill, so that broadcast, outcome and settlement are the ordinary attempt code.
type ColdRefiller interface {
	BuildRefill(ctx context.Context, b RefillBuild) (coldsign.BTCRequest, error)
	AdoptRefill(ctx context.Context, tx pgx.Tx, id string, req coldsign.BTCRequest, raw []byte) error
	ColdAvailable(ctx context.Context, coldAddress string) (*big.Int, error)
	// ReplaceRefill builds the next revision of a request: the same inputs, the same payment, a higher fee taken from the change (the rule of a withdrawal's
	// bump, under the core's caps), so that the offline signer accepts it as a replacement of what it may already have signed. Every input must still be an
	// available cold output, or one reserved by this refill. Without a change output, or when the change would fall to dust, it returns ErrCannotBump.
	ReplaceRefill(ctx context.Context, prev coldsign.BTCRequest, id string, revision int) (coldsign.BTCRequest, error)
	// UnsentAttempt is the signed transaction of the refill that was imported and not broadcast yet (a replacement), if any; DropUnsentAttempt forgets it
	// (the node would not take it; the earlier attempt may still confirm).
	UnsentAttempt(ctx context.Context, id string) (raw []byte, ok bool, err error)
	DropUnsentAttempt(ctx context.Context, id string) error
}

// Settler is implemented by a chain cell that must update its own books when a transaction of an owner settles, in the settlement's database
// transaction (Bitcoin: its inputs become spent and its change becomes an available output).
type Settler interface {
	Settle(ctx context.Context, tx pgx.Tx, ownerKind, ownerID, txHash string) error
}

// Releaser is implemented by a chain cell whose reservation can be given back when the owner's attempt was refused and nothing was signed
// (Bitcoin: reserved outputs become available again). The caller has already checked that no signature can exist.
type Releaser interface {
	ReleaseUnsigned(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) error
}

// AddressNormalizer is implemented by a cell that validates withdrawal destinations for its network and returns the canonical form.
// Without it the service validates the destination as an EVM address.
type AddressNormalizer interface {
	NormalizeAddress(address string) (string, error)
}

// Errors a chain cell gives for the ways sending or replacing a transaction can fail, so the workflows can tell them apart instead of retrying
// for ever.
var (
	// ErrBroadcastStuck: the node refused the transaction for a reason a higher fee or time may cure (fee below the relay or mempool minimum, the
	// replacement rules, a conflict with a pending transaction of ours). The attempt is stuck, not failed: the workflow keeps waiting and bumps.
	ErrBroadcastStuck = errors.New("chain: the node refused the transaction for now")
	// ErrInputsSpent: an input of the transaction is missing or already spent. It goes to the outcome check, which tells whether one of our own
	// attempts spent it or something else did.
	ErrInputsSpent = errors.New("chain: an input of the transaction is missing or spent")
	// ErrCannotBump: no replacement or cancel can be built (no change to pay more from, change that would fall to dust, a fee ceiling). The
	// workflow raises an ALERT and keeps waiting.
	// ErrSweepFeePolicy: the fee rate does not allow this sweep now (above the sweep ceiling for a routine one, above the cap for any). Not
	// retryable: the sweep ends and the planner decides again later.
	ErrSweepFeePolicy = errors.New("chain: the fee rate does not allow this sweep now")
	ErrCannotBump     = errors.New("chain: the transaction cannot be bumped")
)

// ErrNotEnoughOutputs is returned by BuildWithdrawal when the partition's available outputs cannot pay the amount and the fee now. It is
// retryable: outputs may free up or arrive, so the withdrawal waits.
var ErrNotEnoughOutputs = errors.New("chain: not enough available outputs")

// ScannedBlock is the height and hash of a block a scan read.
type ScannedBlock struct {
	Height uint64
	Hash   string
}

// DeferredDeposit is a deposit that is credited only once the scan has covered height ReleaseAt.
type DeferredDeposit struct {
	Deposit   ObservedDeposit
	ReleaseAt uint64
}

// ErrReorgTooDeep is returned by Scan when the chain no longer contains a block the scanner already read and credited
// from: a reorganization deeper than the safe depth. Credits are never reversed automatically; the caller stops scanning
// and an operator decides.
var ErrReorgTooDeep = errors.New("chain: reorganization deeper than the safe depth")

// WithdrawalIntent asks for a transfer out of a partition's wallet.
type WithdrawalIntent struct {
	// OwnerKind names the owner of the nonce this transfer takes: "withdrawal" (the default when empty), "to-cold" for a
	// hot-to-cold move or "rebalance" for a move between hot shards (EVM only). The kind decides how the transaction is found again for replacement and cancel.
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
