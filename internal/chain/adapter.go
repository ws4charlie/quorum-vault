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

// ErrNotSupported is returned by BuildReplacement on chains without replacement.
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
	// BuildCancel builds a transaction that frees the sequence number (nonce)
	// reserved for (ownerKind, ownerID) when its job was refused, so later
	// transactions of the same sender can proceed. Chains without strictly
	// sequential nonces return ErrNotSupported.
	BuildCancel(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (UnsignedTx, error)
	Assemble(u UnsignedTx, sig Signature) (SignedTx, error)
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
	// OwnerKind names the owner of the nonce this transfer takes: "withdrawal" (the default when empty) or "to-cold" for a
	// hot-to-cold move. The kind decides how the transaction is found again for replacement and cancel.
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

// UnsignedTx is a built transaction waiting for a signature.
type UnsignedTx struct {
	Chain   string
	Digest  []byte // what the signer signs
	Payload []byte // opaque, chain-specific; Assemble consumes it
	KeyRef  KeyRef
}

// Signature is a raw signature over UnsignedTx.Digest.
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

// TxVerifier checks a built transaction offline. It recomputes the digest from
// Payload, compares it to u.Digest, decodes Payload, and returns an error
// unless destination, asset and amount match the intent. The signing gateway
// runs it in the signing zone, with no chain access.
type TxVerifier interface {
	Verify(u UnsignedTx, i signjob.Intent) error
}
