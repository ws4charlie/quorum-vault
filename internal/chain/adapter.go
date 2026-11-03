// Package chain defines the chain-neutral interface every chain cell
// implements (EVM, BTC, Solana). Frozen after P0; changes go through the lead.
// The demo's Ethereum signing helpers live in internal/chain/eth and are unrelated.
package chain

import (
	"context"
	"math/big"
)

// Adapter is one chain cell: address derivation, deposit scanning, and
// building, assembling, broadcasting and tracking transactions. It never signs;
// signatures come back through the sign-job path.
type Adapter interface {
	Chain() string
	DeriveDepositAddress(ctx context.Context, customerID string, index uint64) (DepositAddress, error)
	// Scan returns deposits observed from fromHeight up to the chain's safe head.
	Scan(ctx context.Context, fromHeight uint64) (ScanResult, error)
	BuildWithdrawal(ctx context.Context, w WithdrawalIntent) (UnsignedTx, error)
	BuildSweep(ctx context.Context, s SweepIntent) (UnsignedTx, error)
	Assemble(u UnsignedTx, sig Signature) (SignedTx, error)
	Broadcast(ctx context.Context, s SignedTx) (txHash string, err error)
	Status(ctx context.Context, txHash string) (TxStatus, error)
	EstimateSweepFee(ctx context.Context, s SweepIntent) (*big.Int, error)
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
