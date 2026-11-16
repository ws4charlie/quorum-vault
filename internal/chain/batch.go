package chain

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// BatchMember is one withdrawal of a batch to build (Bitcoin): its id, destination and amount in base units (satoshis). The order of a list of members
// is the order of the payments, first approved first.
type BatchMember struct {
	ID     string
	To     string
	Amount uint64
	// ResendOf is the batch this withdrawal was in before that batch was cancelled ("" for a withdrawal that was never in a batch). A batch that pays it
	// again must spend an output of the cancel that ended that batch, which the chain cell holds for it (HoldForResend): the signing zone refuses the
	// batch otherwise.
	ResendOf string
}

// BatchBuild is a batch built from the head of a member list.
type BatchBuild struct {
	// Tx is the unsigned transaction: every input, then the payments in member order, then the change.
	Tx UnsignedTx
	// Funded is how many leading members it pays: the longest prefix of the list the available outputs can fund within max_inputs with the fee-bump
	// reserve for the whole batch. Member i is output i.
	Funded int
	// FeeShares has one entry per funded member: its share of Fee in satoshis (see btc.FeeShares), summing to Fee exactly.
	FeeShares []uint64
	Fee       uint64
	VSize     uint64
	Change    uint64
}

// BatchBuilder is implemented by a chain cell that can pay several withdrawals in one transaction (Bitcoin).
//
// BuildBatch runs in the caller's transaction: it reserves the outputs it spends for the batch and records the attempt, so both commit or roll back
// with the batch row. It never skips a member: when the head cannot be funded it returns ErrNotEnoughOutputs (wrapping ErrFeeReserve when only the
// reserve is missing) and reserves nothing.
//
// A batch that pays again a withdrawal of a cancelled batch must spend the output of the cancel that ended it. HoldForResend, called in the transaction
// that settles that cancel, sets the cancel's output aside for the old batch (no other build takes it); BuildBatch spends it for the members that name
// the old batch (and never splits those members: all of them or none are in one batch); ReleaseResend gives it back when no member needs it any more.
//
// BatchShares splits the fee a confirmed attempt of the batch paid between its first n payments, as at build time (deterministic, summing to the fee).
type BatchBuilder interface {
	BuildBatch(ctx context.Context, tx pgx.Tx, batchID, partitionID string, members []BatchMember) (BatchBuild, error)
	HoldForResend(ctx context.Context, tx pgx.Tx, cancelTxID, oldBatchID string) error
	ReleaseResend(ctx context.Context, tx pgx.Tx, oldBatchID string) error
	BatchShares(ctx context.Context, q Querier, batchID, txid string, n int, fee uint64) ([]uint64, error)
}

// BatchMemberError says one member of a batch cannot be paid at all (a destination that is not an address of the network, an amount below dust): the
// batch is to be built again without that withdrawal.
type BatchMemberError struct {
	ID  string
	Err error
}

func (e *BatchMemberError) Error() string { return fmt.Sprintf("batch member %s: %v", e.ID, e.Err) }
func (e *BatchMemberError) Unwrap() error { return e.Err }
