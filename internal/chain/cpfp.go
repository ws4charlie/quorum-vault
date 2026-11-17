package chain

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// CPFPBuilder is implemented by a chain cell that can pull a stuck transaction in with a child that pays for both (Bitcoin). The child spends the
// stuck transaction's change back to the same hot shard, so it needs no approval: the signing zone checks that it is exactly that and that the two
// together stay within the zone's own fee caps.
type CPFPBuilder interface {
	// BuildCPFP builds the owner's CPFP child, or the next fee bump of the child it already has (the same inputs, a higher fee). It returns
	// ErrCannotBump when no child can help (no change, no room under the caps, or a cancel is in progress) and ErrNotSupported when the owner's kind
	// has no change to spend.
	BuildCPFP(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (UnsignedTx, error)
}
