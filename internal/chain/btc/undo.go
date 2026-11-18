package btc

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// UndoUnsent forgets a build of the owner that was never broadcast: its attempts are deleted and the outputs it reserved are available again. It
// refuses when any attempt of the owner was handed to the node. A withdrawal whose first send the zone refused only because the core and the zone
// were on different fee-cap changes (feecaps.go) is rebuilt this way, under the caps in force now.
func (a *Adapter) UndoUnsent(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) error {
	var sent int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND broadcast_at IS NOT NULL`,
		a.cfg.Chain, ownerKind, ownerID).Scan(&sent); err != nil {
		return err
	}
	if sent > 0 {
		return fmt.Errorf("btc: %s %s has a broadcast attempt: it cannot be rebuilt", ownerKind, ownerID)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3`, a.cfg.Chain, ownerKind, ownerID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='available', owner_kind=NULL, owner_id=NULL, updated_at=now() WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved'`,
		a.cfg.Chain, ownerKind, ownerID)
	return err
}
