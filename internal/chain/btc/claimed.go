package btc

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// OwnerGen is the generation of the account key the inputs of the owner's newest send are under (1 for the first). The core asks it to know whether a refused
// payment's coins are those of a generation marked compromised (a claim the zone may still hold for them).
func (a *Adapter) OwnerGen(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (int, error) {
	p, _, err := a.lastSend(ctx, tx, ownerKind, ownerID)
	if err != nil {
		return 0, err
	}
	if len(p.Inputs) == 0 {
		return 1, nil
	}
	return int(genOf(p.Inputs[0].Gen)), nil
}

// ReservedOwner is a group of the partition's shard coins reserved by one owner that is not a drain.
type ReservedOwner struct {
	Kind, ID string
	Coins    int
	Sats     uint64
}

// ReservedOwnersUnder lists who holds the reserved coins of the partition's shard under generation gen (a drain's own reservations excluded): the planner says
// which are held by a payment the zone refused.
func (a *Adapter) ReservedOwnersUnder(ctx context.Context, partitionID string, gen int) ([]ReservedOwner, error) {
	sh, err := a.shardOfGen(partitionID, gen)
	if err != nil {
		return nil, err
	}
	rows, err := a.pool.Query(ctx, `SELECT owner_kind, owner_id, count(*), COALESCE(sum(value),0) FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND path=$3 AND status='reserved' AND owner_kind <> $4
		GROUP BY owner_kind, owner_id ORDER BY owner_kind, owner_id`, a.cfg.Chain, partitionID, sh.keyPath(), OwnerKindDrain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReservedOwner
	for rows.Next() {
		var o ReservedOwner
		var sats int64
		if err := rows.Scan(&o.Kind, &o.ID, &o.Coins, &sats); err != nil {
			return nil, err
		}
		o.Sats = uint64(sats)
		out = append(out, o)
	}
	return out, rows.Err()
}

// OwnerKindClaimed is the owner kind of coins the zone reported as claimed by a payment the core does not know to be refused (a drain move was refused
// replay_nonce_taken for them): they stay reserved, out of every drain move, until a person looks (docs/runbooks/stolen-hot-key.md).
const OwnerKindClaimed = "claimed"

// HoldClaimed reserves the coins (outpoints "<txid>:<vout>") that are still available under owner kind "claimed", owner id the intent that holds the claim.
// It returns how many it held. Outpoints that are not available, or not ours, are left alone.
func (a *Adapter) HoldClaimed(ctx context.Context, tx pgx.Tx, outpoints []string, intentID string) (int, error) {
	n := 0
	for _, op := range outpoints {
		txid, vout, ok := splitOutpoint(op)
		if !ok {
			continue
		}
		tag, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='reserved', owner_kind=$4, owner_id=$5, updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3 AND status='available'`,
			a.cfg.Chain, txid, vout, OwnerKindClaimed, intentID)
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

// splitOutpoint parses "<txid>:<vout>".
func splitOutpoint(op string) (string, int, bool) {
	i := strings.LastIndex(op, ":")
	if i <= 0 {
		return "", 0, false
	}
	v, err := strconv.Atoi(op[i+1:])
	if err != nil || v < 0 {
		return "", 0, false
	}
	return op[:i], v, true
}
