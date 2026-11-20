package sol

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// Generations of a hot shard's key (K4). The keyset registry of the business database (internal/partition) says which key serves a shard: the config's address
// is generation 1, active; a replacement registers a candidate, activates it and drains the old one. New work (withdrawals, sweeps, the creation of a pool)
// is built from the ACTIVE generation, on that generation's own pool of nonce accounts. Work built before a replacement stays with the key it was built for:
// a replacement or cancel reads the payer out of the stored message, so a version of an old withdrawal is signed by the old key and lands or is cancelled on
// the old pool's nonce.

// ErrNoActiveHot: the shard has no active key now (a replacement is between "start draining" and "activate"). It wraps chain.ErrNotEnoughOutputs, so a
// withdrawal waits and builds again.
var ErrNoActiveHot = fmt.Errorf("sol: the shard has no active hot key (a key replacement is in progress): %w", chain.ErrNotEnoughOutputs)

// activeHot is the key of the active generation of the shard that serves partitionID. A shard the registry has no row for (tools and tests that never
// bootstrap it) has its configured key.
func (a *Adapter) activeHot(ctx context.Context, q chain.Querier, partitionID string) ([32]byte, error) {
	base, ok := a.cfg.hot[partitionID]
	if !ok {
		return [32]byte{}, fmt.Errorf("sol: partition %q has no hot shard", partitionID)
	}
	k, err := partition.Parse(partitionID)
	if err != nil {
		return [32]byte{}, err
	}
	var addr string
	err = q.QueryRow(ctx, `SELECT address FROM keysets WHERE shard_id=$1 AND state='active'`, string(k.ShardID())).Scan(&addr)
	switch {
	case err == nil:
		raw, perr := ParseAddress(addr)
		if perr != nil {
			return [32]byte{}, fmt.Errorf("sol: the registry's active key of %s: %w", k.ShardID(), perr)
		}
		return raw, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return [32]byte{}, err
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM keysets WHERE shard_id=$1`, string(k.ShardID())).Scan(&n); err != nil {
		return [32]byte{}, err
	}
	if n == 0 {
		return base, nil
	}
	return [32]byte{}, ErrNoActiveHot
}

// HotKeyOfGeneration is the key of generation gen of the shard that serves partitionID, and its state (0: the active generation). Generation 1 of a shard
// the registry does not know is the configured key.
func (a *Adapter) HotKeyOfGeneration(ctx context.Context, partitionID string, gen int) ([32]byte, string, error) {
	if gen == 0 {
		h, err := a.activeHot(ctx, a.pool, partitionID)
		return h, partition.StateActive, err
	}
	base, ok := a.cfg.hot[partitionID]
	if !ok {
		return [32]byte{}, "", fmt.Errorf("sol: partition %q has no hot shard", partitionID)
	}
	k, err := partition.Parse(partitionID)
	if err != nil {
		return [32]byte{}, "", err
	}
	var addr, state string
	err = a.pool.QueryRow(ctx, `SELECT address, state FROM keysets WHERE shard_id=$1 AND generation=$2`, string(k.ShardID()), gen).Scan(&addr, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		if gen == 1 {
			return base, partition.StateActive, nil
		}
		return [32]byte{}, "", fmt.Errorf("sol: shard %s has no generation %d", k.ShardID(), gen)
	}
	if err != nil {
		return [32]byte{}, "", err
	}
	raw, err := ParseAddress(addr)
	return raw, state, err
}
