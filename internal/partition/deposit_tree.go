package partition

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// DepositTreePool is the pool field of the registry ID of a chain's deposit key tree (Bitcoin account key, Solana deposit node). The tree is not a hot
// shard: it holds no funds of its own and no partition. Its generations live in the same registry as the shards' (docs/key-replacement.md, role
// "deposit-tree"), so one table says which key serves what.
const DepositTreePool = "deposit-tree"

// DepositTreeID is the registry ID of the deposit key tree of a chain: entity/chain/deposit-tree/0.
func DepositTreeID(entity, chain string) (ShardID, error) {
	id := ShardID(strings.Join([]string{entity, chain, DepositTreePool, "0"}, sep))
	if err := checkRegistryID(id); err != nil {
		return "", err
	}
	return id, nil
}

// IsDepositTree says whether the ID names a deposit key tree.
func (id ShardID) IsDepositTree() bool {
	p := strings.Split(string(id), sep)
	return len(p) == 4 && p[2] == DepositTreePool && p[3] == "0"
}

// DepositTreeLike is the SQL pattern (for LIKE) of the registry ID of the deposit tree of the chain, whatever the entity. The entity and chain fields hold
// no separator, so the pattern cannot match another chain's tree.
func DepositTreeLike(chain string) string {
	return "%" + sep + chain + sep + DepositTreePool + sep + "0"
}

// checkRegistryID accepts a shard ID or the ID of a deposit tree.
func checkRegistryID(id ShardID) error {
	if id.IsDepositTree() {
		if p := strings.Split(string(id), sep); p[0] == "" || p[1] == "" {
			return fmt.Errorf("partition: deposit tree id %q: empty entity or chain", id)
		}
		return nil
	}
	_, err := ParseShardID(string(id))
	return err
}

// WatchedSQL is the SQL condition (on a deposit_addresses row aliased d) that keeps the addresses of every generation of the chain's deposit tree that is
// not retired: the watch list of the scan and Reconcile. A draining or compromised generation is watched like an active one; a retired one is not. An
// address whose generation has no registry row (a database from before the registry knew the tree) is watched: nothing is dropped by default.
const WatchedSQL = `NOT EXISTS (SELECT 1 FROM keysets k WHERE k.shard_id LIKE '%/' || d.chain || '/deposit-tree/0' AND k.generation = d.generation AND k.state = 'retired')`

// DepositGeneration returns generation gen of a chain's deposit tree.
func DepositGeneration(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, chain string, gen int) (Keyset, error) {
	k, err := scanKeyset(q.QueryRow(ctx, `SELECT `+keysetCols+` FROM keysets WHERE shard_id LIKE $1 AND generation = $2`, DepositTreeLike(chain), gen))
	if errors.Is(err, pgx.ErrNoRows) {
		return Keyset{}, fmt.Errorf("%w: deposit tree of %s generation %d", ErrKeysetNotFound, chain, gen)
	}
	return k, err
}

// ActiveDeposit returns the active generation of a chain's deposit tree.
func ActiveDeposit(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, chain string) (Keyset, error) {
	k, err := scanKeyset(q.QueryRow(ctx, `SELECT `+keysetCols+` FROM keysets WHERE shard_id LIKE $1 AND state = 'active'`, DepositTreeLike(chain)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Keyset{}, fmt.Errorf("%w: no active deposit tree for %s", ErrKeysetNotFound, chain)
	}
	return k, err
}
