package custody

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// shardIDOf is the stable ID of hot shard i of this chain (omnibus pool).
func (c *Config) shardIDOf(i int) partition.ShardID {
	return c.PartitionKey(c.Native, i).ShardID()
}

// loadKeysets registers generation 1 of every configured shard as active (idempotent; a registered shard whose generation-1 address differs from the
// configuration refuses the start: a shard's address changes only through a new keyset generation) and marks the registry as loaded. From here on
// ShardAddressOf answers from the registry, live, at every call: an admin in one process changes it and every other process sees it at its next call.
// A shard with no active generation is not an error at start: that is the short window of a key replacement between "start draining" and "activate", and
// new work for the shard waits until the successor is active.
func (s *Service) loadKeysets(ctx context.Context) error {
	c := s.Cfg
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		for i := 0; i < c.shardCount(); i++ {
			addr, _, err := c.ShardAddressOf(c.PartitionKey(c.Native, i).String())
			if err != nil {
				return err
			}
			if _, err := partition.RegisterInitial(ctx, tx, "system", c.shardIDOf(i), addr, "", nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("custody: keyset registry: %w", err)
	}
	active, err := partition.ActiveAll(ctx, s.Pool)
	if err != nil {
		return fmt.Errorf("custody: keyset registry: %w", err)
	}
	// keep this chain's shards only (the registry may serve several chains)
	mine := map[partition.ShardID]partition.Keyset{}
	for i := 0; i < c.shardCount(); i++ {
		id := c.shardIDOf(i)
		if k, ok := active[id]; ok {
			mine[id] = k
		}
	}
	s.keysets.Store(&mine)
	return nil
}

// ErrNoActiveKeyset: the shard has no active generation now (a replacement is between "start draining" and "activate").
var ErrNoActiveKeyset = errors.New("custody: the shard has no active keyset (a key replacement is in progress)")

// kq is what the registry reads go through: a pool, a transaction or a snapshot.
type kq interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ShardAddressOf is the hot address of a partition's shard, the address of the shard's active keyset, in the form the family's chain cell takes,
// and the shard's index. Before Bootstrap has loaded the registry (tools and tests that never bootstrap) it is the configured address. After it, the
// registry is read at every call, so a change made through any process is seen by the next call of every process.
func (s *Service) ShardAddressOf(partitionID string) (string, int, error) {
	addr, i, err := s.Cfg.ShardAddressOf(partitionID)
	if err != nil {
		return "", 0, err
	}
	if s.keysets.Load() == nil {
		return addr, i, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := s.ActiveAddressOf(ctx, s.Pool, partitionID)
	if err != nil {
		return "", 0, err
	}
	return a, i, nil
}

// ActiveAddressOf is the address of the active keyset of the partition's shard, read from q.
func (s *Service) ActiveAddressOf(ctx context.Context, q kq, partitionID string) (string, error) {
	if s.Cfg.Family == FamilyBTC {
		// The hot shards of a Bitcoin cell derive from the account key of the deposit tree: its active generation says which address serves new work.
		if h, ok := s.Chain.(interface {
			ActiveHotAddress(context.Context, string) (string, error)
		}); ok {
			a, err := h.ActiveHotAddress(ctx, partitionID)
			if errors.Is(err, chain.ErrNotEnoughOutputs) {
				return "", fmt.Errorf("%w: %v", ErrNoActiveKeyset, err)
			}
			return a, err
		}
	}
	k, err := partition.Parse(partitionID)
	if err != nil {
		return "", err
	}
	ks, err := partition.Active(ctx, q, k.ShardID())
	if errors.Is(err, partition.ErrKeysetNotFound) {
		return "", fmt.Errorf("%w: %s", ErrNoActiveKeyset, k.ShardID())
	}
	if err != nil {
		return "", err
	}
	return ks.Address, nil
}

// KeysetInfo is a generation as the admin API and Reconcile see it.
type KeysetInfo struct {
	partition.Keyset
	Successor int      // the generation it empties into (draining or compromised), else 0
	Dust      *big.Int // the native amount written off at retirement (the address still holds it), else nil
}

const keysetInfoCols = `shard_id, generation, key_ref, address, public_key, state, created_at, state_changed_at, COALESCE(successor, 0), COALESCE(dust_written_off, 0)::text`

func scanKeysetInfo(row pgx.Row) (KeysetInfo, error) {
	var k KeysetInfo
	var id string
	var dust string
	err := row.Scan(&id, &k.Generation, &k.KeyRef, &k.Address, &k.PublicKey, &k.State, &k.CreatedAt, &k.ChangedAt, &k.Successor, &dust)
	k.ShardID = partition.ShardID(id)
	k.Dust = parseBig(dust)
	return k, err
}

// shardKeysets lists the generations of one shard in order of generation.
func shardKeysets(ctx context.Context, q kq, shard partition.ShardID) ([]KeysetInfo, error) {
	rows, err := q.Query(ctx, `SELECT `+keysetInfoCols+` FROM keysets WHERE shard_id=$1 ORDER BY generation`, string(shard))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeysetInfo
	for rows.Next() {
		k, err := scanKeysetInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// WatchList is the addresses of the shard's generations that are not retired, with their generation and state: the addresses Reconcile adds up for
// the shard and compares with the shard's one ledger account. A shard the registry does not know (tools and tests that never bootstrap) has its
// configured address as generation 1.
func (s *Service) WatchList(ctx context.Context, q kq, i int) ([]KeysetInfo, error) {
	ks, err := shardKeysets(ctx, q, s.Cfg.shardIDOf(i))
	if err != nil {
		return nil, err
	}
	var out []KeysetInfo
	for _, k := range ks {
		if k.State != partition.StateRetired {
			out = append(out, k)
		}
	}
	if len(ks) == 0 && s.Cfg.Family == FamilyEVM && i < len(s.Cfg.HotShards) {
		out = append(out, KeysetInfo{Keyset: partition.Keyset{ShardID: s.Cfg.shardIDOf(i), Generation: 1, Address: s.Cfg.HotShards[i].Hex(), State: partition.StateActive}})
	}
	return out, nil
}

// shardLeaving reports whether the shard has a generation that is draining or compromised and not yet found drained: its funds are still moving to
// the successor, so what the shard's ledger account holds is not all at the active address yet.
func shardLeaving(ctx context.Context, q kq, shard partition.ShardID) (bool, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM keysets k WHERE k.shard_id=$1 AND k.state IN ('draining','compromised')
		AND NOT EXISTS (SELECT 1 FROM keyset_drains d WHERE d.shard_id=k.shard_id AND d.generation=k.generation AND d.state='drained')`, string(shard)).Scan(&n)
	return n > 0, err
}

// ErrSuccessorUnfunded: the shard's active generation does not hold what the work needs yet, while an older generation of the shard is still draining
// into it. It wraps chain.ErrNotEnoughOutputs, so a withdrawal waits (its workflow polls and tries again) with this reason instead of failing.
var ErrSuccessorUnfunded = fmt.Errorf("%w: successor key not funded yet", chain.ErrNotEnoughOutputs)

// checkActiveFunded is the gas and funds check of new EVM work from a shard that is being drained: the active address must hold the asset for what it
// sends (and, for a token, native for the gas), because the shard's one ledger account says the shard has the money but the money may still be at the
// old address. It changes nothing for a shard with one generation or one that is fully drained.
func (s *Service) checkActiveFunded(ctx context.Context, q kq, partitionID, asset string, amount *big.Int) error {
	if s.Cfg.Family != FamilyEVM && s.Cfg.Family != "" {
		return nil
	}
	k, err := partition.Parse(partitionID)
	if err != nil {
		return err
	}
	leaving, err := shardLeaving(ctx, q, k.ShardID())
	if err != nil || !leaving {
		return err
	}
	act, err := partition.Active(ctx, q, k.ShardID())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSuccessorUnfunded, err)
	}
	bal, err := s.balancesAt(ctx, act.Address)
	if err != nil {
		return fmt.Errorf("%w: cannot read %s: %v", ErrSuccessorUnfunded, act.Address, err)
	}
	need := map[string]*big.Int{asset: new(big.Int).Set(amount)}
	if asset != s.Cfg.Native {
		need[s.Cfg.Native] = new(big.Int).Set(s.Cfg.NativeReserve()) // the gas of the transfer
	}
	for sym, n := range need {
		if bal[sym].Cmp(n) < 0 {
			return fmt.Errorf("%w: generation %d of %s (%s) holds %s %s, the transfer needs %s; the old generation is draining into it, so the work waits", ErrSuccessorUnfunded,
				act.Generation, k.ShardID(), act.Address, bal[sym], sym, n)
		}
	}
	return nil
}
