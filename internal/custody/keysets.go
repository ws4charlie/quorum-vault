package custody

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// shardIDOf is the stable ID of hot shard i of this chain (omnibus pool).
func (c *Config) shardIDOf(i int) partition.ShardID {
	return c.PartitionKey(c.Native, i).ShardID()
}

// loadKeysets registers generation 1 of every configured shard as active (idempotent; a registered shard whose address differs from the configuration
// refuses the start: a shard's address changes only through a new keyset generation) and then reads the active keyset of every shard from the registry.
// From here on ShardAddressOf answers from the registry. With one generation per shard it answers what the configuration says.
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
		k, ok := active[id]
		if !ok {
			return fmt.Errorf("custody: keyset registry: shard %s has no active keyset", id)
		}
		mine[id] = k
	}
	s.keysets.Store(&mine)
	return nil
}

// ShardAddressOf is the hot address of a partition's shard, the address of the shard's active keyset, in the form the family's chain cell takes,
// and the shard's index. Before Bootstrap has loaded the registry (tools and tests that never bootstrap) it is the configured address.
func (s *Service) ShardAddressOf(partitionID string) (string, int, error) {
	addr, i, err := s.Cfg.ShardAddressOf(partitionID)
	if err != nil {
		return "", 0, err
	}
	m := s.keysets.Load()
	if m == nil {
		return addr, i, nil
	}
	k, err := partition.Parse(partitionID)
	if err != nil {
		return "", 0, err
	}
	ks, ok := (*m)[k.ShardID()]
	if !ok {
		return "", 0, fmt.Errorf("custody: shard %s has no active keyset", k.ShardID())
	}
	return ks.Address, i, nil
}
