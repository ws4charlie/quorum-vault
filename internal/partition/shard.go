package partition

import (
	"fmt"
	"strconv"
	"strings"
)

// ShardID names one hot shard of one pool of one chain: entity/chain/pool/shard. It is the shard's identity for good: it holds no key and no address,
// so it does not change when the shard's key does (the keyset registry says which key serves it). Every asset of a shard shares it: the partition IDs
// entity/chain/ASSET/hot/pool/shard of one shard all map to the same ShardID. Today the shard number is the shard's position in the chain's config
// list; it must never be reused for another shard.
type ShardID string

// ShardID returns the shard this partition belongs to. It is meaningful for hot partitions only.
func (k Key) ShardID() ShardID {
	return ShardID(strings.Join([]string{k.Entity, k.Chain, k.Pool, strconv.Itoa(k.Shard)}, sep))
}

// NewShardID builds a ShardID from its parts.
func NewShardID(entity, chain, pool string, shard int) (ShardID, error) {
	id := ShardID(strings.Join([]string{entity, chain, pool, strconv.Itoa(shard)}, sep))
	if _, err := ParseShardID(string(id)); err != nil {
		return "", err
	}
	return id, nil
}

// ParseShardID checks the form of a shard ID.
func ParseShardID(s string) (ShardID, error) {
	parts := strings.Split(s, sep)
	if len(parts) != 4 {
		return "", fmt.Errorf("partition: shard id %q: want 4 %q-separated fields, got %d", s, sep, len(parts))
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil || n < 0 {
		return "", fmt.Errorf("partition: shard id %q: bad shard number", s)
	}
	// reuse Key.Validate for the other fields
	if err := (Key{Entity: parts[0], Chain: parts[1], Asset: "x", Tier: TierHot, Pool: parts[2], Shard: n}).Validate(); err != nil {
		return "", err
	}
	return ShardID(s), nil
}

// Shard returns the shard number of the ID (0 when the ID is malformed).
func (id ShardID) Shard() int {
	p := strings.Split(string(id), sep)
	n, _ := strconv.Atoi(p[len(p)-1])
	return n
}
