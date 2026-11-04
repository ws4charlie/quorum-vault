// Package partition defines the key that identifies a fund partition: one hot
// or cold wallet (or one shard of a hot wallet) of one asset in one pool.
package partition

import (
	"fmt"
	"strconv"
	"strings"
)

// Tiers.
const (
	TierHot  = "hot"
	TierCold = "cold"
)

// PoolOmnibus is the shared pool; segregated pools are "segregated:<client>".
const PoolOmnibus = "omnibus"

const sep = "/"

// Key identifies a partition. Shard picks one of K hot child addresses under
// one master key (to spread nonce load); it is 0 for cold and unsharded wallets.
type Key struct {
	Entity string
	Chain  string
	Asset  string
	Tier   string
	Pool   string
	Shard  int
}

// Validate reports whether every field is usable in a String()/Parse() round trip.
func (k Key) Validate() error {
	for name, v := range map[string]string{"entity": k.Entity, "chain": k.Chain, "asset": k.Asset, "tier": k.Tier, "pool": k.Pool} {
		if v == "" {
			return fmt.Errorf("partition: empty %s", name)
		}
		if strings.Contains(v, sep) {
			return fmt.Errorf("partition: %s %q contains %q", name, v, sep)
		}
	}
	if k.Tier != TierHot && k.Tier != TierCold {
		return fmt.Errorf("partition: tier %q is not hot or cold", k.Tier)
	}
	if k.Pool != PoolOmnibus {
		if client, ok := strings.CutPrefix(k.Pool, "segregated:"); !ok || client == "" {
			return fmt.Errorf("partition: pool %q is not omnibus or segregated:<client>", k.Pool)
		}
	}
	if k.Shard < 0 {
		return fmt.Errorf("partition: negative shard %d", k.Shard)
	}
	return nil
}

// String returns entity/chain/asset/tier/pool/shard, the value stored in partitions.id.
func (k Key) String() string {
	return strings.Join([]string{k.Entity, k.Chain, k.Asset, k.Tier, k.Pool, strconv.Itoa(k.Shard)}, sep)
}

// Parse is the inverse of String.
func Parse(s string) (Key, error) {
	parts := strings.Split(s, sep)
	if len(parts) != 6 {
		return Key{}, fmt.Errorf("partition: %q: want 6 %q-separated fields, got %d", s, sep, len(parts))
	}
	shard, err := strconv.Atoi(parts[5])
	if err != nil {
		return Key{}, fmt.Errorf("partition: %q: bad shard: %w", s, err)
	}
	k := Key{Entity: parts[0], Chain: parts[1], Asset: parts[2], Tier: parts[3], Pool: parts[4], Shard: shard}
	if err := k.Validate(); err != nil {
		return Key{}, err
	}
	return k, nil
}
