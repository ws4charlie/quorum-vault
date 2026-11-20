package btc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// Hot shards under later generations of the account key (K6). The hot shard addresses of a Bitcoin cell derive from the same account key as its deposit
// tree (branch 1), so one registry entry, the deposit tree's, says which generation serves the hot shards too: new work (withdrawals, batches, moves to
// cold, consolidations, sweeps) is built from the ACTIVE generation's shard, and every generation's shard is recognised when an output to it is seen.
// Generation 1 is the configured shard, byte for byte.

// ErrNoActiveGeneration: the deposit tree has registry rows and none is active (a replacement between "start draining" and "activate"). It wraps
// chain.ErrNotEnoughOutputs, so a withdrawal waits and a sweep is tried again.
var ErrNoActiveGeneration = fmt.Errorf("%w: no active key generation (a key replacement is in progress)", chain.ErrNotEnoughOutputs)

// keyPath is the key reference of the shard's keys: the path of generation 1, "g<N>/<path>" after.
func (s shard) keyPath() string { return chain.KeyPathAt(s.gen, PathString(s.path)) }

// payloadGen is the Gen of a payload input under this shard (absent for generation 1).
func (s shard) payloadGen() uint32 {
	if s.gen <= 1 {
		return 0
	}
	return uint32(s.gen)
}

type genShards struct {
	mu sync.Mutex
	by map[int][]shard // generation -> its shards, derived once (a generation's key never changes)
}

// shardsOfGen are the hot shards of every partition under generation gen.
func (a *Adapter) shardsOfGen(gen int) ([]shard, error) {
	if gen <= 1 {
		return a.shards, nil
	}
	a.gs.mu.Lock()
	defer a.gs.mu.Unlock()
	if s, ok := a.gs.by[gen]; ok {
		return s, nil
	}
	var out []shard
	for _, b := range a.shards {
		addr, err := a.acct.AddressAt(uint32(gen), b.path)
		if err != nil {
			return nil, err
		}
		script, err := OutputScript(addr, a.cfg.params)
		if err != nil {
			return nil, err
		}
		out = append(out, shard{partition: b.partition, address: addr, path: b.path, script: script, gen: gen})
	}
	if a.gs.by == nil {
		a.gs.by = map[int][]shard{}
	}
	a.gs.by[gen] = out
	return out, nil
}

// treeStates reads the generations of the chain's deposit tree and their states (nil: the registry has no row for it).
func (a *Adapter) treeStates(ctx context.Context) (map[int]string, error) {
	rows, err := a.pool.Query(ctx, `SELECT generation, state FROM keysets WHERE shard_id LIKE $1`, partition.DepositTreeLike(a.cfg.Chain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out map[int]string
	for rows.Next() {
		var g int
		var st string
		if err := rows.Scan(&g, &st); err != nil {
			return nil, err
		}
		if out == nil {
			out = map[int]string{}
		}
		out[g] = st
	}
	return out, rows.Err()
}

// ActiveGeneration is the generation that serves new work: 1 when the registry has no row for the tree, else its active generation, else
// ErrNoActiveGeneration.
func (a *Adapter) ActiveGeneration(ctx context.Context) (int, error) {
	t, err := a.treeStates(ctx)
	if err != nil {
		return 0, err
	}
	if t == nil {
		return 1, nil
	}
	for g, st := range t {
		if st == partition.StateActive {
			return g, nil
		}
	}
	return 0, ErrNoActiveGeneration
}

// shardOf is the hot shard of a partition that serves new work: the one under the active generation.
func (a *Adapter) shardOf(ctx context.Context, partitionID string) (shard, error) {
	gen, err := a.ActiveGeneration(ctx)
	if err != nil {
		return shard{}, err
	}
	return a.shardOfGen(partitionID, gen)
}

// shardOfGen is the hot shard of a partition under a given generation.
func (a *Adapter) shardOfGen(partitionID string, gen int) (shard, error) {
	ss, err := a.shardsOfGen(gen)
	if err != nil {
		return shard{}, err
	}
	for _, s := range ss {
		if s.partition == partitionID {
			return s, nil
		}
	}
	return shard{}, fmt.Errorf("btc: partition %q has no hot shard", partitionID)
}

// hotByAddr finds the hot shard an address belongs to, under any generation of the tree that is not a mere candidate's... (a candidate's shard can be
// funded before it is active, so it is recognised too).
func (a *Adapter) hotByAddr(ctx context.Context, addr string) (shard, bool) {
	if sh, ok := a.byAddr[addr]; ok {
		return sh, true
	}
	t, err := a.treeStates(ctx)
	if err != nil {
		return shard{}, false
	}
	for g := range t {
		if g < 2 {
			continue
		}
		ss, err := a.shardsOfGen(g)
		if err != nil {
			continue
		}
		for _, s := range ss {
			if s.address == addr {
				return s, true
			}
		}
	}
	return shard{}, false
}

// HotAddresses lists the addresses of every hot shard under every generation of the tree, retired ones included (what a retired generation still
// holds, dust at most, is still the shard's money in the books).
func (a *Adapter) HotAddresses(ctx context.Context) ([]string, error) {
	var out []string
	for _, s := range a.shards {
		out = append(out, s.address)
	}
	t, err := a.treeStates(ctx)
	if err != nil {
		return nil, err
	}
	for g := range t {
		if g < 2 {
			continue
		}
		ss, err := a.shardsOfGen(g)
		if err != nil {
			return nil, err
		}
		for _, s := range ss {
			out = append(out, s.address)
		}
	}
	return out, nil
}

// HotAddressesOf lists the addresses of one partition's shard under every generation, generation 1 first.
func (a *Adapter) HotAddressesOf(ctx context.Context, partitionID string) ([]string, error) {
	t, err := a.treeStates(ctx)
	if err != nil {
		return nil, err
	}
	gens := []int{1}
	for g := range t {
		if g > 1 {
			gens = append(gens, g)
		}
	}
	sort.Ints(gens)
	var out []string
	for _, g := range gens {
		sh, err := a.shardOfGen(partitionID, g)
		if err != nil {
			return nil, err
		}
		out = append(out, sh.address)
	}
	return out, nil
}

// ActiveHotAddress is the address of the partition's shard under the active generation.
func (a *Adapter) ActiveHotAddress(ctx context.Context, partitionID string) (string, error) {
	sh, err := a.shardOf(ctx, partitionID)
	return sh.address, err
}

var _ = errors.New

// ShardAddressAtGen is the address of the partition's shard under generation gen.
func (a *Adapter) ShardAddressAtGen(partitionID string, gen int) (string, error) {
	sh, err := a.shardOfGen(partitionID, gen)
	return sh.address, err
}

// ReservedUnder counts the outputs of the partition's shard under generation gen that an owner other than a drain has reserved: work built from the old
// generation that is not final yet.
func (a *Adapter) ReservedUnder(ctx context.Context, partitionID string, gen int) (int, error) {
	sh, err := a.shardOfGen(partitionID, gen)
	if err != nil {
		return 0, err
	}
	var n int
	err = a.pool.QueryRow(ctx, `SELECT count(*) FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND path=$3 AND status='reserved' AND owner_kind <> $4`,
		a.cfg.Chain, partitionID, sh.keyPath(), OwnerKindDrain).Scan(&n)
	return n, err
}

// HeldUnder is what the partition's shard under generation gen holds in outputs the books know (available or reserved), in satoshis.
func (a *Adapter) HeldUnder(ctx context.Context, partitionID string, gen int) (*big.Int, error) {
	sh, err := a.shardOfGen(partitionID, gen)
	if err != nil {
		return nil, err
	}
	var s string
	err = a.pool.QueryRow(ctx, `SELECT COALESCE(SUM(value),0)::text FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND path=$3 AND NOT deposit AND NOT cold AND status IN ('available','reserved')`,
		a.cfg.Chain, partitionID, sh.keyPath()).Scan(&s)
	n, _ := new(big.Int).SetString(s, 10)
	return n, err
}
