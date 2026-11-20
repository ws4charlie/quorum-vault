package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// A hot shard may have more than one key generation (research/Key-replacement.md). The configuration names generation 1 of every shard; the
// keyset registry of the business database (table keysets, internal/partition) says which generation is active now. New work (withdrawals, sweeps,
// rebalances, cold moves) is built from the ACTIVE generation's address; work already built keeps the address it was built for (the nonce allocation
// stores it), so a replacement or a cancel of it is signed by the generation that signed the original.

// ErrNoActiveKeyset: the shard has generations but none is active (a replacement is between "start draining" and "activate"). It wraps
// chain.ErrNotEnoughOutputs so a withdrawal waits for the successor instead of failing; the message says why.
var ErrNoActiveKeyset = fmt.Errorf("%w: the shard has no active keyset (a key replacement is in progress)", chain.ErrNotEnoughOutputs)

// shardOf is the shard a partition belongs to.
func shardOf(partitionID string) (partition.ShardID, error) {
	k, err := partition.Parse(partitionID)
	if err != nil {
		return "", err
	}
	return k.ShardID(), nil
}

// activeOfShard reads the address of the shard's active generation. known is false when the registry has no row for the shard at all (a database
// that never registered it: tools and tests), so the caller uses the configured address.
func activeOfShard(ctx context.Context, q queryer, shard partition.ShardID) (addr common.Address, known bool, err error) {
	var a string
	err = q.QueryRow(ctx, `SELECT address FROM keysets WHERE shard_id=$1 AND state='active'`, string(shard)).Scan(&a)
	if err == nil {
		return common.HexToAddress(a), true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return common.Address{}, false, fmt.Errorf("evm: keyset registry: %w", err)
	}
	var any bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM keysets WHERE shard_id=$1)`, string(shard)).Scan(&any); err != nil {
		return common.Address{}, false, fmt.Errorf("evm: keyset registry: %w", err)
	}
	if !any {
		return common.Address{}, false, nil
	}
	return common.Address{}, true, fmt.Errorf("%w: %s", ErrNoActiveKeyset, shard)
}

// hotFor is the address that sends new work for the partition: its shard's active generation.
func (a *Adapter) hotFor(ctx context.Context, q queryer, partitionID string) (common.Address, error) {
	static, err := a.cfg.hot(partitionID)
	if err != nil {
		return common.Address{}, err
	}
	shard, err := shardOf(partitionID)
	if err != nil {
		return static, nil // not a partition ID the registry can know (a test's name for a hot wallet): the configured address
	}
	addr, known, err := activeOfShard(ctx, q, shard)
	if err != nil {
		return common.Address{}, err
	}
	if !known {
		return static, nil
	}
	return addr, nil
}

// sweepDestination is where the factory must pay: the active address of the shard the configuration names as the sweep destination.
func (a *Adapter) sweepDestination(ctx context.Context, q queryer) (common.Address, error) {
	p := a.cfg.partitionOf(a.cfg.SweepDestination)
	if p == "" {
		return a.cfg.SweepDestination, nil
	}
	return a.hotFor(ctx, q, p)
}

// partitionOfAddress is a partition whose shard the address serves, for the key reference of a transaction built for an address that is not in the
// configuration (a later generation).
func (a *Adapter) partitionOfAddress(ctx context.Context, q queryer, from common.Address) string {
	if p := a.cfg.partitionOf(from); p != "" {
		return p
	}
	var shard string
	if err := q.QueryRow(ctx, `SELECT shard_id FROM keysets WHERE lower(address)=lower($1) LIMIT 1`, from.Hex()).Scan(&shard); err != nil {
		return ""
	}
	best := ""
	for p := range a.cfg.HotAddresses {
		if s, err := shardOf(p); err == nil && string(s) == shard && (best == "" || p < best) {
			best = p
		}
	}
	return best
}

// NativeDrainReserve is the native amount that stays at an old address when it is drained: what the last transfer's gas needs, with room for one
// fee bump of a stuck replacement (twice a plain transfer at the current fee cap), and never more than the configured cap of a transaction's fee.
func (a *Adapter) NativeDrainReserve(ctx context.Context) (*big.Int, error) {
	_, feeCap, _, err := a.fees(ctx)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).Mul(new(big.Int).SetUint64(2*DefaultCancelGas), feeCap)
	if a.cfg.MaxTxFeeWei != nil && r.Cmp(a.cfg.MaxTxFeeWei) > 0 {
		r = new(big.Int).Set(a.cfg.MaxTxFeeWei)
	}
	return r, nil
}
