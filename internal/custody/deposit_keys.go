package custody

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// depositTreeID is the registry ID of this chain's deposit key tree.
func (c *Config) depositTreeID() (partition.ShardID, error) {
	return partition.DepositTreeID(c.Entity, c.Chain)
}

// depositIdentity is what the configuration says the deposit tree's generation 1 is: the account xpub on Bitcoin, the deposit node on Solana. ok is false
// for a family whose deposit addresses come from no key (EVM forwarders: the factory makes them, so no key replacement changes them).
func (c *Config) depositIdentity() (identity string, pub []byte, ok bool, err error) {
	switch c.Family {
	case FamilyBTC:
		identity, pub, err = btc.DepositIdentity(c.BTC.Network, c.BTC.AccountXpub)
	case FamilySOL:
		identity, pub, err = sol.DepositIdentity(c.SOL.AccountPublicKey, c.SOL.AccountChainCode)
	default:
		return "", nil, false, nil
	}
	return identity, pub, err == nil, err
}

// loadDepositTree registers generation 1 of the chain's deposit key tree as active (idempotent). The registered identity is the configured account key; a
// registered generation 1 with another key refuses the start, as for a hot shard: the key of a generation never changes, a replacement is a new generation.
// On Bitcoin the hot shard addresses derive from this same account (branch 1, docs/key-replacement.md), so the deposit tree's entry and the hot
// shards' entries are generation 1 of one key; replacing it (K6) replaces both.
func (s *Service) loadDepositTree(ctx context.Context) error {
	identity, pub, ok, err := s.Cfg.depositIdentity()
	if err != nil {
		return fmt.Errorf("custody: deposit key: %w", err)
	}
	if !ok {
		return nil
	}
	id, err := s.Cfg.depositTreeID()
	if err != nil {
		return err
	}
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		_, err := partition.RegisterInitial(ctx, tx, "system", id, identity, "", pub)
		return err
	}); err != nil {
		return fmt.Errorf("custody: deposit key registry: %w", err)
	}
	return nil
}
