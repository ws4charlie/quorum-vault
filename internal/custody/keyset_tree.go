package custody

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// The admin steps of the deposit key tree of a Bitcoin or Solana chain (K6). The registry entry is entity/chain/deposit-tree/0; a candidate's "address" is
// the public identity the deposit addresses derive from (the account xpub, or "<node key hex>:<chain code hex>"), its key_ref the keyset the parties sign
// with. Like the hot shards' mirror it only plans: the signing zone decides from its own signed records.

// isDepositTree reports whether shardID is this chain's deposit tree.
func (s *Service) isDepositTree(shardID string) bool {
	if s.Cfg.Family != FamilyBTC && s.Cfg.Family != FamilySOL {
		return false
	}
	want, err := s.Cfg.depositTreeID()
	return err == nil && string(want) == shardID
}

// treeIdentity checks a candidate's identity against the chain and returns the registry's public key for it.
func (s *Service) treeIdentity(identity string) (string, []byte, error) {
	switch s.Cfg.Family {
	case FamilyBTC:
		id, pub, err := btc.DepositIdentity(s.Cfg.BTC.Network, identity)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return id, pub, nil
	case FamilySOL:
		p, c, ok := strings.Cut(identity, ":")
		a, e1 := hex.DecodeString(p)
		b, e2 := hex.DecodeString(c)
		if !ok || e1 != nil || e2 != nil || len(a) != 32 || len(b) != 32 {
			return "", nil, fmt.Errorf("%w: the identity of a Solana deposit node is <32-byte key hex>:<32-byte chain code hex>", ErrInvalid)
		}
		id, pub, err := sol.DepositIdentity(p, c)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return id, pub, nil
	}
	return "", nil, ErrInvalid
}

// registerTreeCandidate records the next generation of the deposit tree as a candidate.
func (s *Service) registerTreeCandidate(ctx context.Context, shard partition.ShardID, identity, keyRef string) (KeysetInfo, error) {
	if keyRef == "" {
		return KeysetInfo{}, fmt.Errorf("%w: a deposit tree candidate needs its key_ref (the keyset the parties sign with)", ErrInvalid)
	}
	id, pub, err := s.treeIdentity(identity)
	if err != nil {
		return KeysetInfo{}, err
	}
	var out KeysetInfo
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM keysets WHERE shard_id=$1 AND (state='candidate' OR address=$2 OR key_ref=$3)`, string(shard), id, keyRef).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %s already has a candidate, or already has that key", partition.ErrIllegalTransition, shard)
		}
		k, err := partition.RegisterCandidate(ctx, tx, actorOf(ctx), shard, id, keyRef, pub)
		out = KeysetInfo{Keyset: k}
		return err
	})
	return out, err
}

// retireTree retires a draining generation of the deposit tree after the checks the zone cannot make (it has no chain access): the window (when the
// caller gives the one the signed draining record names, the generation must have been draining that long), no deposit address of the generation holds
// more than dust, no transaction of it is in flight, and, on Bitcoin, the hot shards under it are empty and no drain is open. A compromised generation
// is never retired.
func (s *Service) retireTree(ctx context.Context, shard partition.ShardID, gen int, windowSeconds int64) (KeysetInfo, error) {
	cur, err := scanKeysetInfo(s.Pool.QueryRow(ctx, `SELECT `+keysetInfoCols+` FROM keysets WHERE shard_id=$1 AND generation=$2`, string(shard), gen))
	if err != nil {
		if isNoRows(err) {
			return KeysetInfo{}, fmt.Errorf("%w: %s generation %d", partition.ErrKeysetNotFound, shard, gen)
		}
		return KeysetInfo{}, err
	}
	if cur.State != partition.StateDraining {
		return KeysetInfo{}, fmt.Errorf("%w: %s generation %d is %s, retire needs draining", partition.ErrIllegalTransition, shard, gen, cur.State)
	}
	if windowSeconds > 0 {
		if until := cur.ChangedAt.Add(time.Duration(windowSeconds) * time.Second); time.Now().Before(until) {
			return KeysetInfo{}, fmt.Errorf("%w: the deposit addresses of generation %d stay swept until %s (the window of the signed draining record)", ErrNotDrained, gen, until.UTC().Format(time.RFC3339))
		}
	}
	if err := s.treeFundsLeft(ctx, gen); err != nil {
		return KeysetInfo{}, err
	}
	var out KeysetInfo
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		k, err := partition.Retire(ctx, tx, actorOf(ctx), shard, gen)
		out = KeysetInfo{Keyset: k, Successor: cur.Successor}
		return err
	})
	return out, err
}

// treeFundsLeft refuses while anything of generation gen is not final: funds above dust at its deposit addresses, a sweep or drain in flight, a hot shard
// (Bitcoin) that still holds coins.
func (s *Service) treeFundsLeft(ctx context.Context, gen int) error {
	c := s.Cfg
	switch c.Family {
	case FamilyBTC:
		dust := int64(btc.DustLimit(btc.KindP2WPKH))
		pathCond := `path NOT LIKE 'g%'`
		if gen > 1 {
			pathCond = fmt.Sprintf(`path LIKE 'g%d/%%'`, gen)
		}
		var n int
		var sum string
		if err := s.Pool.QueryRow(ctx, `SELECT count(*), COALESCE(SUM(value),0)::text FROM btc_utxos WHERE chain=$1 AND deposit AND status IN ('available','reserved') AND value > $2 AND `+pathCond,
			c.Chain, dust).Scan(&n, &sum); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %d outputs (%s sats) at deposit addresses of generation %d are not swept yet", ErrNotDrained, n, sum, gen)
		}
		var open int
		if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM drain_moves WHERE chain=$1 AND from_generation=$2 AND status NOT IN ('confirmed','failed')`, c.Chain, gen).Scan(&open); err != nil {
			return err
		}
		if open > 0 {
			return fmt.Errorf("%w: %d drain moves of generation %d are still open", ErrNotDrained, open, gen)
		}
		d, ok := s.Chain.(interface {
			HeldUnder(context.Context, string, int) (*big.Int, error)
			ReservedUnder(context.Context, string, int) (int, error)
		})
		if !ok {
			return fmt.Errorf("%w: this chain cell cannot say what its hot shards hold", ErrNotDrained)
		}
		for i := range c.BTC.HotShards {
			p := c.PartitionKey(c.Native, i).String()
			held, err := d.HeldUnder(ctx, p, gen)
			if err != nil {
				return err
			}
			if held.Cmp(big.NewInt(dust)) > 0 {
				return fmt.Errorf("%w: the hot shard of %s under generation %d still holds %s sats", ErrNotDrained, p, gen, held)
			}
		}
		return nil
	case FamilySOL:
		rows, err := s.Pool.Query(ctx, `SELECT address FROM deposit_addresses WHERE chain=$1 AND generation=$2 ORDER BY address`, c.Chain, gen)
		if err != nil {
			return err
		}
		var addrs []string
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				rows.Close()
				return err
			}
			addrs = append(addrs, a)
		}
		rows.Close()
		for _, a := range addrs {
			left, err := s.balancesAt(ctx, a)
			if err != nil {
				return fmt.Errorf("%w: cannot read the balances of %s: %v", ErrNotDrained, a, err)
			}
			for _, sym := range c.AssetList {
				dust, err := s.dustOf(ctx, sym)
				if err != nil {
					return err
				}
				if left[sym].Cmp(dust) > 0 {
					return fmt.Errorf("%w: deposit address %s of generation %d still holds %s %s", ErrNotDrained, a, gen, left[sym], sym)
				}
			}
		}
		var inflight int
		if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM sweeps s JOIN deposit_addresses d ON d.chain=s.chain AND d.address=s.from_address WHERE s.chain=$1 AND d.generation=$2 AND s.status NOT IN ('confirmed','failed')`,
			c.Chain, gen).Scan(&inflight); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if inflight > 0 {
			return fmt.Errorf("%w: %d sweeps of generation %d are still in flight", ErrNotDrained, inflight, gen)
		}
	}
	return nil
}

// treeDrainView is what the planner found for the hot shards under a generation of a Bitcoin deposit tree, in one line: moving while any shard moves,
// waiting (with the first reason) while one waits, drained when all are.
func (s *Service) treeDrainView(ctx context.Context, gen int) (*DrainView, error) {
	if s.Cfg.Family != FamilyBTC {
		return nil, nil
	}
	id, err := s.Cfg.depositTreeID()
	if err != nil {
		return nil, err
	}
	var d DrainView
	err = s.Pool.QueryRow(ctx, `SELECT state, reason FROM keyset_drains WHERE shard_id=$1 AND generation=$2`, string(id), gen).Scan(&d.State, &d.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &d, err
}
