package custody

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// OwnerKindRebalance is the owner kind (nonce owner, sign-job track, intent kind) of a hot-shard rebalance.
const OwnerKindRebalance = "rebalance"

// Sweeps all land on one hot shard (the factory's destination), so the other shards run dry. A rebalance moves funds from the
// fullest shard of a pool to a shard that is below its target, so the nonce load spreads again. It is a transfer out of the
// source shard's hot address, like a hot-to-cold move, to another hot address of the same pool, and it is booked the same way,
// through a clearing account:
//
//	broadcast  rebal -> hot(source)   (the funds are on their way)
//	confirmed  hot(dest) -> rebal     (they arrived)
//	reverted   hot(source) -> rebal   (the broadcast booking is undone; only the fee stays)
//
// plus the network fee, paid by the source shard: fee -> hot(source), as everywhere. No human approves a rebalance: the signing
// zone pins the destination to its own list of hot shards, so it can only move money between wallets the operator already runs.
//
// Order against hot-to-cold moves (the rules that keep them from fighting, each one tested):
//  1. Both planners count a planned or signing move as already gone from its source (freeHot), so one pass never spends the same
//     funds twice, and a withdrawal never counts on funds that are leaving.
//  2. The cold planner counts a rebalance on its way TO a shard as that shard's liquidity when it asks "is this shard below its
//     low-water mark?", so a refill ceremony is not opened for a shard that a rebalance is already feeding. It does not count it
//     when it asks "is it above the high-water mark?": funds that have not arrived cannot be moved on.
//  3. Config validation requires low <= rebalance target <= cold target for every shard. A rebalance fills a shard only up to its
//     rebalance target, which is below its high-water mark, so a rebalance never makes a shard eligible for a move to cold; and a
//     move to cold leaves a shard at its cold target, which is at or above its rebalance target, so a move to cold never makes a
//     shard want a rebalance.

// RebalanceMove is a row of rebalance_moves.
type RebalanceMove struct {
	ID            string
	Asset         string
	PartitionID   string // the source shard: its key signs, its wallet pays the gas
	ToPartitionID string
	To            string
	Amount        *big.Int
	Status        string
	TxHash        string
	JobID         string
	Reason        string
}

// Parked reports whether the move needs an operator.
func (m RebalanceMove) Parked() bool { return strings.HasPrefix(m.Reason, ParkedPrefix) }

// Owner returns the move as a transaction owner.
func (m RebalanceMove) Owner() Owner {
	return Owner{Kind: OwnerKindRebalance, ID: m.ID, PartitionID: m.PartitionID}
}

const rebalCols = `id, asset, partition_id, to_partition_id, to_address, amount::text, status, COALESCE(tx_hash,''), COALESCE(job_id,''), COALESCE(failure_reason,'')`

func scanRebal(row pgx.Row) (RebalanceMove, error) {
	var m RebalanceMove
	var amt string
	if err := row.Scan(&m.ID, &m.Asset, &m.PartitionID, &m.ToPartitionID, &m.To, &amt, &m.Status, &m.TxHash, &m.JobID, &m.Reason); err != nil {
		return m, err
	}
	m.Amount = parseBig(amt)
	return m, nil
}

// GetRebalance reads one rebalance.
func (s *Service) GetRebalance(ctx context.Context, id string) (RebalanceMove, error) {
	m, err := scanRebal(s.Pool.QueryRow(ctx, `SELECT `+rebalCols+` FROM rebalance_moves WHERE id=$1`, id))
	if isNoRows(err) {
		return m, fmt.Errorf("%w: rebalance %s", ErrNotFound, id)
	}
	return m, err
}

// OpenRebalances lists rebalances that are not finished and not parked.
func (s *Service) OpenRebalances(ctx context.Context) ([]RebalanceMove, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+rebalCols+` FROM rebalance_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed')
		AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' ORDER BY created_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RebalanceMove
	for rows.Next() {
		m, err := scanRebal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// incomingRebalance is what open rebalances will still bring to the shard: booked at confirmation, so not in its balance yet.
func (s *Service) incomingRebalance(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, partitionID string) (*big.Int, error) {
	var sum string
	if err := q.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0)::text FROM rebalance_moves WHERE to_partition_id=$1 AND status NOT IN ('confirmed','failed')`,
		partitionID).Scan(&sum); err != nil {
		return nil, err
	}
	return parseBig(sum), nil
}

type shardState struct {
	part     string
	free     *big.Int // freeHot: what the shard can still pay out
	eff      *big.Int // free plus what open rebalances are bringing
	target   *big.Int
	outgoing bool // an open rebalance already leaves this shard (one open per source and asset)
	incoming bool
}

// PlanRebalances gives every shard that is below its target funds from the fullest shard of its asset, when that shard holds more
// than its own target. What a shard holds is its free liquidity (hot balance less what open withdrawals reserved, less moves that
// are planned or signing), so reserved funds are never moved. It returns the moves it created.
func (s *Service) PlanRebalances(ctx context.Context, log *slog.Logger) ([]RebalanceMove, error) {
	c := s.Cfg
	if len(c.RebalanceTargets) == 0 {
		return nil, nil
	}
	var created []RebalanceMove
	for _, sym := range c.AssetList {
		if _, ok := c.RebalanceTargets[c.PartitionKey(sym, 0).String()]; !ok {
			continue
		}
		var made []RebalanceMove
		err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			made = nil
			// Serialize with withdrawal reservations and the cold planner on every shard of the asset, in one order.
			parts := make([]string, c.shardCount())
			for i := range parts {
				parts[i] = c.PartitionKey(sym, i).String()
			}
			sort.Strings(parts)
			for _, p := range parts {
				if _, err := tx.Exec(ctx, `SELECT 1 FROM partitions WHERE id=$1 FOR UPDATE`, p); err != nil {
					return err
				}
			}
			shards := make([]*shardState, c.shardCount())
			for i := range shards {
				p := c.PartitionKey(sym, i).String()
				tgt, ok := c.RebalanceTargets[p]
				if !ok {
					return fmt.Errorf("custody: no rebalance target for %s", p)
				}
				free, err := s.freeHot(ctx, tx, p)
				if err != nil {
					return err
				}
				in, err := s.incomingRebalance(ctx, tx, p)
				if err != nil {
					return err
				}
				st := &shardState{part: p, free: free, eff: new(big.Int).Add(free, in), target: tgt, incoming: in.Sign() > 0}
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rebalance_moves WHERE partition_id=$1 AND status NOT IN ('confirmed','failed'))`, p).Scan(&st.outgoing); err != nil {
					return err
				}
				shards[i] = st
			}
			for _, d := range shards {
				if d.incoming || d.eff.Cmp(d.target) >= 0 {
					continue
				}
				// Candidates: shards above their own target, fullest first (lower shard index on a tie).
				var cands []*shardState
				for _, sh := range shards {
					if sh != d && !sh.outgoing && sh.free.Cmp(sh.target) > 0 {
						cands = append(cands, sh)
					}
				}
				sort.SliceStable(cands, func(i, j int) bool { return cands[i].free.Cmp(cands[j].free) > 0 })
				for _, src := range cands {
					ok, err := s.sourceHasGas(ctx, tx, log, sym, src.part)
					if err != nil {
						return err
					}
					if !ok {
						continue
					}
					amt := new(big.Int).Sub(d.target, d.eff)
					if room := new(big.Int).Sub(src.free, src.target); room.Cmp(amt) < 0 {
						amt = room
					}
					if amt.Sign() <= 0 {
						break
					}
					toAddr, _, err := c.ShardAddressOf(d.part)
					if err != nil {
						return err
					}
					id := "rb-" + uuid.NewString()
					tag, err := tx.Exec(ctx, `INSERT INTO rebalance_moves (id, chain, asset, partition_id, to_partition_id, to_address, amount, status)
						VALUES ($1,$2,$3,$4,$5,$6,$7::numeric,'planned') ON CONFLICT DO NOTHING`, id, c.Chain, sym, src.part, d.part, toAddr, amt.String())
					if err != nil {
						return fmt.Errorf("custody: insert rebalance: %w", err)
					}
					if tag.RowsAffected() == 1 {
						made = append(made, RebalanceMove{ID: id, Asset: sym, PartitionID: src.part, ToPartitionID: d.part, To: toAddr, Amount: amt, Status: "planned"})
						src.outgoing, src.free = true, new(big.Int).Sub(src.free, amt)
						d.incoming = true
						if err := emit(ctx, tx, outbox.TopicColdMoves, id, "rebalance.planned", map[string]any{"chain": c.Chain, "asset": sym,
							"from": src.part, "to_partition": d.part, "to": toAddr, "amount": amt.String()}); err != nil {
							return err
						}
					}
					break
				}
			}
			return nil
		})
		if err != nil {
			return created, err
		}
		created = append(created, made...)
	}
	return created, nil
}

// sourceHasGas reports whether the source shard can pay the gas of a move of asset. A native move pays its gas out of what it
// moves (the amount is bounded by the free balance, which leaves the fee unreserved: see MaxTxFeeWei), so only a token move is
// checked: the shard's native balance must cover the worst-case fee. Without it the move is skipped with one ALERT per outage.
func (s *Service) sourceHasGas(ctx context.Context, tx pgx.Tx, log *slog.Logger, asset, source string) (bool, error) {
	c := s.Cfg
	if asset == c.Native {
		return true, nil
	}
	_, shard, err := c.ShardAddressOf(source)
	if err != nil {
		return false, err
	}
	var posted string
	if err := tx.QueryRow(ctx, `SELECT posted::text FROM ledger_accounts WHERE id=$1`, hotAcct(c.PartitionKey(c.Native, shard).String())).Scan(&posted); err != nil {
		return false, err
	}
	have := new(big.Int).Neg(parseBig(posted))
	var alerted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rebalance_gas_alerts WHERE partition_id=$1)`, source).Scan(&alerted); err != nil {
		return false, err
	}
	if have.Cmp(c.NativeReserve()) >= 0 {
		if alerted {
			_, err = tx.Exec(ctx, `DELETE FROM rebalance_gas_alerts WHERE partition_id=$1`, source)
		}
		return true, err
	}
	if !alerted {
		if _, err := tx.Exec(ctx, `INSERT INTO rebalance_gas_alerts (partition_id) VALUES ($1) ON CONFLICT DO NOTHING`, source); err != nil {
			return false, err
		}
		log.Error("ALERT: a hot shard has no gas to rebalance a token; fund it with the native asset, the rebalance from it is skipped until then",
			"partition", source, "asset", asset, "native_balance", have.String(), "needs", c.NativeReserve().String())
	}
	return false, nil
}

// BuildRebalanceJob builds the transfer (allocating the source's nonce) and enqueues its sign job, in one transaction. Repeating it
// after a crash returns the existing job. The intent carries no approvals: the destination is pinned in the signing zone.
func (s *Service) BuildRebalanceJob(ctx context.Context, id string) (string, error) {
	jobID := OwnerTrack(Owner{Kind: OwnerKindRebalance, ID: id}).FirstJob()
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanRebal(tx.QueryRow(ctx, `SELECT `+rebalCols+` FROM rebalance_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.JobID != "" || m.Status != "planned" {
			return nil
		}
		u, err := s.Chain.BuildWithdrawal(ctx, tx, chain.WithdrawalIntent{OwnerKind: OwnerKindRebalance, ID: id, PartitionID: m.PartitionID,
			Asset: m.Asset, To: m.To, Amount: m.Amount})
		if err != nil {
			return err
		}
		ib, err := json.Marshal(signjob.Intent{Kind: OwnerKindRebalance, ID: id, PartitionID: m.PartitionID, Chain: s.Cfg.Chain, Asset: m.Asset,
			To: m.To, Amount: m.Amount.String()})
		if err != nil {
			return err
		}
		if err := EnqueueUnsigned(ctx, tx, jobID, m.PartitionID, u, ib, nil); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE rebalance_moves SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, id, jobID)
		return err
	})
	return jobID, err
}

// RecordRebalanceBroadcast stores the hash and books the funds as on their way: rebal -> hot(source). Repeating it changes nothing.
func (s *Service) RecordRebalanceBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanRebal(tx.QueryRow(ctx, `SELECT `+rebalCols+` FROM rebalance_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		return s.recordRebalBroadcastTx(ctx, tx, m, txHash)
	})
}

func (s *Service) recordRebalBroadcastTx(ctx context.Context, tx pgx.Tx, m RebalanceMove, txHash string) error {
	if m.Status == "confirmed" || m.Status == "failed" || m.Status == "broadcast" {
		return nil
	}
	if err := s.transfer(ctx, tx, "rb-bcast:"+m.ID, rebalAcct(s.Cfg.Chain, m.Asset), hotAcct(m.PartitionID), m.Amount,
		map[string]any{"rebalance": m.ID, "tx": txHash}); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE rebalance_moves SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1`, m.ID, txHash); err != nil {
		return err
	}
	return emit(ctx, tx, outbox.TopicColdMoves, m.ID, "rebalance.broadcast",
		map[string]any{"chain": s.Cfg.Chain, "asset": m.Asset, "from": m.PartitionID, "to_partition": m.ToPartitionID, "amount": m.Amount.String(), "tx": txHash})
}

// SettleRebalance books a mined rebalance. Confirmed: the funds are in the receiving shard (hot(dest) -> rebal). Reverted: the
// broadcast booking is undone (hot(source) -> rebal) and the move ends failed, so the planner may plan another. Either way the fee is
// booked against the source. One transaction, ledger IDs derived from the move ID: a repeat changes nothing.
func (s *Service) SettleRebalance(ctx context.Context, id, txHash string, status chain.TxStatus) error {
	fee, err := s.Chain.TxFee(ctx, txHash)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanRebal(tx.QueryRow(ctx, `SELECT `+rebalCols+` FROM rebalance_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.Status == "confirmed" || m.Status == "failed" {
			return nil
		}
		if err := s.recordRebalBroadcastTx(ctx, tx, m, txHash); err != nil { // crash between broadcast and its record
			return err
		}
		final, evt, reason := "confirmed", "rebalance.confirmed", ""
		if status == chain.TxConfirmed {
			if err := s.transfer(ctx, tx, "rb-arrive:"+id, hotAcct(m.ToPartitionID), rebalAcct(s.Cfg.Chain, m.Asset), m.Amount,
				map[string]any{"rebalance": id, "tx": txHash}); err != nil {
				return err
			}
		} else {
			final, evt, reason = "failed", "rebalance.failed", "transaction reverted"
			if err := s.transfer(ctx, tx, "rb-back:"+id, hotAcct(m.PartitionID), rebalAcct(s.Cfg.Chain, m.Asset), m.Amount,
				map[string]any{"rebalance": id, "tx": txHash}); err != nil {
				return err
			}
		}
		if err := s.recordFee(ctx, tx, txHash, m.PartitionID, fee); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE rebalance_moves SET status=$2, fee=$3::numeric, failure_reason=NULLIF($4,''), updated_at=now() WHERE id=$1`,
			id, final, fee.String(), reason); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, evt, map[string]any{"chain": s.Cfg.Chain, "asset": m.Asset, "from": m.PartitionID,
			"to_partition": m.ToPartitionID, "amount": m.Amount.String(), "tx": txHash, "fee": fee.String()})
	})
}

// FailRebalanceBeforeBroadcast ends a rebalance whose job was refused or failed twice, after its nonce was freed by a confirmed
// cancel. Nothing was booked for the move, so there is nothing to reverse; the planner may plan it again. The cancel paid gas from the source shard, so
// its fee (feeTx, if any) is booked (see VoidWithdrawal).
func (s *Service) FailRebalanceBeforeBroadcast(ctx context.Context, id, reason, feeTx string) error {
	fee, err := s.cancelFee(ctx, feeTx)
	if err != nil {
		return err
	}
	o := Owner{Kind: OwnerKindRebalance, ID: id}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		open, err := s.ReservationOpen(ctx, tx, o)
		if err != nil {
			return err
		}
		if open {
			return ErrReservationOpen
		}
		fs := ""
		if fee != nil {
			fs = fee.String()
		}
		var part string
		err = tx.QueryRow(ctx, `UPDATE rebalance_moves SET status='failed', failure_reason=$2, fee=NULLIF($3,'')::numeric, updated_at=now() WHERE id=$1 AND status IN ('planned','signing') RETURNING partition_id`,
			id, reason, fs).Scan(&part)
		if isNoRows(err) {
			return nil // already ended: a repeat books nothing
		}
		if err != nil {
			return err
		}
		if err := s.recordFee(ctx, tx, feeTx, part, fee); err != nil { // the cancel paid gas from the shard's address
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, "rebalance.failed", map[string]any{"reason": reason})
	})
}

// ParkRebalance records that the move needs a person (see ParkWithdrawal).
func (s *Service) ParkRebalance(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE rebalance_moves SET failure_reason=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('confirmed','failed')`, id, ParkedPrefix+" "+reason)
	return err
}
