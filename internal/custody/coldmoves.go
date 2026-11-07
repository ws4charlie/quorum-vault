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

// OwnerKindToCold is the owner kind (nonce owner, sign-job track, intent kind) of a hot-to-cold move.
const OwnerKindToCold = "to-cold"

// A cold move takes the excess of a hot partition to the cold address. It is a transfer out of a hot address, like a
// withdrawal, with a destination that only the signing zone's config can name, and it is booked through a clearing account,
// like a sweep:
//
//	broadcast  tocold -> hot    (the funds are on their way: hot goes down, tocold holds minus the amount)
//	confirmed  cold  -> tocold  (they arrived: cold holds minus the on-chain cold balance, tocold is back to zero)
//	reverted   hot -> tocold    (the broadcast booking is undone; only the fee stays)
//
// plus the network fee: fee -> hot, as everywhere. No human approves a move: it can only make funds safer.

// ColdMove is a row of cold_moves.
type ColdMove struct {
	ID          string
	Asset       string
	PartitionID string
	To          string
	Amount      *big.Int
	Status      string
	TxHash      string
	JobID       string
	Reason      string
}

// Parked reports whether the move needs an operator.
func (m ColdMove) Parked() bool { return strings.HasPrefix(m.Reason, ParkedPrefix) }

// Owner returns the move as a transaction owner.
func (m ColdMove) Owner() Owner {
	return Owner{Kind: OwnerKindToCold, ID: m.ID, PartitionID: m.PartitionID}
}

const coldCols = `id, asset, partition_id, to_address, amount::text, status, COALESCE(tx_hash,''), COALESCE(job_id,''), COALESCE(failure_reason,'')`

func scanCold(row pgx.Row) (ColdMove, error) {
	var m ColdMove
	var amt string
	if err := row.Scan(&m.ID, &m.Asset, &m.PartitionID, &m.To, &amt, &m.Status, &m.TxHash, &m.JobID, &m.Reason); err != nil {
		return m, err
	}
	m.Amount = parseBig(amt)
	return m, nil
}

// GetColdMove reads one move.
func (s *Service) GetColdMove(ctx context.Context, id string) (ColdMove, error) {
	m, err := scanCold(s.Pool.QueryRow(ctx, `SELECT `+coldCols+` FROM cold_moves WHERE id=$1`, id))
	if isNoRows(err) {
		return m, fmt.Errorf("%w: cold move %s", ErrNotFound, id)
	}
	return m, err
}

// OpenColdMoves lists moves that are not finished and not parked.
func (s *Service) OpenColdMoves(ctx context.Context) ([]ColdMove, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+coldCols+` FROM cold_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed')
		AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' ORDER BY created_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ColdMove
	for rows.Next() {
		m, err := scanCold(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PlanColdMoves looks at every hot partition that has limits and creates a move for each one above its high-water mark. What
// a move may take is the hot balance minus the liquidity that open withdrawals have reserved on that partition, so a move
// never takes money a withdrawal is counting on; it brings that free amount down to the target. Below the low-water mark it
// logs an ALERT once and not again until the balance has been back above the mark. It returns the moves it created.
func (s *Service) PlanColdMoves(ctx context.Context, log *slog.Logger) ([]ColdMove, error) {
	c := s.Cfg
	if len(c.ColdLimits) == 0 {
		return nil, nil
	}
	parts := make([]string, 0, len(c.ColdLimits))
	for p := range c.ColdLimits {
		parts = append(parts, p)
	}
	sort.Strings(parts)
	var created []ColdMove
	for _, p := range parts {
		lim := c.ColdLimits[p]
		var mv *ColdMove
		err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			mv = nil
			// Serialize with withdrawal reservations on this partition.
			var asset string
			if err := tx.QueryRow(ctx, `SELECT asset FROM partitions WHERE id=$1 FOR UPDATE`, p).Scan(&asset); err != nil {
				return err
			}
			var open bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cold_moves WHERE partition_id=$1 AND status NOT IN ('confirmed','failed'))`, p).Scan(&open); err != nil {
				return err
			}
			free, err := s.freeHot(ctx, tx, p)
			if err != nil {
				return err
			}
			// A rebalance on its way to this shard counts as its liquidity for the low-water mark (no refill ceremony for a shard
			// that is being fed), but not for the high-water mark: funds that have not arrived cannot be moved on.
			incoming, err := s.incomingRebalance(ctx, tx, p)
			if err != nil {
				return err
			}
			withIncoming := new(big.Int).Add(free, incoming)
			var alerted bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM hot_low_alerts WHERE partition_id=$1)`, p).Scan(&alerted); err != nil {
				return err
			}
			switch {
			case withIncoming.Cmp(lim.Low) < 0:
				// Ask for a refill (one open at a time per cold address), and say so in the ALERT, once per outage.
				need := new(big.Int).Sub(lim.Target, withIncoming)
				rid, opened, err := s.openRefill(ctx, tx, p, asset, need)
				if err != nil {
					return err
				}
				if !alerted {
					if _, err := tx.Exec(ctx, `INSERT INTO hot_low_alerts (partition_id) VALUES ($1) ON CONFLICT DO NOTHING`, p); err != nil {
						return err
					}
					note := "refill request opened"
					if rid == "" {
						note = "the cold address holds no available output to refill from"
					} else if !opened {
						note = "a refill is already open for this cold address and must finish first"
					}
					log.Error("ALERT: hot wallet is below its low-water mark; it needs a refill from cold storage, which takes an offline ceremony",
						"partition", p, "free", free.String(), "low", lim.Low.String(), "target", lim.Target.String(), "refill", rid, "note", note)
				}
			case alerted:
				if _, err := tx.Exec(ctx, `DELETE FROM hot_low_alerts WHERE partition_id=$1`, p); err != nil {
					return err
				}
			}
			if open || free.Cmp(lim.High) <= 0 {
				return nil
			}
			amt := new(big.Int).Sub(free, lim.Target)
			if amt.Sign() <= 0 {
				return nil
			}
			toAddr, err := c.ColdAddressOf(p, asset)
			if err != nil {
				return err
			}
			if mc, ok := s.Chain.(chain.MoveCapacity); ok {
				// One transaction carries at most max_inputs outputs: a bigger excess moves in rounds, each round what the oldest available
				// outputs can carry. Reserved outputs are not counted, so a move never competes with a withdrawal for one.
				capAmt, err := mc.MaxMove(ctx, p)
				if err != nil {
					return err
				}
				if capAmt.Sign() <= 0 {
					return nil // nothing available to move yet: wait, and open no move
				}
				if capAmt.Cmp(amt) < 0 {
					amt = capAmt
				}
			}
			id := "cm-" + uuid.NewString()
			tag, err := tx.Exec(ctx, `INSERT INTO cold_moves (id, chain, asset, partition_id, to_address, amount, status)
				VALUES ($1,$2,$3,$4,$5,$6::numeric,'planned') ON CONFLICT DO NOTHING`, id, c.Chain, asset, p, toAddr, amt.String())
			if err != nil {
				return fmt.Errorf("custody: insert cold move: %w", err)
			}
			if tag.RowsAffected() == 1 {
				mv = &ColdMove{ID: id, Asset: asset, PartitionID: p, To: toAddr, Amount: amt, Status: "planned"}
				return emit(ctx, tx, outbox.TopicColdMoves, id, "cold_move.planned",
					map[string]any{"chain": c.Chain, "asset": asset, "partition": p, "to": toAddr, "amount": amt.String()})
			}
			return nil
		})
		if err != nil {
			return created, err
		}
		if mv != nil {
			created = append(created, *mv)
		}
	}
	return created, nil
}

// BuildColdMoveJob builds the transfer (allocating the hot address's nonce) and enqueues its sign job, in one transaction.
// Repeating it after a crash returns the existing job. The intent carries no approvals: the destination is pinned in the
// signing zone.
func (s *Service) BuildColdMoveJob(ctx context.Context, id string) (string, error) {
	jobID := OwnerTrack(Owner{Kind: OwnerKindToCold, ID: id}).FirstJob()
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanCold(tx.QueryRow(ctx, `SELECT `+coldCols+` FROM cold_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.JobID != "" || m.Status != "planned" {
			return nil
		}
		u, err := s.Chain.BuildWithdrawal(ctx, tx, chain.WithdrawalIntent{OwnerKind: OwnerKindToCold, ID: id, PartitionID: m.PartitionID,
			Asset: m.Asset, To: m.To, Amount: m.Amount})
		if err != nil {
			return err
		}
		ib, err := json.Marshal(signjob.Intent{Kind: OwnerKindToCold, ID: id, PartitionID: m.PartitionID, Chain: s.Cfg.Chain, Asset: m.Asset,
			To: m.To, Amount: m.Amount.String()})
		if err != nil {
			return err
		}
		if err := EnqueueUnsigned(ctx, tx, jobID, m.PartitionID, u, ib, nil); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE cold_moves SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, id, jobID)
		return err
	})
	return jobID, err
}

// RecordColdMoveBroadcast stores the hash and books the funds as on their way: tocold -> hot. Repeating it changes nothing.
func (s *Service) RecordColdMoveBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanCold(tx.QueryRow(ctx, `SELECT `+coldCols+` FROM cold_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		return s.recordColdBroadcastTx(ctx, tx, m, txHash)
	})
}

func (s *Service) recordColdBroadcastTx(ctx context.Context, tx pgx.Tx, m ColdMove, txHash string) error {
	if m.Status == "confirmed" || m.Status == "failed" || m.Status == "broadcast" {
		return nil
	}
	if err := s.transfer(ctx, tx, "cm-bcast:"+m.ID, toColdAcct(s.Cfg.Chain, m.Asset), hotAcct(m.PartitionID), m.Amount,
		map[string]any{"cold_move": m.ID, "tx": txHash}); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE cold_moves SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1`, m.ID, txHash); err != nil {
		return err
	}
	return emit(ctx, tx, outbox.TopicColdMoves, m.ID, "cold_move.broadcast",
		map[string]any{"chain": s.Cfg.Chain, "asset": m.Asset, "partition": m.PartitionID, "amount": m.Amount.String(), "tx": txHash})
}

// SettleColdMove books a mined move. Confirmed: the funds are in cold (cold -> tocold). Reverted: the broadcast booking is
// undone (hot -> tocold) and the move ends failed, so the planner may plan another. Either way the fee is booked. Everything is one
// transaction with ledger IDs derived from the move ID, so a repeat changes nothing.
func (s *Service) SettleColdMove(ctx context.Context, id, txHash string, status chain.TxStatus) error {
	fee, err := s.Chain.TxFee(ctx, txHash)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanCold(tx.QueryRow(ctx, `SELECT `+coldCols+` FROM cold_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.Status == "confirmed" || m.Status == "failed" {
			return nil
		}
		if err := s.recordColdBroadcastTx(ctx, tx, m, txHash); err != nil { // crash between broadcast and its record
			return err
		}
		final, evt, reason := "confirmed", "cold_move.confirmed", ""
		if st, ok := s.Chain.(chain.Settler); ok {
			// The cell's own books: the inputs of the confirmed transaction are spent and its change is an available output. On Bitcoin the
			// only "failed" settlement is a confirmed cancel of the move (the same inputs back to the shard): its output is settled the same way.
			if err := st.Settle(ctx, tx, OwnerKindToCold, id, txHash); err != nil {
				return err
			}
		}
		if status == chain.TxConfirmed {
			if err := s.transfer(ctx, tx, "cm-cold:"+id, coldAcct(m.PartitionID), toColdAcct(s.Cfg.Chain, m.Asset), m.Amount,
				map[string]any{"cold_move": id, "tx": txHash}); err != nil {
				return err
			}
		} else {
			final, evt, reason = "failed", "cold_move.failed", "transaction reverted"
			if _, ok := s.Chain.(chain.Settler); ok {
				reason = "cancelled: the move never confirmed, a cancel returned the inputs to the shard"
			}
			if err := s.transfer(ctx, tx, "cm-back:"+id, hotAcct(m.PartitionID), toColdAcct(s.Cfg.Chain, m.Asset), m.Amount,
				map[string]any{"cold_move": id, "tx": txHash}); err != nil {
				return err
			}
		}
		if err := s.recordFee(ctx, tx, txHash, m.PartitionID, fee); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE cold_moves SET status=$2, fee=$3::numeric, failure_reason=NULLIF($4,''), updated_at=now() WHERE id=$1`,
			id, final, fee.String(), reason); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, evt, map[string]any{"chain": s.Cfg.Chain, "asset": m.Asset, "partition": m.PartitionID,
			"amount": m.Amount.String(), "tx": txHash, "fee": fee.String()})
	})
}

// FailColdMoveBeforeBroadcast ends a move whose job was refused or failed twice, after its nonce was freed by a confirmed
// cancel. Nothing was booked for the move, so there is nothing to reverse; the planner may plan the move again. The cancel paid gas, so its fee
// (feeTx, if any) is booked (see VoidWithdrawal).
func (s *Service) FailColdMoveBeforeBroadcast(ctx context.Context, id, reason, feeTx string) error {
	fee, err := s.cancelFee(ctx, feeTx)
	if err != nil {
		return err
	}
	o := Owner{Kind: OwnerKindToCold, ID: id}
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
		err = tx.QueryRow(ctx, `UPDATE cold_moves SET status='failed', failure_reason=$2, fee=NULLIF($3,'')::numeric, updated_at=now() WHERE id=$1 AND status IN ('planned','signing') RETURNING partition_id`,
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
		return emit(ctx, tx, outbox.TopicColdMoves, id, "cold_move.failed", map[string]any{"reason": reason})
	})
}

// ParkColdMove records that the move needs a person (see ParkWithdrawal).
func (s *Service) ParkColdMove(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE cold_moves SET failure_reason=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('confirmed','failed')`, id, ParkedPrefix+" "+reason)
	return err
}
