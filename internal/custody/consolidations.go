package custody

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// OwnerKindConsolidate is the owner kind (attempt owner, sign-job track, intent kind) of a Bitcoin consolidation.
const OwnerKindConsolidate = "consolidate"

// A consolidation merges the smallest available outputs of one hot shard into a single output back to the same shard, so that a shard fed by many
// small outputs stays spendable within max_inputs. The value does not move, so the ledger books nothing at broadcast and only the network fee at
// settlement (fee -> hot, as everywhere). It needs no approval: the signing zone refuses anything but the shard's own outputs going back to the shard.

// Consolidation is a row of consolidations.
type Consolidation struct {
	ID          string
	Asset       string
	PartitionID string
	Amount      *big.Int // the sum of the inputs
	Status      string
	TxHash      string
	JobID       string
	Reason      string
}

// Parked reports whether the consolidation needs an operator.
func (m Consolidation) Parked() bool { return strings.HasPrefix(m.Reason, ParkedPrefix) }

// Owner returns the consolidation as a transaction owner.
func (m Consolidation) Owner() Owner {
	return Owner{Kind: OwnerKindConsolidate, ID: m.ID, PartitionID: m.PartitionID}
}

const consolCols = `id, asset, partition_id, amount::text, status, COALESCE(tx_hash,''), COALESCE(job_id,''), COALESCE(failure_reason,'')`

func scanConsolidation(row pgx.Row) (Consolidation, error) {
	var m Consolidation
	var amt string
	if err := row.Scan(&m.ID, &m.Asset, &m.PartitionID, &amt, &m.Status, &m.TxHash, &m.JobID, &m.Reason); err != nil {
		return m, err
	}
	m.Amount = parseBig(amt)
	return m, nil
}

// GetConsolidation reads one consolidation.
func (s *Service) GetConsolidation(ctx context.Context, id string) (Consolidation, error) {
	m, err := scanConsolidation(s.Pool.QueryRow(ctx, `SELECT `+consolCols+` FROM consolidations WHERE id=$1`, id))
	if isNoRows(err) {
		return m, fmt.Errorf("%w: consolidation %s", ErrNotFound, id)
	}
	return m, err
}

// OpenConsolidations lists consolidations that are not finished and not parked.
func (s *Service) OpenConsolidations(ctx context.Context) ([]Consolidation, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+consolCols+` FROM consolidations WHERE chain=$1 AND status NOT IN ('confirmed','failed')
		AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' ORDER BY created_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Consolidation
	for rows.Next() {
		m, err := scanConsolidation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// consolidationBackoff reports whether the partition is being left alone after failed consolidations: one the gateway refuses every time (its hourly
// limit, say) would otherwise be planned, refused and released at every pass. The wait starts at retry_after and doubles for each failure in a row, up
// to an hour; one that confirmed ends it.
func (s *Service) consolidationBackoff(ctx context.Context, partitionID string) (bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT status, EXTRACT(EPOCH FROM (now() - updated_at)) FROM consolidations WHERE chain=$1 AND partition_id=$2
		ORDER BY created_at DESC LIMIT 12`, s.Cfg.Chain, partitionID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	n := 0
	var age float64
	for rows.Next() {
		var st string
		var a float64
		if err := rows.Scan(&st, &a); err != nil {
			return false, err
		}
		if st != "failed" {
			break
		}
		if n == 0 {
			age = a
		}
		n++
	}
	if n == 0 {
		return false, rows.Err()
	}
	wait := s.Cfg.SweepRetryAfter
	for i := 1; i < n && wait < time.Hour; i++ {
		wait *= 2
	}
	return time.Duration(age*float64(time.Second)) < min(wait, time.Hour), rows.Err()
}

// PlanConsolidations looks at every hot partition of a chain that can consolidate (consolidate_above is set) and creates a consolidation for each one
// the chain says has something worth merging: more available outputs than the threshold, a fee rate at or below the ceiling, at least two outputs worth
// spending. It starts none on a partition that has a consolidation or a hot-to-cold move open (that move is already spending its outputs), and none while
// scanning is halted (the books cannot be trusted then). It returns the consolidations it created.
func (s *Service) PlanConsolidations(ctx context.Context, log *slog.Logger) ([]Consolidation, error) {
	c := s.Cfg
	cons, ok := s.Chain.(chain.Consolidator)
	if !ok || c.Family != FamilyBTC || c.BTC.ConsolidateAbove <= 0 {
		return nil, nil
	}
	if halted, _, err := s.ScanHalted(ctx); err != nil || halted {
		return nil, err
	}
	var created []Consolidation
	for i := range c.BTC.HotShards {
		p := c.PartitionKey(c.Native, i).String()
		if back, err := s.consolidationBackoff(ctx, p); err != nil {
			return created, err
		} else if back {
			continue
		}
		var busy bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM consolidations WHERE partition_id=$1 AND status NOT IN ('confirmed','failed'))
			OR EXISTS (SELECT 1 FROM cold_moves WHERE partition_id=$1 AND status NOT IN ('confirmed','failed'))`, p).Scan(&busy); err != nil {
			return created, err
		}
		if busy {
			continue
		}
		plan, err := cons.PlanConsolidation(ctx, p)
		if err != nil {
			log.Warn("consolidation plan failed; skipping", "partition", p, "error", err.Error())
			continue
		}
		if plan.Wait != "" || plan.Amount == nil || plan.Amount.Sign() <= 0 || plan.Inputs < 2 {
			continue
		}
		var mv *Consolidation
		err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			mv = nil
			// Serialize with withdrawal reservations and the cold planner on this partition, and look again under the lock.
			var asset string
			if err := tx.QueryRow(ctx, `SELECT asset FROM partitions WHERE id=$1 FOR UPDATE`, p).Scan(&asset); err != nil {
				return err
			}
			var open bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM consolidations WHERE partition_id=$1 AND status NOT IN ('confirmed','failed'))
				OR EXISTS (SELECT 1 FROM cold_moves WHERE partition_id=$1 AND status NOT IN ('confirmed','failed'))`, p).Scan(&open); err != nil {
				return err
			}
			if open {
				return nil
			}
			id := "co-" + uuid.NewString()
			tag, err := tx.Exec(ctx, `INSERT INTO consolidations (id, chain, asset, partition_id, amount, status)
				VALUES ($1,$2,$3,$4,$5::numeric,'planned') ON CONFLICT DO NOTHING`, id, c.Chain, asset, p, plan.Amount.String())
			if err != nil {
				return fmt.Errorf("custody: insert consolidation: %w", err)
			}
			if tag.RowsAffected() == 1 {
				mv = &Consolidation{ID: id, Asset: asset, PartitionID: p, Amount: plan.Amount, Status: "planned"}
				return emit(ctx, tx, outbox.TopicColdMoves, id, "consolidation.planned",
					map[string]any{"chain": c.Chain, "asset": asset, "partition": p, "amount": plan.Amount.String(), "inputs": plan.Inputs})
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

// BuildConsolidationJob builds the transaction (reserving the partition's smallest outputs) and enqueues its sign job, in one transaction. Repeating it
// after a crash returns the existing job. The intent carries no approvals: the signing zone pins the shape.
func (s *Service) BuildConsolidationJob(ctx context.Context, id string) (string, error) {
	jobID := OwnerTrack(Owner{Kind: OwnerKindConsolidate, ID: id}).FirstJob()
	cons, ok := s.Chain.(chain.Consolidator)
	if !ok {
		return "", fmt.Errorf("custody: chain %s cannot consolidate", s.Cfg.Chain)
	}
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanConsolidation(tx.QueryRow(ctx, `SELECT `+consolCols+` FROM consolidations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.JobID != "" || m.Status != "planned" {
			return nil
		}
		to, err := s.Cfg.BTCShardAddress(m.PartitionID)
		if err != nil {
			return err
		}
		u, err := cons.BuildConsolidation(ctx, tx, chain.ConsolidateIntent{ID: id, PartitionID: m.PartitionID, Amount: m.Amount})
		if err != nil {
			return err
		}
		ib, err := json.Marshal(signjob.Intent{Kind: OwnerKindConsolidate, ID: id, PartitionID: m.PartitionID, Chain: s.Cfg.Chain, Asset: m.Asset,
			To: to, Amount: m.Amount.String()})
		if err != nil {
			return err
		}
		if err := EnqueueUnsigned(ctx, tx, jobID, m.PartitionID, u, ib, nil); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE consolidations SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, id, jobID)
		return err
	})
	return jobID, err
}

// RecordConsolidationBroadcast stores the hash. Nothing is booked: the value stays on the shard. Repeating it changes nothing.
func (s *Service) RecordConsolidationBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanConsolidation(tx.QueryRow(ctx, `SELECT `+consolCols+` FROM consolidations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.Status == "confirmed" || m.Status == "failed" || m.Status == "broadcast" {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE consolidations SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1`, id, txHash); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, "consolidation.broadcast",
			map[string]any{"chain": s.Cfg.Chain, "asset": m.Asset, "partition": m.PartitionID, "amount": m.Amount.String(), "tx": txHash})
	})
}

// SettleConsolidation books a mined consolidation, or a confirmed cancel of it (the same inputs back to the shard in one output, which is the same
// shape): the chain cell turns the inputs into spent and the output into an available hot row, and the fee is booked from the hot account to the fee
// account. Everything is one transaction with ledger IDs derived from the transaction, so a repeat changes nothing.
func (s *Service) SettleConsolidation(ctx context.Context, id, txHash string) error {
	fee, err := s.Chain.TxFee(ctx, txHash)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanConsolidation(tx.QueryRow(ctx, `SELECT `+consolCols+` FROM consolidations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.Status == "confirmed" || m.Status == "failed" {
			return nil
		}
		if st, ok := s.Chain.(chain.Settler); ok {
			if err := st.Settle(ctx, tx, OwnerKindConsolidate, id, txHash); err != nil {
				return err
			}
		}
		if err := s.recordFee(ctx, tx, txHash, m.PartitionID, fee); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE consolidations SET status='confirmed', tx_hash=$2, fee=$3::numeric, updated_at=now() WHERE id=$1`, id, txHash, fee.String()); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, "consolidation.confirmed", map[string]any{"chain": s.Cfg.Chain, "asset": m.Asset,
			"partition": m.PartitionID, "amount": m.Amount.String(), "tx": txHash, "fee": fee.String()})
	})
}

// FailConsolidationBeforeBroadcast ends a consolidation whose job was refused or failed twice, or that could not be built, after its outputs were
// released. Nothing was booked, so there is nothing to reverse; the planner may plan another after a wait.
func (s *Service) FailConsolidationBeforeBroadcast(ctx context.Context, id, reason string) error {
	o := Owner{Kind: OwnerKindConsolidate, ID: id}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		open, err := s.ReservationOpen(ctx, tx, o)
		if err != nil {
			return err
		}
		if open {
			return ErrReservationOpen
		}
		tag, err := tx.Exec(ctx, `UPDATE consolidations SET status='failed', failure_reason=$2, updated_at=now() WHERE id=$1 AND status IN ('planned','signing')`, id, reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, "consolidation.failed", map[string]any{"reason": reason})
	})
}

// ParkConsolidation records that the consolidation needs a person (see ParkWithdrawal).
func (s *Service) ParkConsolidation(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE consolidations SET failure_reason=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('confirmed','failed')`, id, ParkedPrefix+" "+reason)
	return err
}
