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

// OwnerKindBatch is the owner kind (attempt owner, sign-job track, reserved-output owner) of a Bitcoin batch of withdrawals.
const OwnerKindBatch = "batch"

// Batch statuses (btc_batches.status).
const (
	BatchSealed    = "sealed"    // members chosen, no coins yet
	BatchSigning   = "signing"   // built: coins reserved, sign jobs enqueued
	BatchBroadcast = "broadcast" // an attempt was sent
	BatchConfirmed = "confirmed" // an attempt confirmed: every member is booked
	BatchCancelled = "cancelled" // a cancel of the whole batch confirmed: the members are back in the queue
	BatchDiscarded = "discarded" // nothing was signed: the coins were released and the members are back in the queue
)

// refusalsToPark is how many batches the signing zone may refuse with the same withdrawal in them, none of them naming it, before it is parked.
const refusalsToPark = 3

// Batch is a row of btc_batches: one transaction paying several withdrawals of one hot shard.
type Batch struct {
	ID              string
	PartitionID     string
	Status          string
	JobID           string
	TxHash          string
	CancelTx        string
	ResendHeld      bool
	CancelRequested bool
	Fee             *big.Int
	Reason          string
}

// BatchItem is one member of a batch: output Vout of its transaction.
type BatchItem struct {
	WithdrawalID string
	Position     int
	Vout         int
	Amount       *big.Int
	FeeShare     *big.Int
	ResendOf     string
}

// Owner returns the batch as a transaction owner.
func (b Batch) Owner() Owner {
	return Owner{Kind: OwnerKindBatch, ID: b.ID, PartitionID: b.PartitionID}
}

// Parked reports whether the batch needs an operator.
func (b Batch) Parked() bool { return strings.HasPrefix(b.Reason, ParkedPrefix) }

const batchCols = `id, partition_id, status, COALESCE(job_id,''), COALESCE(tx_hash,''), COALESCE(cancel_tx,''), resend_held, cancel_requested, COALESCE(fee::text,''), COALESCE(reason,'')`

func scanBatch(row pgx.Row) (Batch, error) {
	var b Batch
	var fee string
	if err := row.Scan(&b.ID, &b.PartitionID, &b.Status, &b.JobID, &b.TxHash, &b.CancelTx, &b.ResendHeld, &b.CancelRequested, &fee, &b.Reason); err != nil {
		return b, err
	}
	if fee != "" {
		b.Fee = parseBig(fee)
	}
	return b, nil
}

// GetBatch reads one batch.
func (s *Service) GetBatch(ctx context.Context, id string) (Batch, error) {
	b, err := scanBatch(s.Pool.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1`, id))
	if isNoRows(err) {
		return b, fmt.Errorf("%w: batch %s", ErrNotFound, id)
	}
	return b, err
}

// BatchItems lists the members of a batch in payment order.
func (s *Service) BatchItems(ctx context.Context, id string) ([]BatchItem, error) {
	return batchItems(ctx, s.Pool, id)
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func batchItems(ctx context.Context, q querier, id string) ([]BatchItem, error) {
	rows, err := q.Query(ctx, `SELECT withdrawal_id, position, vout, amount::text, COALESCE(fee_share::text,''), COALESCE(resend_of,'') FROM btc_batch_items WHERE batch_id=$1 ORDER BY position`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BatchItem
	for rows.Next() {
		var it BatchItem
		var amt, share string
		if err := rows.Scan(&it.WithdrawalID, &it.Position, &it.Vout, &amt, &share, &it.ResendOf); err != nil {
			return nil, err
		}
		it.Amount = parseBig(amt)
		if share != "" {
			it.FeeShare = parseBig(share)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// OpenBatches lists the batches that are not finished and not parked.
func (s *Service) OpenBatches(ctx context.Context) ([]Batch, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE chain=$1 AND status IN ('sealed','signing','broadcast')
		AND COALESCE(reason,'') NOT LIKE 'parked:%' ORDER BY sealed_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Batch
	for rows.Next() {
		b, err := scanBatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// batchMargin is how long before a withdrawal's not_after it is no longer put in a batch: the zone refuses a batch with a member that expired, and a
// batch needs time to be signed.
func (s *Service) batchMargin() time.Duration { return 2*s.Cfg.SignTimeout + 30*time.Second }

// Batched reports whether withdrawals of the partition go through the batch queue now.
func (s *Service) Batched(partitionID string) bool {
	if s.Cfg.Family != FamilyBTC || !s.Cfg.BatchingOf(partitionID).Active() {
		return false
	}
	_, ok := s.Chain.(chain.BatchBuilder)
	return ok
}

// EnqueueForBatch puts an approved withdrawal whose hot liquidity is reserved in the queue of its shard, at the time it is called (its place in the
// FIFO order, kept for good, also when its batch is cancelled). It reports false when the partition does not batch: the withdrawal then goes the
// single-transaction way. Repeating it changes nothing.
func (s *Service) EnqueueForBatch(ctx context.Context, id string) (bool, error) {
	queued := false
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		var part string
		var at *time.Time
		if err := tx.QueryRow(ctx, `SELECT partition_id, queued_at FROM withdrawals WHERE id=$1 FOR UPDATE`, id).Scan(&part, &at); err != nil {
			return err
		}
		if at != nil {
			queued = true
			return nil
		}
		if !s.Batched(part) {
			queued = false
			return nil
		}
		queued = true
		if _, err := tx.Exec(ctx, `UPDATE withdrawals SET queued_at=$2, updated_at=now() WHERE id=$1`, id, s.Now()); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "withdrawal.queued", map[string]any{"partition": part})
	})
	return queued, err
}

// QueueTick is one look of a queued withdrawal's workflow: it voids the withdrawal if it is still waiting in the queue and its approval is about to
// lapse (a batch would need more time than is left), and returns where the withdrawal stands.
type QueueState struct {
	Status  string
	Parked  bool
	Queued  bool // queued_at is set: the withdrawal belongs to the batch queue
	InBatch string
}

// QueueTick reads the state, voiding a queued withdrawal whose approval is about to lapse.
func (s *Service) QueueTick(ctx context.Context, id string) (QueueState, error) {
	w, err := s.GetWithdrawal(ctx, id)
	if err != nil {
		return QueueState{}, err
	}
	if w.Status != WdConfirmed && w.Status != WdFailed && !w.Parked() && w.BatchID == "" && s.Now().Add(s.batchMargin()).Unix() >= w.NotAfter {
		if err := s.VoidWithdrawal(ctx, id, "approval window passed before the withdrawal was in a batch", ""); err != nil {
			return QueueState{}, err
		}
		if w, err = s.GetWithdrawal(ctx, id); err != nil {
			return QueueState{}, err
		}
	}
	var queued bool
	if err := s.Pool.QueryRow(ctx, `SELECT queued_at IS NOT NULL FROM withdrawals WHERE id=$1`, id).Scan(&queued); err != nil {
		return QueueState{}, err
	}
	return QueueState{Status: w.Status, Parked: w.Parked(), Queued: queued, InBatch: w.BatchID}, nil
}

type queued struct {
	id       string
	resendOf string
}

// PlanBatches seals a batch on every Bitcoin hot shard that batches and is due. A shard's queue is its approved withdrawals not in a batch, oldest
// approval first (then id). A batch seals when the oldest has waited max_wait, or max_outputs are queued, whichever comes first, if the shard has
// fewer than max_in_flight batches sealed or signed and not yet confirmed or cancelled. Its members are the head of the queue, in order, never skipping
// one; withdrawals that were in a cancelled batch stay together. The same queue at the same time always gives the same batch. It also gives back the
// held output of a cancelled batch that none of its members needs any more. It returns the batches it sealed.
func (s *Service) PlanBatches(ctx context.Context, log *slog.Logger) ([]Batch, error) {
	c := s.Cfg
	if c.Family != FamilyBTC {
		return nil, nil
	}
	bb, ok := s.Chain.(chain.BatchBuilder)
	if !ok {
		return nil, nil
	}
	if halted, _, err := s.ScanHalted(ctx); err != nil || halted {
		return nil, err
	}
	var sealed []Batch
	for i := range c.BTC.HotShards {
		p := c.PartitionKey(c.Native, i).String()
		cfg := c.BatchingOf(p)
		if !cfg.Enabled {
			continue
		}
		if err := s.releaseOrphanHolds(ctx, bb, p); err != nil {
			return sealed, err
		}
		if !cfg.Active() {
			continue
		}
		var b *Batch
		err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			b = nil
			// Serialize with the other planners and the hot reservations of this partition.
			var asset string
			if err := tx.QueryRow(ctx, `SELECT asset FROM partitions WHERE id=$1 FOR UPDATE`, p).Scan(&asset); err != nil {
				return err
			}
			var inFlight int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM btc_batches WHERE chain=$1 AND partition_id=$2 AND status IN ('sealed','signing','broadcast')`, c.Chain, p).Scan(&inFlight); err != nil {
				return err
			}
			if inFlight >= cfg.MaxInFlight {
				return nil
			}
			now := s.Now()
			lastOK := now.Add(s.batchMargin()).Unix()
			where := `chain=$1 AND partition_id=$2 AND queued_at IS NOT NULL AND batch_id IS NULL AND status='approved'
				AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' AND COALESCE(not_after,0) > $3`
			var n int
			var oldest *time.Time
			if err := tx.QueryRow(ctx, `SELECT count(*), min(queued_at) FROM withdrawals WHERE `+where, c.Chain, p, lastOK).Scan(&n, &oldest); err != nil {
				return err
			}
			if n == 0 || oldest == nil {
				return nil
			}
			if n < cfg.MaxOutputs && oldest.Add(cfg.MaxWait).After(now) {
				return nil // not due: fewer than max_outputs, and the oldest has not waited max_wait
			}
			rows, err := tx.Query(ctx, `SELECT id, COALESCE(resend_of,'') FROM withdrawals WHERE `+where+` ORDER BY queued_at, id LIMIT $4 FOR UPDATE`, c.Chain, p, lastOK, cfg.MaxOutputs)
			if err != nil {
				return err
			}
			var q []queued
			for rows.Next() {
				var m queued
				if err := rows.Scan(&m.id, &m.resendOf); err != nil {
					rows.Close()
					return err
				}
				q = append(q, m)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			if q, err = s.keepGroupsWhole(ctx, tx, where, c.Chain, p, lastOK, q); err != nil {
				return err
			}
			// The core's destination rule, again, at seal time. A withdrawal it refuses leaves the queue, parked with an alert.
			var members []queued
			for _, m := range q {
				w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1`, m.id))
				if err != nil {
					return err
				}
				if why := s.screen(ctx, w); why != "" {
					log.Error("ALERT: a withdrawal failed the destination check when its batch was sealed; parked", "withdrawal", m.id, "why", why)
					if _, err := tx.Exec(ctx, `UPDATE withdrawals SET failure_reason=$2, updated_at=now() WHERE id=$1`, m.id, ParkedPrefix+" destination check at seal time: "+why); err != nil {
						return err
					}
					continue
				}
				members = append(members, m)
			}
			if len(members) == 0 {
				return nil
			}
			id := "bt-" + uuid.NewString()
			if _, err := tx.Exec(ctx, `INSERT INTO btc_batches (id, chain, partition_id, status, sealed_at) VALUES ($1,$2,$3,'sealed',$4)`, id, c.Chain, p, now); err != nil {
				return fmt.Errorf("custody: insert batch: %w", err)
			}
			for pos, m := range members {
				if _, err := tx.Exec(ctx, `INSERT INTO btc_batch_items (batch_id, withdrawal_id, position, vout, amount, resend_of)
					SELECT $1, id, $3, $3, amount, NULLIF(resend_of,'') FROM withdrawals WHERE id=$2`, id, m.id, pos); err != nil {
					return fmt.Errorf("custody: insert batch item: %w", err)
				}
				if _, err := tx.Exec(ctx, `UPDATE withdrawals SET batch_id=$2, updated_at=now() WHERE id=$1`, m.id, id); err != nil {
					return err
				}
			}
			b = &Batch{ID: id, PartitionID: p, Status: BatchSealed}
			return emit(ctx, tx, outbox.TopicWithdrawals, id, "batch.sealed", map[string]any{"chain": c.Chain, "partition": p, "members": len(members)})
		})
		if err != nil {
			return sealed, err
		}
		if b != nil {
			sealed = append(sealed, *b)
		}
	}
	return sealed, nil
}

// keepGroupsWhole trims the head of a queue so that it does not end inside the withdrawals of one cancelled batch (they share one output that only
// one batch can spend). If the very first group does not fit, it is taken whole.
func (s *Service) keepGroupsWhole(ctx context.Context, tx pgx.Tx, where, chainName, p string, lastOK int64, q []queued) ([]queued, error) {
	if len(q) == 0 || q[len(q)-1].resendOf == "" {
		return q, nil
	}
	g := q[len(q)-1].resendOf
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM withdrawals WHERE `+where+` AND resend_of=$4`, chainName, p, lastOK, g).Scan(&total); err != nil {
		return nil, err
	}
	have := 0
	for _, m := range q {
		if m.resendOf == g {
			have++
		}
	}
	if have == total {
		return q, nil
	}
	cut := len(q)
	for cut > 0 && q[cut-1].resendOf == g {
		cut--
	}
	if cut > 0 {
		return q[:cut], nil
	}
	rows, err := tx.Query(ctx, `SELECT id, COALESCE(resend_of,'') FROM withdrawals WHERE `+where+` AND resend_of=$4 ORDER BY queued_at, id FOR UPDATE`, chainName, p, lastOK, g)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []queued
	for rows.Next() {
		var m queued
		if err := rows.Scan(&m.id, &m.resendOf); err != nil {
			return nil, err
		}
		all = append(all, m)
	}
	return all, rows.Err()
}

// screen is the core's destination rule: the address is one of the network and the optional Service.Screen accepts the withdrawal. It returns why not.
func (s *Service) screen(ctx context.Context, w Withdrawal) string {
	if _, err := s.normalizeDestination(w.To); err != nil {
		return err.Error()
	}
	if s.Screen != nil {
		if err := s.Screen(ctx, w); err != nil {
			return err.Error()
		}
	}
	return ""
}

// releaseOrphanHolds gives back the output a cancelled batch held for its members when none of them is waiting for it any more (all were paid,
// voided or parked).
func (s *Service) releaseOrphanHolds(ctx context.Context, bb chain.BatchBuilder, partitionID string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT b.id FROM btc_batches b WHERE b.chain=$1 AND b.partition_id=$2 AND b.status='cancelled' AND b.resend_held
			AND NOT EXISTS (SELECT 1 FROM withdrawals w WHERE w.resend_of=b.id AND w.status NOT IN ('confirmed','failed')
				AND COALESCE(w.failure_reason,'') NOT LIKE 'parked:%') FOR UPDATE OF b`, s.Cfg.Chain, partitionID)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			if err := bb.ReleaseResend(ctx, tx, id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE btc_batches SET resend_held=false, updated_at=now() WHERE id=$1`, id); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

// PrepareBatch runs before a sealed batch is built: it takes out of the batch every member that can no longer go (its approval is about to lapse, or
// the core's destination rule refuses it now: parked with an alert), and discards the batch if none is left. It reports how many members remain.
func (s *Service) PrepareBatch(ctx context.Context, id string, log *slog.Logger) (int, error) {
	left := 0
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if b.Status != BatchSealed {
			left = -1
			return nil
		}
		items, err := batchItems(ctx, tx, id)
		if err != nil {
			return err
		}
		lastOK := s.Now().Add(s.batchMargin()).Unix()
		left = 0
		for _, it := range items {
			w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, it.WithdrawalID))
			if err != nil {
				return err
			}
			drop, why := false, ""
			if w.NotAfter <= lastOK {
				drop = true // it waits in the queue; its own workflow voids it
			} else if why = s.screen(ctx, w); why != "" {
				drop = true
				log.Error("ALERT: a withdrawal failed the destination check before its batch was signed; parked", "withdrawal", w.ID, "batch", id, "why", why)
				if _, err := tx.Exec(ctx, `UPDATE withdrawals SET failure_reason=$2, updated_at=now() WHERE id=$1`, w.ID, ParkedPrefix+" destination check before signing: "+why); err != nil {
					return err
				}
			}
			if drop {
				if _, err := tx.Exec(ctx, `UPDATE withdrawals SET batch_id=NULL, updated_at=now() WHERE id=$1`, w.ID); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `DELETE FROM btc_batch_items WHERE batch_id=$1 AND withdrawal_id=$2`, id, w.ID); err != nil {
					return err
				}
				continue
			}
			left++
		}
		if left == 0 {
			_, err := tx.Exec(ctx, `UPDATE btc_batches SET status='discarded', reason='no member left to pay', updated_at=now() WHERE id=$1`, id)
			return err
		}
		return nil
	})
	return left, err
}

// BuildBatchJob builds the sealed batch's transaction for the longest prefix of its members the shard's available outputs can fund (the rest go back to
// the queue) and enqueues its sign jobs, in one transaction. The sign job's intent is the batch: every member's own intent and approvals, in payment
// order. Repeating it after a crash returns the existing job. When not even the head can be funded it returns chain.ErrNotEnoughOutputs and changes nothing.
func (s *Service) BuildBatchJob(ctx context.Context, id string) (string, error) {
	jobID := OwnerTrack(Owner{Kind: OwnerKindBatch, ID: id}).FirstJob()
	bb, ok := s.Chain.(chain.BatchBuilder)
	if !ok {
		return "", fmt.Errorf("custody: chain %s cannot batch", s.Cfg.Chain)
	}
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if b.Status != BatchSealed {
			return nil
		}
		items, err := batchItems(ctx, tx, id)
		if err != nil {
			return err
		}
		var ws []Withdrawal
		var members []chain.BatchMember
		for _, it := range items {
			w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, it.WithdrawalID))
			if err != nil {
				return err
			}
			if !w.Amount.IsUint64() {
				return fmt.Errorf("custody: withdrawal %s: amount out of range", w.ID)
			}
			ws = append(ws, w)
			members = append(members, chain.BatchMember{ID: w.ID, To: w.To, Amount: w.Amount.Uint64(), ResendOf: it.ResendOf})
		}
		built, err := bb.BuildBatch(ctx, tx, id, b.PartitionID, members)
		if err != nil {
			return err
		}
		// The members behind the funded prefix go back to the queue, at their place.
		for i := built.Funded; i < len(ws); i++ {
			if _, err := tx.Exec(ctx, `UPDATE withdrawals SET batch_id=NULL, updated_at=now() WHERE id=$1`, ws[i].ID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM btc_batch_items WHERE batch_id=$1 AND withdrawal_id=$2`, id, ws[i].ID); err != nil {
				return err
			}
		}
		ws = ws[:built.Funded]
		batch := signjob.Batch{Kind: signjob.KindBatch, ID: id, PartitionID: b.PartitionID, Chain: s.Cfg.Chain, Asset: s.Cfg.Native}
		for i, w := range ws {
			batch.Members = append(batch.Members, signjob.BatchMember{Intent: s.IntentOf(w), Approvals: w.Approvals})
			if _, err := tx.Exec(ctx, `UPDATE btc_batch_items SET fee_share=$3::numeric WHERE batch_id=$1 AND withdrawal_id=$2`, id, w.ID, fmt.Sprint(built.FeeShares[i])); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE withdrawals SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, w.ID, jobID); err != nil {
				return err
			}
		}
		ib, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		if err := EnqueueUnsigned(ctx, tx, jobID, b.PartitionID, built.Tx, ib, nil); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE btc_batches SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, id, jobID); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "batch.signing", map[string]any{"job": jobID, "members": len(ws)})
	})
	return jobID, err
}

// RecordBatchBroadcast stores the hash of the first attempt that was sent and marks the batch and its members broadcast. Repeating it changes nothing.
func (s *Service) RecordBatchBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if b.Status != BatchSigning {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE btc_batches SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1`, id, txHash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE withdrawals SET status='broadcast', tx_hash=$2, updated_at=now() WHERE batch_id=$1 AND status='signing'`, id, txHash); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "batch.broadcast", map[string]any{"tx": txHash})
	})
}

// SettleBatch books a batch whose transaction confirmed: every member once, by its own output of the transaction (output i is member i), with its
// share of the real fee (the shares add up to the fee to the satoshi); the network fee is booked once; the cell's own books change (inputs spent, change
// available). All in one transaction with ledger IDs derived from the withdrawals and the hash, so a repeat changes nothing. txHash may be any attempt
// that confirmed: an earlier attempt, not the latest, books exactly the same way.
func (s *Service) SettleBatch(ctx context.Context, id, txHash string) error {
	fee, err := s.Chain.TxFee(ctx, txHash)
	if err != nil {
		return err
	}
	bb, ok := s.Chain.(chain.BatchBuilder)
	if !ok {
		return fmt.Errorf("custody: chain %s cannot batch", s.Cfg.Chain)
	}
	c := s.Cfg
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if b.Status == BatchConfirmed {
			return nil
		}
		items, err := batchItems(ctx, tx, id)
		if err != nil {
			return err
		}
		shares, err := bb.BatchShares(ctx, tx, id, txHash, len(items), fee.Uint64())
		if err != nil {
			return err
		}
		for i, it := range items {
			w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, it.WithdrawalID))
			if err != nil {
				return err
			}
			if w.Status == WdConfirmed {
				continue
			}
			if w.Status == WdFailed {
				return fmt.Errorf("custody: withdrawal %s was voided; its batch %s mined anyway (%s)", w.ID, id, txHash)
			}
			if err := s.Led.Post(ctx, tx, "wd-hold:"+w.ID, "wd-post:"+w.ID); err != nil {
				return err
			}
			if err := s.transfer(ctx, tx, "wd-out:"+w.ID, wdAcct(c.Chain, w.Asset), hotAcct(w.PartitionID), w.Amount,
				map[string]any{"withdrawal": w.ID, "tx": txHash, "batch": id, "vout": it.Vout}); err != nil {
				return err
			}
			share := new(big.Int).SetUint64(shares[i])
			if _, err := tx.Exec(ctx, `UPDATE btc_batch_items SET fee_share=$3::numeric WHERE batch_id=$1 AND withdrawal_id=$2`, id, w.ID, share.String()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE withdrawals SET status='confirmed', tx_hash=$2, fee=$3::numeric, hot_reserved=false, updated_at=now() WHERE id=$1`, w.ID, txHash, share.String()); err != nil {
				return err
			}
			if err := emit(ctx, tx, outbox.TopicWithdrawals, w.ID, "withdrawal.confirmed", map[string]any{
				"customer": w.Customer, "chain": c.Chain, "asset": w.Asset, "to": w.To, "amount": w.Amount.String(), "tx": txHash, "fee": share.String(),
				"batch": id, "vout": it.Vout}); err != nil {
				return err
			}
		}
		if err := s.recordFee(ctx, tx, txHash, b.PartitionID, fee); err != nil {
			return err
		}
		if st, ok := s.Chain.(chain.Settler); ok {
			if err := st.Settle(ctx, tx, OwnerKindBatch, id, txHash); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE btc_batches SET status='confirmed', tx_hash=$2, fee=$3::numeric, updated_at=now() WHERE id=$1`, id, txHash, fee.String()); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "batch.confirmed", map[string]any{"tx": txHash, "fee": fee.String(), "members": len(items)})
	})
}

// SettleBatchCancel ends a batch whose cancel confirmed: the cancel's fee is booked, the cell's books change (the inputs are spent, the one output is the
// shard's again), the members go back to the queue at their original place, and the cancel's output is held for them: the signing zone lets a withdrawal
// it signed in a batch be paid again only by a batch that spends it.
func (s *Service) SettleBatchCancel(ctx context.Context, id, cancelTx string) error {
	fee, err := s.Chain.TxFee(ctx, cancelTx)
	if err != nil {
		return err
	}
	bb, ok := s.Chain.(chain.BatchBuilder)
	if !ok {
		return fmt.Errorf("custody: chain %s cannot batch", s.Cfg.Chain)
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if b.Status == BatchCancelled {
			return nil
		}
		if st, ok := s.Chain.(chain.Settler); ok {
			if err := st.Settle(ctx, tx, OwnerKindBatch, id, cancelTx); err != nil {
				return err
			}
		}
		if err := s.recordFee(ctx, tx, cancelTx, b.PartitionID, fee); err != nil {
			return err
		}
		res, err := tx.Exec(ctx, `UPDATE withdrawals SET status='approved', batch_id=NULL, job_id=NULL, tx_hash=NULL, resend_of=$1, updated_at=now()
			WHERE batch_id=$1 AND status NOT IN ('confirmed','failed')`, id)
		if err != nil {
			return err
		}
		held := res.RowsAffected() > 0
		if held {
			if err := bb.HoldForResend(ctx, tx, cancelTx, id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE btc_batches SET status='cancelled', cancel_tx=$2, resend_held=$3, fee=$4::numeric, reason='cancelled', updated_at=now() WHERE id=$1`,
			id, cancelTx, held, fee.String()); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "batch.cancelled", map[string]any{"cancel_tx": cancelTx, "fee": fee.String()})
	})
}

// DiscardBatch ends a batch that was never signed: its coins are released and its members go back to the queue at their original place, in one
// transaction. It reports false, changing nothing, when a signature of the batch may exist (the batch then needs a cancel). refused says the signing
// zone refused it: a member the refusal names is parked with an alert; if it names none, every member's count of refusals goes up and one that reaches
// three is parked.
func (s *Service) DiscardBatch(ctx context.Context, id, reason string, refused bool, log *slog.Logger) (bool, error) {
	done := false
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		done = false
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if b.Status == BatchDiscarded || b.Status == BatchCancelled || b.Status == BatchConfirmed {
			done = true
			return nil
		}
		if b.Status == BatchBroadcast {
			return nil
		}
		if b.Status == BatchSigning {
			released, err := s.releaseIfUnsignedTx(ctx, tx, b.Owner())
			if err != nil || !released {
				return err
			}
		}
		done = true
		return s.discardLocked(ctx, tx, b, reason, refused, log)
	})
	return done, err
}

// discardLocked returns the members of a locked batch (whose coins are already released, or never were taken) to the queue.
func (s *Service) discardLocked(ctx context.Context, tx pgx.Tx, b Batch, reason string, refused bool, log *slog.Logger) error {
	bb, _ := s.Chain.(chain.BatchBuilder)
	items, err := batchItems(ctx, tx, b.ID)
	if err != nil {
		return err
	}
	named := map[string]bool{}
	if refused {
		for _, it := range items {
			if strings.Contains(reason, "withdrawal "+it.WithdrawalID+":") || strings.Contains(reason, "withdrawal "+it.WithdrawalID+" ") {
				named[it.WithdrawalID] = true
			}
		}
	}
	holds := map[string]bool{}
	for _, it := range items {
		var resend string
		var refusals int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(resend_of,''), batch_refusals FROM withdrawals WHERE id=$1 AND batch_id=$2 FOR UPDATE`, it.WithdrawalID, b.ID).Scan(&resend, &refusals); err != nil {
			if isNoRows(err) {
				continue
			}
			return err
		}
		park := ""
		switch {
		case named[it.WithdrawalID]:
			park = "the signing zone refused it: " + reason
		case refused && len(named) == 0:
			refusals++
			if refusals >= refusalsToPark {
				park = fmt.Sprintf("the signing zone refused %d batches it was in: %s", refusals, reason)
			}
		}
		fr := ""
		if park != "" {
			fr = ParkedPrefix + " " + park
			if log != nil {
				log.Error("ALERT: a withdrawal is parked after the signing zone refused its batch", "withdrawal", it.WithdrawalID, "batch", b.ID, "why", park)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE withdrawals SET status='approved', batch_id=NULL, job_id=NULL, tx_hash=NULL, batch_refusals=$2,
			failure_reason=CASE WHEN $3 <> '' THEN $3 ELSE failure_reason END, updated_at=now() WHERE id=$1`, it.WithdrawalID, refusals, fr); err != nil {
			return err
		}
		if resend != "" {
			holds[resend] = true
		}
	}
	// What a member that was in an earlier cancelled batch still needs, an output of that batch's cancel, was released with the coins: hold it again.
	if bb != nil {
		for old := range holds {
			var cancelTx string
			if err := tx.QueryRow(ctx, `SELECT COALESCE(cancel_tx,'') FROM btc_batches WHERE id=$1`, old).Scan(&cancelTx); err != nil {
				return err
			}
			if cancelTx != "" {
				if err := bb.HoldForResend(ctx, tx, cancelTx, old); err != nil {
					return err
				}
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE btc_batches SET status='discarded', reason=$2, updated_at=now() WHERE id=$1`, b.ID, reason); err != nil {
		return err
	}
	return emit(ctx, tx, outbox.TopicWithdrawals, b.ID, "batch.discarded", map[string]any{"reason": reason})
}

// CancelWithdrawal cancels one withdrawal that is not signed yet and voids it (its hold is released). While it waits in the queue that removes it from
// the queue. In a sealed batch that was not signed, the unsigned batch is discarded (its coins released) and the others return to the queue in the same
// order. Once the batch is signed or broadcast it is refused (ErrBatchLocked): only the whole batch can be cancelled, see CancelBatch.
func (s *Service) CancelWithdrawal(ctx context.Context, id, reason string, log *slog.Logger) error {
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if w.Status == WdConfirmed || w.Status == WdFailed || w.BatchID == "" {
			return nil
		}
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, w.BatchID))
		if err != nil {
			return err
		}
		switch b.Status {
		case BatchSealed:
		case BatchSigning:
			released, err := s.releaseIfUnsignedTx(ctx, tx, b.Owner())
			if err != nil {
				return err
			}
			if !released {
				return ErrBatchLocked
			}
		default:
			return ErrBatchLocked
		}
		return s.discardLocked(ctx, tx, b, "withdrawal "+id+" was cancelled", false, log)
	})
	if err != nil {
		return err
	}
	return s.VoidWithdrawal(ctx, id, "cancelled: "+reason, "")
}

// CancelBatch is an operator's request to cancel a whole batch. An unsigned batch is discarded at once (coins released, members back in the queue). A
// signed one gets the existing cancel path: its workflow builds a cancel that spends the same coins back to the shard, with the cancel's own fee
// escalation, and when it confirms the members return to the queue at their place (SettleBatchCancel). If the batch confirms first, it is booked as usual.
func (s *Service) CancelBatch(ctx context.Context, id string, log *slog.Logger) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		b, err := scanBatch(tx.QueryRow(ctx, `SELECT `+batchCols+` FROM btc_batches WHERE id=$1 FOR UPDATE`, id))
		if isNoRows(err) {
			return fmt.Errorf("%w: batch %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		switch b.Status {
		case BatchSealed:
			return s.discardLocked(ctx, tx, b, "cancelled by an operator", false, log)
		case BatchSigning:
			released, err := s.releaseIfUnsignedTx(ctx, tx, b.Owner())
			if err != nil {
				return err
			}
			if released {
				return s.discardLocked(ctx, tx, b, "cancelled by an operator", false, log)
			}
		case BatchBroadcast:
		default:
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE btc_batches SET cancel_requested=true, updated_at=now() WHERE id=$1`, id)
		return err
	})
}

// BatchCancelRequested reports whether an operator asked to cancel the batch.
func (s *Service) BatchCancelRequested(ctx context.Context, id string) (bool, error) {
	var r bool
	err := s.Pool.QueryRow(ctx, `SELECT cancel_requested FROM btc_batches WHERE id=$1`, id).Scan(&r)
	return r, err
}

// ParkBatch records that the batch needs a person (see ParkWithdrawal). Its members stay where they are.
func (s *Service) ParkBatch(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE btc_batches SET reason=$2, updated_at=now() WHERE id=$1 AND status IN ('sealed','signing','broadcast')`, id, ParkedPrefix+" "+reason)
	return err
}

// InBatchQueue reports whether the withdrawal belongs to the batch queue (it was queued when its approval and hot liquidity were in place).
func (s *Service) InBatchQueue(ctx context.Context, id string) (bool, error) {
	var q bool
	err := s.Pool.QueryRow(ctx, `SELECT queued_at IS NOT NULL FROM withdrawals WHERE id=$1`, id).Scan(&q)
	if isNoRows(err) {
		return false, nil
	}
	return q, err
}
