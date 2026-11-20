package custody

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Draining a Solana hot shard (K4). The rules of drains.go hold (no approval, the operator-signed record is the authorisation, one open move per generation,
// a refusal ends the move and never the drain) but the mechanics differ, because a drain on Solana cannot ride a durable nonce: it also empties the old key's
// nonce accounts and its last lamports. Each move is ONE transaction on a recent blockhash, built by the chain cell from what the old address holds at finalized
// commitment (sol.Adapter.NextDrainStep), and is driven here, by the planner itself, not by a workflow:
//
//	signing    the job is with the signing zone (the move row and the job are written in one transaction, so a crash leaves both or neither)
//	broadcast  the signature is known and recorded, then the transaction is sent (again, on every pass, while its blockhash is valid)
//	confirmed  final and succeeded: the cost (the fee, less the rent that came back) is booked; the next step is built from the chain
//	failed     refused by the zone, failed on the chain, or its blockhash expired unsent or unconfirmed (then it can never land): nothing moved that the
//	           chain does not show, and the planner builds the next step from the chain
//
// The kind of a move is the prefix of its ID: dr-token, dr-close, dr-nonce, dr-sol.

// solDrainer is what the Solana cell gives the planner.
type solDrainer interface {
	NextDrainStep(ctx context.Context, shardPart, oldAddr, succAddr string, succGen int) (*sol.DrainStep, sol.DrainReport, error)
	RecentSubmit(ctx context.Context, raw []byte) (string, error)
	RecentStatus(ctx context.Context, hash string, bh [32]byte) (sol.RecentState, error)
	DrainCost(ctx context.Context, hash, oldAddr, succAddr string) (*big.Int, error)
	OpenOwnWork(ctx context.Context, q chain.Querier, addr string) (int, error)
}

// planSolDrains drives every leaving generation of this Solana chain one pass: advance its open move, then plan and send the next steps while time and the
// chain allow. It returns the moves it created.
func (s *Service) planSolDrains(ctx context.Context, log *slog.Logger) ([]DrainMove, error) {
	sd, ok := s.Chain.(solDrainer)
	if !ok {
		return nil, nil
	}
	var created []DrainMove
	for i := 0; i < s.Cfg.shardCount(); i++ {
		ks, err := shardKeysets(ctx, s.Pool, s.Cfg.shardIDOf(i))
		if err != nil {
			return created, err
		}
		for _, k := range ks {
			if k.State != partition.StateDraining && k.State != partition.StateCompromised {
				continue
			}
			made, err := s.driveSolGeneration(ctx, log, sd, i, k, ks)
			created = append(created, made...)
			if err != nil {
				log.Error("could not drive a drain", "shard", k.ShardID, "generation", k.Generation, "error", err.Error())
			}
		}
	}
	return created, nil
}

func solMoveKind(id string) string {
	k := strings.TrimPrefix(id, "dr-")
	if i := strings.Index(k, "-"); i > 0 {
		return k[:i]
	}
	return k
}

// driveSolGeneration advances one leaving generation: at most a few steps a pass, each ending in the next wait the chain imposes.
func (s *Service) driveSolGeneration(ctx context.Context, log *slog.Logger, sd solDrainer, shardIdx int, from KeysetInfo, all []KeysetInfo) ([]DrainMove, error) {
	var created []DrainMove
	shard := string(from.ShardID)
	wait := func(reason string, retry time.Duration) error {
		return InTx(ctx, s.Pool, func(tx pgx.Tx) error { return setDrainState(ctx, tx, shard, from.Generation, "waiting", reason, retry) })
	}
	var succ *KeysetInfo
	for i := range all {
		if all[i].Generation == from.Successor {
			succ = &all[i]
		}
	}
	if from.Successor == 0 || succ == nil {
		return nil, wait("no successor is named for this generation", 0)
	}
	if succ.State != partition.StateActive {
		return nil, wait(fmt.Sprintf("the successor, generation %d, is %s: a drain needs it active", succ.Generation, succ.State), 0)
	}
	nativePart := s.Cfg.PartitionKey(s.Cfg.Native, shardIdx).String()
	for step := 0; step < 8; step++ {
		if err := ctx.Err(); err != nil {
			return created, nil
		}
		var open *DrainMove
		if m, err := scanDrain(s.Pool.QueryRow(ctx, `SELECT `+drainCols+` FROM drain_moves WHERE shard_id=$1 AND from_generation=$2 AND status NOT IN ('confirmed','failed') ORDER BY created_at LIMIT 1`, shard, from.Generation)); err == nil {
			open = &m
		} else if !isNoRows(err) {
			return created, err
		}
		if open != nil {
			if open.Parked() {
				return created, nil
			}
			finished, err := s.driveSolMove(ctx, log, sd, *open)
			if err != nil {
				return created, err
			}
			if !finished {
				return created, nil // the zone, or the chain, is not done yet: the next pass looks again
			}
			continue
		}
		var retryAt *time.Time
		if err := s.Pool.QueryRow(ctx, `SELECT retry_after FROM keyset_drains WHERE shard_id=$1 AND generation=$2 AND state='waiting'`, shard, from.Generation).Scan(&retryAt); err != nil && !isNoRows(err) {
			return created, err
		}
		if retryAt != nil && time.Now().Before(*retryAt) {
			return created, nil // the zone's refusal is being waited out
		}
		busy, err := sd.OpenOwnWork(ctx, s.Pool, from.Address)
		if err != nil {
			return created, err
		}
		if busy > 0 {
			return created, wait(fmt.Sprintf("%d transactions built from the old address are still in flight; the drain starts when they are final", busy), 0)
		}
		st, rep, err := sd.NextDrainStep(ctx, nativePart, from.Address, succ.Address, succ.Generation)
		if err != nil {
			return created, wait("cannot read the old address: "+err.Error(), 0)
		}
		if rep.Wait != "" {
			return created, wait(rep.Wait, 0)
		}
		if rep.Done {
			reason := ""
			if len(rep.Unknown) > 0 {
				reason = "the old address still holds what the books do not know and the drain never moves: " + strings.Join(rep.Unknown, "; ")
				log.Error("ALERT a drained Solana generation still holds tokens or accounts the drain does not move: report them, decide by hand, never burn", "shard", shard, "generation", from.Generation, "holdings", rep.Unknown)
			}
			err := InTx(ctx, s.Pool, func(tx pgx.Tx) error { return setDrainState(ctx, tx, shard, from.Generation, "drained", reason, 0) })
			if err == nil {
				log.Info("a generation is drained; retiring it is an operator step", "shard", shard, "generation", from.Generation, "address", from.Address)
			}
			return created, err
		}
		m, err := s.startSolMove(ctx, from, *succ, st)
		if err != nil {
			return created, err
		}
		if m != nil {
			log.Info("a drain move is with the signing zone", "shard", shard, "from_generation", from.Generation, "step", st.Kind, "amount", st.Amount.String(), "what", st.Note)
			created = append(created, *m)
		}
	}
	return created, nil
}

// startSolMove writes the move and its sign job in one transaction.
func (s *Service) startSolMove(ctx context.Context, from, succ KeysetInfo, st *sol.DrainStep) (*DrainMove, error) {
	c := s.Cfg
	shard := string(from.ShardID)
	id := "dr-" + st.Kind + "-" + uuid.NewString()
	part := st.Tx.KeyRef.PartitionID
	var made *DrainMove
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		made = nil
		tag, err := tx.Exec(ctx, `INSERT INTO drain_moves (id, chain, shard_id, from_generation, to_generation, from_address, to_address, asset, partition_id, amount, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::numeric,'planned') ON CONFLICT DO NOTHING`,
			id, c.Chain, shard, from.Generation, succ.Generation, from.Address, succ.Address, st.Asset, part, st.Amount.String())
		if err != nil {
			return fmt.Errorf("custody: insert drain: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		m := DrainMove{ID: id, ShardID: shard, FromGeneration: from.Generation, ToGeneration: succ.Generation, From: from.Address, To: succ.Address,
			Asset: st.Asset, PartitionID: part, Amount: st.Amount, Status: "planned"}
		if err := s.enqueueDrain(ctx, tx, m, OwnerTrack(m.Owner()).FirstJob(), st.Tx); err != nil {
			return err
		}
		if err := setDrainState(ctx, tx, shard, from.Generation, "moving", fmt.Sprintf("moving %s %s (%s)", st.Amount, st.Asset, st.Kind), 0); err != nil {
			return err
		}
		made = &m
		return emit(ctx, tx, outbox.TopicColdMoves, id, "drain.planned", map[string]any{"chain": c.Chain, "shard": shard, "from_generation": from.Generation,
			"to_generation": succ.Generation, "from": from.From(), "to": succ.Address, "asset": st.Asset, "amount": st.Amount.String(), "step": st.Kind})
	})
	return made, err
}

// From is the source address (for event payloads that name the keyset).
func (k KeysetInfo) From() string { return k.Address }

// driveSolMove advances one open move by what its job and its transaction show. It returns true when the move ended (confirmed or failed), so the caller
// can plan the next one.
func (s *Service) driveSolMove(ctx context.Context, log *slog.Logger, sd solDrainer, m DrainMove) (bool, error) {
	attempt := OwnerTrack(m.Owner()).FirstJob()
	switch m.Status {
	case "planned", "signing":
		st, reason, err := s.JobStatus(ctx, attempt)
		if err != nil {
			return false, err
		}
		switch st {
		case JobPending:
			return false, nil
		case JobRejected, JobFailed:
			why := "the signing zone refused: " + reason
			if st == JobFailed {
				why = "the signing zone could not sign it: " + reason
			}
			return true, s.endSolMove(ctx, m, why, "")
		}
		jobs, err := jobGroup(ctx, s.Pool, attempt)
		if err != nil || len(jobs) != 1 {
			return false, fmt.Errorf("custody: drain %s: %d jobs (%v)", m.ID, len(jobs), err)
		}
		hash := base58.Encode(jobs[0].Signature)
		if _, err := s.Pool.Exec(ctx, `UPDATE drain_moves SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1 AND status IN ('planned','signing')`, m.ID, hash); err != nil {
			return false, err
		}
		m.Status, m.TxHash = "broadcast", hash
		fallthrough
	case "broadcast":
		jobs, err := jobGroup(ctx, s.Pool, attempt)
		if err != nil || len(jobs) != 1 {
			return false, fmt.Errorf("custody: drain %s: %d jobs (%v)", m.ID, len(jobs), err)
		}
		bh, err := sol.BlockhashOf(jobs[0].Payload)
		if err != nil {
			return false, err
		}
		state, err := sd.RecentStatus(ctx, m.TxHash, bh)
		if err != nil {
			return false, err
		}
		switch state {
		case sol.RecentPending:
			// sent (again): sending a transaction the node already has is not an error, and one that was recorded but never sent goes out now
			stx, err := s.Chain.Assemble(unsignedOf(jobs[0]), []chain.Signature{{Bytes: jobs[0].Signature}})
			if err != nil {
				return false, err
			}
			if _, err := sd.RecentSubmit(ctx, stx.Raw); err != nil {
				log.Warn("could not send a drain transaction yet", "drain", m.ID, "error", err.Error())
			}
			return false, nil
		case sol.RecentExpired:
			return true, s.endSolMove(ctx, m, "the transaction's blockhash expired before it landed; nothing moved", m.TxHash)
		default:
			cost, err := sd.DrainCost(ctx, m.TxHash, m.From, m.To)
			if err != nil {
				return false, err
			}
			return true, s.settleSolMove(ctx, m, cost, state == sol.RecentFailed)
		}
	}
	return true, nil
}

// endSolMove ends a move that moved nothing, keeping the reason on the generation as a wait; the planner tries again after DrainRetryAfter.
func (s *Service) endSolMove(ctx context.Context, m DrainMove, reason, hash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE drain_moves SET status='failed', failure_reason=$2, updated_at=now() WHERE id=$1 AND status IN ('planned','signing','broadcast')`, m.ID, reason)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		if err := setDrainState(ctx, tx, m.ShardID, m.FromGeneration, "waiting", reason, s.drainRetryAfter()); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, m.ID, "drain.failed", map[string]any{"reason": reason, "tx": hash})
	})
}

// settleSolMove books a final drain transaction: its cost, as a cost of the shard (negative when rent came back), and ends the move. A repeat changes nothing.
func (s *Service) settleSolMove(ctx context.Context, m DrainMove, cost *big.Int, failed bool) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		cur, err := scanDrain(tx.QueryRow(ctx, `SELECT `+drainCols+` FROM drain_moves WHERE id=$1 FOR UPDATE`, m.ID))
		if err != nil {
			return err
		}
		if cur.Status == "confirmed" || cur.Status == "failed" {
			return nil
		}
		final, evt, reason := "confirmed", "drain.confirmed", ""
		if failed {
			final, evt, reason = "failed", "drain.failed", "transaction failed on the chain"
		}
		if err := s.recordFee(ctx, tx, m.TxHash, m.PartitionID, cost); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE drain_moves SET status=$2, fee=$3::numeric, failure_reason=NULLIF($4,''), updated_at=now() WHERE id=$1`, m.ID, final, cost.String(), reason); err != nil {
			return err
		}
		if failed {
			if err := setDrainState(ctx, tx, m.ShardID, m.FromGeneration, "waiting", reason, s.drainRetryAfter()); err != nil {
				return err
			}
		}
		return emit(ctx, tx, outbox.TopicColdMoves, m.ID, evt, map[string]any{"chain": s.Cfg.Chain, "shard": m.ShardID, "asset": m.Asset, "from": m.From, "to": m.To,
			"amount": m.Amount.String(), "tx": m.TxHash, "cost": cost.String(), "step": solMoveKind(m.ID)})
	})
}

var _ = json.Marshal
var _ = signjob.KindDrain
