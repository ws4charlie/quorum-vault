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
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// OwnerKindDrain is the owner kind (nonce owner, sign-job track, intent kind) of a drain move.
const OwnerKindDrain = "drain"

// A drain empties an old generation of an EVM hot shard into its successor, one asset at a time: every token that has a balance, then the native
// asset last, keeping only what the final transfer's gas needs. It moves money between two addresses of the SAME shard, so the shard's ledger
// account does not change and nothing is booked for the amount. Only the gas is booked, as a cost, like the fee of any other transaction:
//
//	broadcast  (nothing)
//	confirmed  fee -> hot(shard native)
//	reverted   fee -> hot(shard native)   (the move ends failed; the planner makes another)
//
// There is no approval: the operator-signed record in the signing zone (qv-keysets start-draining, with the successor and a cap per asset) is the
// authorisation, and the zone decides from its own records. The core plans from its mirror of the registry. What the planner finds is kept in
// keyset_drains so the admin API can show it:
//
//	moving   a drain move is open
//	waiting  nothing could be sent now, and why (the zone refused or delays; work from the old address is in flight; the old address has no gas)
//	drained  nothing above dust is left at the old address; retiring it is an operator step, never automatic
//
// A refusal by the zone ends the move (the nonce is freed by a cancel) and never the drain: the planner looks at the chain again after
// DrainRetryAfter and makes the next move from what the address holds then, so no place is lost.
//
// One drain move is open per shard and source generation (a unique index), so a crash cannot make two transfers of one asset, and the nonce of the
// old address is used by one drain at a time.

// DrainMove is a row of drain_moves.
type DrainMove struct {
	ID             string
	ShardID        string
	FromGeneration int
	ToGeneration   int
	From, To       string
	Asset          string
	PartitionID    string
	Amount         *big.Int
	Status         string
	TxHash         string
	JobID          string
	Reason         string
}

// Parked reports whether the move needs an operator.
func (m DrainMove) Parked() bool { return strings.HasPrefix(m.Reason, ParkedPrefix) }

const drainCols = `id, shard_id, from_generation, to_generation, from_address, to_address, asset, partition_id, amount::text, status, COALESCE(tx_hash,''), COALESCE(job_id,''), COALESCE(failure_reason,'')`

func scanDrain(row pgx.Row) (DrainMove, error) {
	var m DrainMove
	var amt string
	if err := row.Scan(&m.ID, &m.ShardID, &m.FromGeneration, &m.ToGeneration, &m.From, &m.To, &m.Asset, &m.PartitionID, &amt, &m.Status, &m.TxHash, &m.JobID, &m.Reason); err != nil {
		return m, err
	}
	m.Amount = parseBig(amt)
	return m, nil
}

// GetDrain reads one drain move.
func (s *Service) GetDrain(ctx context.Context, id string) (DrainMove, error) {
	m, err := scanDrain(s.Pool.QueryRow(ctx, `SELECT `+drainCols+` FROM drain_moves WHERE id=$1`, id))
	if isNoRows(err) {
		return m, fmt.Errorf("%w: drain %s", ErrNotFound, id)
	}
	return m, err
}

// OpenDrains lists drain moves that are not finished and not parked.
func (s *Service) OpenDrains(ctx context.Context) ([]DrainMove, error) {
	if s.Cfg.Family == FamilySOL {
		return nil, nil // a Solana drain is driven by the planner itself (drains_sol.go), not by a workflow per move
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+drainCols+` FROM drain_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed')
		AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' ORDER BY created_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DrainMove
	for rows.Next() {
		m, err := scanDrain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Owner returns the move as a transaction owner.
func (m DrainMove) Owner() Owner {
	return Owner{Kind: OwnerKindDrain, ID: m.ID, PartitionID: m.PartitionID}
}

func (s *Service) drainRetryAfter() time.Duration {
	if s.Cfg.DrainRetryAfter > 0 {
		return s.Cfg.DrainRetryAfter
	}
	return time.Minute
}

func (s *Service) drainWindow() time.Duration {
	if s.Cfg.DrainWindow > 0 {
		return s.Cfg.DrainWindow
	}
	return 10 * time.Minute
}

// setDrainState records what the planner found for a leaving generation.
func setDrainState(ctx context.Context, tx pgx.Tx, shard string, gen int, state, reason string, retryAfter time.Duration) error {
	var ra any
	if retryAfter > 0 {
		ra = time.Now().Add(retryAfter)
	}
	_, err := tx.Exec(ctx, `INSERT INTO keyset_drains (shard_id, generation, state, reason, retry_after) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (shard_id, generation) DO UPDATE SET state=EXCLUDED.state, reason=EXCLUDED.reason, retry_after=EXCLUDED.retry_after, updated_at=now()`,
		shard, gen, state, reason, ra)
	return err
}

// PlanDrains looks at every generation of this chain's shards that is draining or compromised and has an active successor, and for each one with no
// move open makes the next move: a token with a balance, then the native asset last. It returns the moves it created. It changes nothing for a chain
// whose cell cannot build a drain (Bitcoin, Solana) or a shard with one generation.
func (s *Service) PlanDrains(ctx context.Context, log *slog.Logger) ([]DrainMove, error) {
	if s.Cfg.Family == FamilyBTC {
		return s.planBTCDrains(ctx, log)
	}
	if s.Cfg.Family == FamilySOL {
		return s.planSolDrains(ctx, log)
	}
	if s.Cfg.Family != FamilyEVM && s.Cfg.Family != "" {
		return nil, nil
	}
	if _, ok := s.Chain.(drainBuilder); !ok {
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
			m, err := s.planDrain(ctx, log, i, k, ks)
			if err != nil {
				log.Error("could not plan a drain", "shard", k.ShardID, "generation", k.Generation, "error", err.Error())
				continue
			}
			if m != nil {
				created = append(created, *m)
			}
		}
	}
	return created, nil
}

// drainBuilder is what a chain cell needs for the drain: build a transfer from an old address.
type drainBuilder interface {
	BuildDrain(ctx context.Context, tx pgx.Tx, d evm.DrainRequest) (chain.UnsignedTx, error)
}

// planDrain makes the next move of one leaving generation, or records why not.
func (s *Service) planDrain(ctx context.Context, log *slog.Logger, shardIdx int, from KeysetInfo, all []KeysetInfo) (*DrainMove, error) {
	c := s.Cfg
	shard := string(from.ShardID)
	wait := func(reason string) (*DrainMove, error) {
		err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			return setDrainState(ctx, tx, shard, from.Generation, "waiting", reason, 0)
		})
		return nil, err
	}
	var succ *KeysetInfo
	for i := range all {
		if all[i].Generation == from.Successor {
			succ = &all[i]
		}
	}
	if from.Successor == 0 || succ == nil {
		return wait("no successor is named for this generation")
	}
	if succ.State != partition.StateActive {
		return wait(fmt.Sprintf("the successor, generation %d, is %s: a drain needs it active", succ.Generation, succ.State))
	}
	var open bool
	var retryAt *time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM drain_moves WHERE shard_id=$1 AND from_generation=$2 AND status NOT IN ('confirmed','failed')),
		(SELECT retry_after FROM keyset_drains WHERE shard_id=$1 AND generation=$2 AND state='waiting')`, shard, from.Generation).Scan(&open, &retryAt); err != nil {
		return nil, err
	}
	if open {
		return nil, nil
	}
	if retryAt != nil && time.Now().Before(*retryAt) {
		return nil, nil // the zone's refusal is being waited out
	}
	// Work from the old address that is not ours to drain (a withdrawal or sweep built before the replacement) finishes first: the drain would spend
	// the balance it needs and share its nonces.
	var busy int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM evm_nonce_allocations WHERE chain=$1 AND lower(address)=lower($2) AND status IN ('allocated','broadcast') AND owner_kind <> $3`,
		c.Chain, from.Address, OwnerKindDrain).Scan(&busy); err != nil {
		return nil, err
	}
	if busy > 0 {
		return wait(fmt.Sprintf("%d transactions built from the old address are still in flight; the drain starts when they are final", busy))
	}
	bal, err := s.balancesAt(ctx, from.Address)
	if err != nil {
		return wait("cannot read the balance of the old address: " + err.Error())
	}
	nativeDust, err := s.dustOf(ctx, c.Native)
	if err != nil {
		return wait("cannot work out the gas of the last transfer: " + err.Error())
	}
	// Tokens first, the native asset last.
	asset, amount := "", new(big.Int)
	for _, sym := range c.AssetList {
		if sym != c.Native && bal[sym].Sign() > 0 {
			asset, amount = sym, bal[sym]
			break
		}
	}
	if asset == "" && bal[c.Native].Cmp(nativeDust) > 0 {
		asset, amount = c.Native, new(big.Int).Sub(bal[c.Native], nativeDust)
	}
	if asset == "" {
		err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			return setDrainState(ctx, tx, shard, from.Generation, "drained", "", 0)
		})
		if err == nil {
			log.Info("a generation is drained; retiring it is an operator step", "shard", shard, "generation", from.Generation, "address", from.Address)
		}
		return nil, err
	}
	if asset != c.Native && bal[c.Native].Cmp(c.NativeReserve()) < 0 {
		return wait(fmt.Sprintf("the old address holds %s %s and no gas for the token transfer (it needs %s); fund it with the native asset", amount, asset, c.NativeReserve()))
	}
	log.Info("planning a drain move", "shard", shard, "from_generation", from.Generation, "asset", asset, "amount", amount.String(), "old_address_native", bal[c.Native].String(), "native_dust", nativeDust.String())
	part := c.PartitionKey(asset, shardIdx).String()
	id := "dr-" + uuid.NewString()
	var made *DrainMove
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		made = nil
		tag, err := tx.Exec(ctx, `INSERT INTO drain_moves (id, chain, shard_id, from_generation, to_generation, from_address, to_address, asset, partition_id, amount, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::numeric,'planned') ON CONFLICT DO NOTHING`,
			id, c.Chain, shard, from.Generation, succ.Generation, from.Address, succ.Address, asset, part, amount.String())
		if err != nil {
			return fmt.Errorf("custody: insert drain: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		made = &DrainMove{ID: id, ShardID: shard, FromGeneration: from.Generation, ToGeneration: succ.Generation, From: from.Address, To: succ.Address,
			Asset: asset, PartitionID: part, Amount: amount, Status: "planned"}
		if err := setDrainState(ctx, tx, shard, from.Generation, "moving", fmt.Sprintf("moving %s %s", amount, asset), 0); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, "drain.planned", map[string]any{"chain": c.Chain, "shard": shard, "from_generation": from.Generation,
			"to_generation": succ.Generation, "from": from.Address, "to": succ.Address, "asset": asset, "amount": amount.String()})
	})
	return made, err
}

// BuildDrainJob builds the transfer (allocating the OLD address's nonce) and enqueues its sign job, in one transaction. Repeating it after a crash
// returns the existing job. The intent names the source and the successor and has a short not_after, which bounds how long the zone waits for its own
// view to catch up (docs/runbooks/key-replacement.md).
func (s *Service) BuildDrainJob(ctx context.Context, id string) (string, error) {
	jobID := OwnerTrack(Owner{Kind: OwnerKindDrain, ID: id}).FirstJob()
	if s.Cfg.Family == FamilyBTC {
		return s.buildBTCDrainJob(ctx, id, jobID)
	}
	db, ok := s.Chain.(drainBuilder)
	if !ok {
		return "", fmt.Errorf("%w: this chain cannot drain", ErrInvalid)
	}
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanDrain(tx.QueryRow(ctx, `SELECT `+drainCols+` FROM drain_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.JobID != "" || m.Status != "planned" {
			return nil
		}
		u, err := db.BuildDrain(ctx, tx, evm.DrainRequest{ID: id, PartitionID: m.PartitionID, From: m.From, To: m.To, Asset: m.Asset, Amount: m.Amount})
		if err != nil {
			return err
		}
		return s.enqueueDrain(ctx, tx, m, jobID, u)
	})
	return jobID, err
}

// enqueueDrain writes the intent of a drain move and its first sign job, and marks the move signing.
func (s *Service) enqueueDrain(ctx context.Context, tx pgx.Tx, m DrainMove, jobID string, u chain.UnsignedTx) error {
	ib, err := json.Marshal(signjob.Intent{Kind: signjob.KindDrain, ID: m.ID, PartitionID: m.PartitionID, Chain: s.Cfg.Chain, Asset: m.Asset,
		From: m.From, To: m.To, Amount: m.Amount.String(), NotAfter: s.Now().Add(s.drainWindow()).Unix()})
	if err != nil {
		return err
	}
	if err := EnqueueUnsigned(ctx, tx, jobID, m.PartitionID, u, ib, nil); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE drain_moves SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, m.ID, jobID)
	return err
}

// RecordDrainBroadcast stores the hash. Nothing is booked for the amount: it stays in the shard. Repeating it changes nothing.
func (s *Service) RecordDrainBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanDrain(tx.QueryRow(ctx, `SELECT `+drainCols+` FROM drain_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		return s.recordDrainBroadcastTx(ctx, tx, m, txHash)
	})
}

func (s *Service) recordDrainBroadcastTx(ctx context.Context, tx pgx.Tx, m DrainMove, txHash string) error {
	if m.Status == "confirmed" || m.Status == "failed" || m.Status == "broadcast" {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE drain_moves SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1`, m.ID, txHash); err != nil {
		return err
	}
	return emit(ctx, tx, outbox.TopicColdMoves, m.ID, "drain.broadcast",
		map[string]any{"chain": s.Cfg.Chain, "shard": m.ShardID, "asset": m.Asset, "from": m.From, "to": m.To, "amount": m.Amount.String(), "tx": txHash})
}

// SettleDrain books a mined drain: only its fee, as a cost of the shard. A reverted one ends failed (the money did not move) and the planner makes
// another from what the address holds then. One transaction: a repeat changes nothing.
func (s *Service) SettleDrain(ctx context.Context, id, txHash string, status chain.TxStatus) error {
	fee, err := s.Chain.TxFee(ctx, txHash)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		m, err := scanDrain(tx.QueryRow(ctx, `SELECT `+drainCols+` FROM drain_moves WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if m.Status == "confirmed" || m.Status == "failed" {
			return nil
		}
		if err := s.recordDrainBroadcastTx(ctx, tx, m, txHash); err != nil { // crash between the broadcast and its record
			return err
		}
		final, evt, reason := "confirmed", "drain.confirmed", ""
		if status != chain.TxConfirmed {
			final, evt, reason = "failed", "drain.failed", "transaction reverted"
		}
		if st, ok := s.Chain.(chain.Settler); ok { // the cell's own books (Bitcoin: spent inputs, the output at the successor, or a mined cancel's change)
			if err := st.Settle(ctx, tx, OwnerKindDrain, id, txHash); err != nil {
				return err
			}
		}
		if err := s.recordFee(ctx, tx, txHash, m.PartitionID, fee); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE drain_moves SET status=$2, fee=$3::numeric, failure_reason=NULLIF($4,''), updated_at=now() WHERE id=$1`, id, final, fee.String(), reason); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, evt, map[string]any{"chain": s.Cfg.Chain, "shard": m.ShardID, "asset": m.Asset, "from": m.From, "to": m.To,
			"amount": m.Amount.String(), "tx": txHash, "fee": fee.String()})
	})
}

// FailDrainBeforeBroadcast ends a drain move whose job was refused (or could not be built), after its nonce was freed by a confirmed cancel. Nothing
// was booked for the amount. The reason is kept on the generation as a wait, and the planner tries again after DrainRetryAfter: a refusal never ends
// the drain. The cancel paid gas from the old address, so its fee (feeTx, if any) is booked.
func (s *Service) FailDrainBeforeBroadcast(ctx context.Context, id, reason, feeTx string) error {
	fee, err := s.cancelFee(ctx, feeTx)
	if err != nil {
		return err
	}
	o := Owner{Kind: OwnerKindDrain, ID: id}
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
		var part, shard string
		var gen int
		err = tx.QueryRow(ctx, `UPDATE drain_moves SET status='failed', failure_reason=$2, fee=NULLIF($3,'')::numeric, updated_at=now() WHERE id=$1 AND status IN ('planned','signing')
			RETURNING partition_id, shard_id, from_generation`, id, reason, fs).Scan(&part, &shard, &gen)
		if isNoRows(err) {
			return nil // already ended: a repeat books nothing
		}
		if err != nil {
			return err
		}
		if err := s.recordFee(ctx, tx, feeTx, part, fee); err != nil {
			return err
		}
		if err := setDrainState(ctx, tx, shard, gen, "waiting", reason, s.drainRetryAfter()); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, "drain.failed", map[string]any{"reason": reason})
	})
}

// ParkDrain records that the move needs a person (see ParkWithdrawal).
func (s *Service) ParkDrain(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE drain_moves SET failure_reason=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('confirmed','failed')`, id, ParkedPrefix+" "+reason)
	return err
}
