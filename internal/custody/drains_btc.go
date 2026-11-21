package custody

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// The drain of a Bitcoin cell (K6). The hot shards derive from the same account key as the deposit tree, so a generation of the tree that is draining
// or compromised has, for every hot partition, a shard under it that must move to the successor generation's shard. The move is a drain_moves row like
// an EVM drain's (shard_id is the hot shard's, from_generation and to_generation are generations of the tree), built by the cell as a transaction in
// the consolidation's shape: the partition's outputs under the old key, one output to the successor's address. Up to max_inputs outputs a move; the
// planner makes the next move when the last is final, until nothing above dust is left. The zone's operator-signed record (the cap per asset) is the
// authorisation; the core only plans from its mirror.

type btcDrainer interface {
	PlanDrain(ctx context.Context, partitionID, from string) (btc.DrainPlan, error)
	BuildDrain(ctx context.Context, tx pgx.Tx, d btc.DrainRequest) (chain.UnsignedTx, error)
	ShardAddressAtGen(partitionID string, gen int) (string, error)
	ReservedUnder(ctx context.Context, partitionID string, gen int) (int, error)
}

// planBTCDrains plans the next move of every hot shard under a generation of the deposit tree that is leaving.
func (s *Service) planBTCDrains(ctx context.Context, log *slog.Logger) ([]DrainMove, error) {
	d, ok := s.Chain.(btcDrainer)
	if !ok {
		return nil, nil
	}
	tree, err := s.Cfg.depositTreeID()
	if err != nil {
		return nil, err
	}
	ks, err := shardKeysets(ctx, s.Pool, tree)
	if err != nil {
		return nil, err
	}
	var created []DrainMove
	for _, k := range ks {
		if k.State != partition.StateDraining && k.State != partition.StateCompromised {
			continue
		}
		// One state row per generation of the tree (keyset_drains is keyed by it), aggregated over the hot partitions: moving while any moves, waiting
		// (the first reason) while any waits, drained when all are.
		agg := btcDrainState{state: "drained"}
		for i := range s.Cfg.BTC.HotShards {
			m, st, err := s.planBTCDrain(ctx, log, d, i, k, ks)
			if err != nil {
				log.Error("could not plan a drain", "shard", s.Cfg.shardIDOf(i), "generation", k.Generation, "error", err.Error())
				agg = agg.merge(btcDrainState{state: "waiting", reason: err.Error()})
				continue
			}
			agg = agg.merge(st)
			if m != nil {
				created = append(created, *m)
			}
		}
		if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
			return setDrainState(ctx, tx, string(tree), k.Generation, agg.state, agg.reason, 0)
		}); err != nil {
			return created, err
		}
	}
	return created, nil
}

type btcDrainState struct{ state, reason string }

// merge puts two partitions' findings together: moving beats waiting beats drained.
func (a btcDrainState) merge(b btcDrainState) btcDrainState {
	rank := map[string]int{"drained": 0, "waiting": 1, "moving": 2}
	if rank[b.state] > rank[a.state] || (b.state == a.state && a.reason == "") {
		return b
	}
	return a
}

func (s *Service) planBTCDrain(ctx context.Context, log *slog.Logger, d btcDrainer, shardIdx int, from KeysetInfo, all []KeysetInfo) (*DrainMove, btcDrainState, error) {
	c := s.Cfg
	shard := string(from.ShardID) // the deposit tree: drain_moves and keyset_drains refer to its generations
	part := c.PartitionKey(c.Native, shardIdx).String()
	wait := func(reason string) (*DrainMove, btcDrainState, error) {
		return nil, btcDrainState{state: "waiting", reason: reason}, nil
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
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM drain_moves WHERE shard_id=$1 AND from_generation=$2 AND partition_id=$3 AND status NOT IN ('confirmed','failed')),
		(SELECT retry_after FROM keyset_drains WHERE shard_id=$1 AND generation=$2 AND state='waiting')`, shard, from.Generation, part).Scan(&open, &retryAt); err != nil {
		return nil, btcDrainState{}, err
	}
	if open {
		return nil, btcDrainState{state: "moving", reason: "a move is open"}, nil
	}
	if retryAt != nil && time.Now().Before(*retryAt) {
		return nil, btcDrainState{state: "waiting", reason: "the zone's refusal is being waited out"}, nil
	}
	fromAddr, err := d.ShardAddressAtGen(part, from.Generation)
	if err != nil {
		return wait("cannot derive the old shard address: " + err.Error())
	}
	toAddr, err := d.ShardAddressAtGen(part, succ.Generation)
	if err != nil {
		return wait("cannot derive the successor's shard address: " + err.Error())
	}
	reserved, err := d.ReservedUnder(ctx, part, from.Generation)
	if err != nil {
		return nil, btcDrainState{}, err
	}
	// A draining generation waits for the transactions it has in flight. A compromised one does not: nothing new is signed from it but its own cancels, so the
	// coins that are free move at once, and the held ones (reserved by a payment the zone refused: its cancel is on the way) are picked up when they come back.
	compromised := from.State == partition.StateCompromised
	if reserved > 0 && !compromised {
		return wait(fmt.Sprintf("%d outputs of the old shard are reserved by transactions that are not final; the drain starts when they are", reserved))
	}
	note := ""
	if reserved > 0 {
		note = s.btcHeldNote(ctx, d, part, from.Generation)
	}
	plan, err := d.PlanDrain(ctx, part, fromAddr)
	if err != nil {
		return wait("cannot plan the drain: " + err.Error())
	}
	if plan.Wait != "" {
		return wait(plan.Wait)
	}
	if plan.Amount == nil || plan.Amount.Sign() <= 0 {
		if reserved > 0 {
			return wait(cmp.Or(note, fmt.Sprintf("%d outputs of the old shard are reserved by transactions that are not final; the drain starts when they are", reserved)))
		}
		return nil, btcDrainState{state: "drained"}, nil
	}
	id := "dr-" + uuid.NewString()
	var made *DrainMove
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		made = nil
		tag, err := tx.Exec(ctx, `INSERT INTO drain_moves (id, chain, shard_id, from_generation, to_generation, from_address, to_address, asset, partition_id, amount, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::numeric,'planned') ON CONFLICT DO NOTHING`,
			id, c.Chain, shard, from.Generation, succ.Generation, fromAddr, toAddr, c.Native, part, plan.Amount.String())
		if err != nil {
			return fmt.Errorf("custody: insert drain: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		made = &DrainMove{ID: id, ShardID: shard, FromGeneration: from.Generation, ToGeneration: succ.Generation, From: fromAddr, To: toAddr,
			Asset: c.Native, PartitionID: part, Amount: new(big.Int).Set(plan.Amount), Status: "planned"}
		return emit(ctx, tx, outbox.TopicColdMoves, id, "drain.planned", map[string]any{"chain": c.Chain, "shard": shard, "from_generation": from.Generation,
			"to_generation": succ.Generation, "from": fromAddr, "to": toAddr, "asset": c.Native, "amount": plan.Amount.String()})
	})
	st := btcDrainState{state: "moving", reason: fmt.Sprintf("moving %s %s in %d outputs", plan.Amount, c.Native, plan.Inputs)}
	if note != "" {
		st.reason += "; " + note
	}
	return made, st, err
}

// buildBTCDrainJob builds the move (reserving the old shard's outputs) and enqueues its sign job, in one transaction.
func (s *Service) buildBTCDrainJob(ctx context.Context, id, jobID string) (string, error) {
	d, ok := s.Chain.(btcDrainer)
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
		u, err := d.BuildDrain(ctx, tx, btc.DrainRequest{ID: id, PartitionID: m.PartitionID, From: m.From, To: m.To, Amount: m.Amount})
		if err != nil {
			return err
		}
		return s.enqueueDrain(ctx, tx, m, jobID, u)
	})
	return jobID, err
}
