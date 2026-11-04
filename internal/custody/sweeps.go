package custody

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Sweep is a row of sweeps.
type Sweep struct {
	ID          string
	Asset       string
	From        string
	PartitionID string
	Amount      *big.Int
	Status      string
	TxHash      string
	JobID       string
	Reason      string // failure_reason; ParkedPrefix when it needs an operator
}

// Parked reports whether the sweep needs an operator.
func (sw Sweep) Parked() bool { return strings.HasPrefix(sw.Reason, ParkedPrefix) }

func (sw Sweep) Owner() Owner { return Owner{Kind: "sweep", ID: sw.ID, PartitionID: sw.PartitionID} }

const sweepCols = `id, asset, from_address, to_partition_id, amount::text, status, COALESCE(tx_hash,''), COALESCE(job_id,''), COALESCE(failure_reason,'')`

func scanSweep(row pgx.Row) (Sweep, error) {
	var sw Sweep
	var amt string
	if err := row.Scan(&sw.ID, &sw.Asset, &sw.From, &sw.PartitionID, &amt, &sw.Status, &sw.TxHash, &sw.JobID, &sw.Reason); err != nil {
		return sw, err
	}
	sw.Amount = parseBig(amt)
	return sw, nil
}

// GetSweep reads one sweep.
func (s *Service) GetSweep(ctx context.Context, id string) (Sweep, error) {
	sw, err := scanSweep(s.Pool.QueryRow(ctx, `SELECT `+sweepCols+` FROM sweeps WHERE id=$1`, id))
	if isNoRows(err) {
		return sw, fmt.Errorf("%w: sweep %s", ErrNotFound, id)
	}
	return sw, err
}

// OpenSweeps lists sweeps that are not finished.
func (s *Service) OpenSweeps(ctx context.Context) ([]Sweep, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+sweepCols+` FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed') AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' ORDER BY created_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sweep
	for rows.Next() {
		sw, err := scanSweep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rows.Err()
}

// valueWei converts base units of asset to wei using the fixed price table.
func (s *Service) valueWei(asset string, amt *big.Int) *big.Int {
	return new(big.Int).Mul(amt, s.Cfg.Assets[asset].PriceWei)
}

// unswept returns credited deposits minus everything sweeps already moved,
// per (address, asset), for amounts still on deposit addresses. Funds a sweep
// moved that had not been credited yet make the figure negative; it is clamped
// at zero, and the later credit cancels it.
func (s *Service) unswept(ctx context.Context) (map[[2]string]*big.Int, error) {
	out := map[[2]string]*big.Int{}
	add := func(q string, sign int) error {
		rows, err := s.Pool.Query(ctx, q, s.Cfg.Chain)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var addr, asset, amt string
			if err := rows.Scan(&addr, &asset, &amt); err != nil {
				return err
			}
			k := [2]string{addr, asset}
			if out[k] == nil {
				out[k] = new(big.Int)
			}
			v := parseBig(amt)
			if sign < 0 {
				v.Neg(v)
			}
			out[k].Add(out[k], v)
		}
		return rows.Err()
	}
	if err := add(`SELECT address, asset, SUM(amount)::text FROM deposits WHERE chain=$1 AND status='credited' GROUP BY address, asset`, 1); err != nil {
		return nil, err
	}
	if err := add(`SELECT address, asset, SUM(amount)::text FROM sweep_moves WHERE chain=$1 GROUP BY address, asset`, -1); err != nil {
		return nil, err
	}
	return out, nil
}

// PlanSweeps creates a sweep row for every (address, asset) whose unswept
// credited funds pass the rule value >= max(min_sweep, k x estimated fee),
// compared in wei with the fixed price table, and that has no open sweep. A
// frozen factory stops planning quietly: it returns ErrSweepFrozen and creates
// nothing. It returns the sweeps it created.
func (s *Service) PlanSweeps(ctx context.Context, log *slog.Logger) ([]Sweep, error) {
	// Bounds: one pass asks the node about each candidate, and every open sweep
	// takes row locks on the same few ledger accounts (dep, sweep, hot, fee) and
	// a nonce on the one sweep destination, so more than a handful in flight only
	// queues. The rest wait for a later pass.
	const maxPerPass, maxOpen = 25, 12
	var open int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed')`, s.Cfg.Chain).Scan(&open); err != nil {
		return nil, err
	}
	room := min(maxPerPass, maxOpen-open)
	c := s.Cfg
	un, err := s.unswept(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([][2]string, 0, len(un))
	for k, v := range un {
		if v.Sign() > 0 {
			keys = append(keys, k)
		}
	}
	// Deterministic order keeps runs comparable.
	sortPairs(keys)
	var created []Sweep
	for _, k := range keys {
		if len(created) >= room {
			break
		}
		addr, asset := k[0], k[1]
		amt := un[k]
		value := s.valueWei(asset, amt)
		if value.Cmp(c.MinSweepWei) < 0 {
			continue
		}
		var open bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sweeps WHERE chain=$1 AND from_address=$2 AND asset=$3 AND status NOT IN ('confirmed','failed'))`,
			c.Chain, addr, asset).Scan(&open); err != nil {
			return created, err
		}
		if open {
			continue
		}
		fee, err := s.Chain.EstimateSweepFee(ctx, chain.SweepIntent{ID: "estimate", Asset: asset, From: addr, ToPartition: c.SinkPartition(asset), Amount: amt})
		if errors.Is(err, evm.ErrSweepFrozen) {
			return created, ErrSweepFrozen
		}
		if err != nil {
			log.Warn("sweep fee estimate failed; skipping", "address", addr, "asset", asset, "error", err.Error())
			continue
		}
		need := new(big.Int).Mul(fee, big.NewInt(int64(c.SweepK)))
		if need.Cmp(c.MinSweepWei) < 0 {
			need = c.MinSweepWei
		}
		if value.Cmp(need) < 0 {
			continue
		}
		id := "sw-" + uuid.NewString()
		tag, err := s.Pool.Exec(ctx, `INSERT INTO sweeps (id, chain, asset, from_address, to_partition_id, amount, status)
			VALUES ($1,$2,$3,$4,$5,$6::numeric,'planned') ON CONFLICT DO NOTHING`, id, c.Chain, asset, addr, c.SinkPartition(asset), amt.String())
		if err != nil {
			return created, fmt.Errorf("custody: insert sweep: %w", err)
		}
		if tag.RowsAffected() == 1 {
			created = append(created, Sweep{ID: id, Asset: asset, From: addr, PartitionID: c.SinkPartition(asset), Amount: amt, Status: "planned"})
		}
	}
	return created, nil
}

func sortPairs(p [][2]string) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && (p[j][0] < p[j-1][0] || (p[j][0] == p[j-1][0] && p[j][1] < p[j-1][1])); j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

// BuildSweepJob builds the sweep transaction and enqueues its sign job in one
// transaction (the nonce allocation commits with the job). Repeating it after
// a crash returns the existing job. A frozen factory marks the sweep failed
// (nothing was allocated) and returns ErrSweepFrozen: the planner will plan it
// again once sweeping is unfrozen.
func (s *Service) BuildSweepJob(ctx context.Context, id string) (string, error) {
	jobID := OwnerTrack(Owner{Kind: "sweep", ID: id}).FirstJob()
	var frozen bool
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		frozen = false
		sw, err := scanSweep(tx.QueryRow(ctx, `SELECT `+sweepCols+` FROM sweeps WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if sw.JobID != "" || sw.Status != "planned" {
			return nil
		}
		u, err := s.Chain.BuildSweep(ctx, tx, chain.SweepIntent{ID: id, Asset: sw.Asset, From: sw.From, ToPartition: sw.PartitionID, Amount: sw.Amount})
		if errors.Is(err, evm.ErrSweepFrozen) {
			frozen = true
			_, uerr := tx.Exec(ctx, `UPDATE sweeps SET status='failed', failure_reason='sweeping is frozen', updated_at=now() WHERE id=$1`, id)
			return uerr
		}
		if err != nil {
			return err
		}
		intent := signjob.Intent{Kind: "sweep", ID: id, PartitionID: sw.PartitionID, Chain: s.Cfg.Chain, Asset: sw.Asset,
			From: sw.From, To: s.Cfg.EVM.SweepDestination.Hex(), Amount: sw.Amount.String()}
		ib, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: jobID, PartitionID: sw.PartitionID, KeyRef: u.KeyRef.Path, Chain: u.Chain,
			Intent: ib, Digest: u.Digest, Payload: u.Payload}); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE sweeps SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, id, jobID)
		return err
	})
	if err != nil {
		return "", err
	}
	if frozen {
		return "", ErrSweepFrozen
	}
	return jobID, nil
}

// RecordSweepBroadcast stores the transaction hash and books the expected
// amount as in transit: sweep -> dep. Repeating it changes nothing.
func (s *Service) RecordSweepBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		sw, err := scanSweep(tx.QueryRow(ctx, `SELECT `+sweepCols+` FROM sweeps WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		return s.recordSweepBroadcastTx(ctx, tx, sw, txHash)
	})
}

func (s *Service) recordSweepBroadcastTx(ctx context.Context, tx pgx.Tx, sw Sweep, txHash string) error {
	if sw.Status == "confirmed" || sw.Status == "failed" {
		return nil
	}
	if err := s.transfer(ctx, tx, "sw-bcast:"+sw.ID, sweepAcct(s.Cfg.Chain, sw.Asset), depAcct(s.Cfg.Chain, sw.Asset), sw.Amount,
		map[string]any{"sweep": sw.ID}); err != nil {
		return err
	}
	if sw.Status != "broadcast" {
		if _, err := tx.Exec(ctx, `UPDATE sweeps SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1`, sw.ID, txHash); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicSweeps, sw.ID, "sweep.broadcast",
			map[string]any{"chain": s.Cfg.Chain, "asset": sw.Asset, "address": sw.From, "amount": sw.Amount.String(), "tx": txHash})
	}
	return nil
}

// FailSweepBeforeBroadcast ends a sweep whose job was refused or failed twice
// after its nonce was freed by a confirmed cancel. Nothing was booked, so there
// is nothing to reverse.
func (s *Service) FailSweepBeforeBroadcast(ctx context.Context, id, reason string) error {
	o := Owner{Kind: "sweep", ID: id}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		open, err := s.NonceOpen(ctx, tx, o)
		if err != nil {
			return err
		}
		if open {
			return ErrNonceOpen
		}
		tag, err := tx.Exec(ctx, `UPDATE sweeps SET status='failed', failure_reason=$2, updated_at=now() WHERE id=$1 AND status IN ('planned','signing')`, id, reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return emit(ctx, tx, outbox.TopicSweeps, id, "sweep.failed", map[string]any{"reason": reason})
	})
}

// SettleSweep books a mined sweep from what the chain says happened:
//
//   - hot <- what actually moved, per asset, through the sweep account;
//   - moved more than expected: the excess goes sweep -> dep (credited by the
//     next scan, or true-up sends it to suspense); less: the difference is
//     reversed so sweep returns to zero;
//   - the network fee: fee -> hot.
//
// A reverted sweep moves nothing: the expected amount is reversed and only the
// fee is booked. Everything is one transaction, and every ledger ID is derived
// from the sweep ID, so a repeat changes nothing.
func (s *Service) SettleSweep(ctx context.Context, id, txHash string, status chain.TxStatus) error {
	c := s.Cfg
	var moved []chain.MovedAsset
	if status == chain.TxConfirmed {
		var err error
		if moved, err = s.Chain.MovedAssets(ctx, txHash); err != nil {
			return err
		}
	}
	fee, err := s.Chain.TxFee(ctx, txHash)
	if err != nil {
		return err
	}
	height, err := s.Reader.TxBlock(ctx, txHash)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		sw, err := scanSweep(tx.QueryRow(ctx, `SELECT `+sweepCols+` FROM sweeps WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if sw.Status == "confirmed" || sw.Status == "failed" {
			return nil
		}
		if err := s.recordSweepBroadcastTx(ctx, tx, sw, txHash); err != nil { // crash between broadcast and its record
			return err
		}
		byAsset := map[string]*big.Int{}
		for _, m := range moved {
			if m.Address != sw.From {
				continue // nothing else is expected from one sweep; ignore rather than guess
			}
			if byAsset[m.Asset] == nil {
				byAsset[m.Asset] = new(big.Int)
			}
			byAsset[m.Asset].Add(byAsset[m.Asset], m.Amount)
		}
		trueup := false
		for _, asset := range sortedKeys(byAsset) {
			amt := byAsset[asset]
			if err := s.transfer(ctx, tx, "sw-move:"+id+":"+asset, hotAcct(c.SinkPartition(asset)), sweepAcct(c.Chain, asset), amt,
				map[string]any{"sweep": id, "tx": txHash}); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO sweep_moves (sweep_id, chain, address, asset, amount) VALUES ($1,$2,$3,$4,$5::numeric) ON CONFLICT DO NOTHING`,
				id, c.Chain, sw.From, asset, amt.String()); err != nil {
				return err
			}
			if asset != sw.Asset {
				// Rode along (e.g. ETH with a token sweep): all of it is excess.
				if err := s.transfer(ctx, tx, "sw-excess:"+id+":"+asset, sweepAcct(c.Chain, asset), depAcct(c.Chain, asset), amt,
					map[string]any{"sweep": id}); err != nil {
					return err
				}
				trueup = true
			}
		}
		movedMain := byAsset[sw.Asset]
		if movedMain == nil {
			movedMain = new(big.Int)
		}
		switch cmp := movedMain.Cmp(sw.Amount); {
		case cmp > 0:
			if err := s.transfer(ctx, tx, "sw-excess:"+id+":"+sw.Asset, sweepAcct(c.Chain, sw.Asset), depAcct(c.Chain, sw.Asset),
				new(big.Int).Sub(movedMain, sw.Amount), map[string]any{"sweep": id}); err != nil {
				return err
			}
			trueup = true
		case cmp < 0:
			if err := s.transfer(ctx, tx, "sw-shortfall:"+id, depAcct(c.Chain, sw.Asset), sweepAcct(c.Chain, sw.Asset),
				new(big.Int).Sub(sw.Amount, movedMain), map[string]any{"sweep": id}); err != nil {
				return err
			}
		}
		if err := s.recordFee(ctx, tx, txHash, sw.PartitionID, fee); err != nil {
			return err
		}
		final, evt := "confirmed", "sweep.confirmed"
		reason := ""
		if status != chain.TxConfirmed {
			final, evt, reason = "failed", "sweep.failed", "transaction reverted"
		}
		if _, err := tx.Exec(ctx, `UPDATE sweeps SET status=$2, moved=$3::numeric, fee=$4::numeric, settled_height=$5, trueup_done=$6,
			failure_reason=NULLIF($7,''), updated_at=now() WHERE id=$1`,
			id, final, movedMain.String(), fee.String(), int64(height), !trueup, reason); err != nil {
			return err
		}
		ev := map[string]any{"chain": c.Chain, "asset": sw.Asset, "address": sw.From, "expected": sw.Amount.String(), "moved": movedMain.String(),
			"fee": fee.String(), "tx": txHash}
		for a, amt := range byAsset {
			ev["moved_"+a] = amt.String()
		}
		return emit(ctx, tx, outbox.TopicSweeps, id, evt, ev)
	})
}

// TrueUp finishes a settled sweep that moved more than was ever recorded as a
// deposit. Once the scan cursor is past the sweep's block, every deposit that
// could explain the excess has been recorded; whatever is still unexplained
// (ETH sent by an internal call, say) goes dep -> suspense and is recorded as
// an 'unexplained' deposit. It returns false while the scan has not caught up.
func (s *Service) TrueUp(ctx context.Context, id string) (done bool, err error) {
	c := s.Cfg
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		var height *int64
		var tdone bool
		var status string
		if err := tx.QueryRow(ctx, `SELECT settled_height, trueup_done, status FROM sweeps WHERE id=$1 FOR UPDATE`, id).Scan(&height, &tdone, &status); err != nil {
			return err
		}
		if tdone {
			done = true
			return nil
		}
		if height == nil || status != "confirmed" {
			return fmt.Errorf("custody: sweep %s is not settled", id)
		}
		cur, err := s.cursorTx(ctx, tx)
		if err != nil {
			return err
		}
		if cur <= uint64(*height) {
			done = false
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT address, asset FROM sweep_moves WHERE sweep_id=$1 ORDER BY asset`, id)
		if err != nil {
			return err
		}
		var pairs [][2]string
		for rows.Next() {
			var a, as string
			if err := rows.Scan(&a, &as); err != nil {
				rows.Close()
				return err
			}
			pairs = append(pairs, [2]string{a, as})
		}
		rows.Close()
		for _, p := range pairs {
			var movedTotal, recorded string
			if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(m.amount),0)::text FROM sweep_moves m JOIN sweeps sw ON sw.id=m.sweep_id
				WHERE m.chain=$1 AND m.address=$2 AND m.asset=$3 AND sw.settled_height <= $4`, c.Chain, p[0], p[1], *height).Scan(&movedTotal); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0)::text FROM deposits
				WHERE chain=$1 AND address=$2 AND asset=$3 AND status IN ('credited','suspense') AND block_height <= $4`, c.Chain, p[0], p[1], *height).Scan(&recorded); err != nil {
				return err
			}
			un := new(big.Int).Sub(parseBig(movedTotal), parseBig(recorded))
			if un.Sign() <= 0 {
				continue
			}
			did := "unexplained:" + id + ":" + p[1]
			if _, err := tx.Exec(ctx, `INSERT INTO deposits (id, chain, asset, address, amount, dedup_key, status, block_height, origin)
				VALUES ($1,$2,$3,$4,$5::numeric,$6,'suspense',$7,'unexplained') ON CONFLICT (dedup_key) DO NOTHING`,
				did, c.Chain, p[1], p[0], un.String(), c.Chain+":"+did, *height); err != nil {
				return err
			}
			if err := s.transfer(ctx, tx, "dep-credit:"+did, depAcct(c.Chain, p[1]), suspenseAcct(c.Chain, p[1]), un, map[string]any{"sweep": id}); err != nil {
				return err
			}
			if err := emit(ctx, tx, outbox.TopicDeposits, did, "deposit.suspense", map[string]any{"chain": c.Chain, "asset": p[1], "address": p[0],
				"amount": un.String(), "status": "suspense", "origin": "unexplained", "sweep": id}); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE sweeps SET trueup_done=true, updated_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
		done = true
		return nil
	})
	return done, err
}

func (s *Service) cursorTx(ctx context.Context, tx pgx.Tx) (uint64, error) {
	var n int64
	err := tx.QueryRow(ctx, `SELECT next_height FROM chain_cursors WHERE chain=$1`, s.Cfg.Chain).Scan(&n)
	if isNoRows(err) {
		return s.Cfg.StartHeight, nil
	}
	return uint64(n), err
}

var _ = common.Address{}

// ParkSweep records that the sweep needs a person (see ParkWithdrawal). The
// open-sweep index keeps the planner from starting another one meanwhile.
func (s *Service) ParkSweep(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sweeps SET failure_reason=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('confirmed','failed')`, id, ParkedPrefix+" "+reason)
	return err
}
