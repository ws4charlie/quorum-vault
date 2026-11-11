package custody

import (
	"context"
	"log/slog"
	"math/big"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Solana sweeps. A sweep is one transaction that takes the credited funds of several deposit addresses of ONE asset into the hot shard of the sink
// partition; the sweeps row holds the total and the first address, sweep_items holds every address with its amount. Everything else (the workflow, the
// books at broadcast and at settlement, the true-up) is the sweep flow of the other families.

// sweepLegs reads the addresses of a batched sweep; none for a sweep of the one address in the row (every other family).
func (s *Service) sweepLegs(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}, sw Sweep) ([]chain.SweepLeg, error) {
	rows, err := q.Query(ctx, `SELECT address, amount::text, close_account FROM sweep_items WHERE sweep_id=$1 ORDER BY ord`, sw.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []chain.SweepLeg
	for rows.Next() {
		var l chain.SweepLeg
		var amt string
		if err := rows.Scan(&l.From, &amt, &l.Close); err != nil {
			return nil, err
		}
		l.Amount = parseBig(amt)
		out = append(out, l)
	}
	return out, rows.Err()
}

func sortedPairKeys(m map[[2]string]*big.Int) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// planSweepsSOL decides which deposit addresses are worth sweeping and groups them. An address is swept when its credited, unswept funds are worth at
// least max(min_sweep, k x the fee of sweeping it alone): below that the dust stays. Only credited deposits count, so nothing the scan has not credited
// at finalized commitment is ever swept. An address with a sweep in flight is left alone. The addresses of one asset are grouped, up to sweep_batch to a
// transaction, in a fixed order. A token address is also marked for closing when it has had no credited deposit for close_quiet_after.
func (s *Service) planSweepsSOL(ctx context.Context, log *slog.Logger) ([]Sweep, error) {
	c := s.Cfg
	// Every open sweep holds a nonce account of the shard's pool for its whole life. The planner never lets sweeps take them all: one account stays for
	// withdrawals, and a sweep that finds none free would only fail to build and be planned again.
	maxOpen := max(1, c.SOL.NoncePool-1)
	var open int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed')`, c.Chain).Scan(&open); err != nil {
		return nil, err
	}
	room := maxOpen - open
	if room <= 0 {
		return nil, nil
	}
	un, err := s.unswept(ctx)
	if err != nil {
		return nil, err
	}
	busy := map[[2]string]bool{}
	rows, err := s.Pool.Query(ctx, `SELECT from_address, asset FROM sweeps WHERE chain=$1 AND status NOT IN ('confirmed','failed')
		UNION SELECT i.address, w.asset FROM sweep_items i JOIN sweeps w ON w.id=i.sweep_id WHERE w.chain=$1 AND w.status NOT IN ('confirmed','failed')`, c.Chain)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a, as string
		if err := rows.Scan(&a, &as); err != nil {
			rows.Close()
			return nil, err
		}
		busy[[2]string{a, as}] = true
	}
	rows.Close()
	keys := make([][2]string, 0, len(un))
	for k, v := range un {
		if v.Sign() > 0 && !busy[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][1] != keys[j][1] {
			return keys[i][1] < keys[j][1]
		}
		return keys[i][0] < keys[j][0]
	})
	byAsset := map[string][]chain.SweepLeg{}
	var assets []string
	for _, k := range keys {
		addr, asset := k[0], k[1]
		amt := un[k]
		value := s.valueWei(asset, amt)
		if value.Cmp(c.MinSweepWei) < 0 {
			continue
		}
		if backoff, err := s.sweepBackoff(ctx, addr, asset); err != nil {
			return nil, err
		} else if backoff {
			continue
		}
		fee, err := s.Chain.EstimateSweepFee(ctx, chain.SweepIntent{ID: "estimate", Asset: asset, From: addr, ToPartition: c.SinkPartition(asset), Amount: amt})
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
		leg := chain.SweepLeg{From: addr, Amount: amt}
		if asset != c.Native && c.CloseQuiet > 0 {
			var last *time.Time
			if err := s.Pool.QueryRow(ctx, `SELECT max(created_at) FROM deposits WHERE chain=$1 AND address=$2 AND asset=$3`, c.Chain, addr, asset).Scan(&last); err != nil {
				return nil, err
			}
			leg.Close = last == nil || time.Since(*last) >= c.CloseQuiet
		}
		if _, seen := byAsset[asset]; !seen {
			assets = append(assets, asset)
		}
		byAsset[asset] = append(byAsset[asset], leg)
	}
	var created []Sweep
	for _, asset := range assets {
		legs := byAsset[asset]
		for len(legs) > 0 && room > 0 {
			n := min(len(legs), c.SweepBatch)
			batch := legs[:n]
			legs = legs[n:]
			total := new(big.Int)
			for _, l := range batch {
				total.Add(total, l.Amount)
			}
			id := "sw-" + uuid.NewString()
			err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `INSERT INTO sweeps (id, chain, asset, from_address, to_partition_id, amount, status)
					VALUES ($1,$2,$3,$4,$5,$6::numeric,'planned')`, id, c.Chain, asset, batch[0].From, c.SinkPartition(asset), total.String()); err != nil {
					return err
				}
				for i, l := range batch {
					if _, err := tx.Exec(ctx, `INSERT INTO sweep_items (sweep_id, address, amount, close_account, ord) VALUES ($1,$2,$3::numeric,$4,$5)`,
						id, l.From, l.Amount.String(), l.Close, i); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return created, err
			}
			created = append(created, Sweep{ID: id, Asset: asset, From: batch[0].From, PartitionID: c.SinkPartition(asset), Amount: total, Status: "planned"})
			room--
		}
	}
	return created, nil
}
