package sole2e

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
)

// ---- helpers ----

func (s *wdSys) openMoves() int {
	return s.count(`SELECT count(*) FROM cold_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed')`, s.chain) +
		s.count(`SELECT count(*) FROM rebalance_moves WHERE chain=$1 AND status NOT IN ('confirmed','failed')`, s.chain)
}

func (s *wdSys) movesDone(table string) int {
	return s.count(`SELECT count(*) FROM `+table+` WHERE chain=$1 AND status='confirmed'`, s.chain)
}

func (s *wdSys) coldBalance(asset string) uint64 {
	if asset == "SOL" {
		return s.lamports(s.coldAdr)
	}
	return s.tokensOf(s.coldAdr)
}

// shardBalance is what shard i holds on the chain (finalized): lamports, or tokens in its associated token account.
func (s *wdSys) shardBalance(i int, asset string) uint64 {
	if asset == "SOL" {
		return s.lamports(sol.Address(s.hots[i]))
	}
	return s.tokensOf(sol.Address(s.hots[i]))
}

// ---- hot to cold and rebalance ----

func TestColdMovesAndRebalance(t *testing.T) {
	s := newWdSystem(t, wdOpts{
		pool: 4, shards: 2,
		seedSOL: []uint64{30 * oneSOL, oneSOL / 5}, seedTKN: []uint64{8_000 * tknUnit, 0},
		cold: map[string]coldBand{
			"SOL": {low: fmt.Sprint(2 * oneSOL), high: fmt.Sprint(25 * oneSOL), target: fmt.Sprint(12 * oneSOL)},
			"TKN": {low: fmt.Sprint(100 * tknUnit), high: fmt.Sprint(6_000 * tknUnit), target: fmt.Sprint(3_000 * tknUnit)},
		},
		rebalance: map[string]string{"SOL": fmt.Sprint(5 * oneSOL), "TKN": fmt.Sprint(1_000 * tknUnit)},
	})
	stop := s.watchReconcile()
	s.waitFor(240*time.Second, "the cold moves and rebalances to settle", func() bool {
		return s.openMoves() == 0 && s.movesDone("cold_moves") >= 2 && s.movesDone("rebalance_moves") >= 2
	})
	s.holds(6*time.Second, "nothing more is planned once every shard is inside its band", func() bool { return s.openMoves() == 0 })
	if bad := stop(); len(bad) > 0 {
		t.Fatalf("Reconcile failed while the moves ran: %v", bad)
	}
	s.reconcileClean("after the moves")

	// SOL: the excess left the first shard for the pool's cold address, a rebalance fed the dry shard, and the money is all still there
	seedSOL := uint64(30*oneSOL) + oneSOL/5
	sh0, sh1, cold := s.shardBalance(0, "SOL"), s.shardBalance(1, "SOL"), s.coldBalance("SOL")
	t.Logf("SOL: shard 0 %d, shard 1 %d, cold %d", sh0, sh1, cold)
	if sh0+sh1+cold > seedSOL || sh0+sh1+cold < seedSOL-16_000_000 { // fees, the rent of two nonce pools (8 accounts) and of the cold token account
		t.Fatalf("SOL is not conserved: %d on the chain, %d put in", sh0+sh1+cold, seedSOL)
	}
	if sh0 > 25*oneSOL || sh1 < 4*oneSOL || cold < 10*oneSOL {
		t.Fatalf("SOL bands: shard 0 %d (max 25), shard 1 %d (rebalance target 5), cold %d", sh0, sh1, cold)
	}
	// the token: same, with the cold token account opened by the hot shard on the first move
	tok0, tok1, tcold := s.shardBalance(0, "TKN"), s.shardBalance(1, "TKN"), s.coldBalance("TKN")
	t.Logf("TKN: shard 0 %d, shard 1 %d, cold %d", tok0, tok1, tcold)
	if tok0+tok1+tcold != 8_000*tknUnit {
		t.Fatalf("tokens are not conserved: %d on the chain, %d put in", tok0+tok1+tcold, 8_000*tknUnit)
	}
	if tok0 > 6_000*tknUnit || tok1 < 900*tknUnit || tcold == 0 {
		t.Fatalf("TKN bands: shard 0 %d, shard 1 %d, cold %d", tok0, tok1, tcold)
	}

	// noise below the high-water mark moves nothing: a customer withdraws a little
	s.deposit("cold-c", 5*oneSOL, 0)
	s.waitDeposits("cold-c", 5*oneSOL, 0)
	moves := s.movesDone("cold_moves") + s.movesDone("rebalance_moves")
	w := s.request("initiator", "k-noise", "cold-c", "SOL", s.freshAddr(), oneSOL)
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	s.holds(6*time.Second, "a withdrawal inside the band moves nothing", func() bool {
		return s.openMoves() == 0 && s.movesDone("cold_moves")+s.movesDone("rebalance_moves") == moves
	})
	s.reconcileClean("after the withdrawal")
	_ = big.NewInt
}
