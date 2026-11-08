package custody_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// A sweep, a hot-to-cold move or a rebalance that the gateway refuses after a nonce was allocated is ended with a cancel transaction at that
// nonce. The cancel pays gas from the shard's address, so its fee must be booked, once, on the partition that paid; Reconcile is clean before the
// cancel mines, while it is mined and not settled, and after.
func TestMinedCancelBooksItsGas(t *testing.T) {
	for _, kind := range []string{"sweep", "to-cold", "rebalance"} {
		t.Run(kind, func(t *testing.T) {
			o := opts{gwRefuse: kind}
			switch kind {
			case "to-cold":
				o.cold = &coldOpts{ethHigh: hugeMark, usdtHigh: hugeMark}
			case "rebalance":
				o.shards = 2
			}
			s := newSystem(t, o)
			t.Cleanup(func() {
				if t.Failed() {
					s.dump("mined cancel of a " + kind)
				}
			})
			table := map[string]string{"sweep": "sweeps", "to-cold": "cold_moves", "rebalance": "rebalance_moves"}[kind]
			var addr string
			s.automine(true)
			switch kind {
			case "sweep":
				a := s.newCustomer("c-cg")
				addr = a.Hex()
				s.sendETH(a, eth(2))
				s.waitAvailable("c-cg", "ETH", eth(2), 30*time.Second)
			case "to-cold":
				free := s.mirrored(custody.HotAccount(s.hotPart("ETH")))
				s.setLimits("ETH", new(big.Int), new(big.Int).Sub(free, big.NewInt(1)), new(big.Int).Sub(free, eth(5)))
			case "rebalance":
				f0 := s.mirrored(custody.HotAccount(s.shardPart("ETH", 0)))
				f1 := s.mirrored(custody.HotAccount(s.shardPart("ETH", 1)))
				s.setRebalance("ETH", new(big.Int).Sub(f0, eth(5)), new(big.Int).Add(f1, eth(5)))
			}
			s.automine(false) // the cancel stays in the mempool until the test mines it
			t.Cleanup(func() { s.automine(true) })
			switch kind {
			case "to-cold":
				if mv, err := s.svc.PlanColdMoves(s.ctx, nullLog); err != nil || len(mv) != 1 {
					t.Fatalf("planned %v, %v", mv, err)
				}
			case "rebalance":
				if mv, err := s.svc.PlanRebalances(s.ctx, nullLog); err != nil || len(mv) != 1 {
					t.Fatalf("planned %v, %v", mv, err)
				}
			}
			s.waitFor(90*time.Second, "the cancel to be broadcast", func() bool {
				return s.count(`SELECT count(*) FROM evm_tx_attempts WHERE kind='cancel'`) >= 1
			})
			s.requireCleanIn("refused, cancel in the mempool", 1)
			s.stopWorker()
			s.automine(true)
			s.mine()
			s.scanUp()
			rep := s.requireCleanIn("cancel mined, not settled", 1)
			if !adjusted(rep, "hot", s.shardAddr[0].Hex()) {
				t.Fatalf("no adjustment for the gas of a mined cancel: %+v", rep.Checks)
			}
			s.startWorker("")
			s.waitFor(90*time.Second, "the item to end failed", func() bool {
				return s.count(`SELECT count(*) FROM `+table+` WHERE status='failed'`) >= 1
			})
			s.scanUp()
			// Fresh items may follow (a planner pass); the one that failed is settled, and the books are exact.
			var cancelTx string
			if err := s.pool.QueryRow(s.ctx, `SELECT tx_hash FROM evm_tx_attempts WHERE kind='cancel' ORDER BY created_at LIMIT 1`).Scan(&cancelTx); err != nil {
				t.Fatal(err)
			}
			if n := s.count(`SELECT count(*) FROM ledger_txns WHERE id=$1`, "fee:"+cancelTx); n != 1 {
				t.Fatalf("the cancel's fee was booked %d times", n)
			}
			var fee string
			if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(fee::text,'') FROM `+table+` WHERE status='failed' ORDER BY created_at LIMIT 1`).Scan(&fee); err != nil || fee == "" || fee == "0" {
				t.Fatalf("fee on the failed row = %q, %v", fee, err)
			}
			_ = addr
			s.reconcileClean()
		})
	}
}
