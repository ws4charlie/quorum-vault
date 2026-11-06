package btce2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// sweepSystem is a system with the whole withdrawal path and the sweep planner on, a funded hot shard when hotSats > 0.
func sweepSystem(t *testing.T, o opts, hotSats int64) *system {
	t.Helper()
	o.withdraw, o.sweep = true, true
	s := newSystem(t, o)
	s.cf.Withdrawal.HotWait = "3m"
	if hotSats > 0 {
		s.fundHot(hotSats)
	}
	return s
}

type swp struct {
	ID, Status, From, Tx, Reason string
	Amount, Moved, Fee           int64
	Inputs                       int
}

func (s *system) sweepRows() []swp {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id, status, from_address, COALESCE(tx_hash,''), COALESCE(failure_reason,''), amount::bigint, COALESCE(moved,0)::bigint, COALESCE(fee,0)::bigint
		FROM sweeps WHERE chain=$1 ORDER BY created_at, id`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	var out []swp
	for rows.Next() {
		var w swp
		if err := rows.Scan(&w.ID, &w.Status, &w.From, &w.Tx, &w.Reason, &w.Amount, &w.Moved, &w.Fee); err != nil {
			rows.Close()
			s.t.Fatal(err)
		}
		out = append(out, w)
	}
	rows.Close()
	for i := range out {
		var raw []byte
		if err := s.pool.QueryRow(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND owner_kind='sweep' AND owner_id=$2 ORDER BY created_at LIMIT 1`, s.chain, out[i].ID).Scan(&raw); err == nil {
			if p, err := btc.DecodePayload(raw); err == nil {
				out[i].Inputs = len(p.Inputs)
			}
		}
	}
	return out
}

func (s *system) sweepsIn(status string) int {
	n := 0
	for _, w := range s.sweepRows() {
		if w.Status == status {
			n++
		}
	}
	return n
}

// untilSweepsConfirmed mines a block every 700 ms until n sweeps are settled.
func (s *system) untilSweepsConfirmed(n int, timeout time.Duration) {
	s.t.Helper()
	stop := s.keepMining()
	defer stop()
	s.waitFor(timeout, fmt.Sprintf("%d sweeps confirmed", n), func() bool {
		for _, w := range s.sweepRows() {
			if w.Status == "failed" {
				s.t.Fatalf("sweep %s failed: %s", w.ID, w.Reason)
			}
		}
		return s.sweepsIn("confirmed") >= n
	})
}

// sinkBalance is what the books say the cell's hot shard holds: the opposite of the hot mirror.
func (s *system) feePosted() int64 { return s.posted("fee:" + s.chain + ":BTC").Int64() }

// The loop closes: a deposit is credited, swept into the hot shard (the full amount leaves the deposit address, the fee is the operator's), and a
// withdrawal then spends the swept output. Ledger and outputs are checked at each step, and the scan does not book the sweep's output as funding.
func TestSweepFullLoopThenAWithdrawalSpendsTheSweptOutput(t *testing.T) {
	s := sweepSystem(t, opts{}, 0)
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: btcAmount(30_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("c1", 30_000_000, 60*time.Second)
	s.untilSweepsConfirmed(1, 90*time.Second)

	sw := s.sweepRows()
	if len(sw) != 1 || sw[0].Amount != 30_000_000 || sw[0].Moved != 30_000_000 || sw[0].Fee <= 0 || sw[0].From != addr || sw[0].Inputs != 1 {
		t.Fatalf("sweeps %+v", sw)
	}
	fee := sw[0].Fee
	// The money is on the hot address, the deposit output is spent, the customer still has all of it.
	if got := s.onChain(s.hotAddr); got != 30_000_000-fee {
		t.Fatalf("the hot address received %d, want %d", got, 30_000_000-fee)
	}
	if got := s.available("c1").Int64(); got != 30_000_000 {
		t.Fatalf("customer has %d", got)
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status='spent'`, s.chain) != 1 ||
		s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status<>'spent'`, s.chain) != 0 ||
		s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND status='available' AND value=$2`, s.chain, 30_000_000-fee) != 1 {
		t.Fatalf("outputs: deposit spent %d, hot available %d", s.utxoCount("spent"), s.utxoCount("available"))
	}
	// Ledger: the full amount moved, the fee is booked to the fee account, the sweep account is empty, the hot mirror is minus what the chain holds.
	if got := s.posted("sweep:" + s.chain + ":BTC").Int64(); got != 0 {
		t.Fatalf("sweep account %d", got)
	}
	if got := s.feePosted(); got != -fee { // the fee account is debited: the operator's cost
		t.Fatalf("fee account %d, want %d", got, -fee)
	}
	if got := s.hotPosted().Int64(); got != -(30_000_000 - fee) {
		t.Fatalf("hot mirror %d, want %d", got, -(30_000_000 - fee))
	}
	if got := s.posted("opfund:" + s.chain + ":BTC").Int64(); got != 0 {
		t.Fatalf("operator funding %d: the sweep's output was booked as funding", got)
	}
	s.ledgerOK()

	// The scan reaches the sweep's block: nothing is booked twice.
	s.node.mine(8, "")
	s.waitFor(60*time.Second, "the scan is past the sweep", func() bool { return s.cursor() >= s.node.height()-5 })
	if got := s.posted("opfund:" + s.chain + ":BTC").Int64(); got != 0 {
		t.Fatalf("operator funding %d after the scan", got)
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1`, s.chain); n != 2 {
		t.Fatalf("%d outputs after the scan, want the spent deposit and the swept one", n)
	}
	s.ledgerOK()

	// A withdrawal spends the swept output (it is the only hot output).
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	if w.Code != 201 {
		t.Fatalf("request: %d %v", w.Code, w.Raw)
	}
	s.settle(w.ID)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("the destination received %d", got)
	}
	var spentFromSweep int
	s.pool.QueryRow(s.ctx, `SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2 AND status='spent'`, s.chain, sw[0].Tx).Scan(&spentFromSweep)
	if spentFromSweep != 1 {
		t.Fatalf("the withdrawal did not spend the sweep's output")
	}
	if a := s.available("c1").Int64(); a != 20_000_000 {
		t.Fatalf("customer has %d", a)
	}
	s.ledgerOK()
}

// Several outputs of one address go in one sweep, and a hot output is never one of its inputs.
func TestSweepSeveralOutputsGoInOneSweepAndNeverTakeAHotOutput(t *testing.T) {
	s := sweepSystem(t, opts{}, 20_000_000)
	hotOut := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit`, s.chain)
	addr := s.newCustomer("c1")
	for _, v := range []int64{1_000_000, 2_000_000, 3_000_000} {
		s.node.pay(map[string]string{addr: btcAmount(v)})
	}
	s.node.mine(6, "")
	s.waitAvailable("c1", 6_000_000, 60*time.Second)
	s.untilSweepsConfirmed(1, 90*time.Second)
	sw := s.sweepRows()
	if len(sw) != 1 || sw[0].Inputs != 3 || sw[0].Amount != 6_000_000 {
		t.Fatalf("sweeps %+v", sw)
	}
	if hotOut != 1 || s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND status='spent'`, s.chain) != 0 {
		t.Fatalf("the funded hot output was touched (hot outputs before %d)", hotOut)
	}
	if got := s.hotPosted().Int64(); got != -20_000_000-(6_000_000-sw[0].Fee) {
		t.Fatalf("hot mirror %d", got)
	}
	s.ledgerOK()
}

// More outputs than max_inputs take two rounds; everything is swept in the end and the totals match.
func TestSweepMoreOutputsThanMaxInputsTakeTwoRounds(t *testing.T) {
	s := sweepSystem(t, opts{maxInputs: 2}, 0)
	addr := s.newCustomer("c1")
	for _, v := range []int64{1_000_000, 2_000_000, 3_000_000} {
		s.node.pay(map[string]string{addr: btcAmount(v)})
	}
	s.node.mine(6, "")
	s.waitAvailable("c1", 6_000_000, 60*time.Second)
	s.untilSweepsConfirmed(2, 120*time.Second)
	sw := s.sweepRows()
	if len(sw) != 2 || sw[0].Inputs != 2 || sw[1].Inputs != 1 || sw[0].Amount+sw[1].Amount != 6_000_000 {
		t.Fatalf("sweeps %+v", sw)
	}
	if got := s.hotPosted().Int64(); got != -(6_000_000 - sw[0].Fee - sw[1].Fee) {
		t.Fatalf("hot mirror %d", got)
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status<>'spent'`, s.chain) != 0 {
		t.Fatal("a deposit output is left")
	}
	s.ledgerOK()
}

// A deposit that lands while a sweep is open (here the spend depth is 8, so the sweep stays open while six more blocks credit it) is not lost: it
// waits, and the next sweep takes it.
func TestSweepDepositLandingWhileASweepIsOpenGoesInTheNext(t *testing.T) {
	s := sweepSystem(t, opts{spendConf: 8}, 0)
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: btcAmount(5_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("c1", 5_000_000, 60*time.Second)
	s.waitFor(60*time.Second, "the first sweep is broadcast", func() bool { return s.sweepsIn("broadcast") == 1 })
	s.node.pay(map[string]string{addr: btcAmount(4_000_000)})
	s.node.mine(6, "") // the sweep has 7 confirmations at most: still open
	s.waitAvailable("c1", 9_000_000, 60*time.Second)
	s.holds(3*time.Second, "one sweep, still open, while the second deposit waits", func() bool {
		return len(s.sweepRows()) == 1 && s.sweepsIn("confirmed") == 0
	})
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status='available'`, s.chain); n != 1 {
		t.Fatalf("%d deposit outputs available while the sweep is open", n)
	}
	s.untilSweepsConfirmed(2, 150*time.Second)
	sw := s.sweepRows()
	if len(sw) != 2 || sw[0].Amount != 5_000_000 || sw[1].Amount != 4_000_000 {
		t.Fatalf("sweeps %+v", sw)
	}
	if got := s.hotPosted().Int64(); got != -(9_000_000 - sw[0].Fee - sw[1].Fee) {
		t.Fatalf("hot mirror %d", got)
	}
	s.ledgerOK()
}

// Below the rule a deposit waits; a second one brings it over and both go in one sweep.
func TestSweepBelowTheRuleWaitsAndTheSecondDepositBringsItOver(t *testing.T) {
	s := sweepSystem(t, opts{minSweep: "1000000"}, 0)
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: btcAmount(600_000)})
	s.node.mine(6, "")
	s.waitAvailable("c1", 600_000, 60*time.Second)
	s.holds(4*time.Second, "no sweep below the floor", func() bool { return len(s.sweepRows()) == 0 })
	s.node.pay(map[string]string{addr: btcAmount(600_000)})
	s.node.mine(6, "")
	s.waitAvailable("c1", 1_200_000, 60*time.Second)
	s.untilSweepsConfirmed(1, 90*time.Second)
	sw := s.sweepRows()
	if len(sw) != 1 || sw[0].Inputs != 2 || sw[0].Amount != 1_200_000 {
		t.Fatalf("sweeps %+v", sw)
	}
	s.ledgerOK()
}

// An output that costs more to spend than it carries never joins a sweep, and an output booked to suspense is never swept: it stays where it is.
func TestSweepLeavesOutAnOutputBelowItsSpendingCostAndNeverTouchesSuspense(t *testing.T) {
	s := sweepSystem(t, opts{fallbackRate: 20, minDeposit: "1000"}, 0)
	addr := s.newCustomer("c1")
	// At 20 sat/vB an input costs 1360 sats: 1200 is credited (above the 1000 minimum) but not worth spending; 800 is below the minimum, so suspense.
	for _, v := range []int64{1_200, 800, 2_000_000} {
		s.node.pay(map[string]string{addr: btcAmount(v)})
	}
	s.node.mine(6, "")
	s.waitAvailable("c1", 2_001_200, 60*time.Second)
	s.untilSweepsConfirmed(1, 90*time.Second)
	sw := s.sweepRows()
	if len(sw) != 1 || sw[0].Inputs != 1 || sw[0].Amount != 2_000_000 {
		t.Fatalf("sweeps %+v", sw)
	}
	s.holds(4*time.Second, "nothing else is swept", func() bool { return len(s.sweepRows()) == 1 })
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND deposit AND status='available' AND value=1200`, s.chain); n != 1 {
		t.Fatalf("the 1200-sat output should wait, %d found", n)
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND value=800`, s.chain); n != 0 {
		t.Fatal("an output in suspense was recorded as spendable")
	}
	if n := s.count(`SELECT count(*) FROM deposits WHERE chain=$1 AND status='suspense' AND amount=800`, s.chain); n != 1 {
		t.Fatalf("%d suspense deposits of 800", n)
	}
	s.ledgerOK()
}
