package btce2e

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// withdrawalSystem is a system with the whole withdrawal path, a funded hot shard, and a customer with a deposit.
func withdrawalSystem(t *testing.T, o opts, hotSats, customerSats int64) *system {
	t.Helper()
	o.withdraw = true
	s := newSystem(t, o)
	s.cf.Withdrawal.HotWait = "3m"
	s.fundHot(hotSats)
	if customerSats > 0 {
		s.deposit("c1", customerSats)
	}
	return s
}

// settle waits for the withdrawal's broadcast, mines to the spend depth, and waits until it is settled.
func (s *system) settle(id string) wd {
	s.t.Helper()
	w := s.waitWd(id, "broadcast", 60*time.Second)
	s.node.mine(2, "")
	var tx struct {
		Confirmations int `json:"confirmations"`
	}
	s.waitFor(20*time.Second, "the transaction has 2 confirmations on the node", func() bool {
		return s.node.root.Call(s.ctx, &tx, "getrawtransaction", w.Tx, true) == nil && tx.Confirmations >= 2
	})
	return s.waitWd(id, "confirmed", 60*time.Second)
}

// keepMining mines a block every 700 ms until stopped, for tests that wait on a chain of withdrawals.
func (s *system) keepMining() (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case <-time.After(700 * time.Millisecond):
				var h []string
				_ = s.node.root.Call(context.Background(), &h, "generatetoaddress", 1, s.node.miner)
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

func (s *system) attemptInputs() map[string]int {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	used := map[string]int{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			s.t.Fatal(err)
		}
		p, err := btc.DecodePayload(raw)
		if err != nil {
			s.t.Fatal(err)
		}
		for _, in := range p.Inputs {
			used[fmt.Sprintf("%s:%d", in.TxID, in.Vout)]++
		}
	}
	return used
}

func (s *system) withdrawalFee(id string) int64 {
	var f int64
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(fee,0) FROM withdrawals WHERE id=$1`, id).Scan(&f); err != nil {
		s.t.Fatal(err)
	}
	return f
}

// A full withdrawal with change: requested, approved by the automated key, built, signed by MPC through the gateway and party B's cosigner,
// broadcast, confirmed to the spend depth and settled. The ledger is balanced, the payment arrived, and the change is spendable by the next one.
func TestWithdrawalWithChangeThenTheChangeIsSpent(t *testing.T) {
	s := withdrawalSystem(t, opts{}, 100_000_000, 30_000_000)
	if got := s.hotPosted().Int64(); got != -100_000_000 {
		t.Fatalf("hot mirror %d after funding", got)
	}
	if got := s.posted("opfund:" + s.chain + ":BTC").Int64(); got != 100_000_000 {
		t.Fatalf("operator funding %d", got)
	}
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	if w.Code != 201 {
		t.Fatalf("request: %d %v", w.Code, w.Raw)
	}
	done := s.settle(w.ID)
	fee := s.withdrawalFee(w.ID)
	if fee <= 0 {
		t.Fatalf("fee %d", fee)
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("the destination received %d", got)
	}
	if a := s.available("c1").Int64(); a != 20_000_000 {
		t.Fatalf("customer has %d", a)
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+10_000_000+fee {
		t.Fatalf("hot mirror %d, want %d", got, -100_000_000+10_000_000+fee)
	}
	if s.utxoCount("spent") != 1 || s.utxoCount("available") != 1 || s.utxoCount("reserved") != 0 || s.utxoValue("available") != 100_000_000-10_000_000-fee {
		t.Fatalf("outputs: spent %d available %d (%d sats) reserved %d", s.utxoCount("spent"), s.utxoCount("available"), s.utxoValue("available"), s.utxoCount("reserved"))
	}
	s.ledgerOK()
	_ = done
	// The scan reaches the withdrawal's block at the deposit depth: our own change is not funding, and is not booked twice.
	s.node.mine(8, "")
	s.waitFor(60*time.Second, "the scan is past the withdrawal", func() bool { return s.cursor() >= s.node.height()-5 })
	if got := s.posted("opfund:" + s.chain + ":BTC").Int64(); got != 100_000_000 {
		t.Fatalf("operator funding %d after the scan saw our change", got)
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit`, s.chain); n != 2 {
		t.Fatalf("%d outputs: our change was recorded twice or as funding", n)
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+10_000_000+fee {
		t.Fatalf("hot mirror %d after the scan, want %d", got, -100_000_000+10_000_000+fee)
	}

	// The change is spendable by the next withdrawal (it is the only output).
	dest2 := s.node.fresh()
	w2 := s.withdraw("ini", "k2", "c1", dest2, 20_000_000)
	s.settle(w2.ID)
	if got := s.received(dest2, 1); got != 20_000_000 {
		t.Fatalf("the second destination received %d", got)
	}
	if s.utxoCount("spent") != 2 || s.utxoCount("available") != 1 {
		t.Fatalf("outputs after the second: spent %d available %d", s.utxoCount("spent"), s.utxoCount("available"))
	}
	if n := s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND broadcast_at IS NOT NULL`, s.chain); n != 2 {
		t.Fatalf("%d attempts for 2 withdrawals", n)
	}
	s.ledgerOK()
}

// Two inputs: the hot shard holds two small outputs, the withdrawal needs both.
func TestTwoInputWithdrawal(t *testing.T) {
	s := withdrawalSystem(t, opts{}, 5_000_000, 20_000_000)
	s.fundHot(5_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 7_000_000)
	s.settle(w.ID)
	if got := s.received(dest, 1); got != 7_000_000 {
		t.Fatalf("received %d", got)
	}
	if s.utxoCount("spent") != 2 {
		t.Fatalf("%d inputs were spent, want both", s.utxoCount("spent"))
	}
	var n int
	s.pool.QueryRow(s.ctx, `SELECT jsonb_array_length(payload->'inputs') FROM btc_attempts WHERE chain=$1`, s.chain).Scan(&n)
	if n != 2 {
		t.Fatalf("the transaction has %d inputs", n)
	}
	s.ledgerOK()
}

// feeOf is the fee the builder pays at the fallback rate (5 sat/vB) for a transaction with one P2WPKH input and the given number of P2WPKH outputs
// (the payment, and change if any). It needs the node to have no fee estimate, which a fresh regtest node has.
func feeOf(s *system, outputs int) int64 {
	var est struct {
		FeeRate float64  `json:"feerate"`
		Errors  []string `json:"errors"`
	}
	if err := s.node.root.Call(s.ctx, &est, "estimatesmartfee", 2); err == nil && est.FeeRate > 0 && len(est.Errors) == 0 {
		s.t.Skip("the node has a fee estimate: the exact-amount cases assume the fallback rate")
	}
	script, _ := btc.OutputScript(s.hotAddr, s.acct.Params)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	for i := 0; i < outputs; i++ {
		tx.AddTxOut(wire.NewTxOut(1, script))
	}
	return btc.EstimateVSize(tx) * 5
}

// An exact amount leaves nothing for change: one output. Change at dust goes to the fee, and the fee actually paid is booked.
func TestExactAmountAndChangeAtDust(t *testing.T) {
	s := newSystem(t, opts{withdraw: true})
	s.cf.Withdrawal.HotWait = "3m"
	fee1, fee2 := feeOf(s, 1), feeOf(s, 2)
	s.fundHot(10_000_000 + fee1) // exactly the payment and the fee of a one-output transaction
	s.deposit("c1", 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "exact", "c1", dest, 10_000_000)
	s.settle(w.ID)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	if s.utxoCount("available") != 0 || s.withdrawalFee(w.ID) != fee1 {
		t.Fatalf("exact: available %d, fee %d (want %d)", s.utxoCount("available"), s.withdrawalFee(w.ID), fee1)
	}
	var outs int
	s.pool.QueryRow(s.ctx, `SELECT jsonb_array_length(payload->'outputs') FROM btc_attempts WHERE chain=$1 AND owner_id=$2`, s.chain, w.ID).Scan(&outs)
	if outs != 1 {
		t.Fatalf("%d outputs, want one", outs)
	}
	// Dust: 100 sats would be left over, below the dust limit: they are fee.
	s.fundHot(10_000_000 + fee2 + 100)
	w2 := s.withdraw("ini", "dust", "c1", dest, 10_000_000)
	s.settle(w2.ID)
	if got := s.withdrawalFee(w2.ID); got != fee2+100 {
		t.Fatalf("dust: fee %d, want %d", got, fee2+100)
	}
	if s.utxoCount("available") != 0 {
		t.Fatalf("dust change became an output")
	}
	s.ledgerOK()
}

// Many withdrawals against few outputs: none picks an output twice, none fails; each builds, or waits for an output to free up (change of an
// earlier one) and then builds.
func TestManyConcurrentWithdrawalsAgainstFewOutputs(t *testing.T) {
	s := newSystem(t, opts{withdraw: true})
	s.cf.Withdrawal.HotWait = "4m"
	for i := 0; i < 3; i++ {
		s.fundHot(30_000_000)
	}
	s.deposit("c1", 100_000_000)
	stop := s.keepMining()
	defer stop()
	const n = 8
	dests := make([]string, n)
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		dests[i] = s.node.fresh()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := s.withdraw("ini", fmt.Sprintf("k%d", i), "c1", dests[i], 5_000_000)
			ids[i] = w.ID
			if w.Code != 201 {
				t.Errorf("request %d: %d %v", i, w.Code, w.Raw)
			}
		}(i)
	}
	wg.Wait()
	for _, id := range ids {
		if id != "" {
			s.waitWd(id, "confirmed", 4*time.Minute)
		}
	}
	for k, c := range s.attemptInputs() {
		if c != 1 {
			t.Fatalf("output %s is spent by %d transactions", k, c)
		}
	}
	for i, d := range dests {
		if got := s.received(d, 1); got != 5_000_000 {
			t.Fatalf("destination %d received %d", i, got)
		}
	}
	if a := s.available("c1").Int64(); a != 100_000_000-n*5_000_000 {
		t.Fatalf("customer has %d", a)
	}
	if s.utxoCount("reserved") != 0 {
		t.Fatalf("%d outputs are still reserved", s.utxoCount("reserved"))
	}
	s.ledgerOK()
}

// Not enough outputs is not a failure: the ledger says the shard can pay, but its only output is reserved by a withdrawal in flight, so the second
// withdrawal waits (nothing is mined, so the first cannot settle and give its change back) and proceeds when it does.
func TestWithdrawalWaitsForAnOutputAndProceeds(t *testing.T) {
	s := withdrawalSystem(t, opts{}, 50_000_000, 60_000_000)
	d1, d2 := s.node.fresh(), s.node.fresh()
	w1 := s.withdraw("ini", "k1", "c1", d1, 30_000_000)
	s.waitWd(w1.ID, "broadcast", 60*time.Second) // its transaction is in the mempool, unconfirmed
	w2 := s.withdraw("ini", "k2", "c1", d2, 10_000_000)
	// The only output is reserved by w1: w2 neither builds nor fails while nothing is mined.
	s.holds(12*time.Second, "w2 waits", func() bool {
		w := s.getWd(w2.ID)
		return w.Status != "failed" && w.Status != "signing" && w.Status != "broadcast" && w.Status != "confirmed"
	})
	if n := s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND owner_id=$2`, s.chain, w2.ID); n != 0 {
		t.Fatalf("w2 built a transaction while no output was available")
	}
	s.node.mine(2, "") // w1 settles, its change is available
	s.waitWd(w1.ID, "confirmed", 60*time.Second)
	s.settle(w2.ID)
	if s.received(d1, 1) != 30_000_000 || s.received(d2, 1) != 10_000_000 {
		t.Fatalf("received %d and %d", s.received(d1, 1), s.received(d2, 1))
	}
	s.ledgerOK()
}

// The gateway refuses (the destination is not on its list): nothing was signed, the hold is released and the outputs are available again.
func TestRefusedByTheGatewayReleasesTheOutputs(t *testing.T) {
	allowed := "bcrt1qq8j5kay3uhhfdys7g64nljk68ercvre0l570gs"
	s := withdrawalSystem(t, opts{gwDest: []string{allowed}}, 50_000_000, 30_000_000)
	dest := s.node.fresh() // not the allowed one
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	got := s.waitWd(w.ID, "failed", 90*time.Second)
	if got.Reason == "" {
		t.Fatal("no failure reason")
	}
	t.Logf("refused: %s", got.Reason)
	if a := s.available("c1").Int64(); a != 30_000_000 {
		t.Fatalf("customer has %d after the void", a)
	}
	if s.utxoCount("available") != 1 || s.utxoCount("reserved") != 0 || s.utxoCount("spent") != 0 {
		t.Fatalf("outputs: available %d reserved %d spent %d", s.utxoCount("available"), s.utxoCount("reserved"), s.utxoCount("spent"))
	}
	if n := s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND broadcast_at IS NOT NULL`, s.chain); n != 0 {
		t.Fatalf("%d broadcast attempts", n)
	}
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE status='done'`); n != 0 {
		t.Fatalf("%d jobs were signed", n)
	}
	if got := s.received(dest, 0); got != 0 {
		t.Fatalf("the destination received %d", got)
	}
	s.ledgerOK()
	// The outputs are usable: a withdrawal to the allowed address goes through.
	w2 := s.withdraw("ini", "k2", "c1", allowed, 10_000_000)
	s.settle(w2.ID)
}

// A reorganization removes a settled withdrawal for a while. Our own transaction spends only our own outputs, so nobody can double-spend it:
// a reorganization can only delay it. Settlement is at the spend depth (2), books stay as they are, no second payment is made, and when the
// transaction is mined again the payment on chain is the one payment.
func TestReorgRemovesASettledWithdrawalForAWhile(t *testing.T) {
	s := withdrawalSystem(t, opts{}, 50_000_000, 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.settle(w.ID)
	fee := s.withdrawalFee(w.ID)
	txid := s.getWd(w.ID).Tx
	var tx struct {
		BlockHash     string `json:"blockhash"`
		Confirmations int    `json:"confirmations"`
	}
	if err := s.node.root.Call(s.ctx, &tx, "getrawtransaction", txid, true); err != nil || tx.BlockHash == "" {
		t.Fatalf("the transaction is not mined: %v %+v", err, tx)
	}
	hot, avail := s.hotPosted().Int64(), s.utxoCount("available")
	// The block that holds it is removed, and empty blocks replace it: the payment is gone from the chain for a while.
	s.node.invalidate(tx.BlockHash)
	for i := 0; i < 3; i++ {
		var out json.RawMessage
		if err := s.node.root.Call(s.ctx, &out, "generateblock", s.node.fresh(), []string{}); err != nil {
			t.Fatal(err)
		}
	}
	var after struct {
		BlockHash     string `json:"blockhash"`
		Confirmations int    `json:"confirmations"`
	}
	if err := s.node.root.Call(s.ctx, &after, "getrawtransaction", txid, true); err != nil || after.Confirmations != 0 || after.BlockHash != "" {
		t.Fatalf("after the reorganization the transaction should be in the mempool only: %v %+v", err, after)
	}
	if got := s.received(dest, 1); got != 0 {
		t.Fatalf("the destination still shows %d on chain", got)
	}
	// Nothing in the books changes, and no second payment is made.
	s.holds(6*time.Second, "books unchanged while the payment is off the chain", func() bool {
		return s.getWd(w.ID).Status == "confirmed" && s.hotPosted().Int64() == hot && s.utxoCount("available") == avail && s.available("c1").Int64() == 20_000_000
	})
	if n := s.count(`SELECT count(*) FROM withdrawals WHERE chain=$1`, s.chain); n != 1 {
		t.Fatalf("%d withdrawals", n)
	}
	// It is mined again, in the new chain: one payment on chain.
	s.node.mine(3, s.node.fresh())
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("the destination received %d after the transaction was mined again", got)
	}
	if got := s.withdrawalFee(w.ID); got != fee {
		t.Fatalf("fee changed from %d to %d", fee, got)
	}
	// The change, recorded at settlement, is spendable: the next withdrawal uses it.
	w2 := s.withdraw("ini", "k2", "c1", s.node.fresh(), 5_000_000)
	s.settle(w2.ID)
	s.ledgerOK()
	_ = custody.AutoApprover
}
