package btc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// depositAddr registers customer i's deposit address and returns it.
func (e *wEnv) depositAddr(i int) string {
	e.t.Helper()
	addr, err := e.a.acct.Address([]uint32{BranchDeposit, uint32(i)})
	if err != nil {
		e.t.Fatal(err)
	}
	cust := fmt.Sprintf("cs%d", i)
	e.a.pool.Exec(context.Background(), `INSERT INTO customers (id, entity) VALUES ($1,'qv-us') ON CONFLICT DO NOTHING`, cust)
	if _, err := e.a.pool.Exec(context.Background(), `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ($1,'btc-t',$2,$3,'xpub') ON CONFLICT DO NOTHING`, cust, addr, i); err != nil {
		e.t.Fatal(err)
	}
	return addr
}

// recordDeposit books a credited deposit output through the adapter's recorder, as the scan transaction does.
func (e *wEnv) recordDeposit(addr string, value int64) string {
	e.t.Helper()
	e.n++
	var h [32]byte
	h[0], h[31] = byte(e.n), 0xDD
	id := fmt.Sprintf("%x", h[:])
	tx, err := e.a.pool.Begin(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	d := chain.ObservedDeposit{Chain: "btc-t", Asset: Native, Address: addr, Amount: big.NewInt(value), TxHash: id, DedupKey: "btc-t:" + id + ":0"}
	if err := e.a.RecordDeposit(context.Background(), tx, d); err != nil {
		tx.Rollback(context.Background())
		e.t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *wEnv) buildSweep(id, from string, amount int64) (chain.UnsignedTx, error) {
	e.t.Helper()
	tx, _ := e.a.pool.Begin(context.Background())
	u, err := e.a.BuildSweep(context.Background(), tx, chain.SweepIntent{ID: id, Asset: Native, From: from, ToPartition: wPart, Amount: big.NewInt(amount)})
	if err != nil {
		tx.Rollback(context.Background())
		return u, err
	}
	if err := tx.Commit(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return u, nil
}

// A recorded deposit output is a deposit output: marked, on the deposit branch at its address's index, aimed at the sink shard, and recording twice
// stores it once.
func TestRecordDepositStoresADepositOutput(t *testing.T) {
	e := newWEnv(t)
	addr := e.depositAddr(3)
	id := e.recordDeposit(addr, 50_000)
	var dep bool
	var path, part, address string
	if err := e.a.pool.QueryRow(context.Background(), `SELECT deposit, path, partition_id, address FROM btc_utxos WHERE chain='btc-t' AND txid=$1`, id).Scan(&dep, &path, &part, &address); err != nil {
		t.Fatal(err)
	}
	if !dep || path != "0/3" || part != wPart || address != addr {
		t.Fatalf("deposit %v path %s partition %s address %s", dep, path, part, address)
	}
	tx, _ := e.a.pool.Begin(context.Background())
	d := chain.ObservedDeposit{Chain: "btc-t", Asset: Native, Address: addr, Amount: big.NewInt(50_000), TxHash: id, DedupKey: "btc-t:" + id + ":0"}
	if err := e.a.RecordDeposit(context.Background(), tx, d); err != nil {
		t.Fatal(err)
	}
	tx.Commit(context.Background())
	if n := e.count("available"); n != 1 {
		t.Fatalf("%d outputs after recording twice", n)
	}
}

// Withdrawals never see a deposit output, and sweeps never see a hot one.
func TestHotAndDepositOutputsNeverMix(t *testing.T) {
	e := newWEnv(t)
	addr := e.depositAddr(1)
	e.recordDeposit(addr, 1_000_000)
	if _, err := e.build("w1", 10_000, false); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("a withdrawal with only a deposit output available: %v", err)
	}
	hot := e.fund(1_000_000)
	u, err := e.build("w2", 10_000, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range e.payload(u).Inputs {
		if in.TxID != hot {
			t.Fatalf("a withdrawal spent %s, which is not the hot output", in.TxID)
		}
	}
	// A sweep of the address takes the deposit output and nothing else, even though a hot output is older than none and larger.
	e.fund(5_000_000)
	cands, err := e.a.SweepCandidates(context.Background())
	if err != nil || len(cands) != 1 || cands[0].Address != addr || cands[0].Amount.Int64() != 1_000_000 {
		t.Fatalf("candidates %v %v", cands, err)
	}
	if _, err := e.buildSweep("s1", addr, 6_000_000); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("a sweep asked to move more than the address holds: %v", err)
	}
	if n := e.count("reserved"); n != 1 { // only w2's output; the failed sweep reserved nothing
		t.Fatalf("%d reserved", n)
	}
	su, err := e.buildSweep("s2", addr, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(su)
	if len(p.Inputs) != 1 || PathString(p.Inputs[0].Path) != "0/1" || su.KeyRef.Path != "0/1" {
		t.Fatalf("sweep inputs %+v, key %s", p.Inputs, su.KeyRef.Path)
	}
	sh := e.a.sinkShard()
	if len(p.Outputs) != 1 || p.Outputs[0].Address != sh.address {
		t.Fatalf("sweep outputs %+v", p.Outputs)
	}
	fee := vsize(1, sh.script) * 10
	if p.Outputs[0].Value != 1_000_000-fee {
		t.Fatalf("output %d, want %d", p.Outputs[0].Value, 1_000_000-fee)
	}
}

// One sweep takes an address's oldest outputs up to the input cap (5 here), skips an output that costs more to spend than it carries, and the
// intent's amount must be exactly what was planned.
func TestSweepCandidatesCapDustAndAmount(t *testing.T) {
	e := newWEnv(t)
	addr := e.depositAddr(2)
	e.recordDeposit(addr, 500) // rate 10: spending costs 680, so this never joins
	var want int64
	for i := 0; i < 7; i++ {
		v := int64(100_000 * (i + 1))
		e.recordDeposit(addr, v)
		if i < 5 {
			want += v
		}
	}
	cands, err := e.a.SweepCandidates(context.Background())
	if err != nil || len(cands) != 1 {
		t.Fatalf("%v %v", cands, err)
	}
	if cands[0].Amount.Int64() != want {
		t.Fatalf("candidate %d, want the oldest five %d", cands[0].Amount.Int64(), want)
	}
	fee, err := e.a.EstimateSweepFee(context.Background(), chain.SweepIntent{From: addr, Amount: cands[0].Amount})
	if err != nil || fee.Uint64() != vsize(5, e.a.sinkShard().script)*10 {
		t.Fatalf("fee %v %v", fee, err)
	}
	if _, err := e.buildSweep("s1", addr, want-1); err == nil { // not a sum of the oldest outputs
		t.Fatal("a sweep built for an amount that is not the oldest outputs' sum")
	}
	if e.count("reserved") != 0 {
		t.Fatalf("%d reserved after a refused build", e.count("reserved"))
	}
	u, err := e.buildSweep("s2", addr, want)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(e.payload(u).Inputs); n != 5 {
		t.Fatalf("%d inputs", n)
	}
	// The second round takes the rest, still without the cheap one.
	cands, _ = e.a.SweepCandidates(context.Background())
	if len(cands) != 1 || cands[0].Amount.Int64() != 600_000+700_000 {
		t.Fatalf("second round %v", cands)
	}
}

// What a sweep moved is the sum of its inputs, at its address; settling it spends the inputs and makes its output an available hot output.
func TestSweepMovedAssetsAndSettle(t *testing.T) {
	e := newWEnv(t)
	addr := e.depositAddr(4)
	e.recordDeposit(addr, 200_000)
	e.recordDeposit(addr, 300_000)
	u, err := e.buildSweep("s1", addr, 500_000)
	if err != nil {
		t.Fatal(err)
	}
	built, _ := BuildUnsigned(e.payload(u), e.a.acct)
	moved, err := e.a.MovedAssets(context.Background(), built.TxID)
	if err != nil || len(moved) != 1 || moved[0].Address != addr || moved[0].Amount.Int64() != 500_000 || moved[0].Asset != Native {
		t.Fatalf("moved %v %v", moved, err)
	}
	fee, err := e.a.TxFee(context.Background(), built.TxID)
	if err != nil || fee.Int64() != 500_000-int64(e.payload(u).Outputs[0].Value) {
		t.Fatalf("fee %v %v", fee, err)
	}
	for i := 0; i < 2; i++ { // twice: settlement is repeatable
		tx, _ := e.a.pool.Begin(context.Background())
		if err := e.a.Settle(context.Background(), tx, "sweep", "s1", built.TxID); err != nil {
			t.Fatal(err)
		}
		tx.Commit(context.Background())
	}
	var dep bool
	var v int64
	if err := e.a.pool.QueryRow(context.Background(), `SELECT deposit, value FROM btc_utxos WHERE chain='btc-t' AND txid=$1 AND vout=0`, built.TxID).Scan(&dep, &v); err != nil {
		t.Fatal(err)
	}
	if dep || v != int64(e.payload(u).Outputs[0].Value) || e.count("spent") != 2 || e.count("available") != 1 {
		t.Fatalf("swept output deposit=%v value=%d spent=%d available=%d", dep, v, e.count("spent"), e.count("available"))
	}
	// The swept output is now spendable by a withdrawal.
	if _, err := e.build("w1", 100_000, true); err != nil {
		t.Fatal(err)
	}
}

// A sweep that needs a bump or a cancel is not built yet: it says so with the typed error that waits with an ALERT and releases nothing.
func TestSweepBumpAndCancelAreRefusedForNow(t *testing.T) {
	e := newWEnv(t)
	addr := e.depositAddr(5)
	e.recordDeposit(addr, 300_000)
	if _, err := e.buildSweep("s1", addr, 300_000); err != nil {
		t.Fatal(err)
	}
	tx, _ := e.a.pool.Begin(context.Background())
	defer tx.Rollback(context.Background())
	if _, err := e.a.BuildReplacement(context.Background(), tx, "sweep", "s1"); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("replacement: %v", err)
	}
	if _, err := e.a.BuildCancel(context.Background(), tx, "sweep", "s1"); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("cancel: %v", err)
	}
}
