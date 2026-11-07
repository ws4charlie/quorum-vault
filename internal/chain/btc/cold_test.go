package btc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
)

func (e *wEnv) buildCold(id string, amount int64) (chain.UnsignedTx, error) {
	var u chain.UnsignedTx
	err := e.commit(func(tx pgx.Tx) (err error) {
		u, err = e.a.BuildWithdrawal(context.Background(), tx, chain.WithdrawalIntent{OwnerKind: "to-cold", ID: id, PartitionID: wPart, Asset: "BTC", To: e.dest, Amount: big.NewInt(amount)})
		return
	})
	return u, err
}

// MaxMove is what the oldest max_inputs available outputs can carry after the fee; a reserved output is not counted.
func TestMaxMoveCountsOnlyAvailableOutputsUpToMaxInputs(t *testing.T) {
	e := newWEnv(t) // max_inputs 5, fee rate 10
	if m, err := e.a.MaxMove(context.Background(), wPart); err != nil || m.Sign() != 0 {
		t.Fatalf("empty shard: %v %v", m, err)
	}
	for i := 0; i < 7; i++ {
		e.fund(1_000_000)
	}
	fee := vsize(5, e.a.sinkShard().script, make([]byte, 34)) * 10
	m, err := e.a.MaxMove(context.Background(), wPart)
	if err != nil || m.Uint64() != 5_000_000-fee {
		t.Fatalf("max move %v, want %d (%v)", m, 5_000_000-fee, err)
	}
	// A withdrawal holds two outputs: they are not available to a move.
	if _, err := e.build("w1", 1_500_000, true); err != nil {
		t.Fatal(err)
	}
	m, _ = e.a.MaxMove(context.Background(), wPart)
	if want := 5_000_000 - fee; m.Uint64() != want { // five of the remaining five outputs
		t.Fatalf("max move %v, want %d", m, want)
	}
}

// A move is built like a withdrawal under its own owner kind: shard inputs, the payment first, change back to the shard; it can be bumped (from the
// change) and cancelled (the same inputs back to the shard), and its cancel settles as the move's own attempt.
func TestToColdBuildBumpAndCancel(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	u, err := e.buildCold("m1", 40_000)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(u)
	if p.Outputs[0].Address != e.dest || p.Outputs[0].Value != 40_000 || len(p.Outputs) != 2 || p.Outputs[1].Address != e.hot {
		t.Fatalf("outputs %+v", p.Outputs)
	}
	if e.count("reserved") != 1 {
		t.Fatal("the input was not reserved")
	}
	var kind string
	if err := e.a.pool.QueryRow(context.Background(), `SELECT owner_kind FROM btc_utxos WHERE chain='btc-t' AND status='reserved'`).Scan(&kind); err != nil || kind != "to-cold" {
		t.Fatalf("reserved by %q (%v)", kind, err)
	}
	if err := e.commit(func(tx pgx.Tx) error {
		_, err := e.a.BuildReplacement(context.Background(), tx, "to-cold", "m1")
		return err
	}); err != nil {
		t.Fatalf("bump: %v", err)
	}
	var c chain.UnsignedTx
	if err := e.commit(func(tx pgx.Tx) (err error) {
		c, err = e.a.BuildCancel(context.Background(), tx, "to-cold", "m1")
		return
	}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	cp := e.payload(c)
	bc, _ := BuildUnsigned(cp, e.a.acct)
	if len(cp.Inputs) != 1 || len(cp.Outputs) != 1 || cp.Outputs[0].Address != e.hot {
		t.Fatalf("cancel %+v", cp)
	}
	if err := e.commit(func(tx pgx.Tx) error { return e.a.Settle(context.Background(), tx, "to-cold", "m1", bc.TxID) }); err != nil {
		t.Fatal(err)
	}
	if e.count("spent") != 1 || e.count("available") != 1 || e.count("reserved") != 0 {
		t.Fatalf("spent %d available %d reserved %d", e.count("spent"), e.count("available"), e.count("reserved"))
	}
	// Not enough outputs: the typed error, nothing reserved.
	if _, err := e.buildCold("m2", 10_000_000); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("a move larger than the shard: %v", err)
	}
}

// ---- refills ----

// coldRow inserts an available cold output of the pool's cold address.
func (e *wEnv) coldRow(cold string, value int64) string {
	e.t.Helper()
	e.n++
	var h [32]byte
	h[0], h[31] = byte(e.n), 0xC1
	id := hex.EncodeToString(h[:])
	if _, err := e.a.pool.Exec(context.Background(), `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path, cold, address, created_at) VALUES ('btc-t',$1,0,$2,'','',true,$3, now() + $4::interval)`,
		id, value, cold, fmt.Sprintf("%d seconds", e.n)); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *wEnv) withCold(t *testing.T) string {
	t.Helper()
	k, _ := btcec.NewPrivateKey()
	cold, err := coldsign.BTCAddressOf("regtest", hex.EncodeToString(k.PubKey().SerializeCompressed()))
	if err != nil {
		t.Fatal(err)
	}
	e.a.coldBy["omnibus"], e.a.cold[cold] = cold, "omnibus"
	return cold
}

// BuildRefill takes the oldest cold outputs, pays the shard, returns the change to the cold address; with an exact fit there is no change; when one
// transaction cannot carry the need (max_inputs), the payment is what the inputs hold less the fee.
func TestBuildRefillChangeNoChangeAndTheInputCap(t *testing.T) {
	e := newWEnv(t) // max_inputs 5, rate 10
	cold := e.withCold(t)
	a, b, c := e.coldRow(cold, 10_000_000), e.coldRow(cold, 10_000_000), e.coldRow(cold, 10_000_000)
	r, err := e.a.BuildRefill(context.Background(), chain.RefillBuild{ID: "rf-1", PartitionID: wPart, Need: big.NewInt(15_000_000), Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inputs) != 2 || r.Inputs[0].TxID != a || r.Inputs[1].TxID != b || r.Outputs[0].Address != e.hot || r.Outputs[0].Value != 15_000_000 || len(r.Outputs) != 2 || r.Outputs[1].Address != cold {
		t.Fatalf("request %+v", r)
	}
	fee, _ := r.Fee()
	if want := vsize(2, e.a.shards[0].script, scriptOrDummy(cold, e.a)) * 10; fee != want || r.From != cold || r.Pool != "omnibus" || r.Network != "regtest" {
		t.Fatalf("fee %d want %d, %+v", fee, want, r)
	}
	// The offline signer would take it: the same rules, checked in coldsign's tests; here the core's own caps hold.
	_ = c
	// An exact fit: the leftover is under dust plus the fee of a change output, so it is all fee.
	e2 := newWEnv(t)
	cold2 := e2.withCold(t)
	feeNC := vsize(1, e2.a.shards[0].script) * 10
	e2.coldRow(cold2, int64(5_000_000+feeNC+100))
	r2, err := e2.a.BuildRefill(context.Background(), chain.RefillBuild{ID: "rf-2", PartitionID: wPart, Need: big.NewInt(5_000_000), Revision: 1})
	if err != nil || len(r2.Outputs) != 1 || r2.Outputs[0].Value != 5_000_000 {
		t.Fatalf("no change: %+v %v", r2, err)
	}
	// More need than max_inputs of 1M outputs can carry: the payment is what five hold less the fee.
	e3 := newWEnv(t)
	cold3 := e3.withCold(t)
	for i := 0; i < 8; i++ {
		e3.coldRow(cold3, 1_000_000)
	}
	r3, err := e3.a.BuildRefill(context.Background(), chain.RefillBuild{ID: "rf-3", PartitionID: wPart, Need: big.NewInt(7_000_000), Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	fee3 := vsize(5, e3.a.shards[0].script) * 10
	if len(r3.Inputs) != 5 || len(r3.Outputs) != 1 || r3.Outputs[0].Value != 5_000_000-fee3 {
		t.Fatalf("capped: %d inputs, %+v (fee %d)", len(r3.Inputs), r3.Outputs, fee3)
	}
	// Nothing to give.
	e4 := newWEnv(t)
	e4.withCold(t)
	if _, err := e4.a.BuildRefill(context.Background(), chain.RefillBuild{ID: "rf-4", PartitionID: wPart, Need: big.NewInt(1), Revision: 1}); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("an empty cold address: %v", err)
	}
}

// Cold outputs are never picked by a withdrawal, a sweep or a move to cold, and a refill never picks a hot or deposit output.
func TestColdOutputsStayApartFromHotAndDepositOutputs(t *testing.T) {
	e := newWEnv(t)
	cold := e.withCold(t)
	e.coldRow(cold, 9_000_000)
	if _, err := e.build("w1", 10_000, false); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("a withdrawal over a cold output: %v", err)
	}
	if m, err := e.a.MaxMove(context.Background(), wPart); err != nil || m.Sign() != 0 {
		t.Fatalf("a move to cold sees a cold output: %v %v", m, err)
	}
	addr := e.depositAddr(1)
	if c, _ := e.a.SweepCandidates(context.Background()); len(c) != 0 {
		t.Fatalf("a sweep candidate from a cold output: %v", c)
	}
	_ = addr
	// And the reverse: hot and deposit outputs are not refill inputs.
	e2 := newWEnv(t)
	cold2 := e2.withCold(t)
	e2.fund(5_000_000)
	e2.recordDeposit(e2.depositAddr(2), 5_000_000)
	if _, err := e2.a.BuildRefill(context.Background(), chain.RefillBuild{ID: "rf", PartitionID: wPart, Need: big.NewInt(1_000_000), Revision: 1}); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("a refill over hot and deposit outputs: %v", err)
	}
	_ = cold2
}
