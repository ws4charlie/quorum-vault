package btc

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
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
