package btc

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

func (e *wEnv) cpfp() (chain.UnsignedTx, error) {
	var u chain.UnsignedTx
	err := e.commit(func(tx pgx.Tx) (err error) {
		u, err = e.a.BuildCPFP(context.Background(), tx, "withdrawal", "w1")
		return
	})
	return u, err
}

// sent marks every attempt of w1 as handed to the node (the builders look only at those).
func (e *wEnv) sent() {
	e.t.Helper()
	if _, err := e.a.pool.Exec(context.Background(), `UPDATE btc_attempts SET broadcast_at = now() WHERE chain='btc-t' AND owner_id='w1' AND broadcast_at IS NULL`); err != nil {
		e.t.Fatal(err)
	}
}

// stuckParent builds a withdrawal paying at 10 sat/vB and marks it sent, then lets the market rise to rate: the parent is now too cheap.
func (e *wEnv) stuckParent(rate uint64) (Payload, *Unsigned, uint64) {
	e.t.Helper()
	e.fund(100_000)
	u, err := e.build("w1", 40_000, true)
	if err != nil {
		e.t.Fatal(err)
	}
	e.sent()
	p := e.payload(u)
	b, _ := BuildUnsigned(p, e.a.acct)
	e.a.cfg.FallbackFeeRate = rate
	return p, b, e.fee(b.TxID)
}

// The child spends the parent's change, one input, and pays it all back to the shard in one output. Its fee lifts the package to the market rate, and
// a second build is a bump of the same child: the same input, a fee that satisfies BIP125 over the first.
func TestBuildCPFPChildShapeAndFee(t *testing.T) {
	e := newWEnv(t)
	pp, pb, pf := e.stuckParent(20)
	vp := uint64(EstimateVSize(pb.Tx))
	u, err := e.cpfp()
	if err != nil {
		t.Fatal(err)
	}
	c := e.payload(u)
	cb, _ := BuildUnsigned(c, e.a.acct)
	vc := uint64(EstimateVSize(cb.Tx))
	change := pp.Outputs[1]
	if len(c.Inputs) != 1 || c.Inputs[0].TxID != pb.TxID || c.Inputs[0].Vout != 1 || c.Inputs[0].Value != change.Value || PathString(c.Inputs[0].Path) != "1/0" {
		t.Fatalf("the child must spend the parent's change: %+v", c.Inputs)
	}
	if len(c.Outputs) != 1 || c.Outputs[0].Address != e.hot {
		t.Fatalf("the child pays the shard, nothing else: %+v", c.Outputs)
	}
	fee := e.fee(cb.TxID)
	if c.Outputs[0].Value != change.Value-fee {
		t.Fatalf("output %d, want %d", c.Outputs[0].Value, change.Value-fee)
	}
	if want := 20*(vp+vc) - pf; fee != want {
		t.Fatalf("fee %d, want %d: the package (%d + %d vbytes) should pay 20 sat/vB", fee, want, vp, vc)
	}
	var kind string
	e.a.pool.QueryRow(context.Background(), `SELECT kind FROM btc_attempts WHERE chain='btc-t' AND txid=$1`, cb.TxID).Scan(&kind)
	if kind != "cpfp" {
		t.Fatalf("kind %q", kind)
	}
	e.sent()
	// The next build is a bump of the child (one child per parent), within the room.
	e.a.cfg.FallbackFeeRate = 30
	u2, err := e.cpfp()
	if err != nil {
		t.Fatal(err)
	}
	c2 := e.payload(u2)
	b2, _ := BuildUnsigned(c2, e.a.acct)
	fee2 := e.fee(b2.TxID)
	if !sameInput(c2.Inputs[0], c.Inputs[0]) || len(c2.Inputs) != 1 {
		t.Fatalf("the bump must spend the same input: %+v", c2.Inputs)
	}
	if fee2 < (fee*115+99)/100 || fee2 < fee+vc {
		t.Fatalf("bump fee %d over %d: BIP125 wants +15%% and +%d", fee2, fee, vc)
	}
	if got := CPFPRoom(25_000, 50, pf, vp, vc); fee2 > got {
		t.Fatalf("fee %d is over the room %d", fee2, got)
	}
}

// A parent that already pays the cap rate leaves a child no room: the package can never be above max_fee_rate and the parent is already there. This is
// why CPFP starts when RBF has nothing left, not at the cap.
func TestBuildCPFPNoRoomAtTheCap(t *testing.T) {
	e := newWEnv(t)
	e.fund(1_000_000)
	if _, err := e.build("w1", 40_000, true); err != nil {
		t.Fatal(err)
	}
	e.sent()
	for i := 0; i < 40; i++ { // bump until the ceiling
		if _, err := e.replace(); err != nil {
			break
		}
		e.sent()
	}
	e.a.cfg.FallbackFeeRate = 50
	_, err := e.cpfp()
	if !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("a child of a parent at the cap: %v", err)
	}
}

// A parent that never reached the node, one with no change, one being cancelled, and an owner of a kind without change are refused or unsupported.
func TestBuildCPFPRefusals(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	if _, err := e.build("w1", 40_000, true); err != nil {
		t.Fatal(err)
	}
	e.a.cfg.FallbackFeeRate = 30
	if _, err := e.cpfp(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("a parent that was never sent: %v", err)
	}
	e.sent()
	e.rewriteLast(func(p *Payload) { p.Outputs = p.Outputs[:1] })
	if _, err := e.cpfp(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("no change: %v", err)
	}
	err := e.commit(func(tx pgx.Tx) error {
		_, err := e.a.BuildCPFP(context.Background(), tx, "sweep", "s1")
		return err
	})
	if !errors.Is(err, chain.ErrNotSupported) {
		t.Fatalf("a sweep has no change: %v", err)
	}
	e2 := newWEnv(t)
	e2.stuckParent(20)
	if _, err := e2.cancel(); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.cpfp(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("a child while a cancel is in progress: %v", err)
	}
}

// Once a child was sent the parent is not replaced; a cancel is still built and pays more than the parent and the child together, since it evicts both.
func TestCPFPBlocksRBFButNotCancel(t *testing.T) {
	e := newWEnv(t)
	_, pb, pf := e.stuckParent(20)
	u, err := e.cpfp()
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := BuildUnsigned(e.payload(u), e.a.acct)
	cf := e.fee(cb.TxID)
	if _, err := e.replace(); err != nil {
		t.Fatalf("an unsent child does not stop a replacement: %v", err)
	}
	e = newWEnv(t)
	_, pb, pf = e.stuckParent(20)
	u, _ = e.cpfp()
	cb, _ = BuildUnsigned(e.payload(u), e.a.acct)
	cf = e.fee(cb.TxID)
	e.sent()
	if _, err := e.replace(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("the parent was replaced under its child: %v", err)
	}
	uc, err := e.cancel()
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := BuildUnsigned(e.payload(uc), e.a.acct)
	if got := e.fee(cc.TxID); got < pf+cf+uint64(EstimateVSize(cc.Tx)) {
		t.Fatalf("the cancel pays %d; it evicts a parent (%d) and a child (%d) and must pay more than both plus its own relay cost", got, pf, cf)
	}
	_ = pb
}

// The owner is decided only when the child is: the parent in a block with the child still unconfirmed is open (and says there is a child), and then the
// parent confirms with its fee and the child's together. Settling replaces the parent's change by the child's output.
func TestCPFPOutcomeFeeAndSettle(t *testing.T) {
	e := newWEnv(t)
	pp, pb, pf := e.stuckParent(20)
	u, err := e.cpfp()
	if err != nil {
		t.Fatal(err)
	}
	cp := e.payload(u)
	cb, _ := BuildUnsigned(cp, e.a.acct)
	cf := e.fee(cb.TxID)
	e.sent()
	ctx := context.Background()

	e.node.txs[pb.TxID], e.node.txs[cb.TxID] = 0, 0
	oc, err := e.a.Outcome(ctx, "withdrawal", "w1")
	if err != nil || oc.State != chain.OutcomeOpen || !oc.Child {
		t.Fatalf("both in the mempool: %+v %v", oc, err)
	}
	e.node.txs[pb.TxID] = 2 // the parent is deep, the child is not mined yet
	if oc, err = e.a.Outcome(ctx, "withdrawal", "w1"); err != nil || oc.State != chain.OutcomeOpen {
		t.Fatalf("the parent without its child must stay open: %+v %v", oc, err)
	}
	e.node.txs[cb.TxID] = 2
	if oc, err = e.a.Outcome(ctx, "withdrawal", "w1"); err != nil || oc.State != chain.OutcomeConfirmed || oc.Hash != pb.TxID || oc.Kind != chain.AttemptSend {
		t.Fatalf("both deep: %+v %v", oc, err)
	}
	if fee, _ := e.a.TxFee(ctx, pb.TxID); fee.Uint64() != pf+cf {
		t.Fatalf("the pair paid %d, want %d + %d", fee.Uint64(), pf, cf)
	}
	if fee, _ := e.a.TxFee(ctx, cb.TxID); fee.Uint64() != cf {
		t.Fatalf("the child alone paid %d, want %d", fee.Uint64(), cf)
	}
	tx, _ := e.a.pool.Begin(ctx)
	if err := e.a.Settle(ctx, tx, "withdrawal", "w1", pb.TxID); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	var n int
	e.a.pool.QueryRow(ctx, `SELECT count(*) FROM btc_utxos WHERE chain='btc-t' AND txid=$1`, pb.TxID).Scan(&n)
	if n != 0 {
		t.Fatalf("the parent's change became a coin (%d rows) though the child spent it", n)
	}
	var v int64
	var st string
	if err := e.a.pool.QueryRow(ctx, `SELECT value, status FROM btc_utxos WHERE chain='btc-t' AND txid=$1 AND vout=0`, cb.TxID).Scan(&v, &st); err != nil || st != "available" || uint64(v) != cp.Outputs[0].Value {
		t.Fatalf("the child's output must be an available coin of %d: %d %s %v", cp.Outputs[0].Value, v, st, err)
	}
	var settled bool
	e.a.pool.QueryRow(ctx, `SELECT settled_at IS NOT NULL FROM btc_attempts WHERE chain='btc-t' AND txid=$1`, cb.TxID).Scan(&settled)
	if !settled {
		t.Fatal("the child attempt must be settled with its parent")
	}
	_ = pp
}

// A child that never confirmed (a cancel replaced the parent) books nothing: the cancel decides the owner, and no coin comes from the child.
func TestCPFPCancelWinsAndChildBooksNothing(t *testing.T) {
	e := newWEnv(t)
	_, pb, _ := e.stuckParent(20)
	u, _ := e.cpfp()
	cb, _ := BuildUnsigned(e.payload(u), e.a.acct)
	e.sent()
	uc, err := e.cancel()
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := BuildUnsigned(e.payload(uc), e.a.acct)
	e.sent()
	ctx := context.Background()
	e.node.txs[cc.TxID] = 2 // the cancel confirmed; the parent and the child are gone from the node
	oc, err := e.a.Outcome(ctx, "withdrawal", "w1")
	if err != nil || oc.State != chain.OutcomeConfirmed || oc.Kind != chain.AttemptCancel || oc.Hash != cc.TxID {
		t.Fatalf("%+v %v", oc, err)
	}
	if fee, _ := e.a.TxFee(ctx, cc.TxID); fee.Uint64() != e.fee(cc.TxID) {
		t.Fatalf("the cancel's cost includes a child that never mined: %d", fee.Uint64())
	}
	tx, _ := e.a.pool.Begin(ctx)
	if err := e.a.Settle(ctx, tx, "withdrawal", "w1", cc.TxID); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	var n int
	e.a.pool.QueryRow(ctx, `SELECT count(*) FROM btc_utxos WHERE chain='btc-t' AND txid IN ($1,$2)`, cb.TxID, pb.TxID).Scan(&n)
	if n != 0 {
		t.Fatalf("%d coins from the evicted parent or child", n)
	}
}

// The consumed check looks at the owner's own transaction, not at the child: the child's input (an unconfirmed change) is not on the chain yet.
func TestCPFPChildInputIsNotAForeignSpend(t *testing.T) {
	e := newWEnv(t)
	_, pb, _ := e.stuckParent(20)
	u, _ := e.cpfp()
	cb, _ := BuildUnsigned(e.payload(u), e.a.acct)
	e.sent()
	e.node.txs[pb.TxID], e.node.txs[cb.TxID] = 0, 0
	e.node.spent[pb.TxID+":1"] = true // gettxout without the mempool knows nothing of the parent's change
	oc, err := e.a.Outcome(context.Background(), "withdrawal", "w1")
	if err != nil || oc.State != chain.OutcomeOpen {
		t.Fatalf("%+v %v", oc, err)
	}
}
