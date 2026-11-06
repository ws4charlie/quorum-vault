package btc

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

func (e *wEnv) commit(f func(tx pgx.Tx) error) error {
	e.t.Helper()
	tx, err := e.a.pool.Begin(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	if err := f(tx); err != nil {
		tx.Rollback(context.Background())
		return err
	}
	if err := tx.Commit(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return nil
}

func (e *wEnv) replace() (chain.UnsignedTx, error) {
	var u chain.UnsignedTx
	err := e.commit(func(tx pgx.Tx) (err error) {
		u, err = e.a.BuildReplacement(context.Background(), tx, "withdrawal", "w1")
		return
	})
	return u, err
}

func (e *wEnv) cancel() (chain.UnsignedTx, error) {
	var u chain.UnsignedTx
	err := e.commit(func(tx pgx.Tx) (err error) {
		u, err = e.a.BuildCancel(context.Background(), tx, "withdrawal", "w1")
		return
	})
	return u, err
}

func (e *wEnv) fee(txid string) uint64 {
	var f int64
	e.a.pool.QueryRow(context.Background(), `SELECT fee FROM btc_attempts WHERE chain='btc-t' AND txid=$1`, txid).Scan(&f)
	return uint64(f)
}

// The replacement spends the same inputs, pays the same payment, takes the extra fee from the change, and pays at least the largest of old fee + 15 percent
// and old fee + vsize at 1 sat/vB. Replacements stack: each is built from the newest.
func TestBuildReplacementRule(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	u0, err := e.build("w1", 40_000, true)
	if err != nil {
		t.Fatal(err)
	}
	p0 := e.payload(u0)
	b0, _ := BuildUnsigned(p0, e.a.acct)
	fee0 := e.fee(b0.TxID)
	vs := uint64(EstimateVSize(b0.Tx))

	u1, err := e.replace()
	if err != nil {
		t.Fatal(err)
	}
	p1 := e.payload(u1)
	b1, _ := BuildUnsigned(p1, e.a.acct)
	fee1 := e.fee(b1.TxID)
	if len(p1.Inputs) != len(p0.Inputs) || !sameInput(p1.Inputs[0], p0.Inputs[0]) || p1.Outputs[0] != p0.Outputs[0] || p1.Outputs[1].Address != p0.Outputs[1].Address {
		t.Fatalf("the replacement changed more than the change: %+v vs %+v", p1, p0)
	}
	want := max((fee0*115+99)/100, fee0+vs, 10*vs) // 10 sat/vB is the fallback rate
	if fee1 != want {
		t.Fatalf("fee %d, want %d (old %d, vsize %d)", fee1, want, fee0, vs)
	}
	if p1.Outputs[1].Value != p0.Outputs[1].Value-(fee1-fee0) {
		t.Fatalf("change %d, want %d", p1.Outputs[1].Value, p0.Outputs[1].Value-(fee1-fee0))
	}
	if b1.TxID == b0.TxID {
		t.Fatal("the replacement has the transaction's txid")
	}
	// They stack.
	u2, err := e.replace()
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := BuildUnsigned(e.payload(u2), e.a.acct)
	if e.fee(b2.TxID) <= fee1 {
		t.Fatalf("the second replacement pays %d, not more than %d", e.fee(b2.TxID), fee1)
	}
	if e.count("reserved") != 1 {
		t.Fatalf("%d reserved: a bump must keep the same inputs", e.count("reserved"))
	}
}

// Nothing to pay more from: no change output, change that would fall to dust, a fee above the cap. Each is chain.ErrCannotBump.
func TestBuildReplacementCannotBump(t *testing.T) {
	// No change: the exact amount.
	e := newWEnv(t)
	fee1 := uint64(vsize(1, mustScript(t, e.dest))) * 10
	e.fund(int64(40_000 + fee1))
	if _, err := e.build("w1", 40_000, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.replace(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("no change output: %v", err)
	}
	// Change that would fall to dust.
	e = newWEnv(t)
	fee2 := uint64(vsize(1, mustScript(t, e.dest), mustScript(t, e.hot))) * 10
	e.fund(int64(40_000 + fee2 + 300)) // 300 sats of change, above dust (294), but a bump needs more than 6
	if u, err := e.build("w1", 40_000, true); err != nil || len(e.payload(u).Outputs) != 2 {
		t.Fatalf("setup: %v", err)
	}
	if _, err := e.replace(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("change would fall to dust: %v", err)
	}
	// The fee ceiling (max_fee_rate 50 sat/vB): bump until the next step is above it.
	e = newWEnv(t)
	e.fund(1_000_000)
	if _, err := e.build("w1", 40_000, true); err != nil {
		t.Fatal(err)
	}
	var last error
	for i := 0; i < 40 && last == nil; i++ {
		_, last = e.replace()
	}
	if !errors.Is(last, chain.ErrCannotBump) {
		t.Fatalf("a bump past the ceiling: %v", last)
	}
}

// A cancel spends exactly the attempt's inputs back to the shard in one output, paying more than every attempt so it replaces whichever is pending;
// when it settles, the inputs are spent and its output is available again.
func TestBuildCancelAndSettle(t *testing.T) {
	e := newWEnv(t)
	if _, err := e.cancel(); !errors.Is(err, chain.ErrNotSupported) {
		t.Fatalf("a cancel with no attempt: %v", err)
	}
	e.fund(60_000)
	e.fund(60_000)
	u0, _ := e.build("w1", 90_000, true)
	p0 := e.payload(u0)
	b0, _ := BuildUnsigned(p0, e.a.acct)
	if _, err := e.replace(); err != nil {
		t.Fatal(err)
	}
	top := uint64(0)
	e.a.pool.QueryRow(context.Background(), `SELECT max(fee) FROM btc_attempts WHERE chain='btc-t'`).Scan(&top)
	uc, err := e.cancel()
	if err != nil {
		t.Fatal(err)
	}
	pc := e.payload(uc)
	bc, _ := BuildUnsigned(pc, e.a.acct)
	if len(pc.Inputs) != 2 || !sameInput(pc.Inputs[0], p0.Inputs[0]) || !sameInput(pc.Inputs[1], p0.Inputs[1]) || len(pc.Outputs) != 1 || pc.Outputs[0].Address != e.hot {
		t.Fatalf("cancel payload %+v", pc)
	}
	if e.fee(bc.TxID) < top+uint64(EstimateVSize(bc.Tx)) {
		t.Fatalf("cancel fee %d does not cover the highest attempt fee %d plus its own relay cost", e.fee(bc.TxID), top)
	}
	var kind string
	e.a.pool.QueryRow(context.Background(), `SELECT kind FROM btc_attempts WHERE chain='btc-t' AND txid=$1`, bc.TxID).Scan(&kind)
	if kind != "cancel" {
		t.Fatalf("kind %s", kind)
	}
	if r, _ := e.a.Reservation(context.Background(), e.a.pool, "withdrawal", "w1"); !r.Open || r.Account != e.hot {
		t.Fatalf("reservation %+v", r)
	}
	tx, _ := e.a.pool.Begin(context.Background())
	if err := e.a.Settle(context.Background(), tx, "withdrawal", "w1", bc.TxID); err != nil {
		t.Fatal(err)
	}
	tx.Commit(context.Background())
	if e.count("spent") != 2 || e.count("available") != 1 || e.count("reserved") != 0 {
		t.Fatalf("spent %d available %d reserved %d", e.count("spent"), e.count("available"), e.count("reserved"))
	}
	if _ = b0; false {
		t.Fatal()
	}
}

// Inputs that cannot pay a cancel's fee: chain.ErrCannotBump (the workflow parks).
func TestBuildCancelNeedsInputsThatCanPayIt(t *testing.T) {
	e := newWEnv(t)
	fee1 := uint64(vsize(1, mustScript(t, e.dest))) * 10
	e.fund(int64(300 + fee1)) // an exact payment of 300 sats (just above dust): the inputs hold little beyond it
	if _, err := e.build("w1", 300, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.cancel(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("%v", err)
	}
}

func (e *wEnv) broadcastOne(owner string, amount int64) (txid string, raw []byte) {
	e.t.Helper()
	u, err := e.build(owner, amount, true)
	if err != nil {
		e.t.Fatal(err)
	}
	st, err := e.a.Assemble(u, e.sign(u))
	if err != nil {
		e.t.Fatal(err)
	}
	built, _ := BuildUnsigned(e.payload(u), e.a.acct)
	if _, err := e.a.Broadcast(context.Background(), st); err != nil {
		e.t.Fatal(err)
	}
	return built.TxID, st.Raw
}

// An input of the attempt is spent on chain and none of our attempts is in a block: something we did not make spent it. An input spent by our own
// attempt in a block, or one only our own mempool transaction holds, is not that case.
func TestOutcomeConsumed(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	txid, _ := e.broadcastOne("w1", 40_000)
	ctx := context.Background()
	in := e.payload(mustUnsigned(t, e, txid)).Inputs[0]
	key := fmt.Sprintf("%s:%d", in.TxID, in.Vout)

	e.node.txs[txid] = 0 // in the mempool: it holds the input, the chain still has it
	if o, _ := e.a.Outcome(ctx, "withdrawal", "w1"); o.State != chain.OutcomeOpen {
		t.Fatalf("our own transaction in the mempool: %+v", o)
	}
	e.node.spent[key] = true
	delete(e.node.txs, txid)
	o, err := e.a.Outcome(ctx, "withdrawal", "w1")
	if err != nil || o.State != chain.OutcomeConsumed || o.Detail == "" {
		t.Fatalf("the input was spent by something else: %+v %v", o, err)
	}
	// Our own attempt in a block spent it: waiting for the depth, not consumed.
	e.node.txs[txid] = 1
	if o, _ := e.a.Outcome(ctx, "withdrawal", "w1"); o.State != chain.OutcomeOpen {
		t.Fatalf("our attempt is in a block: %+v", o)
	}
	e.node.txs[txid] = 2
	if o, _ := e.a.Outcome(ctx, "withdrawal", "w1"); o.State != chain.OutcomeConfirmed {
		t.Fatalf("at the spend depth: %+v", o)
	}
}

func mustUnsigned(t *testing.T, e *wEnv, txid string) chain.UnsignedTx {
	var raw []byte
	if err := e.a.pool.QueryRow(context.Background(), `SELECT payload FROM btc_attempts WHERE chain='btc-t' AND txid=$1`, txid).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return chain.UnsignedTx{Payload: raw}
}

// A confirmed cancel of ours is the outcome, and is not the consumed case.
func TestOutcomeCancelConfirmed(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	e.broadcastOne("w1", 40_000)
	uc, err := e.cancel()
	if err != nil {
		t.Fatal(err)
	}
	st, err := e.a.Assemble(uc, e.sign(uc))
	if err != nil {
		t.Fatal(err)
	}
	built, _ := BuildUnsigned(e.payload(uc), e.a.acct)
	e.a.Broadcast(context.Background(), st)
	for _, in := range e.payload(uc).Inputs {
		e.node.spent[fmt.Sprintf("%s:%d", in.TxID, in.Vout)] = true
	}
	e.node.txs[built.TxID] = 2
	o, err := e.a.Outcome(context.Background(), "withdrawal", "w1")
	if err != nil || o.State != chain.OutcomeConfirmed || o.Kind != chain.AttemptCancel || o.Hash != built.TxID {
		t.Fatalf("%+v %v", o, err)
	}
}

// A transaction the node forgot (it is not in the mempool or a block) is sent again, but not on every poll.
func TestOutcomeRebroadcastsAForgottenTransaction(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	txid, _ := e.broadcastOne("w1", 40_000)
	ctx := context.Background()
	if len(e.node.sent) != 1 {
		t.Fatalf("sent %d", len(e.node.sent))
	}
	// Just sent: not again.
	e.a.Outcome(ctx, "withdrawal", "w1")
	if len(e.node.sent) != 1 {
		t.Fatalf("resent at once: %d", len(e.node.sent))
	}
	// A while later, and the node does not know it: sent again, once.
	e.a.pool.Exec(ctx, `UPDATE btc_attempts SET last_sent_at = now() - interval '1 minute' WHERE txid=$1`, txid)
	e.a.Outcome(ctx, "withdrawal", "w1")
	e.a.Outcome(ctx, "withdrawal", "w1")
	if len(e.node.sent) != 2 {
		t.Fatalf("forgotten transaction was sent %d times", len(e.node.sent))
	}
	// If the node knows it, it is not sent.
	e.node.txs[txid] = 0
	e.a.pool.Exec(ctx, `UPDATE btc_attempts SET last_sent_at = now() - interval '1 minute' WHERE txid=$1`, txid)
	e.a.Outcome(ctx, "withdrawal", "w1")
	if len(e.node.sent) != 2 {
		t.Fatalf("a transaction the node knows was sent again")
	}
}

func TestClassifySend(t *testing.T) {
	for _, tc := range []struct {
		code int
		msg  string
		want error // nil means success
		kind string
	}{
		{-27, "Transaction already in block chain", nil, "success"},
		{-26, "txn-already-in-mempool", nil, "success"},
		{-26, "txn-already-known", nil, "success"},
		{-25, "bad-txns-inputs-missingorspent", chain.ErrInputsSpent, "spent"},
		{-25, "Missing inputs", chain.ErrInputsSpent, "spent"},
		{-26, "min relay fee not met, 100 < 141", chain.ErrBroadcastStuck, "stuck"},
		{-26, "mempool min fee not met", chain.ErrBroadcastStuck, "stuck"},
		{-26, "insufficient fee, rejecting replacement abc", chain.ErrBroadcastStuck, "stuck"},
		{-26, "txn-mempool-conflict", chain.ErrBroadcastStuck, "stuck"},
		{-26, "something new", chain.ErrBroadcastStuck, "stuck"},
	} {
		got := classifySend(&RPCError{Code: tc.code, Message: tc.msg})
		if tc.want == nil && got != nil || tc.want != nil && !errors.Is(got, tc.want) {
			t.Errorf("%d %q: %v, want %s", tc.code, tc.msg, got, tc.kind)
		}
	}
	// A transport error is not a judgement of the node: it is returned as it is, to be retried.
	plain := errors.New("connection refused")
	if got := classifySend(plain); !errors.Is(got, plain) || errors.Is(got, chain.ErrBroadcastStuck) {
		t.Errorf("transport error: %v", got)
	}
}

// An output the chain no longer has means something else spent it: nothing is released (the reservation stays open and the owner is parked), where
// without that the outputs go back to available.
func TestReleaseRefusesWhenTheChainLostAnOutput(t *testing.T) {
	e := newWEnv(t)
	gone := e.fund(100_000)
	e.fund(100_000)
	if _, err := e.build("w1", 150_000, true); err != nil {
		t.Fatal(err)
	}
	e.node.spent[gone+":0"] = true
	e.commit(func(tx pgx.Tx) error { return e.a.ReleaseUnsigned(context.Background(), tx, "withdrawal", "w1") })
	if e.count("reserved") != 2 || e.count("available") != 0 {
		t.Fatalf("reserved %d available %d: an output the chain lost must keep the reservation open", e.count("reserved"), e.count("available"))
	}
	if r, _ := e.a.Reservation(context.Background(), e.a.pool, "withdrawal", "w1"); !r.Open {
		t.Fatal("the reservation closed")
	}
	delete(e.node.spent, gone+":0")
	e.commit(func(tx pgx.Tx) error { return e.a.ReleaseUnsigned(context.Background(), tx, "withdrawal", "w1") })
	if e.count("available") != 2 {
		t.Fatalf("available %d once the chain has them", e.count("available"))
	}
}

func sameInput(a, b PayloadInput) bool {
	return a.TxID == b.TxID && a.Vout == b.Vout && a.Value == b.Value && PathString(a.Path) == PathString(b.Path) && a.Sequence == b.Sequence
}

// A block that holds our own attempt is mined between the moment the outcome reads the attempts and the moment it reads the input: the input is spent
// on chain, but by us. That is not the consumed case (a real crash test hit this race).
func TestOutcomeNotConsumedWhenOurOwnBlockArrivesBetweenTheReads(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	txid, _ := e.broadcastOne("w1", 40_000)
	in := e.payload(mustUnsigned(t, e, txid)).Inputs[0]
	e.node.txs[txid] = 0
	e.node.beforeTxOut = func() { // called with the node's lock held: touch the maps only
		e.node.spent[fmt.Sprintf("%s:%d", in.TxID, in.Vout)] = true
		e.node.txs[txid] = 1
	}
	o, err := e.a.Outcome(context.Background(), "withdrawal", "w1")
	if err != nil || o.State != chain.OutcomeOpen {
		t.Fatalf("%+v %v", o, err)
	}
}
