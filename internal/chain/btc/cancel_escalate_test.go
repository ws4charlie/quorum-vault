package btc

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// cancelRefuse builds the next cancel (the first one through BuildCancel, then replacements), has the node refuse it with msg, and returns its fee.
func (e *wEnv) cancelRefuse(first bool, msg string) uint64 {
	e.t.Helper()
	var u chain.UnsignedTx
	var err error
	if first {
		u, err = e.cancel()
	} else {
		u, err = e.replace()
	}
	if err != nil {
		e.t.Fatalf("build: %v", err)
	}
	st, err := e.a.Assemble(u, e.sign(u))
	if err != nil {
		e.t.Fatal(err)
	}
	e.node.sendErr = &RPCError{Code: -26, Message: msg}
	defer func() { e.node.sendErr = nil }()
	if _, serr := e.a.Broadcast(context.Background(), st); !errors.Is(serr, chain.ErrBroadcastStuck) {
		e.t.Fatalf("the node refused it: %v", serr)
	}
	return feeOf(e.payload(u))
}

func (e *wEnv) cancelRow() (fee int64, n int, rows int) {
	e.a.pool.QueryRow(context.Background(), `SELECT count(*) FROM btc_refusals WHERE chain='btc-t'`).Scan(&rows)
	e.a.pool.QueryRow(context.Background(), `SELECT refused_fee, fee_refusals FROM btc_refusals WHERE chain='btc-t' AND owner_kind='cancel:withdrawal' AND owner_id='w1'`).Scan(&fee, &n)
	return
}

// A cancel the node refuses for the fee raises the next cancel above it, above the live send, across a restart, and never raises a send. Without it the
// refused cancel is deleted and the next replacement would bump the send instead.
func TestRefusedCancelEscalatesAcrossARestart(t *testing.T) {
	e := newWEnv(t)
	e.fund(1_000_000)
	orig, _ := e.broadcastOne("w1", 40_000)
	live := e.fee(orig)
	var last uint64
	for i := 0; i < 3; i++ {
		f := e.cancelRefuse(i == 0, feeMsg)
		if f <= live || f <= last {
			t.Fatalf("cancel %d pays %d: not more than the live send %d and the refused cancel %d", i, f, live, last)
		}
		last = f
	}
	if e.attemptRows() != 1 {
		t.Fatalf("%d attempt rows: refused cancels must leave no trace among the attempts", e.attemptRows())
	}
	if fee, n, rows := e.cancelRow(); uint64(fee) != last || n != 3 || rows != 1 {
		t.Fatalf("cancel row: fee %d (want %d), %d refusals (want 3), %d rows in all (the send's row must stay untouched)", fee, last, n, rows)
	}
	if o, err := e.a.Outcome(context.Background(), "withdrawal", "w1"); err != nil || o.FeeRefusals != 3 || o.Attempts != 1 {
		t.Fatalf("outcome %+v %v", o, err)
	}

	a2, err := New(context.Background(), e.cfg, e.a.pool) // a restarted cell
	if err != nil {
		t.Fatal(err)
	}
	var u chain.UnsignedTx
	tx, _ := e.a.pool.Begin(context.Background())
	if u, err = a2.BuildReplacement(context.Background(), tx, "withdrawal", "w1"); err != nil {
		t.Fatal(err)
	}
	tx.Rollback(context.Background())
	if p := e.payload(u); len(p.Outputs) != 1 || p.Outputs[0].Address != e.hot {
		t.Fatalf("after a restart the replacement of a cancelling owner is not a cancel: %+v", p)
	} else if f := feeOf(p); f <= last {
		t.Fatalf("after a restart the next cancel pays %d, not more than the refused %d", f, last)
	}

	// The send confirms instead: the withdrawal settles and both rows go.
	e.node.txs[orig] = 2
	if err := e.commit(func(tx pgx.Tx) error { return e.a.Settle(context.Background(), tx, "withdrawal", "w1", orig) }); err != nil {
		t.Fatal(err)
	}
	if _, _, rows := e.cancelRow(); rows != 0 {
		t.Fatalf("%d refusal rows after the owner settled", rows)
	}
}

// A cancel accepted but stuck is replaced by a higher cancel (not by a bump of the send), and every one pays more than any accepted attempt.
func TestStuckCancelIsReplacedByAHigherCancel(t *testing.T) {
	e := newWEnv(t)
	e.fund(1_000_000)
	e.broadcastOne("w1", 40_000)
	uc, err := e.cancel()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := e.a.Assemble(uc, e.sign(uc))
	if _, err := e.a.Broadcast(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	prev := feeOf(e.payload(uc))
	for i := 0; i < 3; i++ {
		u, err := e.replace()
		if err != nil {
			t.Fatal(err)
		}
		p := e.payload(u)
		if len(p.Outputs) != 1 || p.Outputs[0].Address != e.hot {
			t.Fatalf("replacement %d is not a cancel: %+v", i, p)
		}
		if f := feeOf(p); f <= prev {
			t.Fatalf("replacement %d pays %d, not more than %d", i, f, prev)
		} else {
			prev = f
		}
		st, _ := e.a.Assemble(u, e.sign(u))
		if _, err := e.a.Broadcast(context.Background(), st); err != nil {
			t.Fatal(err)
		}
	}
}

// A refused send does not raise a cancel (a cancel only has to beat what the node holds), and a cancel at the cap is ErrCannotBump until the cap
// allows it (one ALERT in the workflow, nothing voided); a non-fee refusal changes no fee.
func TestCancelEscalationCapAndNonFeeRefusal(t *testing.T) {
	e := newWEnv(t)
	e.a.cfg.MaxTxFeeSats = 3000 // a validated config can no longer make the total cap bind below the rate cap, so the test sets it on the adapter
	e.fund(1_000_000)
	orig, _ := e.broadcastOne("w1", 40_000)
	live := e.fee(orig)
	f1 := e.cancelRefuse(true, "non-standard")
	f2 := e.cancelRefuse(false, "non-standard")
	if f1 != f2 || f1 <= live {
		t.Fatalf("a non-fee refusal changed the fee: %d then %d (live %d)", f1, f2, live)
	}
	if o, _ := e.a.Outcome(context.Background(), "withdrawal", "w1"); o.Refusal == "" || o.FeeRefusals != 0 {
		t.Fatalf("outcome %+v", o)
	}
	var top uint64
	for { // refuse for the fee until the next step is over the cap
		f := e.cancelRefuseOrStop(feeMsg)
		if f == 0 {
			break
		}
		if f > 3000 {
			t.Fatalf("a cancel pays %d, above the cap 3000", f)
		}
		top = f
	}
	if top == 0 || top <= live {
		t.Fatalf("no cancel above the live send was built (%d, live %d)", top, live)
	}
	if _, err := e.replace(); !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("at the cap: %v", err)
	}
}

// cancelRefuseOrStop is cancelRefuse for a replacement; it returns 0 when none can be built (chain.ErrCannotBump).
func (e *wEnv) cancelRefuseOrStop(msg string) uint64 {
	e.t.Helper()
	if _, err := e.replace(); errors.Is(err, chain.ErrCannotBump) {
		return 0
	} else if err != nil {
		e.t.Fatal(err)
	}
	// replace() committed the attempt; take it back out, refusing it like the node would.
	var raw []byte
	var fee int64
	if err := e.a.pool.QueryRow(context.Background(), `SELECT payload, fee FROM btc_attempts WHERE chain='btc-t' AND kind='cancel' ORDER BY created_at DESC LIMIT 1`).Scan(&raw, &fee); err != nil {
		e.t.Fatal(err)
	}
	p, _ := DecodePayload(raw)
	b, _ := BuildUnsigned(p, e.a.acct)
	e.a.pool.Exec(context.Background(), `DELETE FROM btc_attempts WHERE chain='btc-t' AND txid=$1`, b.TxID)
	if err := e.a.recordRefusal(context.Background(), "cancel:withdrawal", "w1", uint64(fee), chainFeeErr(), true); err != nil {
		e.t.Fatal(err)
	}
	return uint64(fee)
}

func chainFeeErr() error { return classifySend(&RPCError{Code: -26, Message: feeMsg}) }
