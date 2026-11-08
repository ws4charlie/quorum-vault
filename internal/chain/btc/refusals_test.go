package btc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// feeOf is what a built attempt pays: its inputs minus its outputs.
func feeOf(p Payload) uint64 {
	var in, out uint64
	for _, i := range p.Inputs {
		in += i.Value
	}
	for _, o := range p.Outputs {
		out += o.Value
	}
	return in - out
}

// refuse builds the next replacement of w1, has the node refuse it with msg, and returns the fee it paid. The row is gone afterwards.
func (e *wEnv) refuse(code int, msg string) (fee uint64, err error) {
	e.t.Helper()
	u, err := e.replace()
	if err != nil {
		return 0, err
	}
	st, err := e.a.Assemble(u, e.sign(u))
	if err != nil {
		e.t.Fatal(err)
	}
	e.node.sendErr = &RPCError{Code: code, Message: msg}
	defer func() { e.node.sendErr = nil }()
	if _, serr := e.a.Broadcast(context.Background(), st); !errors.Is(serr, chain.ErrBroadcastStuck) {
		e.t.Fatalf("the node refused it: %v", serr)
	}
	b, _ := BuildUnsigned(e.payload(u), e.a.acct)
	e.vs = uint64(EstimateVSize(b.Tx))
	return feeOf(e.payload(u)), nil
}

func (e *wEnv) refusalRow() (fee int64, n int, other string, rows int) {
	e.t.Helper()
	e.a.pool.QueryRow(context.Background(), `SELECT count(*) FROM btc_refusals WHERE chain='btc-t'`).Scan(&rows)
	e.a.pool.QueryRow(context.Background(), `SELECT refused_fee, fee_refusals, other_refusal FROM btc_refusals WHERE chain='btc-t' AND owner_kind='withdrawal' AND owner_id='w1'`).Scan(&fee, &n, &other)
	return
}

const feeMsg = "mempool min fee not met, 300 < 1000"

// A replacement refused for the fee raises the next one: it pays more than the highest refused fee, every time, also after the cell restarts. Without
// that the refused row is gone, the next bump starts again from the accepted fee and builds the very same transaction.
func TestFeeRefusalRaisesTheNextReplacementAcrossARestart(t *testing.T) {
	e := newWEnv(t)
	e.fund(1_000_000)
	orig, _ := e.broadcastOne("w1", 40_000)
	top := e.fee(orig)
	var last uint64
	for i := 0; i < 3; i++ {
		f, err := e.refuse(-26, feeMsg)
		if err != nil {
			t.Fatalf("refusal %d: %v", i, err)
		}
		if f <= top || f <= last {
			t.Fatalf("attempt %d pays %d: not more than the accepted %d and the refused %d", i, f, top, last)
		}
		last = f
	}
	if e.attemptRows() != 1 {
		t.Fatalf("%d attempt rows: refused replacements must leave no trace among the attempts", e.attemptRows())
	}
	fee, n, other, _ := e.refusalRow()
	if uint64(fee) != last || n != 3 || other != "" {
		t.Fatalf("refusal row: fee %d (want %d), %d fee refusals (want 3), other %q", fee, last, n, other)
	}
	o, err := e.a.Outcome(context.Background(), "withdrawal", "w1")
	if err != nil || o.FeeRefusals != 3 || o.Refusal != "" || o.Attempts != 1 {
		t.Fatalf("outcome %+v %v", o, err)
	}

	// A restarted cell is a new Adapter on the same database.
	a2, err := New(context.Background(), e.cfg, e.a.pool)
	if err != nil {
		t.Fatal(err)
	}
	var u chain.UnsignedTx
	tx, err := e.a.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u, err = a2.BuildReplacement(context.Background(), tx, "withdrawal", "w1"); err != nil {
		t.Fatal(err)
	}
	tx.Rollback(context.Background())
	if f := feeOf(e.payload(u)); f <= last {
		t.Fatalf("after a restart the next attempt pays %d, not more than the refused %d", f, last)
	}

	// Taken at last: the settled owner's row goes with it.
	e.node.txs[orig] = 2
	if err := e.commit(func(tx pgx.Tx) error { return e.a.Settle(context.Background(), tx, "withdrawal", "w1", orig) }); err != nil {
		t.Fatal(err)
	}
	if _, _, _, rows := e.refusalRow(); rows != 0 {
		t.Fatalf("%d refusal rows after the owner settled", rows)
	}
}

// A refusal that a higher fee does not cure changes no fee: the next replacement is the very one that was refused, the refusal is reported for the
// ALERT, and an accepted transaction clears it. The owner's first attempt, refused for the fee, is recorded as a floor but is not a replacement.
func TestNonFeeRefusalDoesNotRaiseTheFee(t *testing.T) {
	e := newWEnv(t)
	e.fund(1_000_000)
	orig, _ := e.broadcastOne("w1", 40_000)
	f1, err := e.refuse(-26, "too-long-mempool-chain, too many unconfirmed ancestors [limit: 25]")
	if err != nil {
		t.Fatal(err)
	}
	f2, err := e.refuse(-26, "non-standard")
	if err != nil {
		t.Fatal(err)
	}
	if f2 != f1 || f1 <= e.fee(orig) {
		t.Fatalf("refused attempts pay %d then %d: the second must be the same replacement as the first (accepted pays %d)", f1, f2, e.fee(orig))
	}
	fee, n, other, _ := e.refusalRow()
	if fee != 0 || n != 0 || !strings.Contains(other, "non-standard") {
		t.Fatalf("row: fee %d, %d fee refusals, other %q", fee, n, other)
	}
	if o, _ := e.a.Outcome(context.Background(), "withdrawal", "w1"); o.Refusal == "" || o.FeeRefusals != 0 {
		t.Fatalf("outcome %+v", o)
	}
	// The node takes the next one: the refusal is cleared.
	_, st := e.replacementAttempt()
	if _, err := e.a.Broadcast(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if o, _ := e.a.Outcome(context.Background(), "withdrawal", "w1"); o.Refusal != "" {
		t.Fatalf("the refusal stays after the node took a transaction: %+v", o)
	}
}

// At a cap the fee is never above it. Refusals that push the next fee over the cap give chain.ErrCannotBump (the workflow raises one ALERT and
// keeps waiting) for as long as the node's fee market has not fallen; once its minimum fee fell, the refusals are forgotten and a fee under the cap
// is built again from the accepted attempt. Both caps of a withdrawal: max_tx_fee_sats and max_fee_rate.
func TestFeeRefusalsStopAtTheCapAndRetryWhenTheMarketFalls(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   func(*Config)
		limit func(vs uint64) uint64
	}{
		{"max_tx_fee_sats", func(c *Config) { c.MaxTxFeeSats = 3000 }, func(uint64) uint64 { return 3000 }},
		{"max_fee_rate", func(c *Config) { c.FallbackFeeRate, c.MaxFeeRate = 1, 4 }, func(vs uint64) uint64 { return 4 * vs }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newWEnvWith(t, tc.cfg)
			e.node.mempoolMin = 40
			e.fund(1_000_000)
			orig, _ := e.broadcastOne("w1", 40_000)
			var top uint64
			var err error
			for i := 0; i < 40; i++ {
				var f uint64
				if f, err = e.refuse(-26, feeMsg); err != nil {
					break
				}
				if f > tc.limit(e.vs) {
					t.Fatalf("a fee of %d is above the cap of %d", f, tc.limit(e.vs))
				}
				top = f
			}
			if !errors.Is(err, chain.ErrCannotBump) {
				t.Fatalf("at the cap: %v", err)
			}
			if top <= e.fee(orig) {
				t.Fatalf("nothing escalated (top %d, accepted %d)", top, e.fee(orig))
			}
			// Waiting changes nothing: the same answer, nothing is recorded, nothing built.
			rows := e.attemptRows()
			for i := 0; i < 3; i++ {
				if _, err := e.replace(); !errors.Is(err, chain.ErrCannotBump) {
					t.Fatalf("while waiting: %v", err)
				}
			}
			if e.attemptRows() != rows {
				t.Fatal("a build that failed left an attempt")
			}
			// A market that rose is not a reason either.
			e.node.mempoolMin = 80
			if _, err := e.replace(); !errors.Is(err, chain.ErrCannotBump) {
				t.Fatalf("market up: %v", err)
			}
			// The minimum fee fell: the refusals were made in a market that is gone.
			e.node.mempoolMin = 10
			u, err := e.replace()
			if err != nil {
				t.Fatalf("market down: %v", err)
			}
			b, _ := BuildUnsigned(e.payload(u), e.a.acct)
			if f := feeOf(e.payload(u)); f <= e.fee(orig) || f > tc.limit(uint64(EstimateVSize(b.Tx))) || f >= top {
				t.Fatalf("after the fall the fee is %d (accepted %d, highest refused %d): built from the accepted attempt, under the cap", f, e.fee(orig), top)
			}
			if fee, _, _, _ := e.refusalRow(); fee != 0 {
				t.Fatalf("refused fee %d remembered after the market fell", fee)
			}
		})
	}
}

// The node's own words, tested exactly: which refusals are about the fee (they raise the next fee) and which are not (they do not).
func TestClassifySendFeeRefusals(t *testing.T) {
	for _, tc := range []struct {
		code int
		msg  string
		fee  bool
	}{
		// Bitcoin Core 29, as sendrawtransaction reports them.
		{-26, "min relay fee not met, 50 < 110", true},
		{-26, "mempool min fee not met, 80 < 110", true},
		{-26, "insufficient fee, rejecting replacement 5f3c1e6a7e0b4d9a8c2f1e3d4b5a69788796a5b4c3d2e1f00112233445566778; new feerate 0.00001000 BTC/kvB <= old feerate 0.00001000 BTC/kvB", true},
		{-26, "insufficient fee, rejecting replacement 5f3c1e6a7e0b4d9a8c2f1e3d4b5a69788796a5b4c3d2e1f00112233445566778, less fees than conflicting txs; 0.00000141 < 0.00000200", true},
		{-26, "insufficient fee, rejecting replacement 5f3c1e6a7e0b4d9a8c2f1e3d4b5a69788796a5b4c3d2e1f00112233445566778, not enough additional fees to relay; 0.00000000 < 0.00000141", true},
		// Refusals a higher fee does not cure.
		{-26, "too-long-mempool-chain, too many unconfirmed ancestors [limit: 25]", false},
		{-26, "too-long-mempool-chain, too many descendants for tx abc [limit: 25]", false},
		{-26, "non-standard", false},
		{-26, "txn-mempool-conflict", false},
		{-26, "replacement-adds-unconfirmed", false},
		{-26, "too many potential replacements", false},
		{-26, "bad-txns-in-belowout", false},
		{-26, "mandatory-script-verify-flag-failed", false},
		{-22, "TX decode failed", false},
		{-26, "something new", false},
	} {
		got := classifySend(&RPCError{Code: tc.code, Message: tc.msg})
		if !errors.Is(got, chain.ErrBroadcastStuck) {
			t.Errorf("%q is not stuck: %v", tc.msg, got)
		}
		if errors.Is(got, chain.ErrFeeTooLow) != tc.fee {
			t.Errorf("%q: fee refusal = %v, want %v", tc.msg, errors.Is(got, chain.ErrFeeTooLow), tc.fee)
		}
	}
	// Spent inputs are decided by the outcome check, never a fee refusal.
	if got := classifySend(&RPCError{Code: -25, Message: "bad-txns-inputs-missingorspent"}); errors.Is(got, chain.ErrFeeTooLow) || !errors.Is(got, chain.ErrInputsSpent) {
		t.Errorf("missing inputs: %v", got)
	}
}
