package btc

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// consolidating: more than 6 available outputs triggers it; at most 5 are merged (max_inputs); the ceiling is 20 sat/vB; the fallback rate is 10.
func newCEnv(t *testing.T) *wEnv {
	return newWEnvWith(t, func(c *Config) { c.ConsolidateAbove, c.ConsolidateMaxFeeRate, c.SweepMaxFeeRate = 6, 20, 30 })
}

func (e *wEnv) plan() chain.Consolidation {
	e.t.Helper()
	c, err := e.a.PlanConsolidation(context.Background(), wPart)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *wEnv) consolidate(id string, amount int64) (chain.UnsignedTx, error) {
	var u chain.UnsignedTx
	err := e.commit(func(tx pgx.Tx) (err error) {
		u, err = e.a.BuildConsolidation(context.Background(), tx, chain.ConsolidateIntent{ID: id, PartitionID: wPart, Amount: big.NewInt(amount)})
		return
	})
	return u, err
}

// The plan takes the smallest outputs, not the oldest; the largest stay free; the amount is exactly what the build then spends.
func TestPlanConsolidationTakesTheSmallestOutputs(t *testing.T) {
	e := newCEnv(t)
	big1, big2 := e.fund(500_000), e.fund(400_000) // the oldest are the largest
	var smalls []string
	for _, v := range []int64{9_000, 5_000, 7_000, 6_000, 8_000, 12_000} {
		smalls = append(smalls, e.fund(v))
	}
	c := e.plan()
	// Eight outputs, six is the threshold: the five smallest (5,6,7,8,9 thousand) go.
	if c.Wait != "" || c.Inputs != 5 || c.Amount.Int64() != 35_000 {
		t.Fatalf("plan %+v, want five inputs and 35000", c)
	}
	u, err := e.consolidate("c1", 35_000)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(u)
	if len(p.Inputs) != 5 || len(p.Outputs) != 1 || p.Outputs[0].Address != e.hot {
		t.Fatalf("payload %+v", p)
	}
	used := map[string]bool{}
	var sum uint64
	for _, in := range p.Inputs {
		used[in.TxID] = true
		sum += in.Value
		if PathString(in.Path) != "1/0" {
			t.Fatalf("input at %s", PathString(in.Path))
		}
	}
	if used[big1] || used[big2] || used[smalls[5]] || sum != 35_000 {
		t.Fatalf("the largest outputs must stay free: used %v (sum %d)", used, sum)
	}
	fee := vsize(5, mustScript(t, e.hot)) * 10
	if p.Outputs[0].Value != 35_000-fee || e.fee(payloadTxID(t, e, p)) != fee {
		t.Fatalf("output %d, want %d less the fee %d", p.Outputs[0].Value, 35_000, fee)
	}
	if e.count("reserved") != 5 {
		t.Fatalf("%d reserved", e.count("reserved"))
	}
	// Reserved outputs are not available: the shard now holds three (two large, one small) and nothing more is planned.
	if c := e.plan(); c.Amount.Sign() != 0 || c.Wait != "" {
		t.Fatalf("a second plan on a shard that holds three outputs: %+v", c)
	}
}

func payloadTxID(t *testing.T, e *wEnv, p Payload) string {
	t.Helper()
	b, err := BuildUnsigned(p, e.a.acct)
	if err != nil {
		t.Fatal(err)
	}
	return b.TxID
}

// Nothing is planned at or below the threshold, with the feature off, with one worthwhile output, or when the result would not clear dust; above the
// ceiling it waits and says why; outputs that cost more to spend than they carry stay where they are.
func TestPlanConsolidationConditions(t *testing.T) {
	// At the threshold: six outputs, threshold six.
	e := newCEnv(t)
	for i := 0; i < 6; i++ {
		e.fund(10_000)
	}
	if c := e.plan(); c.Amount.Sign() != 0 || c.Wait != "" {
		t.Fatalf("at the threshold: %+v", c)
	}
	e.fund(10_000)
	if c := e.plan(); c.Inputs != 5 {
		t.Fatalf("above the threshold: %+v", c)
	}

	// Off: consolidate_above 0.
	off := newWEnv(t)
	for i := 0; i < 12; i++ {
		off.fund(10_000)
	}
	if c := off.plan(); c.Amount.Sign() != 0 || c.Wait != "" {
		t.Fatalf("off: %+v", c)
	}
	if _, err := off.consolidate("c", 50_000); !errors.Is(err, ErrConsolidateWait) {
		t.Fatalf("a build with the feature off: %v", err)
	}

	// The fee rate above the ceiling (25 against 20): it waits, and a build refuses too.
	e.node.mu.Lock()
	e.node.estimate = 25
	e.node.mu.Unlock()
	if c := e.plan(); c.Wait == "" || c.Amount.Sign() != 0 {
		t.Fatalf("above the ceiling: %+v", c)
	}
	if _, err := e.consolidate("c", 50_000); !errors.Is(err, ErrConsolidateWait) {
		t.Fatalf("a build above the ceiling: %v", err)
	}
	if e.count("reserved") != 0 {
		t.Fatal("a refused build reserved outputs")
	}

	// Dust stays: at 10 sat/vB an input costs 680 sats; outputs of 600 are not worth spending. Eight of them and one worthwhile: fewer than two.
	d := newCEnv(t)
	for i := 0; i < 8; i++ {
		d.fund(600)
	}
	d.fund(50_000)
	if c := d.plan(); c.Amount.Sign() != 0 {
		t.Fatalf("dust and one worthwhile output: %+v", c)
	}
	d.fund(60_000)
	if c := d.plan(); c.Inputs != 2 || c.Amount.Int64() != 110_000 {
		t.Fatalf("two worthwhile outputs among dust: %+v", c)
	}
}

// A build whose amount is not what the smallest outputs add up to reserves nothing (the set changed since the plan).
func TestBuildConsolidationNeedsTheExactSum(t *testing.T) {
	e := newCEnv(t)
	for i := 0; i < 8; i++ {
		e.fund(10_000)
	}
	for _, amt := range []int64{49_999, 50_001, 60_000, 1_000_000} {
		if _, err := e.consolidate("c", amt); !errors.Is(err, chain.ErrNotEnoughOutputs) {
			t.Fatalf("amount %d: %v", amt, err)
		}
		if e.count("reserved") != 0 || e.count("available") != 8 {
			t.Fatalf("amount %d left outputs reserved", amt)
		}
	}
	if _, err := e.consolidate("c", 50_000); err != nil {
		t.Fatal(err)
	}
	// Two outputs are the least.
	e2 := newCEnv(t)
	for i := 0; i < 8; i++ {
		e2.fund(10_000)
	}
	if _, err := e2.consolidate("c2", 20_000); err != nil {
		t.Fatalf("two outputs: %v", err)
	}
	e3 := newCEnv(t)
	e3.fund(1_000_000)
	for i := 0; i < 8; i++ {
		e3.fund(10_000)
	}
	// One output is not a consolidation, even when the amount names it exactly.
	if _, err := e3.consolidate("c3", 10_000); err == nil {
		t.Fatal("a consolidation of one output was built")
	}
	if e3.count("reserved") != 0 {
		t.Fatal("a refused build reserved outputs")
	}
}

// A withdrawal that arrives during a consolidation uses the free outputs: the consolidation's are reserved, so it never sees them.
func TestWithdrawalDuringConsolidationUsesTheFreeOutputs(t *testing.T) {
	e := newCEnv(t)
	bigOut := e.fund(500_000)
	for i := 0; i < 7; i++ {
		e.fund(10_000)
	}
	c := e.plan()
	if c.Inputs != 5 {
		t.Fatalf("%+v", c)
	}
	if _, err := e.consolidate("c1", c.Amount.Int64()); err != nil {
		t.Fatal(err)
	}
	u, err := e.build("w", 100_000, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range e.payload(u).Inputs {
		var owner string
		e.a.pool.QueryRow(context.Background(), `SELECT COALESCE(owner_kind,'') FROM btc_utxos WHERE txid=$1`, in.TxID).Scan(&owner)
		if owner == OwnerKindConsolidate && in.TxID != bigOut {
			t.Fatalf("the withdrawal spent an output of the consolidation: %+v", in)
		}
	}
	if in := e.payload(u).Inputs; len(in) != 1 || in[0].TxID != bigOut {
		t.Fatalf("inputs %+v, want the large output alone", in)
	}
}

// Settlement turns the inputs into spent and the output into an available hot output; a bump keeps the inputs and lowers the one output; a cancel
// spends the same inputs back to the shard.
func TestConsolidationBumpCancelAndSettle(t *testing.T) {
	e := newCEnv(t)
	for i := 0; i < 8; i++ {
		e.fund(10_000)
	}
	u0, err := e.consolidate("c1", 50_000)
	if err != nil {
		t.Fatal(err)
	}
	p0 := e.payload(u0)
	fee0 := e.fee(payloadTxID(t, e, p0))

	var u1 chain.UnsignedTx
	if err := e.commit(func(tx pgx.Tx) (err error) {
		u1, err = e.a.BuildReplacement(context.Background(), tx, OwnerKindConsolidate, "c1")
		return
	}); err != nil {
		t.Fatal(err)
	}
	p1 := e.payload(u1)
	fee1 := e.fee(payloadTxID(t, e, p1))
	if len(p1.Inputs) != 5 || len(p1.Outputs) != 1 || p1.Outputs[0].Address != e.hot || fee1 <= fee0 || p1.Outputs[0].Value != 50_000-fee1 {
		t.Fatalf("replacement %+v fee %d -> %d", p1, fee0, fee1)
	}
	for i := range p1.Inputs {
		if !sameInput(p1.Inputs[i], p0.Inputs[i]) {
			t.Fatalf("the replacement changed input %d", i)
		}
	}

	var uc chain.UnsignedTx
	if err := e.commit(func(tx pgx.Tx) (err error) {
		uc, err = e.a.BuildCancel(context.Background(), tx, OwnerKindConsolidate, "c1")
		return
	}); err != nil {
		t.Fatal(err)
	}
	pc := e.payload(uc)
	feec := e.fee(payloadTxID(t, e, pc))
	if len(pc.Inputs) != 5 || len(pc.Outputs) != 1 || pc.Outputs[0].Address != e.hot || feec <= fee1 {
		t.Fatalf("cancel %+v fee %d", pc, feec)
	}

	// Settling the cancel (it mined) spends the inputs and makes the one output an available hot row, as for the consolidation itself.
	cid := payloadTxID(t, e, pc)
	if err := e.commit(func(tx pgx.Tx) error { return e.a.Settle(context.Background(), tx, OwnerKindConsolidate, "c1", cid) }); err != nil {
		t.Fatal(err)
	}
	if e.count("spent") != 5 || e.count("reserved") != 0 || e.count("available") != 3+1 {
		t.Fatalf("spent %d reserved %d available %d", e.count("spent"), e.count("reserved"), e.count("available"))
	}
}

// A bump past the consolidation ceiling is refused (ErrCannotBump), and so is one that would leave the output at dust.
func TestConsolidationBumpRefusals(t *testing.T) {
	e := newCEnv(t)
	for i := 0; i < 8; i++ {
		e.fund(10_000)
	}
	e.node.mu.Lock()
	e.node.estimate = 19
	e.node.mu.Unlock()
	if _, err := e.consolidate("c1", 50_000); err != nil {
		t.Fatal(err)
	}
	// Bumping from 19 sat/vB: at least 15 percent more, which is above the ceiling of 20.
	err := e.commit(func(tx pgx.Tx) error {
		_, err := e.a.BuildReplacement(context.Background(), tx, OwnerKindConsolidate, "c1")
		return err
	})
	if !errors.Is(err, chain.ErrCannotBump) {
		t.Fatalf("a bump above the ceiling: %v", err)
	}
}
