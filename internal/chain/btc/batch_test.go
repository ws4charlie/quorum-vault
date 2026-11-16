package btc

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// buildBatch runs BuildBatch in a transaction of its own and commits it (or rolls it back when commit is false or the build fails).
func (e *wEnv) buildBatch(id string, members []BatchMember, commit bool) (BatchBuild, error) {
	e.t.Helper()
	tx, err := e.a.pool.Begin(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	b, err := e.a.BuildBatch(context.Background(), tx, id, wPart, members)
	if err != nil || !commit {
		tx.Rollback(context.Background())
		return b, err
	}
	if err := tx.Commit(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return b, nil
}

// newBatchVerifierFor is the signing zone's verifier for the adapter's own shard and caps, with a batch ceiling of 8 payments.
func newBatchVerifierFor(t *testing.T, e *wEnv) *Verifier {
	t.Helper()
	v, err := NewVerifier(SigningConfig{Chain: e.cfg.Chain, Network: "regtest", AccountXpub: e.cfg.AccountXpub,
		HotShards:    map[string]HotShard{wPart: {Address: e.hot, Path: []uint32{1, 0}}},
		MaxTxFeeSats: e.cfg.MaxTxFeeSats, MaxFeeRate: e.cfg.MaxFeeRate, MaxInputs: e.cfg.MaxInputs, MaxBatchOutputs: 8, MaxBatchValue: 10_000_000})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func batchIntent(id string) signjob.Intent {
	return signjob.Intent{Kind: signjob.KindBatch, ID: id, PartitionID: wPart, Chain: "btc-t", Asset: "BTC"}
}

func (e *wEnv) members(amounts ...uint64) []BatchMember {
	var out []BatchMember
	for i, a := range amounts {
		out = append(out, BatchMember{ID: fmt.Sprintf("w%d", i+1), To: e.dest, Amount: a})
	}
	return out
}

func sum(xs []uint64) (s uint64) {
	for _, x := range xs {
		s += x
	}
	return
}

// A batch pays its members in order from the oldest outputs, keeps one change to the shard last, reserves what it spends for the batch and records
// its attempt under the batch; the fee shares add up to the real fee.
func TestBuildBatchPaysMembersInOrderWithChange(t *testing.T) {
	e := newWEnvWith(t, func(c *Config) { c.MaxTxFeeSats = 100_000 })
	old1, old2 := e.fund(100_000), e.fund(100_000)
	e.fund(100_000)
	b, err := e.buildBatch("b1", e.members(60_000, 50_000, 40_000), true)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(b.Tx)
	if b.Funded != 3 || len(p.Inputs) != 2 || p.Inputs[0].TxID != old1 || p.Inputs[1].TxID != old2 {
		t.Fatalf("funded %d, inputs %+v", b.Funded, p.Inputs)
	}
	if len(p.Outputs) != 4 || p.Outputs[0].Value != 60_000 || p.Outputs[1].Value != 50_000 || p.Outputs[2].Value != 40_000 || p.Outputs[3].Address != e.hot {
		t.Fatalf("outputs %+v", p.Outputs)
	}
	fee := uint64(vsize(2, mustScript(t, e.dest), mustScript(t, e.dest), mustScript(t, e.dest), mustScript(t, e.hot))) * 10
	if b.Fee != fee || p.Outputs[3].Value != 200_000-150_000-fee || b.Change != p.Outputs[3].Value {
		t.Fatalf("fee %d change %d, want fee %d change %d", b.Fee, p.Outputs[3].Value, fee, 50_000-fee)
	}
	if len(b.FeeShares) != 3 || sum(b.FeeShares) != b.Fee {
		t.Fatalf("shares %v do not add up to the fee %d", b.FeeShares, b.Fee)
	}
	if e.count("reserved") != 2 || e.count("available") != 1 {
		t.Fatalf("reserved %d available %d", e.count("reserved"), e.count("available"))
	}
	var owner string
	var f int64
	e.a.pool.QueryRow(context.Background(), `SELECT owner_kind, fee FROM btc_attempts WHERE chain='btc-t' AND owner_id='b1'`).Scan(&owner, &f)
	if owner != OwnerKindBatch || uint64(f) != fee {
		t.Fatalf("attempt owner %q fee %d", owner, f)
	}
	var kind string
	e.a.pool.QueryRow(context.Background(), `SELECT owner_kind FROM btc_utxos WHERE chain='btc-t' AND txid=$1`, old1).Scan(&kind)
	if kind != OwnerKindBatch {
		t.Fatalf("an input is reserved for %q", kind)
	}
	// The batch is a send the zone accepts as a first send: the reserve holds for the whole batch.
	v := newBatchVerifierFor(t, e)
	if err := v.CheckFirstSend(chain.UnsignedTx{Chain: "btc-t", Payload: b.Tx.Payload, Digest: b.Tx.Digest, KeyRef: b.Tx.KeyRef}, batchIntent("b1")); err != nil {
		t.Fatalf("the zone's reserve rule refuses the batch the builder made: %v", err)
	}
}

// The prefix shrinks, it does not fail: with two inputs of at most 100,000 each, three members of 70,000 cannot all be paid, two can.
func TestBuildBatchPrefixShrinksUnderMaxInputs(t *testing.T) {
	e := newWEnvWith(t, func(c *Config) { c.MaxInputs = 2; c.MaxTxFeeSats = 100_000 })
	e.fund(100_000)
	e.fund(100_000)
	e.fund(100_000) // a third output exists, but a transaction takes only two
	b, err := e.buildBatch("b1", e.members(70_000, 70_000, 70_000), true)
	if err != nil {
		t.Fatal(err)
	}
	if b.Funded != 2 || len(e.payload(b.Tx).Outputs) != 3 || len(b.FeeShares) != 2 || sum(b.FeeShares) != b.Fee {
		t.Fatalf("funded %d, outputs %d, shares %v fee %d", b.Funded, len(e.payload(b.Tx).Outputs), b.FeeShares, b.Fee)
	}
	if e.count("reserved") != 2 {
		t.Fatalf("reserved %d", e.count("reserved"))
	}
}

// When the oldest max_inputs outputs cannot carry the batch but the shard holds more, the largest are taken, as for a single withdrawal.
func TestBuildBatchFallsBackToTheLargestOutputs(t *testing.T) {
	e := newWEnvWith(t, func(c *Config) { c.MaxInputs = 2; c.MaxTxFeeSats = 100_000 })
	e.fund(20_000)
	e.fund(20_000)
	big1 := e.fund(300_000)
	big2 := e.fund(250_000)
	b, err := e.buildBatch("b1", e.members(100_000, 100_000, 100_000), true)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(b.Tx)
	if b.Funded != 3 || len(p.Inputs) != 2 || p.Inputs[0].TxID != big1 || p.Inputs[1].TxID != big2 {
		t.Fatalf("funded %d, inputs %+v", b.Funded, p.Inputs)
	}
}

// No member is skipped: when the head cannot be funded nothing is built and nothing stays reserved, however small the members behind it are.
func TestBuildBatchWaitsWhenTheHeadCannotBeFunded(t *testing.T) {
	e := newWEnvWith(t, func(c *Config) { c.MaxTxFeeSats = 100_000 })
	e.fund(100_000)
	e.fund(100_000)
	_, err := e.buildBatch("b1", e.members(900_000, 10_000, 10_000), true)
	if !errors.Is(err, chain.ErrNotEnoughOutputs) || errors.Is(err, chain.ErrFeeReserve) {
		t.Fatalf("the unfundable head: %v", err)
	}
	if e.count("reserved") != 0 || e.count("available") != 2 {
		t.Fatalf("reserved %d available %d", e.count("reserved"), e.count("available"))
	}
	var n int
	e.a.pool.QueryRow(context.Background(), `SELECT count(*) FROM btc_attempts`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d attempts recorded for a batch that was not built", n)
	}
	// The head fits the payment and today's fee but not the reserve: the error says so, as a single withdrawal's does.
	_, err = e.buildBatch("b2", e.members(192_000), true)
	if !errors.Is(err, chain.ErrNotEnoughOutputs) || !errors.Is(err, chain.ErrFeeReserve) {
		t.Fatalf("the head without its reserve: %v", err)
	}
}

// A build that is rolled back reserves nothing.
func TestBuildBatchRolledBackReservesNothing(t *testing.T) {
	e := newWEnvWith(t, func(c *Config) { c.MaxTxFeeSats = 100_000 })
	e.fund(100_000)
	e.fund(100_000)
	if _, err := e.buildBatch("b1", e.members(60_000, 50_000), false); err != nil {
		t.Fatal(err)
	}
	if e.count("reserved") != 0 {
		t.Fatalf("reserved %d after a rollback", e.count("reserved"))
	}
}

// A member that cannot be paid at all is an error naming it, not a skip.
func TestBuildBatchRefusesAMemberThatCannotBePaid(t *testing.T) {
	e := newWEnvWith(t, func(c *Config) { c.MaxTxFeeSats = 100_000 })
	e.fund(500_000)
	ms := e.members(60_000, 100)
	if _, err := e.buildBatch("b1", ms, true); err == nil || !strings.Contains(err.Error(), "w2") || !strings.Contains(err.Error(), "dust") {
		t.Fatalf("a member below dust: %v", err)
	}
	ms = e.members(60_000, 60_000)
	ms[1].To = "not-an-address"
	if _, err := e.buildBatch("b1", ms, true); err == nil || !strings.Contains(err.Error(), "w2") {
		t.Fatalf("a member with a bad address: %v", err)
	}
	ms = e.members(60_000, 60_000)
	ms[1].ID = "w1"
	if _, err := e.buildBatch("b1", ms, true); err == nil || !strings.Contains(err.Error(), "repeated id") {
		t.Fatalf("a repeated member id: %v", err)
	}
	if e.count("reserved") != 0 {
		t.Fatalf("reserved %d after refusals", e.count("reserved"))
	}
}

// P2WPKH and P2TR members: the larger output pays the larger share; the shares add up to the fee to the satoshi.
func TestBuildBatchMixesAddressKindsAndSplitsTheFee(t *testing.T) {
	e := newWEnvWith(t, func(c *Config) { c.MaxTxFeeSats = 100_000 })
	e.fund(400_000)
	ms := []BatchMember{{ID: "a", To: e.dest, Amount: 50_000}, {ID: "b", To: p2trAddr(t), Amount: 50_000}, {ID: "c", To: e.dest, Amount: 50_000}, {ID: "d", To: p2trAddr(t), Amount: 50_000}}
	b, err := e.buildBatch("mix", ms, true)
	if err != nil {
		t.Fatal(err)
	}
	if b.Funded != 4 || sum(b.FeeShares) != b.Fee {
		t.Fatalf("funded %d shares %v fee %d", b.Funded, b.FeeShares, b.Fee)
	}
	// P2TR outputs are 12 bytes larger than P2WPKH ones: members b and d pay more than c (a gets the remainder satoshis on top).
	if !(b.FeeShares[1] > b.FeeShares[2] && b.FeeShares[3] > b.FeeShares[2]) {
		t.Fatalf("shares %v: P2TR members should pay more than a P2WPKH member", b.FeeShares)
	}
}

// The split of a fee: always exact, deterministic, the remainder to the first member, equal members equal shares.
func TestFeeSharesAddUpExactly(t *testing.T) {
	w := make([]byte, 22)
	tr := make([]byte, 34)
	if got := FeeShares(1000, nil, 100); got != nil {
		t.Fatalf("no members: %v", got)
	}
	if got := FeeShares(1234, [][]byte{w}, 110); len(got) != 1 || got[0] != 1234 {
		t.Fatalf("one member pays all: %v", got)
	}
	// Three equal members and a fee that does not divide by three: the first takes the extra satoshis.
	got := FeeShares(1000, [][]byte{w, w, w}, 300)
	if got[1] != got[2] || got[0] < got[1] || got[0]-got[1] > 2 || sum(got) != 1000 {
		t.Fatalf("equal members: %v", got)
	}
	// A fee of zero, and a fee smaller than the number of members.
	if g := FeeShares(0, [][]byte{w, tr}, 200); sum(g) != 0 {
		t.Fatalf("%v", g)
	}
	if g := FeeShares(2, [][]byte{w, w, w, w}, 400); sum(g) != 2 || g[0] != 2 {
		t.Fatalf("a fee below the member count goes to the earliest: %v", g)
	}
	rnd := rand.New(rand.NewSource(7))
	for i := 0; i < 2000; i++ {
		n := 1 + rnd.Intn(50)
		var scripts [][]byte
		var outs uint64
		for j := 0; j < n; j++ {
			s := w
			if rnd.Intn(2) == 0 {
				s = tr
			}
			scripts = append(scripts, s)
			outs += 8 + 1 + uint64(len(s))
		}
		vs := outs + 11 + uint64(1+rnd.Intn(20))*68 + 31
		fee := uint64(rnd.Int63n(500_000))
		a, b := FeeShares(fee, scripts, vs), FeeShares(fee, scripts, vs)
		if sum(a) != fee || len(a) != n {
			t.Fatalf("n=%d fee=%d: shares %v add up to %d", n, fee, a, sum(a))
		}
		for j := range a {
			if a[j] != b[j] {
				t.Fatal("the split is not deterministic")
			}
		}
	}
}
