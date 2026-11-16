package btc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// batchFixture is the fixture of verify_test.go with a zone that signs batches of at most 5 payments and 2,000,000 sats in all.
type batchFixture struct {
	*fixture
	bv *Verifier
}

const (
	bMaxOutputs = 5
	bMaxValue   = 2_000_000
)

func newBatchFixture(t *testing.T) *batchFixture {
	t.Helper()
	f := newFixture(t)
	v, err := NewVerifier(SigningConfig{Chain: vChain, Network: "regtest", AccountXpub: acctXpub(f.acct),
		HotShards:     map[string]HotShard{pOmni0: {Address: f.hot0, Path: []uint32{1, 0}}, pBeta0: {Address: f.hot1, Path: []uint32{1, 1}}, pSeg0: {Address: f.hotS, Path: []uint32{1, 2}}},
		ColdAddresses: map[string]string{"omnibus/native": f.cold, "segregated:acme/native": f.coldS},
		MaxTxFeeSats:  100_000, MaxFeeRate: 100, MaxInputs: 4, MaxBatchOutputs: bMaxOutputs, MaxBatchValue: bMaxValue})
	if err != nil {
		t.Fatal(err)
	}
	return &batchFixture{fixture: f, bv: v}
}

func member(id, to string, amount uint64) signjob.BatchMember {
	return signjob.BatchMember{Intent: signjob.Intent{Kind: "withdrawal", ID: id, PartitionID: pOmni0, Chain: vChain, Asset: "BTC", To: to, Amount: fmt.Sprint(amount), NotAfter: 1}}
}

// batch is a correct batch of three payments to three addresses (one of them P2TR) from two inputs of the shard, with the change last.
func (f *batchFixture) batch() (Payload, signjob.Batch) {
	to := []string{f.other, f.cold, p2trAddr(f.t)}
	amounts := []uint64{100_000, 150_000, 120_000}
	b := signjob.Batch{Kind: signjob.KindBatch, ID: "b1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC"}
	p := Payload{Version: 2, Inputs: []PayloadInput{in(1, 300_000, 1, 0), in(2, 300_000, 1, 0)}}
	var paid uint64
	for i := range to {
		b.Members = append(b.Members, member(fmt.Sprintf("w%d", i+1), to[i], amounts[i]))
		p.Outputs = append(p.Outputs, PayloadOutput{to[i], amounts[i]})
		paid += amounts[i]
	}
	p.Outputs = append(p.Outputs, PayloadOutput{f.hot0, 600_000 - paid - 2_000})
	return p, b
}

func (f *batchFixture) must(p Payload, b signjob.Batch) {
	f.t.Helper()
	for n := range p.Inputs {
		if _, err := f.bv.VerifyBatch(f.job(p, n), b); err != nil {
			f.t.Fatalf("input %d: %v", n, err)
		}
	}
}

func (f *batchFixture) refuse(name string, p Payload, b signjob.Batch, want string) {
	f.t.Helper()
	for n := range p.Inputs {
		_, err := f.bv.VerifyBatch(f.job(p, n), b)
		if err == nil || !strings.Contains(err.Error(), want) {
			f.t.Fatalf("%s (input %d): got %v, want a refusal containing %q", name, n, err, want)
		}
	}
}

func TestVerifyBatchAcceptsTheRightTransaction(t *testing.T) {
	f := newBatchFixture(t)
	p, b := f.batch()
	f.must(p, b)
	pay, err := f.bv.VerifyBatch(f.job(p, 0), b)
	if err != nil || len(pay) != 3 || pay[1].Amount != 150_000 || pay[1].Destination != f.cold {
		t.Fatalf("payments %+v, %v", pay, err)
	}
	// One member, and no change output at all, are still the batch's own shape; the reserve is the first send's rule (CheckFirstSend).
	one := b
	one.Members = b.Members[:1]
	po := Payload{Version: 2, Inputs: p.Inputs[:1], Outputs: []PayloadOutput{{f.other, 100_000}, {f.hot0, 190_000}}}
	f.must(po, one)
	one.Members = []signjob.BatchMember{member("w1", f.other, 290_000)}
	po.Outputs = []PayloadOutput{{f.other, 290_000}}
	f.must(po, one)
	// Two members may pay the same address the same amount: distinct ids are distinct withdrawals.
	twin := signjob.Batch{Kind: signjob.KindBatch, ID: "b2", PartitionID: pOmni0, Chain: vChain, Asset: "BTC",
		Members: []signjob.BatchMember{member("t1", f.other, 50_000), member("t2", f.other, 50_000)}}
	pt := Payload{Version: 2, Inputs: p.Inputs[:1], Outputs: []PayloadOutput{{f.other, 50_000}, {f.other, 50_000}, {f.hot0, 190_000}}}
	f.must(pt, twin)
}

// A hostile core: every way it can bend the transaction away from the approved members is refused.
func TestVerifyBatchRefusesAHostileCore(t *testing.T) {
	f := newBatchFixture(t)
	p, b := f.batch()
	clone := func() (Payload, signjob.Batch) {
		q := p
		q.Inputs = append([]PayloadInput{}, p.Inputs...)
		q.Outputs = append([]PayloadOutput{}, p.Outputs...)
		c := b
		c.Members = append([]signjob.BatchMember{}, b.Members...)
		return q, c
	}

	q, c := clone()
	q.Outputs = append(q.Outputs[:3], PayloadOutput{f.other, 50_000}, PayloadOutput{f.hot0, q.Outputs[3].Value - 50_000}) // an extra payment before the change
	f.refuse("an added output", q, c, "want the 3 payments and at most one change")
	q, c = clone()
	q.Outputs[3].Value -= 10_000
	q.Outputs = append(q.Outputs, PayloadOutput{f.hot0, 10_000}) // a second change
	f.refuse("a second change output", q, c, "want the 3 payments and at most one change")

	q, c = clone()
	q.Outputs[1].Address = f.coldS // a swapped address
	f.refuse("a swapped address", q, c, "output 1 pays")
	q, c = clone()
	q.Outputs[2].Value += 1_000 // a changed amount
	q.Outputs[3].Value -= 1_000
	f.refuse("a changed amount", q, c, "output 2 pays")
	q, c = clone()
	q.Outputs[0], q.Outputs[1] = q.Outputs[1], q.Outputs[0] // reordered
	f.refuse("reordered outputs", q, c, "output 0 pays")
	q, c = clone()
	c.Members[0], c.Members[1] = c.Members[1], c.Members[0] // reordered members, same transaction
	f.refuse("reordered members", q, c, "output 0 pays")

	q, c = clone()
	q.Outputs[3].Address = f.other // change to someone else
	f.refuse("change to a stranger", q, c, "not the partition's own shard")
	q, c = clone()
	q.Outputs[0], q.Outputs[3] = q.Outputs[3], q.Outputs[0] // change first: a payment lands where the change is
	f.refuse("change moved to the front", q, c, "not the partition's own shard")
	q, c = clone()
	q.Outputs[3].Address = f.hot1 // change to another shard of the zone
	f.refuse("change to another hot shard", q, c, "not the partition's own shard")

	q, c = clone()
	c.Members[2].Intent.ID = "w1" // a repeated id
	f.refuse("a repeated id", q, c, "appears twice")
	q, c = clone()
	c.Members[0].Intent.ID = c.ID
	f.refuse("a member with the batch's id", q, c, "batch's own id")
	q, c = clone()
	c.Members[1].Intent.Kind = "to-cold"
	f.refuse("a member of another kind", q, c, "a batch pays withdrawals")
	q, c = clone()
	c.Members[1].Intent.PartitionID = pBeta0
	f.refuse("a member of another partition", q, c, "differ from the batch's")
	q, c = clone()
	c.Members[1].Intent.Amount = "0150000"
	f.refuse("a non-canonical amount", q, c, "amount")

	// Over the zone's own ceilings.
	big := signjob.Batch{Kind: signjob.KindBatch, ID: "b3", PartitionID: pOmni0, Chain: vChain, Asset: "BTC"}
	pb := Payload{Version: 2, Inputs: []PayloadInput{in(1, 300_000, 1, 0)}}
	for i := 0; i <= bMaxOutputs; i++ {
		big.Members = append(big.Members, member(fmt.Sprintf("m%d", i), f.other, 20_000))
		pb.Outputs = append(pb.Outputs, PayloadOutput{f.other, 20_000})
	}
	pb.Outputs = append(pb.Outputs, PayloadOutput{f.hot0, 300_000 - 6*20_000 - 2_000})
	f.refuse("more outputs than the zone's ceiling", pb, big, "the zone's ceiling is 5")

	rich := signjob.Batch{Kind: signjob.KindBatch, ID: "b4", PartitionID: pOmni0, Chain: vChain, Asset: "BTC",
		Members: []signjob.BatchMember{member("r1", f.other, 1_200_000), member("r2", f.cold, 900_000)}}
	pr := Payload{Version: 2, Inputs: []PayloadInput{in(1, 3_000_000, 1, 0)}, Outputs: []PayloadOutput{{f.other, 1_200_000}, {f.cold, 900_000}, {f.hot0, 890_000}}}
	f.refuse("more value than the zone's ceiling", pr, rich, "ceiling is 2000000")

	// The fee: over the zone's cap for this size, however the outputs add up.
	q, c = clone()
	q.Outputs[3].Value = 100_000 // fee 500,000 - 100,000 ... far above the cap
	f.refuse("a fee over the cap", q, c, "exceeds the cap")

	// Inputs outside the partition's own shard (a deposit key, another shard).
	q, c = clone()
	q.Inputs[1] = in(2, 300_000, 0, 5)
	f.refuse("an input from the deposit branch", q, c, "not the partition's own shard")
	q, c = clone()
	q.Inputs[1] = in(2, 300_000, 1, 1)
	f.refuse("an input of another shard", q, c, "not the partition's own shard")

	// The job's key reference names another partition.
	for n := range p.Inputs {
		u := f.jobFor(pBeta0, p, n)
		if _, err := f.bv.VerifyBatch(u, b); err == nil || !strings.Contains(err.Error(), "key partition") {
			t.Fatalf("a job for another partition: %v", err)
		}
	}
	// A batch that names the wrong chain or asset.
	q, c = clone()
	c.Chain = "other"
	f.refuse("another chain", q, c, "batch chain")
	q, c = clone()
	c.Asset = "ETH"
	f.refuse("another asset", q, c, "batch asset")
	q, c = clone()
	c.Members = nil
	f.refuse("no members", q, c, "at least one member")
}

// A zone with no ceilings signs no batches; the ceilings must be set together; and the fee caps must reach the rate ceiling for the largest batch.
func TestVerifyBatchNeedsTheZonesOwnCeilings(t *testing.T) {
	f := newBatchFixture(t)
	p, b := f.batch()
	if _, err := f.v.VerifyBatch(f.job(p, 0), b); err == nil || !strings.Contains(err.Error(), "does not sign batches") {
		t.Fatalf("a zone without ceilings: %v", err)
	}
	cfg := SigningConfig{Chain: vChain, Network: "regtest", AccountXpub: acctXpub(f.acct), HotShards: map[string]HotShard{pOmni0: {Address: f.hot0, Path: []uint32{1, 0}}},
		MaxTxFeeSats: 100_000, MaxFeeRate: 100, MaxInputs: 4}
	cfg.MaxBatchOutputs = 5
	if _, err := NewVerifier(cfg); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("outputs without a value ceiling: %v", err)
	}
	cfg.MaxBatchOutputs, cfg.MaxBatchValue = 0, 1_000
	if _, err := NewVerifier(cfg); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("a value ceiling without outputs: %v", err)
	}
	// 50 payments and 4 inputs at 100 sat/vB need more than 100,000 sats of cap: the start-up check refuses, with the numbers.
	cfg.MaxBatchOutputs, cfg.MaxBatchValue = 50, 1_000_000
	if _, err := NewVerifier(cfg); err == nil || !strings.Contains(err.Error(), "50 payment output(s)") {
		t.Fatalf("a fee cap that cannot reach the rate ceiling for 50 payments: %v", err)
	}
	cfg.MaxTxFeeSats = 400_000
	if _, err := NewVerifier(cfg); err != nil {
		t.Fatal(err)
	}
}

// The fee-bump reserve applies to the whole batch as the zone sees it: the change must reach zoneFeeCap(vs) - fee + dust, whatever the core reserved.
func TestCheckFirstSendBatchKeepsTheReserve(t *testing.T) {
	f := newBatchFixture(t)
	p, b := f.batch()
	intent := signjob.Intent{Kind: signjob.KindBatch, ID: b.ID, PartitionID: pOmni0, Chain: vChain, Asset: "BTC"}
	// A batch whose change covers the cap: inputs 2 x 300,000, payments 370,000, the rate cap 100 x vs is about 40,000 and the change left is 228,000.
	if err := f.bv.CheckFirstSend(f.job(p, 0), intent); err != nil {
		t.Fatal(err)
	}
	// The core keeps nothing in change: the fee eats it all up to the cap's edge, then no room for a bump.
	q := p
	q.Outputs = append([]PayloadOutput{}, p.Outputs...)
	q.Inputs = []PayloadInput{in(1, 300_000, 1, 0), in(2, 95_000, 1, 0)}
	q.Outputs[3].Value = 395_000 - 370_000 - 1_000 // fee 1,000, change 24,000; the rate cap is 100 sat/vB x 283 vbytes = 28,300, so the reserve is 28,300 + 294 dust
	err := f.bv.CheckFirstSend(f.job(q, 0), intent)
	if err == nil || !strings.Contains(err.Error(), "keeps 24000 sats of change") || !strings.Contains(err.Error(), "at least 27594") || !strings.Contains(err.Error(), CapMismatchNote) {
		t.Fatalf("a batch without the reserve: %v", err)
	}
	// No change output at all: it could never be bumped.
	q.Outputs = q.Outputs[:3]
	if err := f.bv.CheckFirstSend(f.job(q, 0), intent); err == nil || !strings.Contains(err.Error(), "no change output") {
		t.Fatalf("a batch without change: %v", err)
	}
}
