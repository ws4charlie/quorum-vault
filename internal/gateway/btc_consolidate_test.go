package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// consolidation is a consolidation of the omnibus shard: n inputs of 30,000 sats, one output back to the shard for a fee of 1,000 sats.
func (b *btcH) consolidation(id string, base, n int) (btc.Payload, signjob.Intent) {
	p := btc.Payload{Version: 2}
	var sum uint64
	for i := 0; i < n; i++ {
		p.Inputs = append(p.Inputs, btcIn(base+i, 0, 30_000, 1, 0))
		sum += 30_000
	}
	p.Outputs = []btc.PayloadOutput{{Address: b.hot0, Value: sum - 1_000}}
	return p, signjob.Intent{Kind: "consolidate", ID: id, Asset: "BTC", To: b.hot0, Amount: fmt.Sprint(sum)}
}

// A consolidation needs no approval and signs every input, each under the shard's key.
func TestBTCConsolidationSignsWithoutApprovals(t *testing.T) {
	b := newBTCHarness(t)
	p, in := b.consolidation("co1", 60, 3)
	b.mustSignAll(b.jobs("co1", in, p))
	if n := b.tree.calls.Load(); n != 3 {
		t.Fatalf("%d signatures for three inputs", n)
	}
	// The segregated pool's shard consolidates itself under its own partition.
	sp := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(70, 0, 30_000, 1, 2), btcIn(71, 0, 30_000, 1, 2)}, Outputs: []btc.PayloadOutput{{Address: b.hotS, Value: 59_000}}}
	b.mustSignAll(b.jobs("cos", signjob.Intent{Kind: "consolidate", ID: "co-seg", PartitionID: btcPartSeg, To: b.hotS, Amount: "60000"}, sp))
}

// What a compromised business zone could try, each refused by the gateway before a key signs.
func TestBTCConsolidationAttacksAreRefused(t *testing.T) {
	b := newBTCHarness(t)
	n := 0
	try := func(name string, change func(p *btc.Payload, in *signjob.Intent), code string) {
		t.Helper()
		n++
		p, in := b.consolidation(fmt.Sprintf("a%d", n), 100+n*10, 3)
		change(&p, &in)
		before := b.tree.calls.Load()
		d := b.run(b.jobs(fmt.Sprintf("a%d", n), in, p)[0])
		if d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, code+":") {
			t.Fatalf("%s: %s %q, want rejected %s", name, d.Outcome, d.Reason, code)
		}
		if b.tree.calls.Load() != before {
			t.Fatalf("%s: a key signed a refused job", name)
		}
	}
	try("output to any other address", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = b.other }, ReasonTx)
	try("output to the cold address", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = b.cold }, ReasonTx)
	try("output to another partition's shard", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = b.hot1 }, ReasonTx)
	try("the intent names another address", func(_ *btc.Payload, in *signjob.Intent) { in.To = b.other }, ReasonTx)
	try("a second output", func(p *btc.Payload, _ *signjob.Intent) {
		p.Outputs = []btc.PayloadOutput{{Address: b.hot0, Value: 40_000}, {Address: b.other, Value: 49_000}}
	}, ReasonTx)
	try("one input", func(p *btc.Payload, in *signjob.Intent) {
		p.Inputs, p.Outputs, in.Amount = p.Inputs[:1], []btc.PayloadOutput{{Address: b.hot0, Value: 29_000}}, "30000"
	}, ReasonTx)
	try("an input from another partition", func(p *btc.Payload, _ *signjob.Intent) { p.Inputs[1] = btcIn(1, 1, 30_000, 1, 1) }, ReasonTx)
	try("an input from a deposit address", func(p *btc.Payload, _ *signjob.Intent) { p.Inputs[1] = btcIn(2, 1, 30_000, 0, 5) }, ReasonTx)
	// No key of the account signs a cold address's outputs, so there is no path for them: any path off the shard's own is refused (the verifier's own
	// test covers an empty path; the test builder here cannot derive one).
	try("an input at a hot key that no shard pins", func(p *btc.Payload, _ *signjob.Intent) { p.Inputs[1].Path = []uint32{1, 7} }, ReasonTx)
	try("an amount that is not the sum", func(_ *btc.Payload, in *signjob.Intent) { in.Amount = "89999" }, ReasonTx)
	try("an amount that is the output", func(_ *btc.Payload, in *signjob.Intent) { in.Amount = "89000" }, ReasonTx)
	try("a fee above the cap", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Value = 90_000 - 60_000 }, ReasonTx)
}

// At most consolidations_per_hour new consolidations are signed in an hour; the limit counts intents, so a fee bump of one that was signed is not
// counted again, and 0 refuses them all.
func TestBTCConsolidationRateLimit(t *testing.T) {
	b := newBTCHarness(t)
	p1, i1 := b.consolidation("r1", 200, 2)
	b.mustSignAll(b.jobs("r1", i1, p1))
	p2, i2 := b.consolidation("r2", 210, 2)
	b.mustSignAll(b.jobs("r2", i2, p2))
	p3, i3 := b.consolidation("r3", 220, 2)
	b.mustRefuse(b.jobs("r3", i3, p3)[0], ReasonConsolidateRate)

	// A bump of the first: the same inputs and intent, a higher fee. It is not a new consolidation.
	bump := p1
	bump.Outputs = []btc.PayloadOutput{{Address: b.hot0, Value: p1.Outputs[0].Value - 500}}
	b.mustSignAll(b.jobs("r1b", i1, bump))

	// An hour later the window has moved on.
	b.advance(61 * time.Minute)
	b.mustSignAll(b.jobs("r3b", i3, p3))

	// Zero refuses all.
	b.gw.cfg.Chains[btcChain].ConsolidationsPerHour = 0
	p4, i4 := b.consolidation("r4", 230, 2)
	b.mustRefuse(b.jobs("r4", i4, p4)[0], ReasonConsolidateRate)
}

// The cap is a fee cap: a gateway that signs only what it is told is still bounded by max_tx_fee_sats per consolidation, so the loss a rogue
// core can cause is at most the hourly limit times that fee. A consolidation at the cap passes, one satoshi over is refused.
func TestBTCConsolidationFeeIsBoundedByTheCap(t *testing.T) {
	b := newBTCHarness(t)
	p, in := b.consolidation("f1", 300, 3)
	p.Outputs[0].Value = 90_000 - 50_000 // the cap is 50,000 sats; that is a rate above 1000 sat/vB? no: ~270 vB, so 185 sat/vB, under max_fee_rate 1000
	b.mustSignAll(b.jobs("f1", in, p))
	q, qin := b.consolidation("f2", 310, 3)
	q.Outputs[0].Value = 90_000 - 50_001
	b.mustRefuse(b.jobs("f2", qin, q)[0], ReasonTx)
}
