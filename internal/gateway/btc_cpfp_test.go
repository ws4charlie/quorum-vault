package gateway

import (
	"fmt"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A CPFP child is judged against what the zone itself signed: it must spend the change of one of its own sends, to the same shard, and the pair must
// stay within the zone's caps. The harness caps are 50,000 sats and 170 sat/vB.

// signedParent signs a withdrawal paying 100,000 from two inputs and returns its payload and txid. Its fee is 2,000 sats over 209 vbytes.
func (b *btcH) signedParent(id string, n int, fee uint64) (btc.Payload, string) {
	b.t.Helper()
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(n, 0, 150_000, 1, 0), btcIn(n+1, 0, 150_000, 1, 0)},
		Outputs: []btc.PayloadOutput{{Address: b.other, Value: 100_000}, {Address: b.hot0, Value: 300_000 - 100_000 - fee}}}
	b.mustSignAll(b.jobs(id, wdIntent(id, b.other, 100_000), p, "auto"))
	u, _ := btc.BuildUnsigned(p, b.acct)
	return p, u.TxID
}

// child is a child of parent (txid, with change at output 1 holding value) that pays fee, as the core builds it.
func (b *btcH) child(id, parentTxid string, value, fee uint64) (btc.Payload, signjob.Intent) {
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: parentTxid, Vout: 1, Value: value, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: value - fee}}}
	return p, signjob.Intent{Kind: "cpfp", ID: id, To: b.hot0, Amount: "0"}
}

const cpfpRoom = 18_700 // min(50,000 - 2,000, 170 x 110) for a child of 110 vbytes of a parent that paid 2,000

func TestBTCCPFPChildSignsWithoutApprovalsAndIsBumped(t *testing.T) {
	b := newBTCHarness(t)
	pp, txid := b.signedParent("w1", 1, 2_000)
	p, in := b.child("cpfp-w1", txid, pp.Outputs[1].Value, 3_000)
	b.mustSignAll(b.jobs("c1", in, p))
	// A bump of the child: the same input and intent, a higher fee, up to the room.
	q := p
	q.Outputs = []btc.PayloadOutput{{Address: b.hot0, Value: p.Inputs[0].Value - cpfpRoom}}
	b.mustSignAll(b.jobs("c2", in, q))
	// A lower fee is not a bump.
	r := p
	r.Outputs = []btc.PayloadOutput{{Address: b.hot0, Value: p.Inputs[0].Value - 2_500}}
	b.mustRefuse(b.jobs("c3", in, r)[0], ReasonFeeNotHigher)
}

func TestBTCCPFPChildMayAddCoinsOfTheSameShard(t *testing.T) {
	b := newBTCHarness(t)
	pp, txid := b.signedParent("w1", 1, 2_000)
	p, in := b.child("cpfp-w1", txid, pp.Outputs[1].Value, 3_000)
	p.Inputs = append(p.Inputs, btcIn(90, 0, 40_000, 1, 0))
	p.Outputs[0].Value += 40_000
	b.mustSignAll(b.jobs("c1", in, p))
}

// What a compromised business zone could try with a child, each refused before a key signs.
func TestBTCCPFPHostileChildrenAreRefused(t *testing.T) {
	b := newBTCHarness(t)
	pp, txid := b.signedParent("w1", 1, 2_000)
	change := pp.Outputs[1].Value
	n := 0
	try := func(name string, code string, change func(p *btc.Payload, in *signjob.Intent)) {
		t.Helper()
		n++
		id := fmt.Sprintf("h%d", n)
		p, in := b.child("cpfp-"+id, txid, pp.Outputs[1].Value, 3_000)
		change(&p, &in)
		b.mustRefuse(b.jobs(id, in, p)[0], code)
	}
	try("pays another address", ReasonTx, func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = b.other })
	try("pays the cold address", ReasonTx, func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = b.cold })
	try("pays another partition's shard", ReasonTx, func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = b.hot1 })
	try("the intent names another address", ReasonTx, func(_ *btc.Payload, in *signjob.Intent) { in.To = b.other })
	try("a payment output as well", ReasonTx, func(p *btc.Payload, _ *signjob.Intent) {
		p.Outputs = []btc.PayloadOutput{{Address: b.hot0, Value: change - 53_000}, {Address: b.other, Value: 50_000}}
	})
	try("an amount", ReasonTx, func(_ *btc.Payload, in *signjob.Intent) { in.Amount = "1" })
	try("a deposit output as the only input", ReasonTx, func(p *btc.Payload, _ *signjob.Intent) { p.Inputs = []btc.PayloadInput{btcIn(60, 0, change, 0, 5)} })
	try("a coin of another partition", ReasonTx, func(p *btc.Payload, _ *signjob.Intent) { p.Inputs[0].Path = []uint32{1, 1} })
	try("the parent's payment output, not its change", ReasonCPFP, func(p *btc.Payload, _ *signjob.Intent) {
		p.Inputs[0].Vout, p.Inputs[0].Value, p.Outputs[0].Value = 0, 100_000, 97_000
	})
	try("the change with another value", ReasonCPFP, func(p *btc.Payload, _ *signjob.Intent) {
		p.Inputs[0].Value, p.Outputs[0].Value = change+1_000_000, change+1_000_000-3_000
	})
	try("a coin that is not the change of any signed transaction", ReasonCPFP, func(p *btc.Payload, _ *signjob.Intent) {
		p.Inputs = []btc.PayloadInput{btcIn(61, 1, change, 1, 0)}
	})
	try("one satoshi over the child's own rate ceiling", ReasonTx, func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Value = change - (cpfpRoom + 1) })
	try("a child of a different partition than its parent", ReasonCPFP, func(p *btc.Payload, in *signjob.Intent) {
		p.Inputs[0].Path, p.Outputs[0].Address, in.PartitionID, in.To = []uint32{1, 1}, b.hot1, btcPart1, b.hot1
	})
	if b.tree.calls.Load() != 2 { // only the parent's two inputs were ever signed
		t.Fatalf("%d signatures: a key signed a refused child", b.tree.calls.Load())
	}
	// The room itself is allowed.
	p, in := b.child("cpfp-ok", txid, change, cpfpRoom)
	b.mustSignAll(b.jobs("ok", in, p))
}

// The package cap is the zone's own: a parent that paid 35,530 sats (the rate cap of its 209 vbytes) leaves 14,470 under the 50,000 sats cap for a child of
// 110 vbytes (the child's own ceiling, 18,700, is higher). One satoshi more is refused, and nothing signs for it.
func TestBTCCPFPPackageCapIsTheZones(t *testing.T) {
	b := newBTCHarness(t)
	const atCap = 35_530 // 170 sat/vB x 209 vbytes
	pp, txid := b.signedParent("w1", 1, atCap)
	over, oin := b.child("cpfp-w1", txid, pp.Outputs[1].Value, 14_471)
	b.mustRefuse(b.jobs("over", oin, over)[0], ReasonCPFP)
	ok, in := b.child("cpfp-w1", txid, pp.Outputs[1].Value, 14_470)
	b.mustSignAll(b.jobs("ok", in, ok))
}

// One child per parent: a second child under another intent, and a child of a parent whose change something else already spent, are refused.
func TestBTCCPFPOneChildPerParent(t *testing.T) {
	b := newBTCHarness(t)
	pp, txid := b.signedParent("w1", 1, 2_000)
	p, in := b.child("cpfp-a", txid, pp.Outputs[1].Value, 3_000)
	b.mustSignAll(b.jobs("a", in, p))
	q, qin := b.child("cpfp-b", txid, pp.Outputs[1].Value, 4_000)
	b.mustRefuse(b.jobs("b", qin, q)[0], ReasonNonceTaken)
	// A parent whose change a withdrawal already spent.
	pp2, txid2 := b.signedParent("w2", 10, 2_000)
	spend := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: txid2, Vout: 1, Value: pp2.Outputs[1].Value, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: b.other, Value: 100_000}, {Address: b.hot0, Value: pp2.Outputs[1].Value - 100_000 - 2_000}}}
	b.mustSignAll(b.jobs("w3", wdIntent("w3", b.other, 100_000), spend, "auto"))
	r, rin := b.child("cpfp-c", txid2, pp2.Outputs[1].Value, 3_000)
	b.mustRefuse(b.jobs("c", rin, r)[0], ReasonNonceTaken)
}

// A child has one parent: spending the change of two signed sends is refused.
func TestBTCCPFPChildHasOneParent(t *testing.T) {
	b := newBTCHarness(t)
	pa, ta := b.signedParent("w1", 1, 2_000)
	pb, tb := b.signedParent("w2", 10, 2_000)
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{
		{TxID: ta, Vout: 1, Value: pa.Outputs[1].Value, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF},
		{TxID: tb, Vout: 1, Value: pb.Outputs[1].Value, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: pa.Outputs[1].Value + pb.Outputs[1].Value - 3_000}}}
	b.mustRefuse(b.jobs("two", signjob.Intent{Kind: "cpfp", ID: "cpfp-two", To: b.hot0, Amount: "0"}, p)[0], ReasonCPFP)
}

// A cancel of the parent stays possible once a child is signed: it spends the parent's own inputs, and the child's claim (the parent's change) is a
// different claim. The cancel evicts the child on chain.
func TestBTCCPFPCancelOfTheParentStillSigns(t *testing.T) {
	b := newBTCHarness(t)
	pp, txid := b.signedParent("w1", 1, 2_000)
	p, in := b.child("cpfp-w1", txid, pp.Outputs[1].Value, 3_000)
	b.mustSignAll(b.jobs("c", in, p))
	cp := btc.Payload{Version: 2, Inputs: pp.Inputs, Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: 300_000 - 9_000}}}
	b.mustSignAll(b.jobs("k", signjob.Intent{Kind: "cancel", ID: "cancel-w1", To: b.hot0, Amount: "0"}, cp))
}

// A parent that is a hot-to-cold move can be pulled in too, a sweep (no change) cannot be named as a parent: the zone records no change for it.
func TestBTCCPFPParentsAreOnlySendsThatKeepChange(t *testing.T) {
	b := newBTCHarness(t)
	sw := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(70, 0, 80_000, 0, 5)}, Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: 78_000}}}
	b.mustSignAll(b.jobs("s", signjob.Intent{Kind: "sweep", ID: "s1", From: b.dep, To: b.hot0, Amount: "80000"}, sw))
	u, _ := btc.BuildUnsigned(sw, b.acct)
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: u.TxID, Vout: 0, Value: 78_000, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: 76_000}}}
	b.mustRefuse(b.jobs("c", signjob.Intent{Kind: "cpfp", ID: "cpfp-s", To: b.hot0, Amount: "0"}, p)[0], ReasonCPFP)
}

// A batch is a parent like a single send: the zone records its change (the last output) when it signs it, and a child may pull the whole batch in.
func TestBTCCPFPBatchParent(t *testing.T) {
	b := newBatchHarness(t, nil)
	ms := b.threeMembers("m")
	pay := b.batchPayload(b.twoIn(1), ms, 2_000)
	b.mustSignAll(b.batchJobs("b1", b.batchOf("b1", ms...), pay))
	u, _ := btc.BuildUnsigned(pay, b.acct)
	cv := uint32(len(pay.Outputs) - 1)
	value := pay.Outputs[cv].Value
	mk := func(vout uint32, val, fee uint64) btc.Payload {
		return btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: u.TxID, Vout: vout, Value: val, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
			Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: val - fee}}}
	}
	in := signjob.Intent{Kind: "cpfp", ID: "cpfp-b1", To: b.hot0, Amount: "0"}
	b.mustRefuse(b.jobs("x", in, mk(0, 100_000, 3_000))[0], ReasonCPFP) // a member's payment output, not the change
	b.mustSignAll(b.jobs("c", in, mk(cv, value, 3_000)))
}
