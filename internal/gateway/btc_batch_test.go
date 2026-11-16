package gateway

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// batchHarness: a Bitcoin zone that signs batches of at most 4 payments and 1,000,000 sats, with caps that let such a batch reach the rate ceiling.
func newBatchHarness(t *testing.T, tweak func(cf *ChainFile, b *btcH)) *btcH {
	return newBTCHarnessWith(t, func(cf *ChainFile, b *btcH) {
		cf.BTC.MaxTxFeeSats, cf.BTC.MaxFeeRate, cf.BTC.MaxInputs = 100_000, 100, 3
		cf.BTC.MaxBatchOutputs, cf.BTC.MaxBatchValueSats = 4, 1_000_000
		cf.Assets["BTC"] = AssetFile{AnyDestination: true, PerTxCap: "500000", DailyCap: "20000000", Tiers: []TierFile{{"0", 1}, {"400000", 2}}, ToColdDailyCap: "1000000000"}
		if tweak != nil {
			tweak(cf, b)
		}
	})
}

// bm is a member of a batch under test: its id, destination, amount and who approved it.
type bm struct {
	id        string
	to        string
	amount    uint64
	approvers []string
	// notAfter is when the approvals lapse, from now (default one hour); noExpiry leaves not_after at zero.
	notAfter time.Duration
	noExpiry bool
}

func (b *btcH) bmember(m bm) signjob.BatchMember {
	in := signjob.Intent{Kind: "withdrawal", ID: m.id, PartitionID: btcPartition, Chain: btcChain, Asset: "BTC", To: m.to, Amount: fmt.Sprint(m.amount),
		NotAfter: b.clock().Add(cmpDur(m.notAfter, time.Hour)).Unix()}
	if m.noExpiry {
		in.NotAfter = 0
	}
	ap := m.approvers
	if ap == nil {
		ap = []string{"auto"}
	}
	return signjob.BatchMember{Intent: in, Approvals: b.approvals(in, ap...)}
}

func cmpDur(d, def time.Duration) time.Duration {
	if d != 0 {
		return d
	}
	return def
}

func (b *btcH) batchOf(id string, ms ...bm) signjob.Batch {
	bt := signjob.Batch{Kind: signjob.KindBatch, ID: id, PartitionID: btcPartition, Chain: btcChain, Asset: "BTC"}
	for _, m := range ms {
		bt.Members = append(bt.Members, b.bmember(m))
	}
	return bt
}

// batchPayload pays the members in order from the given inputs and returns the change (to the shard) last.
func (b *btcH) batchPayload(ins []btc.PayloadInput, ms []bm, fee uint64) btc.Payload {
	p := btc.Payload{Version: 2, Inputs: ins}
	var in, out uint64
	for _, i := range ins {
		in += i.Value
	}
	for _, m := range ms {
		p.Outputs = append(p.Outputs, btc.PayloadOutput{Address: m.to, Value: m.amount})
		out += m.amount
	}
	p.Outputs = append(p.Outputs, btc.PayloadOutput{Address: b.hot0, Value: in - out - fee})
	return p
}

// batchJobs is one sign job per input of p for the batch bt, as the business zone writes them: the batch is the intent, no approvals at job level.
func (b *btcH) batchJobs(id string, bt signjob.Batch, p btc.Payload) []signjob.Job {
	b.t.Helper()
	u, err := btc.BuildUnsigned(p, b.acct)
	if err != nil {
		b.t.Fatal(err)
	}
	raw := mustJSON(p)
	var out []signjob.Job
	for i := range p.Inputs {
		jid := id
		if i > 0 {
			jid = fmt.Sprintf("%s.%d", id, i)
		}
		out = append(out, signjob.Job{ID: jid, PartitionID: btcPartition, KeyRef: btc.PathString(p.Inputs[i].Path), Chain: btcChain, Intent: mustJSON(bt),
			Digest: u.Digests[i], Payload: raw})
	}
	return out
}

func (b *btcH) twoIn(n int) []btc.PayloadInput {
	return []btc.PayloadInput{btcIn(n, 0, 300_000, 1, 0), btcIn(n+1, 0, 300_000, 1, 0)}
}

func (b *btcH) threeMembers(prefix string) []bm {
	return []bm{{id: prefix + "1", to: b.other, amount: 100_000}, {id: prefix + "2", to: b.cold, amount: 120_000}, {id: prefix + "3", to: b.coldS, amount: 80_000}}
}

func (b *btcH) guardCount(where string, args ...any) int {
	b.t.Helper()
	var n int
	if err := b.guardDB.QueryRow(context.Background(), `SELECT count(*) FROM signed_intents WHERE `+where, args...).Scan(&n); err != nil {
		b.t.Fatal(err)
	}
	return n
}

// A correct batch signs every input, each member is recorded under its own id, and the audit trail names every member and its approvers.
func TestBTCBatchSignsAndRecordsEveryMember(t *testing.T) {
	b := newBatchHarness(t, nil)
	ms := b.threeMembers("m")
	ms[1].approvers = []string{"alice"}
	js := b.batchJobs("b1", b.batchOf("b1", ms...), b.batchPayload(b.twoIn(1), ms, 2_000))
	b.mustSignAll(js)
	if n := b.tree.calls.Load(); n != 2 {
		t.Fatalf("%d signatures for two inputs", n)
	}
	if got := b.guardCount(`batch_id='b1' AND kind='withdrawal'`); got != 3 {
		t.Fatalf("%d member rows", got)
	}
	if got := b.guardCount(`intent_id='b1' AND kind='batch' AND amount=300000`); got != 1 {
		t.Fatal("the batch row is missing or has the wrong amount")
	}
	var payload string
	if err := b.guardDB.QueryRow(context.Background(), `SELECT payload::text FROM audit_log WHERE type='sign.allowed' ORDER BY seq DESC LIMIT 1`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"m1"`, `"m2"`, `"m3"`, `"alice"`, `"auto"`} {
		if !strings.Contains(payload, want) {
			t.Fatalf("the audit record does not name %s: %s", want, payload)
		}
	}
	// The same batch again is a replay: the stored signature, nothing signed again.
	before := b.tree.calls.Load()
	again := js[0]
	again.ID = "b1-again"
	if d := b.run(again); d.Outcome != OutcomeReplayed {
		t.Fatalf("the same job again: %s %s", d.Outcome, d.Reason)
	}
	if b.tree.calls.Load() != before {
		t.Fatal("a key signed a replayed batch")
	}
}

// A hostile core cannot move the transaction away from what the members approved.
func TestBTCBatchRefusesAHostileCore(t *testing.T) {
	b := newBatchHarness(t, nil)
	ms := b.threeMembers("m")
	good := b.batchPayload(b.twoIn(1), ms, 2_000)
	n := 0
	attack := func(name, code string, bt signjob.Batch, p btc.Payload) {
		t.Helper()
		n++
		t.Logf("attack: %s", name)
		b.mustRefuse(b.batchJobs(fmt.Sprintf("x%d", n), bt, p)[0], code)
	}
	clone := func() btc.Payload {
		p := good
		p.Inputs = append([]btc.PayloadInput{}, good.Inputs...)
		p.Outputs = append([]btc.PayloadOutput{}, good.Outputs...)
		return p
	}
	bt := b.batchOf("hb", ms...)

	p := clone()
	p.Outputs = append(p.Outputs[:3], btc.PayloadOutput{Address: b.other, Value: 10_000}, btc.PayloadOutput{Address: b.hot0, Value: p.Outputs[3].Value - 10_000})
	attack("an added output", ReasonTx, bt, p)
	p = clone()
	p.Outputs[1].Address = b.other
	attack("a swapped address", ReasonTx, bt, p)
	p = clone()
	p.Outputs[0], p.Outputs[2] = p.Outputs[2], p.Outputs[0]
	attack("reordered outputs", ReasonTx, bt, p)
	p = clone()
	p.Outputs[3].Address = b.other
	attack("change to a stranger", ReasonTx, bt, p)
	p = clone()
	p.Outputs[0], p.Outputs[3] = p.Outputs[3], p.Outputs[0]
	attack("change first", ReasonTx, bt, p)
	p = clone()
	p.Outputs[2].Value += 5_000
	p.Outputs[3].Value -= 5_000
	attack("a changed amount", ReasonTx, bt, p)

	dup := b.batchOf("hb2", ms...)
	dup.Members[2].Intent.ID = "m1"
	attack("a repeated id", ReasonTx, dup, good)

	// The zone's own ceilings: five payments, then more than a million sats.
	five := []bm{{id: "f1", to: b.other, amount: 10_000}, {id: "f2", to: b.other, amount: 10_000}, {id: "f3", to: b.other, amount: 10_000},
		{id: "f4", to: b.other, amount: 10_000}, {id: "f5", to: b.other, amount: 10_000}}
	attack("more payments than the zone's ceiling", ReasonTx, b.batchOf("hb3", five...), b.batchPayload(b.twoIn(5), five, 2_000))
	rich := []bm{{id: "r1", to: b.other, amount: 400_000, approvers: []string{"alice", "bob"}}, {id: "r2", to: b.cold, amount: 400_000, approvers: []string{"alice", "bob"}},
		{id: "r3", to: b.coldS, amount: 400_000, approvers: []string{"alice", "bob"}}}
	big := []btc.PayloadInput{btcIn(7, 0, 1_000_000, 1, 0), btcIn(8, 0, 1_000_000, 1, 0)}
	attack("more value than the zone's ceiling", ReasonTx, b.batchOf("hb4", rich...), b.batchPayload(big, rich, 2_000))

	// The reserve: change below what the zone's own fee cap needs for a bump (zone cap 100 sat/vB x about 271 vbytes, plus dust).
	thin := []btc.PayloadInput{btcIn(9, 0, 200_000, 1, 0), btcIn(10, 0, 120_000, 1, 0)}
	attack("a batch without the reserve", ReasonTx, b.batchOf("hb5", ms...), b.batchPayload(thin, ms, 1_000))

	// Inputs of a deposit address.
	dep := clone()
	dep.Inputs[1] = btcIn(2, 0, 300_000, 0, 5)
	attack("an input that is not the shard's", ReasonTx, bt, dep)

	if b.tree.calls.Load() != 0 {
		t.Fatal("a key signed")
	}
}

// Approval stays per withdrawal and is judged for each member as for a single withdrawal.
func TestBTCBatchApprovalsArePerMember(t *testing.T) {
	b := newBatchHarness(t, nil)
	i := 0
	try := func(name, code string, mutate func(bt *signjob.Batch, job *signjob.Job), ms []bm) {
		t.Helper()
		i++
		bt := b.batchOf(fmt.Sprintf("ab%d", i), ms...)
		var ins []btc.PayloadInput
		for k := 0; k < 2; k++ {
			ins = append(ins, btcIn(20+i*2+k, 0, 600_000, 1, 0))
		}
		js := b.batchJobs(fmt.Sprintf("ab%d", i), bt, b.batchPayload(ins, ms, 2_000))
		if mutate != nil {
			mutate(&bt, &js[0])
			js[0].Intent = mustJSON(bt)
		}
		t.Logf("case: %s", name)
		b.mustRefuse(js[0], code)
	}
	mk := func(prefix string) []bm {
		return []bm{{id: prefix + "1", to: b.other, amount: 100_000}, {id: prefix + "2", to: b.cold, amount: 120_000}}
	}
	mkWith := func(prefix string, edit func(m *bm)) []bm {
		ms := mk(prefix)
		edit(&ms[1])
		return ms
	}
	try("a member with no approval", ReasonApprovals, func(bt *signjob.Batch, _ *signjob.Job) { bt.Members[1].Approvals = nil }, mk("a"))
	try("an approval by an unknown actor", ReasonApprovals, func(bt *signjob.Batch, _ *signjob.Job) {
		bt.Members[0].Approvals = append(bt.Members[0].Approvals, signjob.Approval{Actor: "mallory", Signature: make([]byte, ed25519.SignatureSize)})
	}, mk("b"))
	try("an approval by a disabled approver next to a valid one", ReasonApprovals, func(bt *signjob.Batch, _ *signjob.Job) {
		h := bt.Members[0].Intent.Hash()
		bt.Members[0].Approvals = append(bt.Members[0].Approvals, signjob.Approval{Actor: "dave", Signature: ed25519.Sign(b.keys["dave"], h[:])})
	}, mk("c"))
	try("an approval over another withdrawal's intent", ReasonApprovals, func(bt *signjob.Batch, _ *signjob.Job) {
		bt.Members[1].Approvals = bt.Members[0].Approvals // member 1's intent is not the one member 0's approver signed
	}, mk("d"))
	try("an approval of the batch itself", ReasonApprovals, func(_ *signjob.Batch, j *signjob.Job) {
		j.Approvals = b.approvals(signjob.Intent{Kind: "withdrawal", ID: "x"}, "alice")
	}, mk("e"))
	try("a large member with one approval", ReasonTier, nil, []bm{{id: "t1", to: b.other, amount: 450_000}})
	try("a member above the per-transaction cap", ReasonPerTxCap, nil, []bm{{id: "p1", to: b.other, amount: 600_000, approvers: []string{"alice", "bob"}}})
	try("an approval that lapsed", ReasonExpired, nil, mkWith("f", func(m *bm) { m.notAfter = -time.Minute }))
	try("a member without not_after", ReasonExpired, nil, mkWith("g", func(m *bm) { m.noExpiry = true }))
	try("a member too far ahead", ReasonExpired, nil, mkWith("h", func(m *bm) { m.notAfter = 48 * time.Hour }))
	// Two approvers lift a member over the tier, and the batch signs.
	ok := []bm{{id: "ok1", to: b.other, amount: 450_000, approvers: []string{"alice", "bob"}}, {id: "ok2", to: b.cold, amount: 100_000}}
	b.mustSignAll(b.batchJobs("abok", b.batchOf("abok", ok...), b.batchPayload([]btc.PayloadInput{btcIn(90, 0, 600_000, 1, 0), btcIn(91, 0, 600_000, 1, 0)}, ok, 2_000)))
}

// The destination rule applies to every member, read from the transaction.
func TestBTCBatchDestinationsAreChecked(t *testing.T) {
	b := newBatchHarness(t, func(cf *ChainFile, b *btcH) {
		a := cf.Assets["BTC"]
		a.AnyDestination, a.WithdrawalDestinations = false, []string{foreignAddr(10)}
		cf.Assets["BTC"] = a
	})
	ms := []bm{{id: "d1", to: b.other, amount: 100_000}, {id: "d2", to: b.cold, amount: 100_000}}
	b.mustRefuse(b.batchJobs("d", b.batchOf("d", ms...), b.batchPayload(b.twoIn(1), ms, 2_000))[0], ReasonDestination)
	ok := []bm{{id: "d3", to: b.other, amount: 100_000}, {id: "d4", to: b.other, amount: 50_000}}
	b.mustSignAll(b.batchJobs("d-ok", b.batchOf("d-ok", ok...), b.batchPayload(b.twoIn(3), ok, 2_000)))
}

// Every member counts towards the hourly limit and the daily cap, like a withdrawal of its own.
func TestBTCBatchMembersCountTowardsTheLimits(t *testing.T) {
	b := newBatchHarness(t, func(cf *ChainFile, _ *btcH) {
		cf.WithdrawalsPerHour = 5
		a := cf.Assets["BTC"]
		a.DailyCap = "700000"
		cf.Assets["BTC"] = a
		cf.BTC.MaxBatchValueSats = 700_000
	})
	first := b.threeMembers("a") // 300,000 in three withdrawals
	b.mustSignAll(b.batchJobs("l1", b.batchOf("l1", first...), b.batchPayload(b.twoIn(1), first, 2_000)))
	second := b.threeMembers("b") // three more: 6 in the hour against a limit of 5
	b.mustRefuse(b.batchJobs("l2", b.batchOf("l2", second...), b.batchPayload(b.twoIn(3), second, 2_000))[0], ReasonWithdrawRate)
	third := []bm{{id: "c1", to: b.other, amount: 450_000, approvers: []string{"alice", "bob"}}} // 300,000 + 450,000 > 700,000 in a day
	b.mustRefuse(b.batchJobs("l3", b.batchOf("l3", third...), b.batchPayload([]btc.PayloadInput{btcIn(9, 0, 600_000, 1, 0), btcIn(10, 0, 600_000, 1, 0)}, third, 2_000))[0], ReasonDailyCap)
	// A single withdrawal sees the batch's members in the hour too: two more fit, a third does not.
	for k := 1; k <= 3; k++ {
		in := wdIntent(fmt.Sprintf("s%d", k), b.other, 100_000)
		js := b.jobs(fmt.Sprintf("s%d", k), in, b.twoInputsAt(30+2*k), "auto")
		if k < 3 {
			b.mustSignAll(js)
		} else {
			b.mustRefuse(js[0], ReasonWithdrawRate)
		}
	}
}

// A withdrawal id the zone signed is signed once, in one batch: not alone, not in another batch. A replacement of the same batch is the only way to
// sign its members again, and a cancel of the batch is the existing cancel of its inputs.
func TestBTCBatchWithdrawalIdsAreUsedOnce(t *testing.T) {
	b := newBatchHarness(t, nil)
	ms := b.threeMembers("m")
	bt := b.batchOf("b1", ms...)
	first := b.batchJobs("b1", bt, b.batchPayload(b.twoIn(1), ms, 2_000))
	b.mustSignAll(first)

	// The same member in a different batch, on other inputs.
	other := []bm{{id: "m2", to: b.cold, amount: 120_000}, {id: "n1", to: b.other, amount: 10_000}}
	b.mustRefuse(b.batchJobs("b2", b.batchOf("b2", other...), b.batchPayload(b.twoIn(5), other, 2_000))[0], ReasonMemberReused)
	// The same member alone, as a single withdrawal, on other inputs.
	p := b.twoInputsAt(60)
	p.Outputs[0].Address = b.cold
	b.mustRefuse(b.jobs("solo", wdIntent("m2", b.cold, 100_000), p, "auto")[0], ReasonMemberReused)
	// A batch whose own id is a member's id, or a single withdrawal's.
	b.mustSignAll(b.jobs("single", wdIntent("w-single", b.other, 100_000), b.twoInputsAt(70), "auto"))
	over := []bm{{id: "n2", to: b.other, amount: 10_000}}
	b.mustRefuse(b.batchJobs("m1", b.batchOf("m1", over...), b.batchPayload(b.twoIn(80), over, 2_000))[0], ReasonMemberReused)
	reuse := []bm{{id: "w-single", to: b.other, amount: 100_000}}
	b.mustRefuse(b.batchJobs("b4", b.batchOf("b4", reuse...), b.batchPayload(b.twoIn(82), reuse, 2_000))[0], ReasonMemberReused)

	// The batch id with other members is another batch.
	changed := []bm{ms[0], ms[1], {id: "m9", to: b.coldS, amount: 80_000}}
	b.mustRefuse(b.batchJobs("b1x", b.batchOf("b1", changed...), b.batchPayload(b.twoIn(1), changed, 4_000))[0], ReasonIntentChanged)
	reordered := []bm{ms[1], ms[0], ms[2]}
	b.mustRefuse(b.batchJobs("b1y", b.batchOf("b1", reordered...), b.batchPayload(b.twoIn(1), reordered, 4_000))[0], ReasonIntentChanged)

	// A replacement of the same batch: same inputs, same payments, a smaller change. A lower fee is not one.
	b.mustRefuse(b.batchJobs("b1r0", bt, b.batchPayload(b.twoIn(1), ms, 1_500))[0], ReasonFeeNotHigher)
	b.mustSignAll(b.batchJobs("b1r1", bt, b.batchPayload(b.twoIn(1), ms, 6_000)))
	// ... on other inputs it is not.
	b.mustRefuse(b.batchJobs("b1r2", bt, b.batchPayload(b.twoIn(3), ms, 9_000))[0], ReasonNonceChanged)

	// The cancel of the batch: its own inputs back to the shard. After it the batch cannot be replaced, and its members are still spent for good.
	cancel := btc.Payload{Version: 2, Inputs: b.twoIn(1), Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: 590_000}}}
	cin := signjob.Intent{Kind: "cancel", ID: "cancel-b1", PartitionID: btcPartition, Chain: btcChain, Asset: "BTC", To: b.hot0, Amount: "0"}
	b.mustSignAll(b.jobs("c1", cin, cancel))
	b.mustRefuse(b.batchJobs("b1r3", bt, b.batchPayload(b.twoIn(1), ms, 12_000))[0], ReasonNonceCancel)
	b.mustRefuse(b.batchJobs("b5", b.batchOf("b5", ms...), b.batchPayload(b.twoIn(90), ms, 2_000))[0], ReasonMemberReused)
}

func (b *btcH) twoInputsAt(n int) btc.Payload {
	p := b.twoInputs(150_000, 150_000, b.other, 197_000) // a fee of 3,000
	p.Inputs = []btc.PayloadInput{btcIn(n, 0, 150_000, 1, 0), btcIn(n+1, 0, 150_000, 1, 0)}
	return p
}

// A zone that sets no ceilings signs no batches, whatever the core sends; the config refuses a batch value outside the policy's caps.
func TestBTCBatchOffByDefault(t *testing.T) {
	b := newBTCHarness(t)
	ms := b.threeMembers("m")
	js := b.batchJobs("off", b.batchOf("off", ms...), b.batchPayload(b.twoIn(1), ms, 2_000))
	d := b.run(js[0])
	if d.Outcome != OutcomeRejected || !strings.Contains(d.Reason, "does not sign batches") {
		t.Fatalf("%s %s", d.Outcome, d.Reason)
	}
	cf := ChainFile{Family: "btc", WithdrawalsPerHour: 10, BTC: &BTCFile{Network: "regtest", AccountXpub: b.gw.cfg.Chains[btcChain].BTC.AccountXpub, MaxTxFeeSats: 100_000, MaxFeeRate: 100, MaxInputs: 3,
		HotShards: map[string]HotShardFile{btcPartition: {Address: b.hot0, Path: []uint32{1, 0}}}, MaxBatchOutputs: 4, MaxBatchValueSats: 50},
		Assets: map[string]AssetFile{"BTC": {AnyDestination: true, PerTxCap: "100", DailyCap: "1000", Tiers: []TierFile{{"0", 1}}}}}
	if _, err := cf.build(btcChain, 4); err == nil || !strings.Contains(err.Error(), "max_batch_value_sats") {
		t.Fatalf("a batch value below the per-transaction cap: %v", err)
	}
	cf.BTC.MaxBatchValueSats = 2_000
	if _, err := cf.build(btcChain, 4); err == nil || !strings.Contains(err.Error(), "max_batch_value_sats") {
		t.Fatalf("a batch value above the daily cap: %v", err)
	}
	cf.BTC.MaxBatchValueSats = 500
	if _, err := cf.build(btcChain, 4); err != nil {
		t.Fatal(err)
	}
}

// The cosigner next to party B runs the same decider from its own config and store: a batch the core sends both parties is checked twice.
func TestBTCBatchCosignerDecidesTheSame(t *testing.T) {
	b := newBatchHarness(t, nil)
	cos := NewDecider(b.cfg, b.gw.codecs, mustGuard(t, b.harness), ModeCosigner, b.clock)
	key, err := b.tree.At(context.Background(), []uint32{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	ms := b.threeMembers("m")
	good := b.batchPayload(b.twoIn(1), ms, 2_000)
	bt := b.batchOf("c1", ms...)
	js := b.batchJobs("c1", bt, good)
	evil := good
	evil.Outputs = append([]btc.PayloadOutput{}, good.Outputs...)
	evil.Outputs[1].Address = b.other
	ej := b.batchJobs("c-evil", bt, evil)
	if _, err := cos.Decide(t.Context(), ej[0], key.PublicKey()); err == nil {
		t.Fatal("the cosigner allowed a swapped address")
	} else if why, _ := IsRejection(err); !strings.HasPrefix(why, ReasonTx+":") {
		t.Fatalf("err %v", err)
	}
	if v, err := cos.Decide(t.Context(), js[0], key.PublicKey()); err != nil || !v.NeedSign {
		t.Fatalf("the right batch: %+v %v", v, err)
	}
	// The cosigner's own store has the members: the same id in another batch is refused there too, whatever the gateway's store says.
	other := []bm{ms[0], {id: "z", to: b.other, amount: 10_000}}
	_, err = cos.Decide(t.Context(), b.batchJobs("c2", b.batchOf("c2", other...), b.batchPayload(b.twoIn(5), other, 2_000))[0], key.PublicKey())
	if why, _ := IsRejection(err); !strings.HasPrefix(why, ReasonMemberReused+":") {
		t.Fatalf("err %v, want %s", err, ReasonMemberReused)
	}
}

// The only way a withdrawal id the zone signed in a batch is signed again: a batch that spends an output of a cancel the zone signed for that
// withdrawal's latest batch. The cancel is signed but never broadcast here: the zone cannot know that, and the rule holds all the same.
func TestBTCBatchResendAfterACancel(t *testing.T) {
	b := newBatchHarness(t, nil)
	ms := b.threeMembers("m")
	bt1 := b.batchOf("b1", ms...)
	b.mustSignAll(b.batchJobs("b1", bt1, b.batchPayload(b.twoIn(1), ms, 2_000)))

	cancelOf := func(id string, ins []btc.PayloadInput, total uint64) (btc.PayloadInput, []signjob.Job) {
		p := btc.Payload{Version: 2, Inputs: ins, Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: total - 3_000}}}
		u, err := btc.BuildUnsigned(p, b.acct)
		if err != nil {
			t.Fatal(err)
		}
		cin := signjob.Intent{Kind: "cancel", ID: "cancel:batch:" + id, PartitionID: btcPartition, Chain: btcChain, Asset: "BTC", To: b.hot0, Amount: "0"}
		return btc.PayloadInput{TxID: u.TxID, Vout: 0, Value: total - 3_000, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}, b.jobs("c-"+id, cin, p)
	}
	out1, c1 := cancelOf("b1", b.twoIn(1), 600_000)

	// Before the cancel is signed: the same members on other coins are refused.
	other := b.batchOf("b2", ms...)
	b.mustRefuse(b.batchJobs("b2-1", other, b.batchPayload(b.twoIn(5), ms, 2_000))[0], ReasonMemberReused)
	b.mustSignAll(c1) // the cancel of b1 is signed (and, for the zone, may be broadcast any time)

	// A batch on other coins is still refused: both could confirm.
	b.mustRefuse(b.batchJobs("b2-2", other, b.batchPayload(b.twoIn(5), ms, 2_000))[0], ReasonMemberReused)
	// One that spends the cancel's output, with a second coin, is signed, and the members move to it.
	ins2 := []btc.PayloadInput{out1, btcIn(6, 0, 300_000, 1, 0)}
	b.mustSignAll(b.batchJobs("b2", other, b.batchPayload(ins2, ms, 2_000)))
	if got := b.guardCount(`batch_id='b2' AND kind='withdrawal'`); got != 3 {
		t.Fatalf("%d members moved to b2", got)
	}
	if got := b.guardCount(`batch_id='b1' AND kind='withdrawal'`); got != 0 {
		t.Fatalf("%d members left in b1", got)
	}
	// They were counted once: the hourly count is three withdrawals, not six.
	if got := b.guardCount(`kind='withdrawal'`); got != 3 {
		t.Fatalf("%d withdrawal rows", got)
	}
	// The same members once more, in b3 that spends the first cancel's output again: not what the rule asks for any more (b2 is their latest batch).
	b3 := b.batchOf("b3", ms...)
	b.mustRefuse(b.batchJobs("b3-1", b3, b.batchPayload([]btc.PayloadInput{btcIn(7, 0, 300_000, 1, 0), btcIn(8, 0, 300_000, 1, 0)}, ms, 2_000))[0], ReasonMemberReused)
	// A chain of cancels: b2 is cancelled too (its inputs include the first cancel's output), and b3 must spend the second cancel's output.
	out2, c2 := cancelOf("b2", ins2, 590_000+300_000)
	b.mustSignAll(c2)
	b.mustRefuse(b.batchJobs("b3-2", b3, b.batchPayload([]btc.PayloadInput{out1, btcIn(9, 0, 300_000, 1, 0)}, ms, 2_000))[0], ReasonMemberReused) // out1 belongs to the first cancel: b2, not b1, is the members' latest batch
	b.mustSignAll(b.batchJobs("b3", b3, b.batchPayload([]btc.PayloadInput{out2, btcIn(10, 0, 300_000, 1, 0)}, ms, 2_000)))
}
