package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Replacing the Bitcoin account key (K6): the zone signs for a second generation of the deposit tree from operator-signed records, by the state of the
// generation and with the generation's own key. The software harness only.

const btcTreeID = "qv-us/" + btcChain + "/deposit-tree/0"

// btcGenRig is a zone with a Bitcoin chain whose account key has two generations; the second is registered by signed records.
type btcGenRig struct {
	*ksRig
	gw         *Gateway
	tree1      *softTree // generation 1
	tree2      *softTree // generation 2
	acct       *btc.Account
	xpub2      string
	hot0, hot2 string // the partition's hot shard under generation 1 and 2
	dep1       string // [0,5] under generation 1
	dep2       string // [0,7] under generation 2
	cold, any  string
	built      int
}

func privAccount(t *testing.T, seed byte) (*hdkeychain.ExtendedKey, string) {
	t.Helper()
	m, err := hdkeychain.NewMaster(bytes.Repeat([]byte{seed}, 32), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	k := m
	for _, n := range []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart} {
		if k, err = k.Derive(n); err != nil {
			t.Fatal(err)
		}
	}
	x, _ := k.Neuter()
	return k, x.String()
}

func newBTCGenRig(t *testing.T) *btcGenRig {
	t.Helper()
	r := &btcGenRig{ksRig: newKSRig(t)}
	ctx := context.Background()
	priv1, xpub1 := privAccount(t, 3)
	priv2, xpub2 := privAccount(t, 4)
	r.xpub2 = xpub2
	r.tree1, r.tree2 = &softTree{acct: priv1}, &softTree{acct: priv2}
	acct, err := btc.NewAccount("regtest", xpub1)
	if err != nil {
		t.Fatal(err)
	}
	acct.SetGenerationLoader(func(g uint32) (string, error) {
		if g == 2 {
			return xpub2, nil
		}
		return "", fmt.Errorf("no generation %d", g)
	})
	r.acct = acct
	r.hot0, _ = acct.Address([]uint32{1, 0})
	r.hot2, _ = acct.AddressAt(2, []uint32{1, 0})
	r.dep1, _ = acct.Address([]uint32{0, 5})
	r.dep2, _ = acct.AddressAt(2, []uint32{0, 7})
	r.cold, r.any = foreignAddr(9), foreignAddr(10)

	ten := 10
	cf := ChainFile{Family: "btc", WithdrawalsPerHour: 1000, SweepsPerHour: 1000, CancelsPerHour: 1000, ToColdPerHour: 1000, ConsolidationsPerHour: 2, DrainsPerHour: &ten,
		BTC: &BTCFile{Network: "regtest", AccountXpub: xpub1, MaxTxFeeSats: 50_000, MaxFeeRate: 170, MaxInputs: 3,
			HotShards:     map[string]HotShardFile{btcPartition: {Address: r.hot0, Path: []uint32{1, 0}}},
			ColdAddresses: map[string]string{"omnibus/native": r.cold}},
		Assets: map[string]AssetFile{"BTC": {AnyDestination: true, PerTxCap: "100000000", DailyCap: "1000000000", Tiers: []TierFile{{"0", 1}}, ToColdDailyCap: "1000000000"}}}
	cc, err := cf.build(btcChain, 4)
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.Chains[btcChain] = cc
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('` + btcChain + `','BTC',8)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + btcPartition + `','qv-us','` + btcChain + `','BTC','hot','omnibus',0)`,
	} {
		if _, err := r.biz.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	gw, err := New(r.cfg, nil, map[string]signer.Signer{btcPartition: r.tree1}, r.guard, r.biz, Options{WorkerID: "btc-gen", Lease: time.Minute, Now: r.clock,
		Generations: func(p string, base signer.Signer, e *KeysetEntry) (signer.Signer, error) {
			r.built++
			if e.KeyRef != "ref-2" {
				return nil, fmt.Errorf("unknown key reference %q", e.KeyRef)
			}
			return r.tree2, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Wait(10 * time.Second) })
	r.gw = gw
	return r
}

// candidate registers generation 2 of the Bitcoin account key.
func (r *btcGenRig) candidate(guards ...*Guard) {
	r.t.Helper()
	r.step(btcTreeID, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.KeyRef, c.PublicKey = "ref-2", r.xpub2 }, guards...)
}

func (r *btcGenRig) drain1(guards ...*Guard) {
	r.t.Helper()
	r.step(btcTreeID, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor, c.Caps = 2, map[string]string{"BTC": "300000"} }, guards...)
}

func (r *btcGenRig) activate2(guards ...*Guard) {
	r.t.Helper()
	r.step(btcTreeID, KeysetActivate, 2, nil, guards...)
}

// job builds the one job per input of p for the intent, with the key references of the inputs' generation.
func (r *btcGenRig) jobs(id string, in signjob.Intent, p btc.Payload, approvers ...string) []signjob.Job {
	r.t.Helper()
	in.Chain, in.PartitionID, in.Asset = btcChain, cmpStr(in.PartitionID, btcPartition), "BTC"
	if in.Kind == "withdrawal" && in.NotAfter == 0 {
		in.NotAfter = r.clock().Add(time.Hour).Unix()
	}
	if in.Kind == signjob.KindDrain && in.NotAfter == 0 {
		in.NotAfter = r.clock().Add(time.Hour).Unix()
	}
	u, err := btc.BuildUnsigned(p, r.acct)
	if err != nil {
		r.t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var out []signjob.Job
	for i, pin := range p.Inputs {
		jid := id
		if i > 0 {
			jid = fmt.Sprintf("%s.%d", id, i)
		}
		out = append(out, signjob.Job{ID: jid, PartitionID: in.PartitionID, KeyRef: chain.KeyPathAt(int(pin.Gen), btc.PathString(pin.Path)), Chain: btcChain, Intent: mustJSON(in),
			Digest: u.Digests[i], Payload: raw, Approvals: r.approvals(in, approvers...)})
	}
	return out
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (r *btcGenRig) run(j signjob.Job) Decision { return r.harness.runWith(r.gw, j) }

func (r *btcGenRig) calls() (int32, int32) { return r.tree1.calls.Load(), r.tree2.calls.Load() }

// signs requires every job to be signed, and by the key of the generation that owns it.
func (r *btcGenRig) signs(js []signjob.Job, gen int) {
	r.t.Helper()
	for _, j := range js {
		d := r.run(j)
		if d.Outcome != OutcomeSigned {
			r.t.Fatalf("job %s: %s %s, want signed", j.ID, d.Outcome, d.Reason)
		}
		var pub *ecdsa.PublicKey
		g, path, err := btc.ParseKeyRef(j.KeyRef)
		if err != nil {
			r.t.Fatal(err)
		}
		if int(g) != gen {
			r.t.Fatalf("job %s names generation %d, the test expects %d", j.ID, g, gen)
		}
		raw, _ := r.acct.PubAt(g, path)
		pub = mustParseCompressed(r.t, raw)
		var dg [32]byte
		copy(dg[:], j.Digest)
		if !signer.Verify(pub, dg, signer.Signature{R: new(big.Int).SetBytes(d.Sig[:32]), S: new(big.Int).SetBytes(d.Sig[32:])}) {
			r.t.Fatalf("job %s: the signature is not by the key of generation %d at %v", j.ID, gen, path)
		}
	}
}

// refuses requires every job to be refused with the code, and that no key signed it.
func (r *btcGenRig) refuses(js []signjob.Job, code string) string {
	r.t.Helper()
	a, b := r.calls()
	var why string
	for _, j := range js {
		d := r.run(j)
		if d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, code+":") {
			r.t.Fatalf("job %s: %s %q, want rejected %s", j.ID, d.Outcome, d.Reason, code)
		}
		why = d.Reason
	}
	if a2, b2 := r.calls(); a2 != a || b2 != b {
		r.t.Fatalf("a key signed a refused job (%d,%d -> %d,%d)", a, b, a2, b2)
	}
	return why
}

func gen2In(n int, vout uint32, value uint64, path ...uint32) btc.PayloadInput {
	in := btcIn(n, vout, value, path...)
	in.Gen = 2
	return in
}

// sweepOf is a sweep of one deposit input to dest.
func sweepOf(in btc.PayloadInput, dest string, from string) (btc.Payload, signjob.Intent) {
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{in}, Outputs: []btc.PayloadOutput{{Address: dest, Value: in.Value - 1000}}}
	return p, signjob.Intent{Kind: "sweep", ID: "sw-" + in.TxID[:2] + "-" + dest[len(dest)-4:], From: from, To: dest, Amount: fmt.Sprint(in.Value)}
}

// withdrawalFrom is a withdrawal from the partition's hot shard under generation gen (change back to that generation's shard).
func (r *btcGenRig) withdrawalFrom(id string, gen uint32, shardAddr string, n int) ([]signjob.Job, btc.Payload) {
	in := btcIn(n, 0, 300_000, 1, 0)
	in.Gen = gen
	if gen == 1 {
		in.Gen = 0
	}
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{in}, Outputs: []btc.PayloadOutput{{Address: r.any, Value: 100_000}, {Address: shardAddr, Value: 190_000}}}
	return r.jobs(id, wdIntent("w-"+id, r.any, 100_000), p, "auto"), p
}

func (r *btcGenRig) drainJobs(id string, from, to string, srcGen uint32, value uint64, n int) []signjob.Job {
	in := btcIn(n, 0, value, 1, 0)
	if srcGen > 1 {
		in.Gen = srcGen
	}
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{in}, Outputs: []btc.PayloadOutput{{Address: to, Value: value - 1000}}}
	return r.jobs(id, signjob.Intent{Kind: signjob.KindDrain, ID: id, From: from, To: to, Amount: fmt.Sprint(value)}, p)
}

// With no record the zone behaves as it always did: generation 1 signs everything, and no later generation exists.
func TestBTCZoneOneGenerationBehavesAsBefore(t *testing.T) {
	r := newBTCGenRig(t)
	js, _ := r.withdrawalFrom("a", 1, r.hot0, 1)
	r.signs(js, 1)
	p, in := sweepOf(btcIn(2, 0, 80_000, 0, 5), r.hot0, r.dep1)
	r.signs(r.jobs("s1", in, p), 1)
	// A payload that names generation 2 is refused: the zone has no key for it.
	p2, in2 := sweepOf(gen2In(3, 0, 80_000, 0, 7), r.hot2, r.dep2)
	r.refuses(r.jobs("s2", in2, p2), ReasonTx)
}

// A candidate signs nothing; once it is active its deposit addresses sweep to its own hot shard, the old generation's to the new one's.
func TestBTCZoneSweepsFollowTheGenerationsState(t *testing.T) {
	r := newBTCGenRig(t)
	r.candidate()

	// Candidate: nothing of generation 2 signs; generation 1 goes on as before.
	p2, in2 := sweepOf(gen2In(10, 0, 80_000, 0, 7), r.hot2, r.dep2)
	why := r.refuses(r.jobs("c2", in2, p2), ReasonKeyset)
	if !strings.Contains(why, "candidate") {
		t.Fatalf("reason %q", why)
	}
	p1, in1 := sweepOf(btcIn(11, 0, 80_000, 0, 5), r.hot0, r.dep1)
	r.signs(r.jobs("c1", in1, p1), 1)

	// Generation 1 draining into the candidate: its sweeps wait for the successor to be active (a refusal the planner retries), nothing signs.
	r.drain1()
	p1b, in1b := sweepOf(btcIn(12, 0, 80_000, 0, 5), r.hot2, r.dep1)
	in1b.ID = "sw-wait"
	r.refuses(r.jobs("d1", in1b, p1b), ReasonKeyset)

	r.activate2()
	// The old address sweeps to the NEW hot shard, with the OLD key; to the old hot shard it is refused.
	pa, ia := sweepOf(btcIn(13, 0, 80_000, 0, 5), r.hot2, r.dep1)
	r.signs(r.jobs("n1", ia, pa), 1)
	pb, ib := sweepOf(btcIn(14, 0, 80_000, 0, 5), r.hot0, r.dep1)
	why = r.refuses(r.jobs("n2", ib, pb), ReasonKeyset)
	if !strings.Contains(why, "successor") {
		t.Fatalf("reason %q", why)
	}
	// The new address sweeps to the new hot shard with the NEW key; to the old hot shard it is refused.
	pc, ic := sweepOf(gen2In(15, 0, 80_000, 0, 7), r.hot2, r.dep2)
	r.signs(r.jobs("n3", ic, pc), 2)
	pd, id := sweepOf(gen2In(16, 0, 80_000, 0, 7), r.hot0, r.dep2)
	r.refuses(r.jobs("n4", id, pd), ReasonKeyset)
	// Withdrawals: the draining generation's hot shard signs none; the active one's does.
	js1, _ := r.withdrawalFrom("wd1", 1, r.hot0, 20)
	r.refuses(js1, ReasonKeyset)
	js2, _ := r.withdrawalFrom("wd2", 2, r.hot2, 21)
	r.signs(js2, 2)
}

// The hot shard of the old generation drains to the new one's: only to the successor, only within the cap, and only for a draining generation.
func TestBTCZoneDrainsTheOldHotShardToTheSuccessorOnly(t *testing.T) {
	r := newBTCGenRig(t)
	r.candidate()
	// Not draining yet: a drain waits (a retry until its not_after, not a refusal): nothing signs.
	d := r.run(r.drainJobs("dr0", r.hot0, r.hot2, 1, 200_000, 30)[0])
	if d.Outcome != OutcomeRetry {
		t.Fatalf("a drain of an active generation: %s %q", d.Outcome, d.Reason)
	}
	r.drain1()
	// The successor is a candidate: the drain waits for it.
	d = r.run(r.drainJobs("dr1", r.hot0, r.hot2, 1, 200_000, 31)[0])
	if d.Outcome != OutcomeRetry {
		t.Fatalf("a drain into a candidate: %s %q", d.Outcome, d.Reason)
	}
	r.activate2()
	r.refuses(r.drainJobs("dr2", r.hot0, r.any, 1, 200_000, 32), ReasonTx)        // to a stranger
	r.refuses(r.drainJobs("dr3", r.hot0, r.hot0, 1, 200_000, 33), ReasonTx)       // to itself
	r.refuses(r.drainJobs("dr4", r.hot0, r.hot2, 1, 400_000, 34), ReasonDrainCap) // more than the cap of the signed record (300000)
	r.signs(r.drainJobs("dr5", r.hot0, r.hot2, 1, 200_000, 35), 1)                // the drain itself
	r.refuses(r.drainJobs("dr6", r.hot0, r.hot2, 1, 200_000, 36), ReasonDrainCap) // 200000 already drained, the cap is 300000
	r.signs(r.drainJobs("dr7", r.hot0, r.hot2, 1, 100_000, 37), 1)                // the rest of the cap
	// An active generation's shard is not drained: the zone waits (it is no refusal that ends the drain) and nothing signs; the new one never pays the old one.
	a, b := r.calls()
	if d := r.run(r.drainJobs("dr8", r.hot2, r.hot0, 2, 100_000, 38)[0]); d.Outcome != OutcomeRetry {
		t.Fatalf("a drain of the active generation: %s %q", d.Outcome, d.Reason)
	}
	if a2, b2 := r.calls(); a2 != a || b2 != b {
		t.Fatal("a key signed a drain of the active generation")
	}
}

// A compromised generation sweeps and drains only to its successor and signs no withdrawal; a retired one signs nothing.
func TestBTCZoneCompromisedAndRetiredGenerations(t *testing.T) {
	r := newBTCGenRig(t)
	r.candidate()
	r.activate2Compromising()
	pa, ia := sweepOf(btcIn(50, 0, 80_000, 0, 5), r.hot2, r.dep1)
	r.signs(r.jobs("k1", ia, pa), 1)
	pb, ib := sweepOf(btcIn(51, 0, 80_000, 0, 5), r.hot0, r.dep1)
	r.refuses(r.jobs("k2", ib, pb), ReasonKeyset)
	js, _ := r.withdrawalFrom("kw", 1, r.hot0, 52)
	r.refuses(js, ReasonKeyset)
	r.signs(r.drainJobs("kd", r.hot0, r.hot2, 1, 100_000, 53), 1)
	// Never retired from compromised: the record does not allow it.
	c := r.ch(btcTreeID, KeysetRetire, 1, nil)
	if err := r.applyKS(r.guard, c); err == nil {
		t.Fatal("a compromised generation was retired")
	}
}

// activate2Compromising marks generation 1 compromised with generation 2 as its successor, then activates 2.
func (r *btcGenRig) activate2Compromising() {
	r.t.Helper()
	r.step(btcTreeID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor, c.Caps = 2, map[string]string{"BTC": "300000"} })
	r.activate2()
}

// A draining generation retires: its deposit addresses sign nothing after that, and nor does the retired hot shard.
func TestBTCZoneRetiredGenerationSignsNothing(t *testing.T) {
	r := newBTCGenRig(t)
	r.candidate()
	r.drain1()
	r.activate2()
	r.step(btcTreeID, KeysetRetire, 1, nil)
	pa, ia := sweepOf(btcIn(60, 0, 80_000, 0, 5), r.hot2, r.dep1)
	why := r.refuses(r.jobs("r1", ia, pa), ReasonKeyset)
	if !strings.Contains(why, "retired") {
		t.Fatalf("reason %q", why)
	}
	r.refuses(r.drainJobs("r2", r.hot0, r.hot2, 1, 100_000, 61), ReasonKeyset)
	// Generation 2 goes on.
	pc, ic := sweepOf(gen2In(62, 0, 80_000, 0, 7), r.hot2, r.dep2)
	r.signs(r.jobs("r3", ic, pc), 2)
}

// The records of a deposit tree: the identity must be an account xpub of the network, a second record must not repeat a key, and a registry change
// that is not signed by operators is ignored.
func TestBTCZoneTreeRecordsAreChecked(t *testing.T) {
	r := newBTCGenRig(t)
	bad := func(f func(c *KeysetChange), want string) {
		t.Helper()
		c := r.ch(btcTreeID, KeysetRegisterCandidate, 2, f)
		err := r.applyKS(r.guard, c)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("got %v, want %q", err, want)
		}
	}
	bad(func(c *KeysetChange) { c.KeyRef, c.PublicKey = "ref-2", "not-an-xpub" }, "xpub")
	bad(func(c *KeysetChange) { c.KeyRef, c.PublicKey = "ref-2", "" }, "key reference and public key")
	bad(func(c *KeysetChange) { c.KeyRef, c.PublicKey, c.Address = "ref-2", r.xpub2, r.hot2 }, "no address")
	_, xpub1 := privAccount(t, 3)
	bad(func(c *KeysetChange) { c.KeyRef, c.PublicKey = "ref-2", xpub1 }, "generation 1")
	bad(func(c *KeysetChange) { c.KeyRef, c.PublicKey = "ref-2", r.xpub2; c.Generation = 3 }, "next generation")
	// A private key is refused.
	m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{5}, 32), &chaincfg.RegressionNetParams)
	bad(func(c *KeysetChange) { c.KeyRef, c.PublicKey = "ref-2", m.String() }, "xpub")
	r.candidate()
	// Two actives are refused; start-draining needs the cap for Bitcoin.
	c := r.ch(btcTreeID, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor = 2 })
	if err := r.applyKS(r.guard, c); err == nil || !strings.Contains(err.Error(), "caps") {
		t.Fatalf("start-draining without the cap: %v", err)
	}
	c = r.ch(btcTreeID, KeysetActivate, 2, nil)
	if err := r.applyKS(r.guard, c); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("a second active generation: %v", err)
	}
}

// The cosigner judges by its own log: a zone whose log lacks the record refuses what the other accepts, and one that has it signs off the same job.
func TestBTCCosignerJudgesByItsOwnLog(t *testing.T) {
	r := newBTCGenRig(t)
	cos := mustGuard(t, r.harness)
	r.candidate(r.guard, cos)
	r.drain1(r.guard, cos)
	r.activate2(r.guard) // the cosigner has not seen the activation
	pc, ic := sweepOf(gen2In(70, 0, 80_000, 0, 7), r.hot2, r.dep2)
	js := r.jobs("cs", ic, pc)
	dec := NewDecider(r.cfg, r.gw.codecs, cos, ModeCosigner, r.clock)
	pub, _ := r.acct.PubAt(2, []uint32{0, 7})
	if _, err := dec.Decide(context.Background(), js[0], mustParseCompressed(t, pub)); err == nil {
		t.Fatal("the cosigner, whose log has no activation, allowed a sweep of a candidate")
	} else if _, ok := IsRejection(err); !ok {
		t.Fatalf("got %v, want a refusal", err)
	}
	r.activate2(cos)
	if v, err := dec.Decide(context.Background(), js[0], mustParseCompressed(t, pub)); err != nil || !v.NeedSign {
		t.Fatalf("the cosigner with the activation: %v", err)
	}
}

// Both sides derive from the signed record only: a payload whose generation the record does not give is refused even for an active one.
func TestBTCZoneRefusesAGenerationNoRecordGives(t *testing.T) {
	r := newBTCGenRig(t)
	r.candidate()
	r.drain1()
	r.activate2()
	in := btcIn(80, 0, 80_000, 0, 5)
	in.Gen = 3
	u := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{in}, Outputs: []btc.PayloadOutput{{Address: r.hot2, Value: 79_000}}}
	raw, _ := json.Marshal(u)
	// Built by hand: the test's own account does not know generation 3, so the digest is borrowed from generation 2's.
	in2 := in
	in2.Gen = 2
	u2 := u
	u2.Inputs = []btc.PayloadInput{in2}
	built, err := btc.BuildUnsigned(u2, r.acct)
	if err != nil {
		t.Fatal(err)
	}
	_, intent := sweepOf(in, r.hot2, r.dep1)
	j := signjob.Job{ID: "g3", PartitionID: btcPartition, KeyRef: "g3/0/5", Chain: btcChain, Intent: mustJSON(withKind(intent, btcPartition)), Digest: built.Digests[0], Payload: raw}
	r.refuses([]signjob.Job{j}, ReasonTx)
	// An explicit generation 1 is refused too: generation 1 is written as no generation.
	in.Gen = 1
	u.Inputs = []btc.PayloadInput{in}
	raw, _ = json.Marshal(u)
	j.ID, j.Payload, j.KeyRef = "g1", raw, "g1/0/5"
	r.refuses([]signjob.Job{j}, ReasonTx)
}

func withKind(i signjob.Intent, part string) signjob.Intent {
	i.Chain, i.PartitionID, i.Asset = btcChain, part, "BTC"
	return i
}

func mustParseCompressed(t *testing.T, raw []byte) *ecdsa.PublicKey {
	t.Helper()
	pub, err := ethCrypto.DecompressPubkey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

var _ = partition.StateActive
