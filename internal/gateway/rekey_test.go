package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Replacing the key of a hot shard (K3): the zone signs from the second generation by its state, the drain counts what was signed, and an operator
// can raise a drain's cap. The software harness only (the package is at the SoftHSM login limit).

// genRig is a key-set rig whose gateway can also sign from a second key: generation 2 of shard 1.
type genRig struct {
	*ksRig
	key2   *ecdsa.PrivateKey
	addr2  common.Address
	signr2 *countingSigner
	built  atomic.Int32 // how many times the zone built the signer of a later generation
}

func newGenRig(t *testing.T) *genRig {
	t.Helper()
	g := &genRig{ksRig: newKSRig(t)}
	g.key2, _ = crypto.GenerateKey()
	g.addr2 = crypto.PubkeyToAddress(g.key2.PublicKey)
	g.signr2 = &countingSigner{Signer: softSigner{g.key2}}
	g.cfg.Chains[testChain].RebalancePerHour = 100
	gw, err := New(g.cfg, nil, map[string]signer.Signer{testPartition: g.signer, testColdPartition: g.signer}, g.guard, g.biz,
		Options{WorkerID: "w-gen", Lease: time.Minute, Now: g.clock, Generations: func(p string, base signer.Signer, e *KeysetEntry) (signer.Signer, error) {
			g.built.Add(1)
			if _, _, err := entryKey(e); err != nil {
				return nil, err
			}
			if e.KeyRef != "ref-2" {
				return nil, fmt.Errorf("unknown key reference %q", e.KeyRef)
			}
			return g.signr2, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	g.gw = gw
	return g
}

// candidate2 registers generation 2 with its key reference and public key, as `qv-rekey candidate` does.
func (g *genRig) candidate2(guards ...*Guard) {
	g.t.Helper()
	g.step(testShardID, KeysetRegisterCandidate, 2, func(c *KeysetChange) {
		c.Address, c.KeyRef, c.PublicKey = g.addr2.Hex(), "ref-2", hex.EncodeToString(crypto.FromECDSAPub(&g.key2.PublicKey))
	}, guards...)
}

// from2 rewrites a job so that its transaction is sent from generation 2.
func (g *genRig) from2(j signjob.Job) signjob.Job {
	var p evm.Payload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		g.t.Fatal(err)
	}
	p.From = g.addr2.Hex()
	j.Payload = mustJSON(p)
	return j
}

func (g *genRig) checkSig2(j signjob.Job, d Decision) {
	g.t.Helper()
	if len(d.Sig) != 64 {
		g.t.Fatalf("signature is %d bytes", len(d.Sig))
	}
	for v := byte(0); v < 2; v++ {
		pub, err := crypto.Ecrecover(j.Digest, append(append([]byte{}, d.Sig...), v))
		if err == nil && common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]) == g.addr2 {
			return
		}
	}
	g.t.Fatalf("job %s: the signature does not recover to generation 2 (%s)", j.ID, g.addr2)
}

func (g *genRig) sign2(j signjob.Job) {
	g.t.Helper()
	d := g.run(j)
	if d.Outcome != OutcomeSigned {
		g.t.Fatalf("job %s: outcome %s (%s), want signed", j.ID, d.Outcome, d.Reason)
	}
	g.checkSig2(j, d)
}

func (g *genRig) wd1(id string, amount int64, nonce uint64) signjob.Job {
	in := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w-" + id, Asset: "ETH", To: addrUser.Hex(), Amount: fmt.Sprint(amount), PartitionID: testColdPartition}
	return g.job(id, in, g.ethTx(addrUser, amount, nonce), "alice", "bob")
}

// ---- the zone signs from generation 2 as its state allows ----

func TestZoneSignsFromTheSecondGenerationByItsState(t *testing.T) {
	g := newGenRig(t)
	g.mustSign(g.wd1("a0", 100, 0)) // one generation: exactly as before, and no later-generation signer is ever built
	if g.built.Load() != 0 {
		t.Fatal("a later generation's signer was built for generation 1")
	}

	g.candidate2()
	// A candidate signs nothing, whichever key the job names.
	d := g.mustReject(g.from2(g.wd1("c1", 100, 0)), ReasonKeyset)
	if !strings.Contains(d.Reason, "candidate") || g.signr2.calls.Load() != 0 {
		t.Fatalf("candidate: %s, signer calls %d", d.Reason, g.signr2.calls.Load())
	}
	g.mustSign(g.wd1("a1", 100, 1)) // generation 1 is untouched by the candidate

	// Draining generation 1 into it, and activating: generation 2 signs what an active key signs; generation 1 only drains.
	g.startDraining(testShardID, 1, 2)
	g.step(testShardID, KeysetActivate, 2, nil)
	g.sign2(g.from2(g.wd1("b0", 101, 0)))
	g.mustReject(g.wd1("a2", 100, 2), ReasonKeyset) // generation 1: no normal work
	g.sign2(g.from2(g.job("b-tc", signjob.Intent{Kind: "to-cold", ID: "tc-2", Asset: "ETH", To: addrCold.Hex(), Amount: "10", PartitionID: testColdPartition}, g.ethTx(addrCold, 10, 1))))
	// The drain is signed by generation 1's own key (the configured signer), to generation 2's address.
	g.mustSign(g.drain("n1", g.addr2, 4000, 2, "ETH"))
	// Generation 2 does not drain: it is active, and the zone treats a drain from it as one that waits for a state that never comes.
	bad := g.from2(g.drain("n2", addrG2, 10, 3, "ETH"))
	d = g.run(bad)
	if d.Outcome == OutcomeSigned {
		t.Fatal("generation 2 signed a drain")
	}
	if g.signr2.calls.Load() != 2 {
		t.Fatalf("generation 2's signer was called %d times, want exactly 2 (two jobs signed)", g.signr2.calls.Load())
	}

	// Retired: nothing, from either key.
	g.step(testShardID, KeysetRetire, 1, nil)
	g.mustReject(g.wd1("a3", 100, 4), ReasonKeyset)
	g.sign2(g.from2(g.wd1("b1", 102, 2)))
}

func TestZoneRefusesAJobWhoseSenderIsNoGenerationOfItsShard(t *testing.T) {
	g := newGenRig(t)
	g.candidate2()
	g.startDraining(testShardID, 1, 2)
	g.step(testShardID, KeysetActivate, 2, nil)
	// A sender that is a generation of ANOTHER shard (or nobody's): the shard's partition does not sign for it.
	stray := g.wd1("s0", 100, 0)
	var p evm.Payload
	json.Unmarshal(stray.Payload, &p)
	p.From = addrShard2.Hex()
	stray.Payload = mustJSON(p)
	g.mustReject(stray, ReasonTx)
	p.From = addrEvil.Hex()
	stray.Payload = mustJSON(p)
	stray.ID = "s1"
	stray.Intent = mustJSON(func() signjob.Intent {
		var in signjob.Intent
		json.Unmarshal(stray.Intent, &in)
		in.ID = "w-s1"
		return in
	}())
	g.mustReject(stray, ReasonTx)
}

func TestZonePolicyCountersArePerShardNotPerGeneration(t *testing.T) {
	g := newGenRig(t)
	// The daily cap of ETH is 8000 and the per-transaction cap 5000 (the harness config): a replacement cannot double the allowance.
	g.mustSign(g.wd1("d0", 5000, 0))
	g.candidate2()
	g.startDraining(testShardID, 1, 2)
	g.step(testShardID, KeysetActivate, 2, nil)
	g.sign2(g.from2(g.wd1("d1", 3000, 0)))
	g.mustReject(g.from2(g.wd1("d2", 1, 1)), ReasonDailyCap) // 5000 from generation 1 + 3000 from generation 2 = the whole day
}

func TestZoneCompromisedGenerationOnlyDrains(t *testing.T) {
	g := newGenRig(t)
	g.candidate2()
	g.step(testShardID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	g.mustReject(g.wd1("x0", 100, 0), ReasonKeyset)
	g.step(testShardID, KeysetActivate, 2, nil)
	g.mustReject(g.wd1("x1", 100, 0), ReasonKeyset)
	g.mustSign(g.drain("x2", g.addr2, 100, 0, "ETH"))
	// ... and only to the successor.
	g.mustReject(g.drain("x3", addrEvil, 100, 1, "ETH"), ReasonKeyset)
	g.sign2(g.from2(g.wd1("x4", 100, 0))) // the new key works
	// A compromised key does not come back.
	if err := g.applyKS(g.guard, g.ch(testShardID, KeysetActivate, 1, nil)); err == nil {
		t.Fatal("a compromised generation was activated")
	}
}

func TestZoneCannotSignFromACandidateRegisteredWithoutAKey(t *testing.T) {
	g := newGenRig(t)
	g.step(testShardID, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.Address = g.addr2.Hex() }) // receives, but the zone has no way to sign from it
	g.startDraining(testShardID, 1, 2)
	g.step(testShardID, KeysetActivate, 2, nil)
	d := g.run(g.from2(g.wd1("n0", 100, 0)))
	if d.Outcome == OutcomeSigned || g.signr2.calls.Load() != 0 {
		t.Fatalf("signed without a key reference: %+v", d)
	}
	g.mustSign(g.drain("n1", g.addr2, 100, 0, "ETH")) // the drain from generation 1 into it still works
}

func TestKeysetCandidateKeyMustBeTheKeyOfItsAddress(t *testing.T) {
	r := newGenRig(t)
	other, _ := crypto.GenerateKey()
	for name, f := range map[string]func(*KeysetChange){
		"another key's address": func(c *KeysetChange) {
			c.Address, c.KeyRef, c.PublicKey = addrG2.Hex(), "ref-2", hex.EncodeToString(crypto.FromECDSAPub(&other.PublicKey))
		},
		"a reference without a key": func(c *KeysetChange) { c.Address, c.KeyRef = r.addr2.Hex(), "ref-2" },
		"a key without a reference": func(c *KeysetChange) {
			c.Address, c.PublicKey = r.addr2.Hex(), hex.EncodeToString(crypto.FromECDSAPub(&r.key2.PublicKey))
		},
		"a compressed key": func(c *KeysetChange) {
			c.Address, c.KeyRef, c.PublicKey = r.addr2.Hex(), "ref-2", hex.EncodeToString(crypto.CompressPubkey(&r.key2.PublicKey))
		},
	} {
		c := r.ch(testShardID, KeysetRegisterCandidate, 2, f)
		if err := r.applyKS(r.guard, c); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	if n := r.rowsKS(r.guard); n != 0 {
		t.Fatalf("%d rows written by refused changes", n)
	}
	// A key reference on any other action is a malformed change.
	r.candidate2()
	c := r.ch(testShardID, KeysetActivate, 2, func(c *KeysetChange) { c.KeyRef = "ref-2" })
	if err := r.applyKS(r.guard, c); err == nil {
		t.Fatal("activate with a key reference applied")
	}
	// The record is in force and audited with the key it names.
	e := r.view(r.guard).entry(partition.ShardID(testShardID), 2)
	if e == nil || e.KeyRef != "ref-2" || e.PublicKey == "" {
		t.Fatalf("entry %+v", e)
	}
	found := false
	for _, a := range r.auditRows() {
		if a.Type == EventKeysetChanged && a.Payload["key_ref"] == "ref-2" {
			found = true
		}
	}
	if !found {
		t.Fatal("the audit event does not name the key reference")
	}
}

// A record written before this release (no key columns) reads back the same: the signed message of a change without a key is byte for byte what it was.
func TestKeysetChangeMessageWithoutAKeyIsUnchanged(t *testing.T) {
	c := KeysetChange{Action: KeysetRegisterCandidate, Shard: testShardID, Generation: 2, Address: addrG2.Hex(), Seq: 1, SignedAt: 5}
	want := `qv-keyset-change-v1
{"action":"register-candidate","shard":"qv-us/evm-test/omnibus/1","generation":2,"address":"` + addrG2.Hex() + `","seq":1,"signed_at":5}`
	if got := string(KeysetChangeMessage(c)); got != want {
		t.Fatalf("message changed:\n%s\nwant\n%s", got, want)
	}
}

// ---- the drain counts what was signed ----

// A drain the signer failed to sign (the other party refused, or the signer was down) is not a drain: it does not use up the rate or the cap once the
// zone has stopped waiting for it, and until then it counts as in progress so that two at once cannot exceed the cap.
func TestDrainRateAndCapCountSignedDrainsOnly(t *testing.T) {
	r := newKSRig(t)
	r.cfg.Chains[testChain].DrainsPerHour = 2
	r.replace()
	fail := errors.New("party B refused")
	r.signer.setBefore(func([32]byte) error { return fail })
	for i := range 4 {
		d := r.run(r.drain(fmt.Sprintf("f%d", i), addrG2, 1000, uint64(i), "ETH"))
		if d.Outcome == OutcomeSigned {
			t.Fatal("signed with a failing signer")
		}
		if i < 2 {
			continue
		}
		// While the two failed ones are still "in progress" (within the sign timeout) they count: the rate is used.
		if d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, ReasonDrainRate+":") {
			t.Fatalf("attempt %d: %s %s", i, d.Outcome, d.Reason)
		}
		break
	}
	// The signer gives up (the sign timeout passes): nothing was signed, so nothing counts, and the full cap (5000 ETH units) and rate are there again.
	r.advance(r.cfg.SignTimeout + time.Second)
	r.signer.setBefore(func([32]byte) error { return nil })
	r.mustSign(r.drain("g0", addrG2, 4000, 10, "ETH"))
	r.mustSign(r.drain("g1", addrG2, 1000, 11, "ETH"))
	r.mustReject(r.drain("g2", addrG2, 1, 12, "ETH"), ReasonDrainRate)
	r.advance(61 * time.Minute)
	r.mustReject(r.drain("g3", addrG2, 1, 12, "ETH"), ReasonDrainCap) // the cap is spent by what was SIGNED: 4000 + 1000
}

// The cosigner never sees a signature (party A stores it), so what it authorised counts.
func TestDrainCosignerCountsWhatItAuthorised(t *testing.T) {
	r := newKSRig(t)
	r.cfg.Chains[testChain].DrainsPerHour = 2
	r.replace()
	cos := NewDecider(r.cfg, r.gw.codecs, mustGuard(t, r.harness), ModeCosigner, r.clock)
	r.replace(cos.guard)
	pub := r.signer.PublicKey()
	for i := range 2 {
		if v, err := cos.Decide(t.Context(), r.drain(fmt.Sprintf("c%d", i), addrG2, 10, uint64(i), "ETH"), pub); err != nil || !v.NeedSign {
			t.Fatalf("cosigner drain %d: %v", i, err)
		}
	}
	_, err := cos.Decide(t.Context(), r.drain("c2", addrG2, 10, 2, "ETH"), pub)
	if why, ok := IsRejection(err); !ok || !strings.HasPrefix(why, ReasonDrainRate+":") {
		t.Fatalf("third drain at the cosigner: %v", err)
	}
	var m bytes.Buffer // the cosigner side counts the same refusal under its own mode
	cos.guard.WriteDrainMetrics(&m, r.cfg, ModeCosigner)
	if want := `qv_drain_refusals_total{mode="cosigner",chain="` + testChain + `",reason="policy_drain_rate"} 1`; !strings.Contains(m.String(), want) {
		t.Errorf("missing %s in:\n%s", want, m.String())
	}
}

// What the business zone could do before and after: a repeating drain that the signer (or a cosigner) always refuses. Before, every attempt was
// recorded when admitted and counted, so ten refused attempts used up the rate and a few big ones the cap, and the real drain could not be signed; now
// the attempts are refused or fail unsigned, count for nothing, and show as a counter and an ALERT.
func TestDrainRefusalStormUsesNothingAndIsCounted(t *testing.T) {
	r := newKSRig(t)
	r.cfg.Chains[testChain].DrainsPerHour = 3
	r.replace()
	before := r.guard.DrainRefusals()
	for i := range 20 {
		// wrong destination, over the cap, an asset without a cap, a state that does not hold: all refused at once
		r.mustReject(r.drain(fmt.Sprintf("s%d", i), addrEvil, 10, uint64(i), "ETH"), ReasonKeyset)
		r.mustReject(r.drain(fmt.Sprintf("o%d", i), addrG2, 999999, uint64(i), "ETH"), ReasonDrainCap)
	}
	if got := r.guard.DrainRefusals() - before; got != 40 {
		t.Fatalf("%d refusals counted, want 40", got)
	}
	// qv_drain_refusals_total, through the real caller: the reason is the rejection's code, not "other"
	var m bytes.Buffer
	r.guard.WriteDrainMetrics(&m, r.cfg, ModeGateway)
	for _, want := range []string{
		`qv_drain_refusals_total{mode="gateway",chain="` + testChain + `",reason="keyset_state"} 20`,
		`qv_drain_refusals_total{mode="gateway",chain="` + testChain + `",reason="policy_drain_cap"} 20`,
		`qv_drain_refusals_total{mode="gateway",chain="` + testChain + `",reason="other"} 0`,
	} {
		if !strings.Contains(m.String(), want) {
			t.Errorf("missing %s in:\n%s", want, m.String())
		}
	}
	// None of it was signed, so the whole allowance is still there.
	r.mustSign(r.drain("ok0", addrG2, 5000, 0, "ETH"))
	if r.guard.DrainRefusals()-before != 40 {
		t.Fatal("a signed drain was counted as a refusal")
	}
}

// ---- raising a cap ----

func TestOperatorsCanSetTheDrainCaps(t *testing.T) {
	r := newKSRig(t)
	r.replace() // caps: ETH 5000, USDT 5000000
	r.mustSign(r.drain("a", addrG2, 5000, 0, "ETH"))
	r.mustReject(r.drain("b", addrG2, 1, 1, "ETH"), ReasonDrainCap)

	// Raising it takes the same operators, window and sequence number as every record.
	raise := func(f func(*KeysetChange)) KeysetChange {
		return r.ch(testShardID, KeysetSetDrainCaps, 1, func(c *KeysetChange) {
			c.Caps = map[string]string{"ETH": "9000"}
			if f != nil {
				f(c)
			}
		})
	}
	one := r.sign(raise(nil), "op1")
	if err := r.applyKS(r.guard, one); err == nil {
		t.Fatal("one operator raised a cap")
	}
	appr := r.sign(raise(nil), "alice", "bob")
	if err := r.applyKS(r.guard, appr); err == nil {
		t.Fatal("approvers raised a cap")
	}
	stale := r.sign(raise(func(c *KeysetChange) { c.SignedAt = r.clock().Add(-time.Hour).Unix() }), "op1", "op2")
	if err := r.applyKS(r.guard, stale); err == nil {
		t.Fatal("a stale record raised a cap")
	}
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetSetDrainCaps, 1, func(c *KeysetChange) { c.Caps = map[string]string{"GOLD": "1"} })); err == nil {
		t.Fatal("a cap for an unknown asset")
	}
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetSetDrainCaps, 1, func(c *KeysetChange) { c.Caps = map[string]string{"ETH": "9000"}; c.Successor = 2 })); err == nil {
		t.Fatal("malformed record applied")
	}
	r.mustReject(r.drain("c", addrG2, 1, 1, "ETH"), ReasonDrainCap) // nothing above changed anything
	if n := r.rowsKS(r.guard); n != 3 {
		t.Fatalf("%d rows, want the 3 of the replacement", n)
	}

	r.step(testShardID, KeysetSetDrainCaps, 1, func(c *KeysetChange) { c.Caps = map[string]string{"ETH": "9000"} })
	r.mustSign(r.drain("d", addrG2, 4000, 1, "ETH")) // 5000 + 4000 = 9000
	r.mustReject(r.drain("e", addrG2, 1, 2, "ETH"), ReasonDrainCap)
	r.mustSign(r.drain("u", addrG2, 5_000_000, 2, "USDT")) // the other asset's cap is as it was
	// A cap can also be set lower (a reset below what was drained stops the drain: it never un-signs anything).
	r.step(testShardID, KeysetSetDrainCaps, 1, func(c *KeysetChange) { c.Caps = map[string]string{"ETH": "1"} })
	r.mustReject(r.drain("f", addrG2, 1, 3, "ETH"), ReasonDrainCap)
	found := false
	for _, a := range r.auditRows() {
		if a.Type == EventKeysetChanged && a.Payload["action"] == KeysetSetDrainCaps && fmt.Sprint(a.Payload["caps"]) == "map[ETH:9000]" {
			found = true
		}
	}
	if !found {
		t.Fatal("no audit event for the cap change")
	}
}

func TestSetDrainCapsOnlyWhereThereIsADrain(t *testing.T) {
	r := newKSRig(t)
	set := func(gen int) error {
		return r.applyKS(r.guard, r.ch(testShardID, KeysetSetDrainCaps, gen, func(c *KeysetChange) { c.Caps = map[string]string{"ETH": "10"} }))
	}
	if err := set(1); err == nil {
		t.Fatal("caps set on an active generation")
	}
	r.candidate(testShardID, 2, addrG2)
	if err := set(2); err == nil {
		t.Fatal("caps set on a candidate")
	}
	r.startDraining(testShardID, 1, 2)
	r.step(testShardID, KeysetActivate, 2, nil)
	r.step(testShardID, KeysetSetDrainCaps, 1, func(c *KeysetChange) { c.Caps = map[string]string{"ETH": "10"} })
	r.step(testShardID, KeysetRetire, 1, nil)
	if err := set(1); err == nil {
		t.Fatal("caps set on a retired generation")
	}
}

// After the replacement the operators set the config's sweep_destination to the new generation's address. The record that registered that address must
// still hold when the log is read back (the config changed under it), and a candidate with that address is still refused when it is registered now.
func TestSweepDestinationMovedToTheNewGenerationKeepsTheLogValid(t *testing.T) {
	g := newGenRig(t)
	g.candidate2()
	g.startDraining(testShardID, 1, 2)
	g.step(testShardID, KeysetActivate, 2, nil)
	g.cfg.Chains[testChain].EVM.SweepDestination = g.addr2 // the manual edit and restart
	v := g.view(g.guard)
	if v.Ignored != 0 || g.state(g.guard, testShardID, 2) != partition.StateActive {
		t.Fatalf("the log did not survive the config edit: ignored %d, generation 2 %s", v.Ignored, g.state(g.guard, testShardID, 2))
	}
	g.sign2(g.from2(g.wd1("sd0", 100, 0)))
	// A new candidate at the sweep destination is refused at registration.
	g2 := newGenRig(t)
	g2.cfg.Chains[testChain].EVM.SweepDestination = g2.addr2
	if err := g2.applyKS(g2.guard, g2.ch(testShardID, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.Address = g2.addr2.Hex() })); err == nil {
		t.Fatal("a candidate at the sweep destination was registered")
	}
}
