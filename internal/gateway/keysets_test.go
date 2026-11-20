package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The operator-signed keyset view of the zone (keysets.go): who may change a state, what each state allows, and the drain. The shard under test is
// shard 1 of the omnibus pool (testColdPartition), whose generation 1 is the harness's hot key; generation 2 is an address nobody holds a key for
// (a drain only pays it).

const testShardID = "qv-us/evm-test/omnibus/1"

var (
	addrG2       = common.HexToAddress("0x00000000000000000000000000000000000062a2") // generation 2 of shard 1
	addrShard2G2 = common.HexToAddress("0x0000000000000000000000000000000000005a22") // generation 2 of shard 2
)

type ksRig struct {
	*regRig
	seq int64
}

func newKSRig(t *testing.T) *ksRig { return &ksRig{regRig: newRegRig(t)} }

// ch builds a change signed by op1 and op2 at the next sequence number; f edits it before it is signed.
func (k *ksRig) ch(shard, action string, gen int, f func(*KeysetChange)) KeysetChange {
	k.t.Helper()
	c := KeysetChange{Action: action, Shard: shard, Generation: gen, Seq: k.seq + 1, SignedAt: k.clock().Unix()}
	if f != nil {
		f(&c)
	}
	return k.sign(c, "op1", "op2")
}

func (k *ksRig) sign(c KeysetChange, signers ...string) KeysetChange {
	k.t.Helper()
	var parts []KeysetChange
	for _, s := range signers {
		priv, ok := k.ops[s]
		if !ok {
			priv = k.keys[s]
		}
		parts = append(parts, SignKeysetChange(priv, s, c))
	}
	out, err := MergeKeysetChanges(parts...)
	if err != nil {
		k.t.Fatal(err)
	}
	return out
}

func (k *ksRig) applyKS(g *Guard, c KeysetChange) error {
	return g.ApplyKeysetChange(context.Background(), k.cfg, c, k.clock(), "gateway")
}

// step applies one change to every guard and moves the sequence on.
func (k *ksRig) step(shard, action string, gen int, f func(*KeysetChange), guards ...*Guard) {
	k.t.Helper()
	if len(guards) == 0 {
		guards = []*Guard{k.guard}
	}
	c := k.ch(shard, action, gen, f)
	for _, g := range guards {
		if err := k.applyKS(g, c); err != nil {
			k.t.Fatalf("%s %s generation %d: %v", action, shard, gen, err)
		}
	}
	k.seq = c.Seq
}

func ethCaps(eth, usdt string) func(*KeysetChange) {
	return func(c *KeysetChange) { c.Caps = map[string]string{"ETH": eth, "USDT": usdt} }
}

func (k *ksRig) candidate(shard string, gen int, addr common.Address, guards ...*Guard) {
	k.t.Helper()
	k.step(shard, KeysetRegisterCandidate, gen, func(c *KeysetChange) { c.Address = addr.Hex() }, guards...)
}

func (k *ksRig) startDraining(shard string, gen, succ int, guards ...*Guard) {
	k.t.Helper()
	k.step(shard, KeysetStartDraining, gen, func(c *KeysetChange) { c.Successor = succ; ethCaps("5000", "5000000")(c) }, guards...)
}

// replace is the whole planned sequence for shard 1: candidate 2, generation 1 draining into it, 2 active.
func (k *ksRig) replace(guards ...*Guard) {
	k.t.Helper()
	k.candidate(testShardID, 2, addrG2, guards...)
	k.startDraining(testShardID, 1, 2, guards...)
	k.step(testShardID, KeysetActivate, 2, nil, guards...)
}

func (k *ksRig) view(g *Guard) *KeysetView {
	k.t.Helper()
	v, err := g.EffectiveKeysets(context.Background(), k.cfg)
	if err != nil {
		k.t.Fatal(err)
	}
	return v
}

func (k *ksRig) state(g *Guard, shard string, gen int) string {
	if e := k.view(g).entry(partition.ShardID(shard), gen); e != nil {
		return e.State
	}
	return ""
}

func (k *ksRig) rowsKS(g *Guard) int {
	var n int
	if err := g.pool.QueryRow(context.Background(), `SELECT count(*) FROM keyset_changes`).Scan(&n); err != nil {
		k.t.Fatal(err)
	}
	return n
}

// drain builds a drain job of shard 1 from generation 1 (the harness key).
func (k *ksRig) drain(id string, to common.Address, amount int64, nonce uint64, asset string) signjob.Job {
	in := signjob.Intent{Kind: signjob.KindDrain, ID: "dr-" + id, PartitionID: testColdPartition, Asset: asset, From: k.hot.Hex(), To: to.Hex(),
		Amount: fmt.Sprint(amount), NotAfter: k.clock().Add(time.Hour).Unix()}
	tx := k.ethTx(to, amount, nonce)
	if asset == "USDT" {
		tx = k.tokenTx(to, amount, nonce)
	}
	return k.job(id, in, tx)
}

func (k *ksRig) onShard1(in signjob.Intent, s txSpec, approvers ...string) signjob.Job {
	return k.onShard1As(in.ID, in, s, approvers...)
}

// onShard1As is onShard1 with a job id of its own (a replacement is a new job of the same intent).
func (k *ksRig) onShard1As(jobID string, in signjob.Intent, s txSpec, approvers ...string) signjob.Job {
	in.PartitionID = testColdPartition
	return k.job(jobID, in, s, approvers...)
}

func (k *ksRig) withdrawalShard1(id string, amount int64, nonce uint64) signjob.Job {
	in := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w-" + id, Asset: "ETH", To: addrUser.Hex(), Amount: fmt.Sprint(amount), PartitionID: testColdPartition}
	return k.job(id, in, k.ethTx(addrUser, amount, nonce), "alice")
}

// ---- the signed records ----

func TestKeysetRegistryStaticViewAndAuditedChange(t *testing.T) {
	r := newKSRig(t)
	v := r.view(r.guard)
	if v.Seq != 0 || len(v.Shards()) != 3 {
		t.Fatalf("static view: seq %d, shards %v", v.Seq, v.Shards())
	}
	if e := v.entry(testShardID, 1); e == nil || e.State != partition.StateActive || e.Address != r.hot.Hex() {
		t.Fatalf("generation 1 of shard 1 = %+v", e)
	}
	// The unparsable legacy partition "p-hot" is no shard: it stays static.
	r.candidate(testShardID, 2, addrG2)
	if got := r.state(r.guard, testShardID, 2); got != partition.StateCandidate {
		t.Fatalf("generation 2 is %q", got)
	}
	var ev []auditRow
	for _, a := range r.auditRows() {
		if a.Type == EventKeysetChanged {
			ev = append(ev, a)
		}
	}
	if len(ev) != 1 || ev[0].Payload["action"] != KeysetRegisterCandidate || ev[0].Payload["shard"] != testShardID || ev[0].Payload["state_after"] != "candidate" {
		t.Fatalf("audit = %+v", ev)
	}
	if ops, _ := ev[0].Payload["operators"].([]any); len(ops) != 2 || ops[0] != "op1" || ops[1] != "op2" {
		t.Fatalf("operators in audit: %v", ev[0].Payload["operators"])
	}
	// The same change again is not an error and adds nothing.
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.Address = addrG2.Hex(); c.Seq = 1 })); err != nil {
		t.Fatal(err)
	}
	if r.rowsKS(r.guard) != 1 {
		t.Fatal("an idempotent apply wrote a row")
	}
}

func TestKeysetRegistryHostileChangesHaveNoEffect(t *testing.T) {
	r := newKSRig(t)
	cand := func(f func(*KeysetChange)) KeysetChange {
		return r.ch(testShardID, KeysetRegisterCandidate, 2, func(c *KeysetChange) {
			c.Address = addrG2.Hex()
			if f != nil {
				f(c)
			}
		})
	}
	good := cand(nil)
	withSigners := func(signers ...string) KeysetChange {
		c := good
		c.Signatures = nil
		return r.sign(c, signers...)
	}
	for name, c := range map[string]KeysetChange{
		"one operator":                withSigners("op1"),
		"the same operator twice":     withSigners("op1", "op1"),
		"approvers as signers":        withSigners("alice", "bob"),
		"an approver and an operator": withSigners("alice", "op1"),
		"stale":                       cand(func(c *KeysetChange) { c.SignedAt = r.clock().Add(-time.Hour).Unix() }),
		"from the future":             cand(func(c *KeysetChange) { c.SignedAt = r.clock().Add(time.Hour).Unix() }),
		"sequence 0":                  cand(func(c *KeysetChange) { c.Seq = 0 }),
		"a tampered address": func() KeysetChange {
			c := good
			c.Address = addrEvil.Hex()
			return c
		}(),
		"a tampered generation": func() KeysetChange {
			c := good
			c.Generation = 3
			return c
		}(),
		"the wrong next generation":    cand(func(c *KeysetChange) { c.Generation = 3 }),
		"an unknown shard":             cand(func(c *KeysetChange) { c.Shard = "qv-us/evm-test/omnibus/9" }),
		"a legacy partition's name":    cand(func(c *KeysetChange) { c.Shard = "p-hot" }),
		"the address of generation 1":  cand(func(c *KeysetChange) { c.Address = r.hot.Hex() }),
		"the address of another shard": cand(func(c *KeysetChange) { c.Address = addrShard2.Hex() }),
		"the factory":                  cand(func(c *KeysetChange) { c.Address = addrFactory.Hex() }),
		"the sweep destination":        cand(func(c *KeysetChange) { c.Address = addrDest.Hex() }),
		"a cold address":               cand(func(c *KeysetChange) { c.Address = addrCold.Hex() }),
		"the zero address":             cand(func(c *KeysetChange) { c.Address = common.Address{}.Hex() }),
		"no address":                   cand(func(c *KeysetChange) { c.Address = "" }),
		"an unknown action":            r.ch(testShardID, "resurrect", 1, nil),
	} {
		if err := r.applyKS(r.guard, c); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	if r.rowsKS(r.guard) != 0 || len(r.view(r.guard).Generations(testShardID)) != 1 {
		t.Fatal("a refused change left a trace")
	}
	// Replay and a lower sequence.
	if err := r.applyKS(r.guard, good); err != nil {
		t.Fatal(err)
	}
	r.seq = 1
	r.startDraining(testShardID, 1, 2)
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetActivate, 2, func(c *KeysetChange) { c.Seq = 1 })); err == nil {
		t.Error("a reused sequence number applied")
	}
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetActivate, 2, func(c *KeysetChange) { c.Seq = 2 })); err == nil {
		t.Error("the current sequence number applied again with other content")
	}

	// The state machine: every illegal transition is refused (the log is in: 1 draining, 2 candidate).
	for name, c := range map[string]KeysetChange{
		"activate a draining generation":   r.ch(testShardID, KeysetActivate, 1, nil),
		"retire a candidate":               r.ch(testShardID, KeysetRetire, 2, nil),
		"start draining a candidate":       r.ch(testShardID, KeysetStartDraining, 2, func(c *KeysetChange) { c.Successor = 3; ethCaps("1", "1")(c) }),
		"start draining a draining one":    r.ch(testShardID, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("1", "1")(c) }),
		"a generation that does not exist": r.ch(testShardID, KeysetActivate, 7, nil),
		"retire what does not exist":       r.ch(testShardID, KeysetRetire, 7, nil),
	} {
		if err := r.applyKS(r.guard, c); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	// Generation 2 may be activated while 1 drains; a second candidate cannot be active beside it.
	r.step(testShardID, KeysetActivate, 2, nil)
	r.candidate(testShardID, 3, common.HexToAddress("0x00000000000000000000000000000000000063a3"))
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetActivate, 3, nil)); !errors.Is(err, partition.ErrActiveExists) {
		t.Errorf("two active generations: %v", err)
	}
	// Retire only from draining; a successor that does not exist, is not higher, or is retired; caps of an unknown asset or zero; no caps.
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetRetire, 2, nil)); err == nil {
		t.Error("retire of an active generation applied")
	}
	for name, f := range map[string]func(*KeysetChange){
		"an unknown successor":       func(c *KeysetChange) { c.Successor = 9; ethCaps("1", "1")(c) },
		"a successor that is lower":  func(c *KeysetChange) { c.Successor = 1; ethCaps("1", "1")(c) },
		"a cap of an unknown asset":  func(c *KeysetChange) { c.Successor = 3; c.Caps = map[string]string{"DOGE": "1"} },
		"a cap of zero":              func(c *KeysetChange) { c.Successor = 3; c.Caps = map[string]string{"ETH": "0"} },
		"a cap that is not a number": func(c *KeysetChange) { c.Successor = 3; c.Caps = map[string]string{"ETH": "1e18"} },
		"no caps":                    func(c *KeysetChange) { c.Successor = 3 },
		"an address with the action": func(c *KeysetChange) { c.Successor = 3; ethCaps("1", "1")(c); c.Address = addrEvil.Hex() },
	} {
		if err := r.applyKS(r.guard, r.ch(testShardID, KeysetStartDraining, 2, f)); err == nil {
			t.Errorf("start-draining with %s applied", name)
		}
	}
	// Generation 1 still has to drain into 2, so 2 may not leave active.
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetStartDraining, 2, func(c *KeysetChange) { c.Successor = 3; ethCaps("1", "1")(c) })); err == nil {
		t.Error("a generation that others still drain into left active")
	}
	r.step(testShardID, KeysetRetire, 1, nil)
	r.startDraining(testShardID, 2, 3)
	// Compromised is final.
	r.step(testShardID, KeysetMarkCompromised, 3, nil)
	for _, a := range []string{KeysetActivate, KeysetRetire} {
		if err := r.applyKS(r.guard, r.ch(testShardID, a, 3, nil)); err == nil {
			t.Errorf("%s of a compromised generation applied", a)
		}
	}
	if err := r.applyKS(r.guard, r.ch(testShardID, KeysetMarkCompromised, 3, nil)); err == nil {
		t.Error("a compromised generation was marked compromised again")
	}
	// A retired one cannot be revived or marked.
	for _, a := range []string{KeysetActivate, KeysetStartDraining, KeysetMarkCompromised} {
		if err := r.applyKS(r.guard, r.ch(testShardID, a, 1, func(c *KeysetChange) {
			if a == KeysetStartDraining {
				c.Successor = 2
				ethCaps("1", "1")(c)
			}
		})); err == nil {
			t.Errorf("%s of a retired generation applied", a)
		}
	}
}

func TestKeysetRegistryDirectInsertIsIgnoredAndCounted(t *testing.T) {
	r := newKSRig(t)
	ctx := context.Background()
	r.candidate(testShardID, 2, addrG2)
	// SQL access to the guard database: generation 1 retired (and 2 activated) with no valid signatures, then with approvers' signatures.
	for _, sigs := range []string{`[]`, `[{"operator":"alice","signature":"00"}]`} {
		for i, q := range []string{
			`INSERT INTO keyset_changes (seq, action, shard, generation, successor, caps, signed_at, signatures) VALUES (2, 'start-draining', $1, 1, 2, '{"ETH":"1"}', $2, $3::jsonb)`,
			`INSERT INTO keyset_changes (seq, action, shard, generation, signed_at, signatures) VALUES (3, 'activate', $1, 2, $2, $3::jsonb)`,
		} {
			if _, err := r.guardDB.Exec(ctx, q, testShardID, r.clock().Unix(), sigs); err != nil {
				t.Fatalf("insert %d: %v", i, err)
			}
		}
	}
	v := r.view(r.guard)
	if v.Ignored != 4 || v.Seq != 1 || r.state(r.guard, testShardID, 1) != partition.StateActive || r.state(r.guard, testShardID, 2) != partition.StateCandidate {
		t.Fatalf("view after forged rows: ignored %d, seq %d, g1 %s, g2 %s", v.Ignored, v.Seq, r.state(r.guard, testShardID, 1), r.state(r.guard, testShardID, 2))
	}
	// The zone keeps signing for generation 1 as before, and a drain does not sign.
	r.mustSign(r.withdrawalShard1("d1", 100, 0))
	if d := r.run(r.drain("d2", addrG2, 100, 1, "ETH")); d.Outcome != OutcomeRetry {
		t.Fatalf("a drain from a generation this zone still sees active: %s %q, want a retry", d.Outcome, d.Reason)
	}
	// A row with a valid signature that does not fit the state machine is ignored too (signed record, wrong content, written by SQL).
	bad := r.ch(testShardID, KeysetActivate, 2, func(c *KeysetChange) { c.Seq = 9 })
	if _, err := r.guardDB.Exec(ctx, `INSERT INTO keyset_changes (seq, action, shard, generation, signed_at, signatures) VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		bad.Seq, bad.Action, bad.Shard, bad.Generation, bad.SignedAt, `[]`); err != nil {
		t.Fatal(err)
	}
	// The forged rows do not take a sequence number from a real change.
	r.startDraining(testShardID, 1, 2)
	// Append-only.
	if _, err := r.guardDB.Exec(ctx, `UPDATE keyset_changes SET shard = 'x'`); err == nil {
		t.Fatal("update of the log")
	}
	if _, err := r.guardDB.Exec(ctx, `DELETE FROM keyset_changes`); err == nil {
		t.Fatal("delete from the log")
	}
	if _, err := r.guardDB.Exec(ctx, `TRUNCATE keyset_changes`); err == nil {
		t.Fatal("truncate of the log")
	}
}

func TestKeysetRegistryConfigAndShardAddresses(t *testing.T) {
	a, b := common.HexToAddress("0x01"), common.HexToAddress("0x02")
	if err := checkShardAddresses("c", map[string]common.Address{"e/c/ETH/hot/omnibus/0": a, "e/c/USDT/hot/omnibus/0": a, "e/c/ETH/hot/omnibus/1": b, "p-hot": a}); err != nil {
		t.Fatal(err)
	}
	if err := checkShardAddresses("c", map[string]common.Address{"e/c/ETH/hot/omnibus/0": a, "e/c/USDT/hot/omnibus/0": b}); err == nil {
		t.Fatal("two addresses for one shard")
	}
}

func TestKeysetConfigDrainsPerHour(t *testing.T) {
	good, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	with := func(v any) (*Config, error) {
		var m map[string]any
		json.Unmarshal(good, &m)
		cm := m["chains"].(map[string]any)["evm-example"].(map[string]any)
		if v != nil {
			cm["drains_per_hour"] = v
		}
		b, _ := json.Marshal(m)
		return ParseConfig(b)
	}
	for v, want := range map[any]int{nil: 10, float64(3): 3, float64(0): 0} {
		c, err := with(v)
		if err != nil || c.Chains["evm-example"].DrainsPerHour != want {
			t.Errorf("drains_per_hour %v: %v, %+v", v, err, c)
		}
	}
	if _, err := with(float64(-1)); err == nil {
		t.Error("a negative drains_per_hour was accepted")
	}
}

// ---- what each state allows ----

func TestKeysetStatesLimitWhatTheShardSigns(t *testing.T) {
	r := newKSRig(t)
	// Generation 1 alone, active: everything as before; a candidate next to it changes nothing for it.
	r.mustSign(r.withdrawalShard1("a0", 100, 0))
	r.candidate(testShardID, 2, addrG2)
	r.mustSign(r.withdrawalShard1("a1", 100, 1))
	wIn := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w-keep", Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
	r.mustSign(r.onShard1(wIn, r.ethTx(addrUser, 100, 2), "alice"))

	// Draining: a signed withdrawal can still be replaced, and a cancel can free a nonce; nothing new is signed.
	r.startDraining(testShardID, 1, 2)
	bump := r.ethTx(addrUser, 100, 2)
	bump.tip, bump.feeCap = big.NewInt(2e9), big.NewInt(6e9)
	r.mustSign(r.onShard1As("keep-bump", wIn, bump, "alice"))
	r.mustSign(r.onShard1(signjob.Intent{Kind: "cancel", ID: "c-1", Asset: "ETH", To: r.hot.Hex(), Amount: "0"}, r.cancelTx(3)))
	r.mustReject(r.withdrawalShard1("a2", 100, 4), ReasonKeyset)
	spec, from := r.sweepTx("cust", 4)
	r.mustReject(r.onShard1(signjob.Intent{Kind: "sweep", ID: "s-1", Asset: "ETH", From: from.Hex(), To: addrDest.Hex(), Amount: "5"}, spec), ReasonKeyset)
	r.mustReject(r.onShard1(signjob.Intent{Kind: "to-cold", ID: "tc-1", Asset: "ETH", To: addrCold.Hex(), Amount: "10"}, r.ethTx(addrCold, 10, 4)), ReasonKeyset)
	r.mustReject(r.onShard1(signjob.Intent{Kind: "rebalance", ID: "rb-1", Asset: "ETH", To: addrShard2.Hex(), Amount: "10"}, r.ethTx(addrShard2, 10, 4)), ReasonKeyset)

	bump2 := r.ethTx(addrUser, 100, 2)
	bump2.tip, bump2.feeCap = big.NewInt(3e9), big.NewInt(9e9)
	// Retired: nothing, not even a cancel or a replacement.
	r.step(testShardID, KeysetRetire, 1, nil)
	r.mustReject(r.onShard1(signjob.Intent{Kind: "cancel", ID: "c-2", Asset: "ETH", To: r.hot.Hex(), Amount: "0"}, r.cancelTx(5)), ReasonKeyset)
	r.mustReject(r.onShard1As("keep-bump2", wIn, bump2, "alice"), ReasonKeyset)
	r.mustReject(r.withdrawalShard1("a3", 100, 5), ReasonKeyset)
}

func TestKeysetRebalanceDestinationMustBeActive(t *testing.T) {
	r := newKSRig(t)
	r.cfg.Chains[testChain].RebalancePerHour = 100
	shard2 := "qv-us/evm-test/omnibus/2"
	rb := func(id string, to common.Address, nonce uint64) signjob.Job {
		return r.onShard1(signjob.Intent{Kind: "rebalance", ID: id, Asset: "ETH", To: to.Hex(), Amount: "10"}, r.ethTx(to, 10, nonce))
	}
	r.mustSign(rb("rb-0", addrShard2, 0)) // generation 1 of shard 2 is active: today's behaviour
	r.step(shard2, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.Address = addrShard2G2.Hex() })
	r.mustSign(rb("rb-1", addrShard2, 1))                    // still active beside a candidate
	d := r.mustReject(rb("rb-2", addrShard2G2, 2), ReasonTx) // a candidate is no destination
	if !contains(d.Reason, "not the hot address of another shard") {
		t.Fatal(d.Reason)
	}
	r.step(shard2, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	r.mustReject(rb("rb-3", addrShard2, 2), ReasonTx)   // draining: no longer a destination
	r.mustReject(rb("rb-4", addrShard2G2, 2), ReasonTx) // and its successor is not active yet
	r.step(shard2, KeysetActivate, 2, nil)
	r.mustSign(rb("rb-5", addrShard2G2, 2))
	r.mustReject(rb("rb-6", addrShard2, 3), ReasonTx)
	r.step(shard2, KeysetRetire, 1, nil)
	r.mustReject(rb("rb-7", addrShard2, 3), ReasonTx)
}

// altDecider is a decider over a config in which generation 1 of shard 1 is addrG2 (nobody's key here) and the harness key is free to be registered as
// a later generation: the way to test a sender that is not generation 1. It must be called before any change is applied.
func (k *ksRig) altDecider() *Decider {
	k.t.Helper()
	k.cfg.Chains[testChain].EVM.HotAddresses[testColdPartition] = addrG2
	codecs, err := NewCodecs(k.cfg)
	if err != nil {
		k.t.Fatal(err)
	}
	return NewDecider(k.cfg, codecs, k.guard, ModeGateway, k.clock)
}

func TestKeysetLaterGenerationsSignByTheirState(t *testing.T) {
	r := newKSRig(t)
	d := r.altDecider() // generation 1 = addrG2, generation 2 will be the harness key
	pub := r.signer.PublicKey()
	w := func(id string) signjob.Job { return r.withdrawalShard1(id, 100, 0) }

	r.step(testShardID, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.Address = r.hot.Hex() })
	// A candidate signs nothing.
	_, err := d.Decide(t.Context(), w("g1"), pub)
	if why, ok := IsRejection(err); !ok || !strings.HasPrefix(why, ReasonKeyset+":") || !contains(why, "candidate") {
		t.Fatalf("candidate sender: %v", err)
	}
	// Once the old key drains and the new one is active, the new one signs what an active key signs and the old one's address is not a sender any more.
	r.step(testShardID, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	r.step(testShardID, KeysetActivate, 2, nil)
	if v, err := d.Decide(t.Context(), w("g2"), pub); err != nil || !v.NeedSign {
		t.Fatalf("active generation 2: %v", err)
	}
	// An active key is a destination of a rebalance only from another shard, a drain's destination only from its own.
	in := signjob.Intent{Kind: "to-cold", ID: "tc-g2", Asset: "ETH", To: addrCold.Hex(), Amount: "10"}
	if _, err := d.Decide(t.Context(), r.onShard1(in, r.ethTx(addrCold, 10, 1)), pub); err != nil {
		t.Fatalf("to-cold from generation 2: %v", err)
	}
}

func TestKeysetSweepDestinationMustBeActive(t *testing.T) {
	r := newKSRig(t)
	shard2 := "qv-us/evm-test/omnibus/2"
	// A zone whose forwarders pay shard 2's hot address (the factory's destination is a hot shard).
	r.cfg.Chains[testChain].EVM.SweepDestination = addrShard2
	codecs, err := NewCodecs(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecider(r.cfg, codecs, r.guard, ModeGateway, r.clock)
	pub := r.signer.PublicKey()
	n := uint64(0)
	sweep := func() signjob.Job {
		n++
		spec, from := r.sweepTx(fmt.Sprintf("cust-%d", n), n)
		return r.onShard1(signjob.Intent{Kind: "sweep", ID: fmt.Sprintf("s-%d", n), Asset: "ETH", From: from.Hex(), To: addrShard2.Hex(), Amount: "5"}, spec)
	}
	if _, err := d.Decide(t.Context(), sweep(), pub); err != nil {
		t.Fatalf("sweep to an active shard address: %v", err)
	}
	r.step(shard2, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.Address = addrShard2G2.Hex() })
	r.step(shard2, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	_, err = d.Decide(t.Context(), sweep(), pub)
	if why, ok := IsRejection(err); !ok || !strings.HasPrefix(why, ReasonKeyset+":") || !contains(why, "sweep destination") {
		t.Fatalf("sweep to a draining shard address: %v", err)
	}
}

func TestKeysetCompromisedAndCandidateSignNothing(t *testing.T) {
	r := newKSRig(t)
	// The only generation is compromised, and no successor is named: it signs nothing and has nowhere to drain.
	r.step(testShardID, KeysetMarkCompromised, 1, nil)
	r.mustReject(r.withdrawalShard1("x1", 100, 0), ReasonKeyset)
	d := r.mustReject(r.drain("x2", addrG2, 100, 0, "ETH"), ReasonKeyset)
	if !contains(d.Reason, "no successor named") {
		t.Fatal(d.Reason)
	}
}

// ---- the drain ----

func TestKeysetDrainSignsFromDrainingToTheActiveSuccessor(t *testing.T) {
	r := newKSRig(t)
	r.replace()
	// No approval and no requester: the signed record is the authorisation. Native, then a token.
	r.mustSign(r.drain("n1", addrG2, 4000, 0, "ETH"))
	r.mustSign(r.drain("t1", addrG2, 3_000_000, 1, "USDT"))
	found := false
	for _, a := range r.auditRows() {
		if a.Type == EventSignAllowed && a.Payload["kind"] == signjob.KindDrain && a.Payload["sender"] == r.hot.Hex() {
			found = true
		}
	}
	if !found {
		t.Fatal("no sign.allowed audit row for the drain")
	}
	// A replacement of a signed drain (same claims, higher fees) is judged without counting its amount again.
	bump := r.ethTx(addrG2, 4000, 0)
	bump.tip, bump.feeCap = big.NewInt(2e9), big.NewInt(6e9)
	in := signjob.Intent{Kind: signjob.KindDrain, ID: "dr-n1", PartitionID: testColdPartition, Asset: "ETH", From: r.hot.Hex(), To: addrG2.Hex(), Amount: "4000", NotAfter: r.clock().Add(time.Hour).Unix()}
	r.mustSign(r.job("n1b", in, bump))
	// A compromised generation drains too, since the funds must be able to leave.
	r.step(testShardID, KeysetMarkCompromised, 1, nil)
	r.mustSign(r.drain("n2", addrG2, 500, 2, "ETH"))
}

func TestKeysetDrainOfACompromisedActiveKeyNamesItsSuccessorInTheRecord(t *testing.T) {
	r := newKSRig(t)
	r.candidate(testShardID, 2, addrG2)
	// The emergency path: the active key is marked compromised and the same signed record names the successor and the caps.
	r.step(testShardID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	r.mustReject(r.withdrawalShard1("e0", 100, 0), ReasonKeyset)
	d := NewDecider(r.cfg, r.gw.codecs, r.guard, ModeGateway, r.clock)
	if _, err := d.Decide(t.Context(), r.drain("e1", addrG2, 100, 0, "ETH"), r.signer.PublicKey()); !errors.Is(err, ErrKeysetLag) {
		t.Fatalf("successor not active yet: %v", err)
	}
	r.step(testShardID, KeysetActivate, 2, nil)
	r.mustSign(r.drain("e2", addrG2, 100, 0, "ETH"))
}

// The emergency: one record stops ordinary signing, names the only drain and carries the caps; the hourly rate of a planned drain does not apply to
// it, the cap does.
func TestKeysetEmergencyRecordStopsSigningAndLiftsTheDrainRateNotTheCap(t *testing.T) {
	r := newKSRig(t)
	r.cfg.Chains[testChain].DrainsPerHour = 1
	r.candidate(testShardID, 2, addrG2)
	r.step(testShardID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	r.step(testShardID, KeysetActivate, 2, nil)
	// Ordinary signing from the generation is refused at once; a withdrawal from its successor is not touched.
	r.mustReject(r.withdrawalShard1("em-w", 100, 0), ReasonKeyset)
	// Four drains in the same hour are signed although the zone's rate is one an hour; the cap of the record is what stops the fifth.
	r.mustSign(r.drain("em1", addrG2, 1000, 0, "ETH"))
	r.mustSign(r.drain("em2", addrG2, 1000, 1, "ETH"))
	r.mustSign(r.drain("em3", addrG2, 1000, 2, "USDT"))
	r.mustSign(r.drain("em4", addrG2, 2000, 3, "ETH"))
	r.mustReject(r.drain("em5", addrG2, 1001, 4, "ETH"), ReasonDrainCap)
	// A planned drain of the same zone is still held to the rate.
	r2 := newKSRig(t)
	r2.cfg.Chains[testChain].DrainsPerHour = 1
	r2.replace()
	r2.mustSign(r2.drain("pl1", addrG2, 1, 0, "ETH"))
	r2.mustReject(r2.drain("pl2", addrG2, 1, 1, "ETH"), ReasonDrainRate)
}

func TestKeysetDrainWithAnApproverAttachedIsNotCounted(t *testing.T) {
	r := newKSRig(t)
	r.replace()
	j := r.drain("n1", addrG2, 100, 0, "ETH")
	var in signjob.Intent
	if err := json.Unmarshal(j.Intent, &in); err != nil {
		t.Fatal(err)
	}
	j.Approvals = r.approvals(in, "alice", "bob") // ignored, not an error
	r.mustSign(j)
	// The requester rule does not apply: a drain has no requester, and one that carries a requester is refused.
	in2 := in
	in2.ID, in2.RequestedBy = "dr-req", "req"
	r.mustReject(r.job("n2", in2, r.ethTx(addrG2, 100, 1)), ReasonRequester)
}

func TestKeysetDrainRefusals(t *testing.T) {
	r := newKSRig(t)
	r.replace()
	good := func(id, asset string) signjob.Intent {
		return signjob.Intent{Kind: signjob.KindDrain, ID: "dr-" + id, PartitionID: testColdPartition, Asset: asset, From: r.hot.Hex(), To: addrG2.Hex(), Amount: "100",
			NotAfter: r.clock().Add(time.Hour).Unix()}
	}
	// To any other address, intent and transaction agreeing: an attacker, the cold address, the sweep destination, another shard's active address, a
	// shard of another pool, a customer.
	for i, to := range []common.Address{addrEvil, addrCold, addrDest, addrShard2, addrOtherPl, addrUser} {
		d := r.mustReject(r.drain(fmt.Sprintf("x%d", i), to, 100, uint64(i), "ETH"), ReasonKeyset)
		if !contains(d.Reason, "is not the successor") {
			t.Fatalf("to %s: %q", to, d.Reason)
		}
	}
	d := r.mustReject(r.drain("self", r.hot, 100, 0, "ETH"), ReasonTx)
	if !contains(d.Reason, "is the source") {
		t.Fatal(d.Reason)
	}
	// The intent names the successor, the transaction pays an attacker; and the other way round.
	r.mustReject(r.job("m1", good("m1", "ETH"), r.ethTx(addrEvil, 100, 0)), ReasonTx)
	in := good("m2", "ETH")
	in.To = addrEvil.Hex()
	r.mustReject(r.job("m2", in, r.ethTx(addrG2, 100, 0)), ReasonTx)
	// Not a plain transfer: data on a native transfer, a call to the factory, more than the intent says, calldata paying an attacker, a native
	// transfer under a token intent.
	withData := r.ethTx(addrG2, 100, 0)
	withData.data = []byte{1, 2, 3}
	r.mustReject(r.job("p1", good("p1", "ETH"), withData), ReasonTx)
	sw, _ := r.sweepTx("cust", 0)
	r.mustReject(r.job("p2", good("p2", "ETH"), sw), ReasonTx)
	r.mustReject(r.job("p3", good("p3", "ETH"), r.ethTx(addrG2, 101, 0)), ReasonTx)
	r.mustReject(r.job("p4", good("p4", "USDT"), r.tokenTx(addrEvil, 100, 0)), ReasonTx)
	r.mustReject(r.job("p5", good("p5", "USDT"), r.ethTx(addrG2, 100, 0)), ReasonTx)
	// A source that is not the sender, or not an address, or empty.
	in = good("f1", "ETH")
	in.From = addrShard2.Hex()
	r.mustReject(r.job("f1", in, r.ethTx(addrG2, 100, 0)), ReasonTx)
	in = good("f2", "ETH")
	in.From = ""
	r.mustReject(r.job("f2", in, r.ethTx(addrG2, 100, 0)), ReasonTx)
	// No expiry, an expiry in the past, one too far ahead.
	for i, na := range []int64{0, r.clock().Add(-time.Minute).Unix(), r.clock().Add(48 * time.Hour).Unix()} {
		in = good(fmt.Sprintf("e%d", i), "ETH")
		in.NotAfter = na
		r.mustReject(r.job(fmt.Sprintf("e%d", i), in, r.ethTx(addrG2, 100, 0)), ReasonExpired)
	}
	// A partition that is not a hot shard with keysets.
	in = good("u1", "ETH")
	in.PartitionID = testPartition
	r.mustReject(r.job("u1", in, r.ethTx(addrG2, 100, 0)), ReasonKeyset)
	// Nothing was signed for any of it, and the right drain still works.
	r.mustSign(r.drain("ok", addrG2, 100, 0, "ETH"))
}

func TestKeysetDrainIsOffWithoutOperators(t *testing.T) {
	h := newHarnessSoft(t) // no operators section: no keyset states, so no drain
	in := signjob.Intent{Kind: signjob.KindDrain, ID: "dr-1", PartitionID: testColdPartition, Asset: "ETH", From: h.hot.Hex(), To: addrG2.Hex(), Amount: "1",
		NotAfter: h.clock().Add(time.Hour).Unix()}
	d := h.mustReject(h.job("o1", in, h.ethTx(addrG2, 1, 0)), ReasonKeyset)
	if !contains(d.Reason, "no operators section") {
		t.Fatal(d.Reason)
	}
}

func TestKeysetDrainCapAndRate(t *testing.T) {
	r := newKSRig(t)
	r.replace()
	// The cap of the signed record is per asset and for all drains of the source together (5000 ETH units, 5000000 USDT units).
	r.mustReject(r.drain("c1", addrG2, 5001, 0, "ETH"), ReasonDrainCap)
	r.mustSign(r.drain("c2", addrG2, 3000, 0, "ETH"))
	r.mustReject(r.drain("c3", addrG2, 2001, 1, "ETH"), ReasonDrainCap)
	r.mustSign(r.drain("c4", addrG2, 2000, 1, "ETH"))
	r.mustReject(r.drain("c5", addrG2, 1, 2, "ETH"), ReasonDrainCap)
	r.mustReject(r.drain("c6", addrG2, 5_000_001, 2, "USDT"), ReasonDrainCap)
	r.mustSign(r.drain("c7", addrG2, 5_000_000, 2, "USDT"))
	// Time does not reset the cap: it is for the whole drain.
	r.advance(48 * time.Hour)
	r.mustReject(r.drain("c8", addrG2, 1, 3, "ETH"), ReasonDrainCap)

	// A record that names a cap for one asset only: the other asset has none, and the drain of it is refused.
	r3 := newKSRig(t)
	r3.candidate(testShardID, 2, addrG2)
	r3.step(testShardID, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor = 2; c.Caps = map[string]string{"ETH": "5000"} })
	r3.step(testShardID, KeysetActivate, 2, nil)
	d := r3.mustReject(r3.drain("k1", addrG2, 1, 0, "USDT"), ReasonDrainCap)
	if !contains(d.Reason, "no cap for USDT") {
		t.Fatal(d.Reason)
	}

	// The rate comes from the zone's own config, 10 an hour unless it says otherwise; 0 turns drains off.
	r2 := newKSRig(t)
	r2.cfg.Chains[testChain].DrainsPerHour = 2
	r2.replace()
	r2.mustSign(r2.drain("r1", addrG2, 1, 0, "ETH"))
	r2.mustSign(r2.drain("r2", addrG2, 1, 1, "ETH"))
	r2.mustReject(r2.drain("r3", addrG2, 1, 2, "ETH"), ReasonDrainRate)
	r2.advance(61 * time.Minute)
	r2.mustSign(r2.drain("r4", addrG2, 1, 2, "ETH"))
	r2.cfg.Chains[testChain].DrainsPerHour = 0
	r2.advance(2 * time.Hour)
	r2.mustReject(r2.drain("r5", addrG2, 1, 3, "ETH"), ReasonDrainRate)
}

func TestKeysetDrainStatesOfSourceAndSuccessor(t *testing.T) {
	r := newKSRig(t)
	d := NewDecider(r.cfg, r.gw.codecs, r.guard, ModeGateway, r.clock)
	pub := r.signer.PublicKey()
	decide := func(j signjob.Job) error { _, err := d.Decide(t.Context(), j, pub); return err }
	rejected := func(err error, code string) bool {
		why, ok := IsRejection(err)
		return ok && strings.HasPrefix(why, code+":")
	}

	// The source is active: nothing here says it drains. This zone cannot tell "forged" from "the other side is ahead", so it waits.
	j := r.drain("s1", addrG2, 100, 0, "ETH")
	if err := decide(j); !errors.Is(err, ErrKeysetLag) || rejected(err, ReasonKeyset) {
		t.Fatalf("from an active source: %v", err)
	}
	// Source draining, successor still a candidate: a wait too. Nothing was recorded for the waiting job.
	r.candidate(testShardID, 2, addrG2)
	r.startDraining(testShardID, 1, 2)
	if err := decide(j); !errors.Is(err, ErrKeysetLag) || !contains(err.Error(), "candidate here") {
		t.Fatalf("successor candidate: %v", err)
	}
	var n int
	r.guardDB.QueryRow(t.Context(), `SELECT count(*) FROM signed_intents WHERE kind = 'drain'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d drains recorded while waiting", n)
	}
	// The wait ends with the intent: after not_after it is the usual refusal.
	r.advance(2 * time.Hour)
	if err := decide(j); !rejected(err, ReasonExpired) {
		t.Fatalf("expired wait: %v", err)
	}
	// Successor active: the drain is decided.
	r.step(testShardID, KeysetActivate, 2, nil)
	if err := decide(r.drain("s2", addrG2, 100, 0, "ETH")); err != nil {
		t.Fatalf("ready drain: %v", err)
	}
	// A retired source: final. (Also from a zone that is behind or ahead: retire is the end of the generation.)
	r.step(testShardID, KeysetRetire, 1, nil)
	if err := decide(r.drain("s3", addrG2, 100, 1, "ETH")); !rejected(err, ReasonKeyset) || !contains(err.Error(), "retired") {
		t.Fatalf("retired source: %v", err)
	}

	// A successor that cannot become active (compromised or retired) is final too.
	r2 := newKSRig(t)
	d2 := NewDecider(r2.cfg, r2.gw.codecs, r2.guard, ModeGateway, r2.clock)
	r2.candidate(testShardID, 2, addrG2)
	r2.startDraining(testShardID, 1, 2)
	r2.step(testShardID, KeysetMarkCompromised, 2, nil)
	_, err := d2.Decide(t.Context(), r2.drain("z1", addrG2, 100, 0, "ETH"), pub)
	if !rejected(err, ReasonKeyset) || !contains(err.Error(), "compromised") {
		t.Fatalf("compromised successor: %v", err)
	}
}

// ---- gateway and cosigners ----

// A cosigner whose log is behind the gateway's waits (a retry, nothing refused, nothing reserved) until it has the same records, and then signs.
func TestKeysetSequenceMismatchDelaysNeverFails(t *testing.T) {
	r := newKSRig(t)
	cosGuard := mustGuard(t, r.harness)
	cos := NewDecider(r.cfg, r.gw.codecs, cosGuard, ModeCosigner, r.clock)
	pub := r.signer.PublicKey()

	// Both have the candidate; the gateway alone has start-draining and the activation.
	r.candidate(testShardID, 2, addrG2, r.guard, cosGuard)
	r.startDraining(testShardID, 1, 2, r.guard)
	r.step(testShardID, KeysetActivate, 2, nil, r.guard)
	j := r.drain("m1", addrG2, 100, 0, "ETH")
	r.mustSign(j) // the gateway signs it
	// The cosigner sees an active source.
	if _, err := cos.Decide(t.Context(), j, pub); !errors.Is(err, ErrKeysetLag) {
		t.Fatalf("cosigner without start-draining: %v, want a retry (ErrKeysetLag)", err)
	} else if _, refused := IsRejection(err); refused {
		t.Fatal("a refusal, not a retry")
	}
	// It has start-draining but not the activation: still a wait.
	if err := cosGuard.ApplyKeysetChange(t.Context(), r.cfg, r.ch(testShardID, KeysetStartDraining, 1, func(c *KeysetChange) { c.Seq = 2; c.Successor = 2; ethCaps("5000", "5000000")(c) }), r.clock(), "cosigner"); err == nil {
		t.Log("a change signed again at the same sequence is the same record")
	}
	if _, err := cos.Decide(t.Context(), j, pub); !errors.Is(err, ErrKeysetLag) {
		t.Fatalf("cosigner with a candidate successor: %v", err)
	}
	// Nothing was reserved or refused on the cosigner's side; once the records arrive the job is judged again and signs.
	for _, row := range loadKeysetRowsT(t, r.guard) {
		if row.Seq == 3 {
			if err := cosGuard.ApplyKeysetChange(t.Context(), r.cfg, row, r.clock(), "cosigner"); err != nil {
				t.Fatalf("catching up: %v", err)
			}
		}
	}
	if v, err := cos.Decide(t.Context(), j, pub); err != nil || !v.NeedSign {
		t.Fatalf("cosigner after the records: %v", err)
	}
	// A wait is not a refusal: the cosigner's audit log has no sign.refused for it.
	for _, a := range auditRowsOf(t, cosGuard) {
		if a.Type == EventSignRefused {
			t.Fatalf("a wait was recorded as a refusal: %+v", a)
		}
	}
}

// A gateway that judges by a view of its own making (its own operators, its own log, its own config: the signing host is compromised) can sign a drain to
// an attacker, but the cosigner decides from ITS config and ITS guard database and does not: the forged records are not signed by its operators.
func TestKeysetCosignerRefusesWhatAForgedGatewayViewSigns(t *testing.T) {
	r := newKSRig(t)
	// The attacker's operators and config.
	evil := *r.cfg
	evilOps := &OperatorConfig{Keys: map[string]ed25519.PublicKey{}, Min: 2, MaxAge: 10 * time.Minute}
	evilPriv := map[string]ed25519.PrivateKey{}
	for _, n := range []string{"e1", "e2"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		evilOps.Keys[n], evilPriv[n] = pub, priv
	}
	evil.Operators = evilOps
	evilGuard := mustGuard(t, r.harness)
	forge := func(seq int64, action string, gen int, f func(*KeysetChange)) KeysetChange {
		c := KeysetChange{Action: action, Shard: testShardID, Generation: gen, Seq: seq, SignedAt: r.clock().Unix()}
		if f != nil {
			f(&c)
		}
		m, err := MergeKeysetChanges(SignKeysetChange(evilPriv["e1"], "e1", c), SignKeysetChange(evilPriv["e2"], "e2", c))
		if err != nil {
			t.Fatal(err)
		}
		if err := evilGuard.ApplyKeysetChange(t.Context(), &evil, m, r.clock(), "gateway"); err != nil {
			t.Fatal(err)
		}
		return m
	}
	forge(1, KeysetRegisterCandidate, 2, func(c *KeysetChange) { c.Address = addrEvil.Hex() })
	forge(2, KeysetStartDraining, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	forge(3, KeysetActivate, 2, nil)
	codecs, err := NewCodecs(&evil)
	if err != nil {
		t.Fatal(err)
	}
	pub := r.signer.PublicKey()
	badGateway := NewDecider(&evil, codecs, evilGuard, ModeGateway, r.clock)
	steal := r.drain("steal", addrEvil, 1000, 0, "ETH")
	if v, err := badGateway.Decide(t.Context(), steal, pub); err != nil || !v.NeedSign {
		t.Fatalf("the forged gateway view should sign the drain to the attacker: %v", err)
	}
	// The cosigner: its own config, its own (empty) guard database: a wait, never a signature.
	cosGuard := mustGuard(t, r.harness)
	cos := NewDecider(r.cfg, r.gw.codecs, cosGuard, ModeCosigner, r.clock)
	if v, err := cos.Decide(t.Context(), steal, pub); err == nil {
		t.Fatalf("the cosigner signed a drain to an attacker: %+v", v)
	}
	// Even with the forged rows copied into its own database (SQL access): ignored, counted, still no signature.
	for _, row := range loadKeysetRowsT(t, evilGuard) {
		sigs := mustJSON(row.Signatures)
		caps := mustJSON(row.Caps)
		if len(row.Caps) == 0 {
			caps = nil
		}
		if _, err := cosGuard.pool.Exec(t.Context(), `INSERT INTO keyset_changes (seq, action, shard, generation, address, successor, caps, signed_at, signatures) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			row.Seq, row.Action, row.Shard, row.Generation, row.Address, row.Successor, caps, row.SignedAt, sigs); err != nil {
			t.Fatal(err)
		}
	}
	if v := r.viewOf(t, cosGuard); v.Ignored != 3 || v.Seq != 0 {
		t.Fatalf("cosigner view after forged rows: ignored %d seq %d", v.Ignored, v.Seq)
	}
	if v, err := cos.Decide(t.Context(), steal, pub); err == nil {
		t.Fatalf("the cosigner signed after forged rows: %+v", v)
	}
	// And the real records, applied to both, still refuse the attacker's address in the cosigner.
	r.replace(cosGuard)
	_, err = cos.Decide(t.Context(), steal, pub)
	if why, ok := IsRejection(err); !ok || !strings.HasPrefix(why, ReasonKeyset+":") || !contains(why, "is not the successor") {
		t.Fatalf("cosigner with the real records: %v", err)
	}
}

func (k *ksRig) viewOf(t *testing.T, g *Guard) *KeysetView {
	t.Helper()
	v, err := g.EffectiveKeysets(t.Context(), k.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func loadKeysetRowsT(t *testing.T, g *Guard) []KeysetChange {
	t.Helper()
	rows, err := loadKeysetRows(t.Context(), g.pool)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func auditRowsOf(t *testing.T, g *Guard) []auditRow {
	t.Helper()
	h := &harness{t: t, guardDB: g.pool}
	return h.auditRows()
}
