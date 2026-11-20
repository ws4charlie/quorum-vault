package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

const shard = "qv-us/evm-test/omnibus/1"

// fakeZone is two guard databases that apply a change the way the real ones would (state machine only: the signatures are the real databases' job).
type fakeZone struct {
	dbs    map[string]*ZoneView
	failOn string // a database that refuses
	min    int
}

func (z *fakeZone) MinOperators() int                { return z.min }
func (z *fakeZone) Partition(string) (string, error) { return "p", nil }
func (z *fakeZone) Views(_ context.Context, _ string) (map[string]ZoneView, error) {
	out := map[string]ZoneView{}
	for n, v := range z.dbs {
		g := map[int]ZoneGen{}
		for k, e := range v.Gens {
			g[k] = e
		}
		out[n] = ZoneView{Seq: v.Seq, Gens: g}
	}
	return out, nil
}
func (z *fakeZone) Apply(_ context.Context, c gateway.KeysetChange) error {
	var bad []string
	for n, v := range z.dbs {
		if n == z.failOn {
			bad = append(bad, n+": refused")
			continue
		}
		if v.Seq >= c.Seq {
			continue
		}
		v.Seq = c.Seq
		e := v.Gens[c.Generation]
		switch c.Action {
		case gateway.KeysetRegisterCandidate:
			e = ZoneGen{State: "candidate", Address: c.Address, KeyRef: c.KeyRef}
		case gateway.KeysetActivate:
			e.State = "active"
		case gateway.KeysetStartDraining:
			e.State, e.Successor = "draining", c.Successor
		case gateway.KeysetRetire:
			e.State = "retired"
		}
		v.Gens[c.Generation] = e
	}
	if len(bad) > 0 {
		return errors.New(strings.Join(bad, "; "))
	}
	return nil
}

type fakeCore struct {
	gens   map[int]CoreGen
	posts  []string
	failOn string // a route that fails once
	drain  string // the drain state shown for the old generation
}

func (c *fakeCore) Keysets(context.Context, string) (map[int]CoreGen, error) {
	out := map[int]CoreGen{}
	for k, v := range c.gens {
		if k == 1 && c.drain != "" && v.State == "draining" {
			v.Drain = &struct {
				State  string `json:"state"`
				Reason string `json:"reason"`
			}{State: c.drain}
		}
		out[k] = v
	}
	return out, nil
}
func (c *fakeCore) Post(_ context.Context, route string, b map[string]any) error {
	if route == c.failOn {
		c.failOn = ""
		return errors.New("core is down")
	}
	c.posts = append(c.posts, route)
	switch route {
	case "candidates":
		c.gens[2] = CoreGen{ShardID: shard, Generation: 2, State: "candidate", Address: b["address"].(string)}
	case "drains":
		g := c.gens[1]
		g.State, g.Successor = "draining", 2
		c.gens[1] = g
	case "activations":
		g := c.gens[2]
		g.State = "active"
		c.gens[2] = g
	case "retirements":
		g := c.gens[1]
		g.State = "retired"
		c.gens[1] = g
	}
	return nil
}

type fakeKeys struct{ made int }

func (k *fakeKeys) New(context.Context, *Plan) (string, string, error) {
	k.made++
	key, _ := crypto.GenerateKey()
	return "ks-2", hexOf(crypto.FromECDSAPub(&key.PublicKey)), nil
}
func (k *fakeKeys) Check(context.Context, *Plan) error { return nil }

func hexOf(b []byte) string { return strings.ToLower(common_hex(b)) }

func common_hex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}

type rig struct {
	t   *testing.T
	z   *fakeZone
	c   *fakeCore
	k   *fakeKeys
	env *Env
	out *bytes.Buffer
	seq int64
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, k: &fakeKeys{}, out: &bytes.Buffer{}}
	g1 := ZoneGen{State: "active", Address: "0x1"}
	r.z = &fakeZone{min: 2, dbs: map[string]*ZoneView{"gateway": {Gens: map[int]ZoneGen{1: g1}}, "cosigner-b": {Gens: map[int]ZoneGen{1: g1}}}}
	r.c = &fakeCore{gens: map[int]CoreGen{1: {ShardID: shard, Generation: 1, State: "active", Address: "0x1"}}}
	r.env = &Env{Dir: t.TempDir(), Zone: r.z, Core: r.c, Keys: r.k, Out: r.out, Now: time.Now}
	return r
}

func (r *rig) run(f func(context.Context) error) error {
	r.out.Reset()
	r.env.ChangeFile = ""
	return f(context.Background())
}

// signed writes a change file as the operators would have made it.
func (r *rig) signed(c gateway.KeysetChange, sigs int) string {
	r.seq++
	c.Seq, c.Shard = r.seq, shard
	for range sigs {
		c.Signatures = append(c.Signatures, gateway.OperatorSignature{Operator: "op", Signature: "00"})
	}
	b, _ := json.Marshal(c)
	p := filepath.Join(r.t.TempDir(), "change.json")
	os.WriteFile(p, b, 0o600)
	return p
}

func (r *rig) with(file string, f func(context.Context) error) error {
	r.out.Reset()
	r.env.ChangeFile = file
	return f(context.Background())
}

func (r *rig) must(err error) {
	r.t.Helper()
	if err != nil {
		r.t.Fatalf("%v\n%s", err, r.out.String())
	}
}

func (r *rig) open() {
	r.t.Helper()
	r.must(r.env.Open(context.Background(), shard, "mpc", "planned"))
	r.must(r.env.DKG(context.Background()))
}

func (r *rig) plan() *Plan {
	p, err := loadPlan(r.env.Dir)
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

func TestWholeReplacementIsResumableAtEveryStep(t *testing.T) {
	r := newRig(t)
	r.open()
	p := r.plan()
	if p.From != 1 || p.To != 2 || p.Address == "" {
		t.Fatalf("plan %+v", p)
	}
	// Without the signed change the step prints the command and does nothing.
	r.must(r.run(r.env.Candidate))
	if !strings.Contains(r.out.String(), "qv-keysets sign") || !strings.Contains(r.out.String(), "-seq 1 ") || r.z.dbs["gateway"].Gens[2].State != "" {
		t.Fatalf("candidate without a change:\n%s", r.out)
	}
	cand := r.signed(gateway.KeysetChange{Action: "register-candidate", Generation: 2, Address: p.Address, KeyRef: p.KeyRef, PublicKey: p.PublicKey}, 2)

	// The core is down after the zone applied: run again, the zone is not touched twice and the core call is repeated.
	r.c.failOn = "candidates"
	if err := r.with(cand, r.env.Candidate); err == nil || !strings.Contains(err.Error(), "core is down") {
		t.Fatalf("expected the core failure: %v", err)
	}
	if r.z.dbs["gateway"].Gens[2].State != "candidate" || r.c.gens[2].State != "" {
		t.Fatal("the zone should have it, the core not")
	}
	r.must(r.env.Status(context.Background())) // a step half done is not a disagreement
	r.must(r.with(cand, r.env.Candidate))
	if r.c.gens[2].State != "candidate" {
		t.Fatal("core not mirrored")
	}
	// Run again: nothing to do, nothing posted.
	n := len(r.c.posts)
	r.must(r.with(cand, r.env.Candidate))
	if len(r.c.posts) != n || !strings.Contains(r.out.String(), "done already") {
		t.Fatalf("not idempotent:\n%s", r.out)
	}

	// drain-start needs caps.
	if err := r.run(r.env.DrainStart); err == nil {
		t.Fatal("drain-start without caps")
	}
	r.env.Caps = []string{"ETH=1000", "USDT=5"}
	drain := r.signed(gateway.KeysetChange{Action: "start-draining", Generation: 1, Successor: 2, Caps: map[string]string{"ETH": "1000", "USDT": "5"}}, 2)
	// One zone database refuses: the others keep it; the core is not asked; fixed, the next run finishes.
	r.z.failOn = "cosigner-b"
	if err := r.with(drain, r.env.DrainStart); err == nil || !strings.Contains(err.Error(), "cosigner-b") {
		t.Fatalf("expected cosigner-b to refuse: %v", err)
	}
	if r.c.gens[1].State != "active" {
		t.Fatal("the core was told before the whole zone had the step")
	}
	r.z.failOn = ""
	r.must(r.with(drain, r.env.DrainStart))
	if r.c.gens[1].State != "draining" || r.z.dbs["cosigner-b"].Gens[1].State != "draining" {
		t.Fatal("drain-start incomplete")
	}

	r.must(r.with(r.signed(gateway.KeysetChange{Action: "activate", Generation: 2}, 2), r.env.Activate))
	if !strings.Contains(r.out.String(), "set-destination") || r.c.gens[2].State != "active" {
		t.Fatalf("activate:\n%s", r.out)
	}

	// Retire waits for the drain, and does not touch anything meanwhile.
	retire := r.signed(gateway.KeysetChange{Action: "retire", Generation: 1}, 2)
	r.c.drain = "moving"
	if err := r.with(retire, r.env.Retire); err == nil || !strings.Contains(err.Error(), "not finished") {
		t.Fatalf("retire during the drain: %v", err)
	}
	if r.z.dbs["gateway"].Gens[1].State != "draining" {
		t.Fatal("the zone retired a generation that was still draining money")
	}
	r.c.drain = "drained"
	r.must(r.with(retire, r.env.Retire))
	r.must(r.env.Status(context.Background()))
	if !strings.Contains(r.out.String(), "complete") {
		t.Fatalf("status:\n%s", r.out)
	}
}

func TestToolRefusesWhenTheZoneAndTheCoreDisagree(t *testing.T) {
	// The core is ahead of the zone: named as the zone being behind.
	r := newRig(t)
	r.open()
	p := r.plan()
	r.c.gens[2] = CoreGen{ShardID: shard, Generation: 2, State: "candidate", Address: p.Address}
	err := r.run(r.env.Candidate)
	if err == nil || !strings.Contains(err.Error(), "behind") || !strings.Contains(err.Error(), "zone") {
		t.Fatalf("core ahead: %v", err)
	}
	if err := r.env.Status(context.Background()); err == nil {
		t.Fatal("status of a disagreement is not an error")
	}
	if !strings.Contains(r.out.String(), "DISAGREEMENT") {
		t.Fatal(r.out.String())
	}

	// The zone is ahead on another generation than the step's: refused, the core named as behind.
	r2 := newRig(t)
	r2.open()
	r2.z.dbs["gateway"].Gens[1] = ZoneGen{State: "draining"}
	r2.z.dbs["cosigner-b"].Gens[1] = ZoneGen{State: "draining"}
	err = r2.run(r2.env.Candidate)
	if err == nil || !strings.Contains(err.Error(), "core is behind") {
		t.Fatalf("zone ahead: %v", err)
	}

	// Two zone databases that differ about an old generation.
	r3 := newRig(t)
	r3.open()
	r3.z.dbs["cosigner-b"].Gens[1] = ZoneGen{State: "retired"}
	if err := r3.run(r3.env.Candidate); err == nil {
		t.Fatal("zone databases that differ were accepted")
	}
}

func TestToolRefusesTheWrongChangeFile(t *testing.T) {
	r := newRig(t)
	r.open()
	p := r.plan()
	for name, c := range map[string]gateway.KeysetChange{
		"another address": {Action: "register-candidate", Generation: 2, Address: "0x2", KeyRef: p.KeyRef, PublicKey: p.PublicKey},
		"another action":  {Action: "activate", Generation: 2},
		"another key":     {Action: "register-candidate", Generation: 2, Address: p.Address, KeyRef: "other", PublicKey: p.PublicKey},
		"too few signers": {Action: "register-candidate", Generation: 2, Address: p.Address, KeyRef: p.KeyRef, PublicKey: p.PublicKey},
	} {
		sigs := 2
		if name == "too few signers" {
			sigs = 1
		}
		if err := r.with(r.signed(c, sigs), r.env.Candidate); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if r.z.dbs["gateway"].Gens[2].State != "" || len(r.c.posts) != 0 {
		t.Fatal("something was applied")
	}
}

func TestOpenRefusesAReplacementInProgressAndAnotherShardsDir(t *testing.T) {
	r := newRig(t)
	r.z.dbs["gateway"].Gens[2] = ZoneGen{State: "candidate"}
	if err := r.env.Open(context.Background(), shard, "mpc", "x"); err == nil {
		t.Fatal("opened with a candidate present")
	}
	r2 := newRig(t)
	if err := r2.env.Open(context.Background(), shard, "mpc", ""); err == nil {
		t.Fatal("opened without a reason")
	}
	r2.must(r2.env.Open(context.Background(), shard, "hsm", "why"))
	if err := r2.env.Open(context.Background(), "qv-us/evm-test/omnibus/2", "hsm", "why"); err == nil {
		t.Fatal("a directory holds one plan")
	}
	r2.must(r2.env.Open(context.Background(), shard, "hsm", "why")) // the same shard again is a no-op
}

func TestDKGIsIdempotent(t *testing.T) {
	r := newRig(t)
	r.open()
	r.must(r.env.DKG(context.Background()))
	if r.k.made != 1 {
		t.Fatalf("the key was made %d times", r.k.made)
	}
}

func TestCapsStepAppliesOnlyToTheZone(t *testing.T) {
	r := newRig(t)
	r.open()
	r.env.Caps = []string{"ETH=9"}
	r.must(r.run(r.env.SetCaps))
	if !strings.Contains(r.out.String(), "set-drain-caps") {
		t.Fatal(r.out.String())
	}
	f := r.signed(gateway.KeysetChange{Action: "set-drain-caps", Generation: 1, Caps: map[string]string{"ETH": "9"}}, 2)
	r.must(r.with(f, r.env.SetCaps))
	if len(r.c.posts) != 0 {
		t.Fatal("the core was called for a cap")
	}
}
