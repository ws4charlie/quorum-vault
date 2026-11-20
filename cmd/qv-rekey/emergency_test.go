package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

// The emergency run goes through every step, ends where a signed record is missing, and a second run goes on from there. It marks the old generation
// compromised (never draining), and watches the drain to the end.
func TestEmergencyRunsInOrderAndResumes(t *testing.T) {
	r := newRig(t)
	r.env.Caps = []string{"ETH=1000", "USDT=5"}
	run := func(changes ...string) error {
		r.out.Reset()
		r.env.Keys = r.k
		return runEmergency(context.Background(), r.env, func(*Plan) (Keys, func(), error) { return r.k, func() {}, nil }, emergencyFlags{shard: shard, mode: "mpc", reason: "the hot key may be stolen", changes: changes, poll: time.Millisecond, stallAfter: 50 * time.Millisecond})
	}
	// Nothing signed: the key is made, the candidate hint is printed, the run ends there.
	if err := run(); err == nil || !strings.Contains(err.Error(), "candidate needs its signed record") {
		t.Fatalf("first run: %v\n%s", err, r.out)
	}
	if r.k.made != 1 || !strings.Contains(r.out.String(), "qv-keysets sign") {
		t.Fatalf("first run made %d keys:\n%s", r.k.made, r.out)
	}
	p := r.plan()
	cand := r.signed(gateway.KeysetChange{Action: "register-candidate", Generation: 2, Address: p.Address, KeyRef: p.KeyRef, PublicKey: p.PublicKey}, 2)
	// With the candidate: the mark is next.
	if err := run(cand); err == nil || !strings.Contains(err.Error(), "needs its signed record") || !strings.Contains(r.out.String(), "-action mark-compromised -generation 1 -successor 2") {
		t.Fatalf("second run: %v\n%s", err, r.out)
	}
	if r.k.made != 1 {
		t.Fatal("a second key was made")
	}
	mark := r.signed(gateway.KeysetChange{Action: "mark-compromised", Generation: 1, Successor: 2, Caps: map[string]string{"ETH": "1000", "USDT": "5"}}, 2)
	act := r.signed(gateway.KeysetChange{Action: "activate", Generation: 2}, 2)
	// All three: the drain is watched and found stalled (the fake core shows no drain), which ends the run with the stall error.
	if err := run(cand, mark, act); !errors.Is(err, ErrStalled) {
		t.Fatalf("third run: %v\n%s", err, r.out)
	}
	if r.c.gens[1].State != "compromised" || r.c.gens[2].State != "active" || r.z.dbs["gateway"].Gens[1].State != "compromised" {
		t.Fatalf("states: %+v", r.c.gens)
	}
	for _, route := range r.c.posts {
		if route == "drains" {
			t.Fatal("the emergency told the core 'draining'")
		}
	}
	// The drain moves: the next run (everything done) watches and ends when drained.
	r.c.drain = "drained"
	if err := run(cand, mark, act); err != nil || !strings.Contains(r.out.String(), "drained") {
		t.Fatalf("fourth run: %v\n%s", err, r.out)
	}
	b := mustRead(t, r.env.Dir+"/emergency.log")
	for _, want := range []string{"start", "candidate", "drain-start", "activate", "STALLED", "drained"} {
		if !strings.Contains(b, want) {
			t.Errorf("emergency.log lacks %q:\n%s", want, b)
		}
	}
}

// A standing candidate (registered earlier, in the zone and the core) is taken as the new generation: no key is made.
func TestEmergencyAdoptsAStandingCandidate(t *testing.T) {
	r := newRig(t)
	r.open()
	p := r.plan()
	r.must(r.with(r.signed(gateway.KeysetChange{Action: "register-candidate", Generation: 2, Address: p.Address, KeyRef: p.KeyRef, PublicKey: p.PublicKey}, 2), r.env.Candidate))
	made := r.k.made
	// A fresh work directory: the plan is opened from what the zone holds.
	r2 := &rig{t: t, z: r.z, c: r.c, k: r.k, out: r.out, seq: r.seq}
	r2.env = &Env{Dir: t.TempDir(), Zone: r.z, Core: r.c, Keys: r.k, Out: r.out, Now: time.Now, Caps: []string{"ETH=1000"}}
	mark := r2.signed(gateway.KeysetChange{Action: "mark-compromised", Generation: 1, Successor: 2, Caps: map[string]string{"ETH": "1000"}}, 2)
	act := r2.signed(gateway.KeysetChange{Action: "activate", Generation: 2}, 2)
	r.c.drain = "drained"
	err := runEmergency(context.Background(), r2.env, func(*Plan) (Keys, func(), error) { return r.k, func() {}, nil }, emergencyFlags{shard: shard, mode: "mpc", reason: "stolen", changes: []string{mark, act}, poll: time.Millisecond})
	if err != nil {
		t.Fatalf("%v\n%s", err, r.out)
	}
	if r.k.made != made {
		t.Fatal("a key was made although a candidate stood")
	}
	if got := r2.plan(); got.To != 2 || got.Address != p.Address {
		t.Fatalf("plan %+v", got)
	}
	if r.c.gens[1].State != "compromised" || r.c.gens[2].State != "active" {
		t.Fatalf("%+v", r.c.gens)
	}
}

func TestEmergencyRefusesAFileThatIsNoStep(t *testing.T) {
	r := newRig(t)
	f := r.signed(gateway.KeysetChange{Action: "retire", Generation: 1}, 2)
	if _, err := changesByAction([]string{f}); err == nil || !strings.Contains(err.Error(), "no step of the emergency") {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A run killed between the zone call and the core call of any step is finished by the next run, whichever step it was.
func TestEmergencyResumesAStepHalfDoneInTheZone(t *testing.T) {
	for _, route := range []string{"candidates", "compromises", "activations"} {
		t.Run(route, func(t *testing.T) {
			r := newRig(t)
			r.env.Caps = []string{"ETH=1000"}
			keys := func(*Plan) (Keys, func(), error) { return r.k, func() {}, nil }
			flags := func(ch ...string) emergencyFlags {
				return emergencyFlags{shard: shard, mode: "mpc", reason: "stolen", changes: ch, stallAfter: 30 * time.Millisecond, poll: time.Millisecond}
			}
			_ = runEmergency(context.Background(), r.env, keys, flags()) // makes the key
			p := r.plan()
			cand := r.signed(gateway.KeysetChange{Action: "register-candidate", Generation: 2, Address: p.Address, KeyRef: p.KeyRef, PublicKey: p.PublicKey}, 2)
			mark := r.signed(gateway.KeysetChange{Action: "mark-compromised", Generation: 1, Successor: 2, Caps: map[string]string{"ETH": "1000"}}, 2)
			act := r.signed(gateway.KeysetChange{Action: "activate", Generation: 2}, 2)
			r.c.failOn = route // the zone takes the step, the core call fails once
			err := runEmergency(context.Background(), r.env, keys, flags(cand, mark, act))
			if err == nil || !strings.Contains(err.Error(), "core is down") {
				t.Fatalf("expected the core failure: %v\n%s", err, r.out)
			}
			r.c.drain = "drained"
			if err := runEmergency(context.Background(), r.env, keys, flags(cand, mark, act)); err != nil {
				t.Fatalf("the rerun: %v\n%s", err, r.out)
			}
			if r.c.gens[1].State != "compromised" || r.c.gens[2].State != "active" {
				t.Fatalf("%+v", r.c.gens)
			}
			if !strings.Contains(r.out.String(), "found half done") {
				t.Fatalf("the rerun did not report the half-done step:\n%s", r.out)
			}
		})
	}
}

// A shard named on the command line must be the shard of the plan in the directory.
func TestEmergencyRefusesAShardThatIsNotThePlans(t *testing.T) {
	r := newRig(t)
	r.open()
	err := runEmergency(context.Background(), r.env, func(*Plan) (Keys, func(), error) { return r.k, func() {}, nil },
		emergencyFlags{shard: "qv-us/evm-test/omnibus/2", mode: "mpc", reason: "x"})
	if err == nil || !strings.Contains(err.Error(), "already holds the plan") {
		t.Fatalf("%v", err)
	}
	if r.c.gens[1].State != "active" {
		t.Fatal("something was changed")
	}
}
