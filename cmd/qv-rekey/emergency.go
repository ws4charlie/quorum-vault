package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// The emergency order (docs/runbooks/stolen-hot-key.md). One command runs what the planned steps do one by one, with the compromised mark in the place of
// "start draining", and then watches the drain until the core finds the old generation empty:
//
//	open (adopting a standing candidate if the zone holds one) -> dkg (only if there is no candidate) -> candidate -> mark compromised -> activate -> watch
//
// The operators sign the records ahead of the run, in the order of their sequence numbers (the sign hints say which), and pass them with -changes; a step
// whose record is missing prints what to sign and ends the run, and running the command again goes on from there: every step looks at the zone and the core
// first and skips what is done, so a kill at any point costs nothing. Each step, and each change the drain makes while watched, goes to emergency.log in the
// work directory with the time since the run first started (the clock is kept in the plan, so a second run continues it).
//
// What the drain moves first is the core's planner's choice (the most valuable asset first, internal/custody/drains.go); this command does not choose it.
// One shard per run: start one run per shard, each in its own -dir, at the same time.

type emergencyFlags struct {
	shard, mode, reason, adminAuth string
	changes                        []string
	poll, stallAfter               time.Duration
}

// ErrStalled ends the watch of a drain that shows no progress.
var ErrStalled = errors.New("the emergency drain is stalled")

// keysFn makes the Keys of a plan when the shard has no candidate yet (main.go keysFor).
func runEmergency(ctx context.Context, env *Env, keysFn func(*Plan) (Keys, func(), error), f emergencyFlags) error {
	env.Compromised = true
	env.AdoptCandidate = true
	if old, err := loadPlan(env.Dir); err == nil {
		// A directory holds one plan: a shard named on the command line must be that one, or the run would drive another shard than the operator means.
		if f.shard != "" && f.shard != old.Shard {
			return fmt.Errorf("%s already holds the plan for %s, not %s: use another -dir for another shard", env.Dir, old.Shard, f.shard)
		}
	} else {
		if f.shard == "" {
			return errors.New("no plan in -dir yet: give -shard, -mode and -reason (the reason is the record of why the key is treated as stolen)")
		}
		if err := env.Open(ctx, f.shard, f.mode, f.reason); err != nil {
			return err
		}
	}
	p, err := loadPlan(env.Dir)
	if err != nil {
		return err
	}
	if p.EmergencyAt.IsZero() {
		p.EmergencyAt = env.Now().UTC()
		if err := savePlan(env.Dir, p); err != nil {
			return err
		}
	}
	files, err := changesByAction(f.changes)
	if err != nil {
		return err
	}
	em := &emergency{env: env, start: p.EmergencyAt, logPath: filepath.Join(env.Dir, "emergency.log")}
	em.logf("start", "shard %s: generation %d is treated as stolen; generation %d takes over (reason: %s)", p.Shard, p.From, p.To, p.Reason)

	// 1. The new key, only if the shard has none ready.
	if p.Address == "" {
		keys, closeKeys, err := keysFn(p)
		if err != nil {
			return err
		}
		defer closeKeys()
		env.Keys = keys
		if err := env.DKG(ctx); err != nil {
			return err
		}
		em.logf("dkg", "new key %s, address %s", p.KeyRef, p.Address)
		if p, err = loadPlan(env.Dir); err != nil {
			return err
		}
	} else {
		em.logf("dkg", "skipped: generation %d has a key already (%s)", p.To, p.Address)
	}

	type step struct {
		name, action string
		gen          func(*Plan) int
		post         string
		run          func(context.Context) error
	}
	steps := []step{
		{StepCandidate, gateway.KeysetRegisterCandidate, func(p *Plan) int { return p.To }, partition.StateCandidate, env.Candidate},
		{StepDrainStart, gateway.KeysetMarkCompromised, func(p *Plan) int { return p.From }, partition.StateCompromised, env.DrainStart},
		{StepActivate, gateway.KeysetActivate, func(p *Plan) int { return p.To }, partition.StateActive, env.Activate},
	}
	// A step half done (the zone has it, the core or a zone database not yet: a run killed between the two calls) is finished first. Its own agreement check
	// allows exactly that difference; run after another step's check it would be refused as an unrelated mismatch. Only one step can be half done, since
	// the steps run one at a time and each ends with both sides agreeing.
	if z, c, err := env.read(ctx, p); err == nil {
		for i, st := range steps {
			if ss := stepState(z, c, st.gen(p), st.post); ss == "zone" || ss == "partial" {
				em.logf(st.name, "found half done (%s): finished first", ss)
				steps = append([]step{st}, append(append([]step{}, steps[:i]...), steps[i+1:]...)...)
				break
			}
		}
	}
	for _, st := range steps {
		env.ChangeFile = files[st.action]
		if err := st.run(ctx); err != nil {
			em.logf(st.name, "FAILED: %v", err)
			return err
		}
		z, c, err := env.read(ctx, p)
		if err != nil {
			return err
		}
		if stepState(z, c, st.gen(p), st.post) != "done" {
			em.logf(st.name, "waits for the signed record (the hint above): run this command again with -changes FILE")
			return fmt.Errorf("%s needs its signed record: sign it, then run the same command again", st.name)
		}
		em.logf(st.name, "done: generation %d is %s in the zone and the core", st.gen(p), st.post)
	}
	return em.watch(ctx, p, f.poll, f.stallAfter)
}

type emergency struct {
	env     *Env
	start   time.Time
	logPath string
}

// logf prints one line and appends it to emergency.log, with the time since the emergency began.
func (em *emergency) logf(step, format string, a ...any) {
	line := fmt.Sprintf("T+%s %-14s %s", em.env.Now().Sub(em.start).Round(time.Second), step, fmt.Sprintf(format, a...))
	em.env.printf("%s\n", line)
	if f, err := os.OpenFile(em.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		fmt.Fprintf(f, "%s %s\n", em.env.Now().UTC().Format(time.RFC3339), line)
		f.Close()
	}
}

// watch follows the drain in the core until it is drained, or shows no change for stallAfter.
func (em *emergency) watch(ctx context.Context, p *Plan, poll, stallAfter time.Duration) error {
	var last string
	sawDrained := false
	lastChange := em.env.Now()
	for {
		c, err := em.env.Core.Keysets(ctx, p.Shard)
		if err != nil {
			return fmt.Errorf("read the core: %w", err)
		}
		d := c[p.From].Drain
		cur := "not started"
		if d != nil {
			cur = d.State
			if d.Reason != "" {
				cur += ": " + d.Reason
			}
		}
		if cur != last {
			em.logf("drain", "%s", cur)
			last, lastChange = cur, em.env.Now()
		}
		if d != nil && d.State == "drained" && poll > 0 && !sawDrained {
			// Drained once is not enough: a sweep that was broadcast before the mark may confirm after the planner looked, and put new funds on the old
			// address. The core reads the balance again after every transaction is final; one more poll shows whether it found more.
			sawDrained = true
			em.logf("drain", "empty at this look; checking once more for what arrives late (a sweep paid to the old address before the mark)")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(poll):
			}
			continue
		}
		sawDrained = d != nil && d.State == "drained"
		if d != nil && d.State == "drained" {
			em.logf("drained", "generation %d holds nothing above dust; it stays compromised and in the watch list. Next: verify (runbook), then the afterwards steps", p.From)
			return nil
		}
		if stallAfter > 0 && em.env.Now().Sub(lastChange) >= stallAfter {
			em.logf("STALLED", "no change for %s (%s). ALERT: read the reason, fix it (gas at the old address, a lagging zone database, the cap: `qv-rekey caps`; "+
				"for work in flight, the transaction named above: docs/runbooks/stolen-hot-key.md, \"Work in flight\"), then run this command again", stallAfter, cur)
			return fmt.Errorf("%w: %s", ErrStalled, cur)
		}
		if poll <= 0 {
			return nil // one look
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// changesByAction reads the signed change files and keys them by action: the emergency needs one each of register-candidate, mark-compromised and
// activate. Each file is checked against the exact step when its step runs (readChange).
func changesByAction(paths []string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range paths {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var c gateway.KeysetChange
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		switch c.Action {
		case gateway.KeysetRegisterCandidate, gateway.KeysetMarkCompromised, gateway.KeysetActivate:
		default:
			return nil, fmt.Errorf("%s: %s is no step of the emergency (register-candidate, mark-compromised, activate)", f, c.Action)
		}
		if _, dup := out[c.Action]; dup {
			return nil, fmt.Errorf("%s: a second %s file", f, c.Action)
		}
		out[c.Action] = f
	}
	return out, nil
}
