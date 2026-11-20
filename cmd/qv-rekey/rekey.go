package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// The replacement of one EVM hot shard's key, step by step (docs/runbooks/key-replacement.md). The tool signs nothing: the operators' signatures on the
// zone's records come in as files made with `qv-keysets sign`, and the tool applies them to the zone's guard databases and then asks the core's admin
// routes to mirror each step, in the order the zone has to be first. It keeps only a small plan file; where a step stands is read from the zone and the
// core every time, so it can be stopped at any point and run again, and it refuses to go on when the two disagree.

// Step names.
const (
	StepOpen       = "open"
	StepDKG        = "dkg"
	StepCandidate  = "candidate"
	StepDrainStart = "drain-start"
	StepActivate   = "activate"
	StepRetire     = "retire"
)

// Plan is what the tool remembers between runs (plan.json in the work directory).
type Plan struct {
	Shard    string    `json:"shard"`
	Mode     string    `json:"mode"` // mpc or hsm
	From     int       `json:"from"` // the generation being replaced
	To       int       `json:"to"`   // the new generation
	Reason   string    `json:"reason"`
	OpenedAt time.Time `json:"opened_at"`
	// The new key, set by the dkg step.
	KeyRef    string `json:"key_ref,omitempty"`    // MPC keyset ID, or HSM CKA_ID in hex
	PublicKey string `json:"public_key,omitempty"` // 65-byte uncompressed, hex
	Address   string `json:"address,omitempty"`
}

var slug = regexp.MustCompile(`[^a-z0-9]+`)

// KeysetID is the name of the new MPC keyset: the shard and the generation.
func (p Plan) KeysetID() string {
	return strings.Trim(slug.ReplaceAllString(strings.ToLower(p.Shard), "-"), "-") + fmt.Sprintf("-g%d", p.To)
}

func planPath(dir string) string { return filepath.Join(dir, "plan.json") }

func loadPlan(dir string) (*Plan, error) {
	b, err := os.ReadFile(planPath(dir))
	if err != nil {
		return nil, fmt.Errorf("no plan in %s (run open first): %w", dir, err)
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func savePlan(dir string, p *Plan) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	tmp := planPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, planPath(dir))
}

// ---- the two sides ----

// Zone is the signing zone's guard databases (the gateway's and every cosigner's).
type Zone interface {
	// Views returns, per database name, the generations of the shard as that database sees them, and its sequence number.
	Views(ctx context.Context, shard string) (map[string]ZoneView, error)
	// Apply puts one signed change into every database (idempotent: one that has it skips it). A database that refuses is named in the error.
	Apply(ctx context.Context, c gateway.KeysetChange) error
	// MinOperators is how many operators must sign a change.
	MinOperators() int
	// Partition is a hot partition of the shard (its signer entry says where the parties or the token are).
	Partition(shard string) (string, error)
}

// ZoneView is one guard database's view of a shard.
type ZoneView struct {
	Seq  int64
	Gens map[int]ZoneGen
}

// ZoneGen is one generation.
type ZoneGen struct {
	State     string
	Address   string
	KeyRef    string
	Successor int
}

// CoreGen is one generation as the core's admin API shows it.
type CoreGen struct {
	ShardID    string `json:"shard_id"`
	Generation int    `json:"generation"`
	Address    string `json:"address"`
	KeyRef     string `json:"key_ref"`
	State      string `json:"state"`
	Successor  int    `json:"successor"`
	Drain      *struct {
		State  string `json:"state"`
		Reason string `json:"reason"`
	} `json:"drain"`
}

// Core is the business core's admin API.
type Core interface {
	Keysets(ctx context.Context, shard string) (map[int]CoreGen, error)
	Post(ctx context.Context, route string, body map[string]any) error
}

// Keys makes the new key.
type Keys interface {
	// New makes the key of the plan's new generation (idempotent in the sense that a key made earlier is found again) and returns its reference and
	// 65-byte uncompressed public key, hex.
	New(ctx context.Context, p *Plan) (keyRef, publicKey string, err error)
	// Check says whether the key is in place and healthy everywhere it must be (the parties agree), or why not.
	Check(ctx context.Context, p *Plan) error
}

// Env is everything a command needs.
type Env struct {
	Dir  string
	Zone Zone
	Core Core
	Keys Keys
	Out  io.Writer
	Now  func() time.Time
	// ChangeFile is the signed change to apply (the candidate, drain-start, activate, caps and retire commands); empty: print what to sign.
	ChangeFile string
	// Caps are the drain caps (drain-start and caps), ASSET=BASE_UNITS.
	Caps []string
	// FactoryDestination, if set, reads the factory's destination on chain (the status check of the cold ceremony).
	FactoryDestination func(ctx context.Context) (string, error)
	// Compromised makes drain-start the emergency step: the old generation is marked compromised (with its successor and caps in the same record)
	// instead of draining. A compromised generation signs only its drain and is never retired.
	Compromised bool
}

func (e *Env) printf(format string, a ...any) { fmt.Fprintf(e.Out, format, a...) }

// ---- agreement ----

var rank = map[string]int{"": 0, partition.StateCandidate: 1, partition.StateActive: 2, partition.StateDraining: 3, partition.StateRetired: 4, partition.StateCompromised: 5}

// Disagreement is a mismatch of the zone and the core that the tool will not step over.
type Disagreement struct{ Msg string }

func (d *Disagreement) Error() string { return d.Msg }

// agree checks that the zone's databases and the core show the same states for every generation of the shard, except generation `moving`, which a step
// is in the middle of: there the zone may be one state ahead of the core (the step's own order: zone first), and nothing else is allowed.
func agree(zone map[string]ZoneView, core map[int]CoreGen, moving int, pre, post string) error {
	names := make([]string, 0, len(zone))
	for n := range zone {
		names = append(names, n)
	}
	sort.Strings(names)
	gens := map[int]bool{}
	for _, n := range names {
		for g := range zone[n].Gens {
			gens[g] = true
		}
	}
	for g := range core {
		gens[g] = true
	}
	order := make([]int, 0, len(gens))
	for g := range gens {
		order = append(order, g)
	}
	slices.Sort(order)
	for _, g := range order {
		cs := core[g].State
		for _, n := range names {
			zs := zone[n].Gens[g].State
			if zs == cs {
				continue
			}
			if g == moving && zs == post && cs == pre {
				continue // the zone has the step, the core not yet: this run finishes it
			}
			if g == moving && zs == pre && cs == pre {
				continue
			}
			behind := "the core is behind the zone"
			if rank[zs] < rank[cs] {
				behind = "the zone database " + n + " is behind the core"
			}
			if g == moving && zs == pre && cs == post {
				return &Disagreement{fmt.Sprintf("generation %d: the core is %s but the zone database %s is still %s: %s. Apply the signed change to the zone first (the zone decides; a core ahead of it stalls work), then run this again", g, cs, n, zs, behind)}
			}
			return &Disagreement{fmt.Sprintf("generation %d: the zone database %s says %q, the core says %q: %s. Bring the lagging side to the other's state before going on", g, n, zs, cs, behind)}
		}
	}
	// The zone databases among themselves: a partial apply of the moving generation is allowed (this run finishes it); anything else is not.
	if len(names) > 1 {
		for _, g := range order {
			if g == moving {
				continue
			}
			ref := zone[names[0]].Gens[g].State
			for _, n := range names[1:] {
				if zone[n].Gens[g].State != ref {
					return &Disagreement{fmt.Sprintf("generation %d: the zone databases %s and %s differ", g, names[0], n)}
				}
			}
		}
	}
	return nil
}

// stepState says where a step stands: "todo" (the zone has not got it), "partial" (some zone databases have it), "zone" (all zone databases have it, the
// core has not), "done" (both).
func stepState(zone map[string]ZoneView, core map[int]CoreGen, gen int, post string) string {
	have := 0
	for _, v := range zone {
		if rank[v.Gens[gen].State] >= rank[post] {
			have++
		}
	}
	switch {
	case have == 0:
		return "todo"
	case have < len(zone):
		return "partial"
	case rank[core[gen].State] >= rank[post]:
		return "done"
	}
	return "zone"
}

// ---- commands ----

func (e *Env) read(ctx context.Context, p *Plan) (map[string]ZoneView, map[int]CoreGen, error) {
	z, err := e.Zone.Views(ctx, p.Shard)
	if err != nil {
		return nil, nil, fmt.Errorf("read the zone: %w", err)
	}
	c, err := e.Core.Keysets(ctx, p.Shard)
	if err != nil {
		return nil, nil, fmt.Errorf("read the core: %w", err)
	}
	return z, c, nil
}

func maxSeq(z map[string]ZoneView) int64 {
	var m int64
	for _, v := range z {
		m = max(m, v.Seq)
	}
	return m
}

// Open checks that the shard can be replaced and writes the plan.
func (e *Env) Open(ctx context.Context, shard, mode, reason string) error {
	if mode != "mpc" && mode != "hsm" {
		return errors.New("-mode is mpc or hsm")
	}
	if _, err := partition.ParseShardID(shard); err != nil {
		return err
	}
	if reason == "" {
		return errors.New("-reason is required: it is the record of why the key is replaced")
	}
	if old, err := loadPlan(e.Dir); err == nil {
		if old.Shard != shard {
			return fmt.Errorf("%s already holds the plan for %s: use another -dir", e.Dir, old.Shard)
		}
		e.printf("the plan for %s is open already (generation %d to %d); `status` shows where it stands\n", old.Shard, old.From, old.To)
		return nil
	}
	p := &Plan{Shard: shard, Mode: mode, Reason: reason, OpenedAt: e.Now().UTC()}
	if _, err := e.Zone.Partition(shard); err != nil {
		return err
	}
	z, c, err := e.read(ctx, p)
	if err != nil {
		return err
	}
	if len(z) == 0 {
		return errors.New("no zone database")
	}
	top, active := 0, 0
	for _, v := range z {
		for g, e := range v.Gens {
			top = max(top, g)
			if e.State == partition.StateActive {
				if active != 0 && active != g {
					return fmt.Errorf("the zone databases disagree about the active generation of %s", shard)
				}
				active = g
			}
			if e.State == partition.StateCandidate || e.State == partition.StateDraining {
				return fmt.Errorf("generation %d of %s is %s: finish or undo that replacement first", g, shard, e.State)
			}
		}
	}
	for g, k := range c {
		top = max(top, g)
		if k.State == partition.StateCandidate || k.State == partition.StateDraining {
			return fmt.Errorf("the core shows generation %d of %s as %s: finish that replacement first", g, shard, k.State)
		}
	}
	if active == 0 {
		return fmt.Errorf("%s has no active generation in the zone", shard)
	}
	if err := agree(z, c, 0, "", ""); err != nil {
		return err
	}
	p.From, p.To = active, top+1
	if err := savePlan(e.Dir, p); err != nil {
		return err
	}
	e.printf("plan: replace generation %d of %s (%s key) with generation %d; reason: %s\n", p.From, p.Shard, p.Mode, p.To, p.Reason)
	e.printf("checked: the zone databases (%s) and the core agree; generation %d is active\n", strings.Join(sortedNames(z), ", "), p.From)
	e.printf("next: dkg\n")
	return nil
}

func sortedNames(z map[string]ZoneView) []string {
	var n []string
	for k := range z {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// DKG makes the new key (idempotent: the plan keeps it).
func (e *Env) DKG(ctx context.Context) error {
	p, err := loadPlan(e.Dir)
	if err != nil {
		return err
	}
	if p.Address == "" {
		ref, pub, err := e.Keys.New(ctx, p)
		if err != nil {
			return err
		}
		addr, err := addressOf(pub)
		if err != nil {
			return err
		}
		p.KeyRef, p.PublicKey, p.Address = ref, pub, addr
		if err := savePlan(e.Dir, p); err != nil {
			return fmt.Errorf("the key %s was made but the plan could not be saved (%v): run dkg again, it finds the key", ref, err)
		}
		e.printf("new key %s: address %s\n", ref, addr)
	} else {
		e.printf("the new key is made already: %s, address %s\n", p.KeyRef, p.Address)
	}
	if err := e.Keys.Check(ctx, p); err != nil {
		return fmt.Errorf("the new key is not healthy yet: %w", err)
	}
	e.printf("the parties (or the token) hold the key and agree on it\nnext: candidate\n")
	return nil
}

// signHint prints the command that makes the zone record for this change, and what to do with the file.
func (e *Env) signHint(z map[string]ZoneView, p *Plan, command, flags string) {
	seq := maxSeq(z) + 1
	e.printf("sign this with %d operators (qv-keysets sign ... -join FILE adds each signature), then run `qv-rekey %s -change FILE`:\n", e.Zone.MinOperators(), command)
	e.printf("  qv-keysets sign -operator NAME -key OPERATOR.key -seq %d -shard %s %s -out change-%d.json\n", seq, p.Shard, flags, seq)
}

// readChange loads a change file and checks it is exactly the step the plan needs.
func (e *Env) readChange(want gateway.KeysetChange) (gateway.KeysetChange, error) {
	b, err := os.ReadFile(e.ChangeFile)
	if err != nil {
		return gateway.KeysetChange{}, err
	}
	var c gateway.KeysetChange
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", e.ChangeFile, err)
	}
	if c.Action != want.Action || c.Shard != want.Shard || c.Generation != want.Generation || c.Successor != want.Successor ||
		!strings.EqualFold(c.Address, want.Address) || c.KeyRef != want.KeyRef || c.PublicKey != want.PublicKey {
		return c, fmt.Errorf("%s is not the change this step needs: want %s generation %d of %s (successor %d, address %q, key %q); it has %s generation %d of %s (successor %d, address %q, key %q)",
			e.ChangeFile, want.Action, want.Generation, want.Shard, want.Successor, want.Address, want.KeyRef,
			c.Action, c.Generation, c.Shard, c.Successor, c.Address, c.KeyRef)
	}
	if len(want.Caps) > 0 && !sameCaps(c.Caps, want.Caps) {
		return c, fmt.Errorf("%s names caps %v, not the %v given", e.ChangeFile, c.Caps, want.Caps)
	}
	if len(c.Signatures) < e.Zone.MinOperators() {
		return c, fmt.Errorf("%s carries %d signatures, the zone needs %d operators", e.ChangeFile, len(c.Signatures), e.Zone.MinOperators())
	}
	return c, nil
}

func sameCaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func parseCaps(in []string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range in {
		a, v, ok := strings.Cut(kv, "=")
		if !ok || a == "" || v == "" {
			return nil, fmt.Errorf("-cap %q: want ASSET=BASE_UNITS", kv)
		}
		out[a] = v
	}
	return out, nil
}

// zoneThenCore is the shape of every state step: check agreement, show what to sign or apply the signed change to the zone, then mirror it in the core.
func (e *Env) zoneThenCore(ctx context.Context, p *Plan, name string, gen int, pre, post string, want gateway.KeysetChange, hint, flags, route string, body map[string]any) error {
	z, c, err := e.read(ctx, p)
	if err != nil {
		return err
	}
	if err := agree(z, c, gen, pre, post); err != nil {
		return err
	}
	switch stepState(z, c, gen, post) {
	case "done":
		e.printf("%s: done already (zone and core both show generation %d %s)\n", name, gen, post)
		return nil
	case "todo", "partial":
		if e.ChangeFile == "" {
			e.signHint(z, p, hint, flags)
			return nil
		}
		change, err := e.readChange(want)
		if err != nil {
			return err
		}
		if err := e.Zone.Apply(ctx, change); err != nil {
			return fmt.Errorf("zone: %w (the databases that took it keep it; fix the cause and run %s again)", err, name)
		}
		e.printf("zone: applied %s generation %d to every guard database\n", change.Action, gen)
		if z, c, err = e.read(ctx, p); err != nil {
			return err
		}
		if err := agree(z, c, gen, pre, post); err != nil {
			return err
		}
	}
	if err := e.Core.Post(ctx, route, body); err != nil {
		return fmt.Errorf("core: %w (the zone has the step; run %s again to repeat the call)", err, name)
	}
	e.printf("core: %s mirrored\n", name)
	return nil
}

// Candidate registers the new generation in the zone and the core.
func (e *Env) Candidate(ctx context.Context) error {
	p, err := loadPlan(e.Dir)
	if err != nil {
		return err
	}
	if p.Address == "" {
		return errors.New("no key yet: run dkg first")
	}
	want := gateway.KeysetChange{Action: gateway.KeysetRegisterCandidate, Shard: p.Shard, Generation: p.To, Address: p.Address, KeyRef: p.KeyRef, PublicKey: p.PublicKey}
	flags := fmt.Sprintf("-action register-candidate -generation %d -address %s -key-ref %s -public-key %s", p.To, p.Address, p.KeyRef, p.PublicKey)
	if err := e.zoneThenCore(ctx, p, StepCandidate, p.To, "", partition.StateCandidate, want, "candidate", flags,
		"candidates", map[string]any{"shard_id": p.Shard, "address": p.Address, "key_ref": p.KeyRef}); err != nil {
		return err
	}
	e.printf("next: drain-start\n")
	return nil
}

// DrainStart makes the old generation draining into the new one in the zone and the core. The shard has no active generation until activate.
func (e *Env) DrainStart(ctx context.Context) error {
	p, err := loadPlan(e.Dir)
	if err != nil {
		return err
	}
	caps, err := parseCaps(e.Caps)
	if err != nil || len(caps) == 0 {
		return errors.New("-cap ASSET=BASE_UNITS is required (the most all drains of that asset from the old key may move: the zone's bound, since it cannot read the chain)")
	}
	action, post, route := gateway.KeysetStartDraining, partition.StateDraining, "drains"
	if e.Compromised {
		action, post, route = gateway.KeysetMarkCompromised, partition.StateCompromised, "compromises"
	}
	want := gateway.KeysetChange{Action: action, Shard: p.Shard, Generation: p.From, Successor: p.To, Caps: caps}
	flags := fmt.Sprintf("-action %s -generation %d -successor %d", action, p.From, p.To)
	for _, k := range sortedCaps(caps) {
		flags += fmt.Sprintf(" -cap %s=%s", k, caps[k])
	}
	z, c, err := e.read(ctx, p)
	if err != nil {
		return err
	}
	if c[p.To].State == "" && z[sortedNames(z)[0]].Gens[p.To].State == "" {
		return errors.New("the new generation is not a candidate yet: run candidate first")
	}
	if err := e.zoneThenCore(ctx, p, StepDrainStart, p.From, partition.StateActive, post, want, "drain-start", flags,
		route, map[string]any{"shard_id": p.Shard, "generation": p.From, "successor": p.To}); err != nil {
		return err
	}
	e.printf("the shard has no active key until activate: new work waits meanwhile, so run it now\nnext: activate\n")
	if e.Compromised {
		e.printf("generation %d is compromised: it signs only its drain, and is never retired (keep its shares for the investigation)\n", p.From)
	}
	return nil
}

func sortedCaps(m map[string]string) []string {
	var k []string
	for a := range m {
		k = append(k, a)
	}
	sort.Strings(k)
	return k
}

// Activate makes the new generation active in the zone and the core, then says what the cold ceremony needs.
func (e *Env) Activate(ctx context.Context) error {
	p, err := loadPlan(e.Dir)
	if err != nil {
		return err
	}
	want := gateway.KeysetChange{Action: gateway.KeysetActivate, Shard: p.Shard, Generation: p.To}
	if err := e.zoneThenCore(ctx, p, StepActivate, p.To, partition.StateCandidate, partition.StateActive, want, "activate",
		fmt.Sprintf("-action activate -generation %d", p.To), "activations", map[string]any{"shard_id": p.Shard, "generation": p.To}); err != nil {
		return err
	}
	z, c, err := e.read(ctx, p)
	if err != nil {
		return err
	}
	if stepState(z, c, p.To, partition.StateActive) != "done" {
		return nil
	}
	e.printf("%s", ceremonyText(p))
	return e.factoryCheck(ctx, p)
}

func ceremonyText(p *Plan) string {
	return fmt.Sprintf(`the cold step is a separate human ceremony, outside this tool (docs/runbooks/key-replacement.md, step "Point deposits at the new key"):
  1. core: POST /v2/cold/actions {"kind":"set-destination","param":"%s"}, then qv-cold inspect/approve/sign/import (M of N custodians; read: destination <old> -> %s).
  2. in every zone config (gateway, each cosigner) and the business config set the sweep destination to %s and restart them.
  Until both are done, sweeps wait ("factory destination differs"); nothing is lost. Run status to see whether the factory points at the new address.
`, p.Address, p.Address, p.Address)
}

func (e *Env) factoryCheck(ctx context.Context, p *Plan) error {
	if e.FactoryDestination == nil {
		return nil
	}
	d, err := e.FactoryDestination(ctx)
	if err != nil {
		e.printf("factory destination: could not be read: %v\n", err)
		return nil
	}
	if strings.EqualFold(d, p.Address) {
		e.printf("factory destination: %s (the new address): the ceremony is done\n", d)
	} else {
		e.printf("factory destination: %s, not the new address yet: the ceremony is not done\n", d)
	}
	return nil
}

// Caps applies a signed set-drain-caps change to the zone (the core has no cap: its drains simply meet the zone's refusal and wait).
func (e *Env) SetCaps(ctx context.Context) error {
	p, err := loadPlan(e.Dir)
	if err != nil {
		return err
	}
	caps, err := parseCaps(e.Caps)
	if err != nil || len(caps) == 0 {
		return errors.New("-cap ASSET=BASE_UNITS is required: the new total the drains of that asset may move")
	}
	z, _, err := e.read(ctx, p)
	if err != nil {
		return err
	}
	if e.ChangeFile == "" {
		flags := fmt.Sprintf("-action set-drain-caps -generation %d", p.From)
		for _, k := range sortedCaps(caps) {
			flags += fmt.Sprintf(" -cap %s=%s", k, caps[k])
		}
		e.signHint(z, p, "caps", flags)
		return nil
	}
	c, err := e.readChange(gateway.KeysetChange{Action: gateway.KeysetSetDrainCaps, Shard: p.Shard, Generation: p.From, Caps: caps})
	if err != nil {
		return err
	}
	if err := e.Zone.Apply(ctx, c); err != nil {
		return err
	}
	e.printf("zone: the drain caps of generation %d are now %v\n", p.From, caps)
	return nil
}

// Retire retires the drained old generation in the zone and the core. It refuses while the core says the drain is not finished.
func (e *Env) Retire(ctx context.Context) error {
	p, err := loadPlan(e.Dir)
	if err != nil {
		return err
	}
	z, c, err := e.read(ctx, p)
	if err != nil {
		return err
	}
	if c[p.From].State == partition.StateCompromised {
		return fmt.Errorf("generation %d is compromised: a compromised generation is never retired (the zone refuses it); it stays in the watch list", p.From)
	}
	if stepState(z, c, p.From, partition.StateRetired) != "done" {
		if k := c[p.From]; k.State != partition.StateRetired {
			if k.State != partition.StateDraining && k.State != partition.StateCompromised {
				return fmt.Errorf("generation %d is %s in the core: it is not draining", p.From, k.State)
			}
			if k.Drain == nil || k.Drain.State != "drained" {
				st := "not started"
				if k.Drain != nil {
					st = k.Drain.State + " " + k.Drain.Reason
				}
				return fmt.Errorf("the drain of generation %d is not finished (%s): retire only after the core says drained", p.From, st)
			}
		}
	}
	want := gateway.KeysetChange{Action: gateway.KeysetRetire, Shard: p.Shard, Generation: p.From}
	if err := e.zoneThenCore(ctx, p, StepRetire, p.From, partition.StateDraining, partition.StateRetired, want, "retire",
		fmt.Sprintf("-action retire -generation %d", p.From), "retirements", map[string]any{"shard_id": p.Shard, "generation": p.From}); err != nil {
		return err
	}
	e.printf("generation %d is retired. Keep its backups and shares until the window in the runbook ends; do not destroy them here.\n", p.From)
	return nil
}

// Status shows where everything stands and what is next. It exits with an error when the zone and the core disagree.
func (e *Env) Status(ctx context.Context) error {
	p, err := loadPlan(e.Dir)
	if err != nil {
		return err
	}
	z, c, err := e.read(ctx, p)
	if err != nil {
		return err
	}
	e.printf("shard %s: replace generation %d with %d (%s key). reason: %s\n", p.Shard, p.From, p.To, p.Mode, p.Reason)
	for _, n := range sortedNames(z) {
		e.printf("  zone %-12s sequence %d:", n, z[n].Seq)
		for _, g := range sortedGens(z[n].Gens) {
			e.printf("  g%d %s", g, z[n].Gens[g].State)
		}
		e.printf("\n")
	}
	e.printf("  core %-12s            :", "")
	for _, g := range sortedCoreGens(c) {
		e.printf("  g%d %s", g, c[g].State)
		if d := c[g].Drain; d != nil {
			e.printf(" (drain %s)", d.State)
			if d.Reason != "" {
				e.printf(" %s", d.Reason)
			}
		}
	}
	e.printf("\n")
	next := ""
	done := func(g int, st string) bool { return stepState(z, c, g, st) == "done" }
	switch {
	case p.Address == "":
		next = StepDKG
	case !done(p.To, partition.StateCandidate):
		next = StepCandidate
	case !done(p.From, partition.StateDraining):
		next = StepDrainStart
	case c[p.From].State == partition.StateCompromised && done(p.To, partition.StateActive):
		next = "(nothing: the compromised generation is drained and stays in the watch list)"
	case !done(p.To, partition.StateActive):
		next = StepActivate
	case !done(p.From, partition.StateRetired):
		next = StepRetire
	default:
		next = "(nothing: the replacement is complete)"
	}
	var derr error
	moving, pre, post := stepOf(next, p)
	if err := agree(z, c, moving, pre, post); err != nil {
		derr = err
		e.printf("DISAGREEMENT: %v\n", err)
	}
	e.printf("next step: %s\n", next)
	if next == StepRetire {
		if d := c[p.From].Drain; d == nil || d.State != "drained" {
			e.printf("  (the old generation is not drained yet: retire waits for the core's drain to finish)\n")
		}
	}
	if done(p.To, partition.StateActive) {
		e.printf("%s", ceremonyText(p))
		_ = e.factoryCheck(ctx, p)
	}
	return derr
}

func stepOf(step string, p *Plan) (gen int, pre, post string) {
	switch step {
	case StepCandidate:
		return p.To, "", partition.StateCandidate
	case StepDrainStart:
		return p.From, partition.StateActive, partition.StateDraining
	case StepActivate:
		return p.To, partition.StateCandidate, partition.StateActive
	case StepRetire:
		return p.From, partition.StateDraining, partition.StateRetired
	}
	return 0, "", ""
}

func sortedGens(m map[int]ZoneGen) []int {
	var o []int
	for g := range m {
		o = append(o, g)
	}
	slices.Sort(o)
	return o
}

func sortedCoreGens(m map[int]CoreGen) []int {
	var o []int
	for g := range m {
		o = append(o, g)
	}
	slices.Sort(o)
	return o
}
