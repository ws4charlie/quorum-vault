package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The operator-signed approver registry (approvers.go): who may change the approver set, what a change must carry, what a decision does with the
// result, and what happens while the gateway and a cosigner are on different sequence numbers.

type regRig struct {
	*harness
	ops  map[string]ed25519.PrivateKey
	newK map[string]ed25519.PrivateKey // keys of approvers to enrol
}

func newRegRig(t *testing.T) *regRig {
	t.Helper()
	r := &regRig{harness: newHarnessSoft(t), ops: map[string]ed25519.PrivateKey{}, newK: map[string]ed25519.PrivateKey{}}
	oc := &OperatorConfig{Keys: map[string]ed25519.PublicKey{}, Min: 2, MaxAge: 10 * time.Minute}
	for _, n := range []string{"op1", "op2", "op3"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		r.ops[n], oc.Keys[n] = priv, pub
	}
	r.cfg.Operators = oc
	return r
}

func (r *regRig) enrolEntry(name string) *ApproverFile {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r.newK[name] = priv
	r.keys[name] = priv
	return &ApproverFile{PublicKey: hex.EncodeToString(pub), Enabled: true}
}

func (r *regRig) change(action, name string, ap *ApproverFile, seq int64, at time.Time, signers ...string) ApproverChange {
	r.t.Helper()
	base := ApproverChange{Action: action, Name: name, Approver: ap, Seq: seq, SignedAt: at.Unix()}
	var parts []ApproverChange
	for _, s := range signers {
		priv, ok := r.ops[s]
		if !ok {
			priv = r.keys[s] // an approver signing as if it were an operator
		}
		parts = append(parts, SignApproverChange(priv, s, base))
	}
	c, err := MergeApproverChanges(parts...)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *regRig) apply(g *Guard, c ApproverChange) error {
	return g.ApplyApproverChange(context.Background(), r.cfg, c, r.clock(), "gateway")
}

func (r *regRig) set(g *Guard) *ApproverSet {
	r.t.Helper()
	s, err := g.EffectiveApprovers(context.Background(), r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *regRig) rows(g *Guard) int {
	var n int
	if err := g.pool.QueryRow(context.Background(), `SELECT count(*) FROM approver_changes`).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func TestApproverRegistryEnrolIsAuditedAndHot(t *testing.T) {
	r := newRegRig(t)
	now := r.clock()
	// Before: erin is nobody; a job she approves waits (not final: the list may be behind).
	ap := r.enrolEntry("erin")
	if err := r.apply(r.guard, r.change(ActionEnrol, "erin", ap, 1, now, "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	// Same gateway, same decider, no restart: the next decision counts erin.
	r.mustSign(r.withdrawal("e1", addrUser, 100, 0, "erin"))
	var ev []auditRow
	for _, a := range r.auditRows() {
		if a.Type == EventApproverChanged {
			ev = append(ev, a)
		}
	}
	if len(ev) != 1 || ev[0].Payload["name"] != "erin" || ev[0].Payload["action"] != ActionEnrol {
		t.Fatalf("audit = %+v", ev)
	}
	if ops, _ := ev[0].Payload["operators"].([]any); len(ops) != 2 || ops[0] != "op1" || ops[1] != "op2" {
		t.Fatalf("operators in audit: %v", ev[0].Payload["operators"])
	}
	// Applying the same change again is not an error and adds nothing.
	if err := r.apply(r.guard, r.change(ActionEnrol, "erin", ap, 1, now, "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	if r.rows(r.guard) != 1 {
		t.Fatal("an idempotent apply wrote a row")
	}
}

func TestApproverRegistryHostileChangesHaveNoEffect(t *testing.T) {
	r := newRegRig(t)
	now := r.clock()
	ap := r.enrolEntry("erin")
	good := r.change(ActionEnrol, "erin", ap, 1, now, "op1", "op2")
	for name, c := range map[string]ApproverChange{
		"one operator":                r.change(ActionEnrol, "erin", ap, 1, now, "op1"),
		"the same operator twice":     r.change(ActionEnrol, "erin", ap, 1, now, "op1", "op1"),
		"approvers as signers":        r.change(ActionEnrol, "erin", ap, 1, now, "alice", "bob"),
		"an approver and an operator": r.change(ActionEnrol, "erin", ap, 1, now, "alice", "op1"),
		"stale":                       r.change(ActionEnrol, "erin", ap, 1, now.Add(-time.Hour), "op1", "op2"),
		"from the future":             r.change(ActionEnrol, "erin", ap, 1, now.Add(time.Hour), "op1", "op2"),
		"sequence 0":                  r.change(ActionEnrol, "erin", ap, 0, now, "op1", "op2"),
		"a tampered entry": func() ApproverChange {
			c := good
			other := *ap
			other.Identity = "mallory"
			c.Approver = &other
			return c
		}(),
		"a disabled enrolment": func() ApproverChange {
			off := *ap
			off.Enabled = false
			return r.change(ActionEnrol, "erin", &off, 1, now, "op1", "op2")
		}(),
	} {
		if err := r.apply(r.guard, c); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	if r.rows(r.guard) != 0 || len(r.set(r.guard).Approvers) != len(r.cfg.Approvers) {
		t.Fatal("a refused change left a trace")
	}
	// An approver cannot revoke or enable anybody either.
	for _, a := range []ApproverChange{r.change(ActionRevoke, "carol", nil, 1, now, "alice", "bob"), r.change(ActionEnable, "dave", nil, 1, now, "alice", "bob")} {
		if err := r.apply(r.guard, a); err == nil {
			t.Fatalf("%s by approvers applied", a.Action)
		}
	}
	// Replay and a lower sequence.
	if err := r.apply(r.guard, good); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(r.guard, r.change(ActionDisable, "carol", nil, 1, now, "op1", "op2")); err == nil {
		t.Error("a reused sequence number applied")
	}
	if err := r.apply(r.guard, r.change(ActionDisable, "carol", nil, 5, now, "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(r.guard, r.change(ActionEnable, "carol", nil, 3, now, "op1", "op2")); err == nil {
		t.Error("a lower sequence number applied")
	}
	// Unknown approver, a name used again, a key used again, an operator's key.
	if err := r.apply(r.guard, r.change(ActionRevoke, "nobody", nil, 6, now, "op1", "op2")); err == nil {
		t.Error("revoke of an unknown approver applied")
	}
	if err := r.apply(r.guard, r.change(ActionEnrol, "erin", ap, 6, now, "op1", "op2")); err == nil {
		t.Error("enrol of an existing name applied")
	}
	dup := *ap
	if err := r.apply(r.guard, r.change(ActionEnrol, "erin2", &dup, 6, now, "op1", "op2")); err == nil {
		t.Error("enrol of a key that is already an approver's applied")
	}
	opKey := &ApproverFile{PublicKey: hex.EncodeToString(r.cfg.Operators.Keys["op3"]), Enabled: true}
	if err := r.apply(r.guard, r.change(ActionEnrol, "mallory", opKey, 6, now, "op1", "op2")); err == nil {
		t.Error("enrol of an operator's key applied")
	}
}

func TestApproverRegistryDirectInsertIsIgnoredAndCounted(t *testing.T) {
	r := newRegRig(t)
	ctx := context.Background()
	// SQL access to the guard database: a revoke of alice with no valid signatures, and one signed by approvers.
	for _, sigs := range []string{`[]`, `[{"operator":"alice","signature":"00"}]`} {
		if _, err := r.guardDB.Exec(ctx, `INSERT INTO approver_changes (seq, action, name, signed_at, signatures) VALUES (1, 'revoke', 'alice', $1, $2::jsonb)`, r.clock().Unix(), sigs); err != nil {
			t.Fatal(err)
		}
	}
	s := r.set(r.guard)
	if s.Ignored != 2 || !s.Approvers["alice"].Enabled || s.Seq != 0 {
		t.Fatalf("set after forged rows: ignored %d, alice %+v, seq %d", s.Ignored, s.Approvers["alice"], s.Seq)
	}
	r.mustSign(r.withdrawal("d1", addrUser, 100, 0, "alice"))
	// The forged rows do not take a sequence number from a real change.
	if err := r.apply(r.guard, r.change(ActionDisable, "dave", nil, 1, r.clock(), "op1", "op2")); err == nil {
		// dave is already disabled: refused for that, which also proves the apply path read the log
		t.Fatal("disable of a disabled approver applied")
	}
	if err := r.apply(r.guard, r.change(ActionDisable, "auto", nil, 1, r.clock(), "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	// Append-only.
	if _, err := r.guardDB.Exec(ctx, `UPDATE approver_changes SET name = 'x'`); err == nil {
		t.Fatal("update of the log")
	}
	if _, err := r.guardDB.Exec(ctx, `DELETE FROM approver_changes`); err == nil {
		t.Fatal("delete from the log")
	}
	if _, err := r.guardDB.Exec(ctx, `TRUNCATE approver_changes`); err == nil {
		t.Fatal("truncate of the log")
	}
}

func TestApproverRegistryRevokeStopsQueuedJobsAtOnce(t *testing.T) {
	r := newRegRig(t)
	now := r.clock()
	// A job queued (built and approved) before the revoke; a bootstrap approver is revoked without a restart.
	queued := r.withdrawal("q1", addrUser, 100, 0, "carol")
	if err := r.apply(r.guard, r.change(ActionRevoke, "carol", nil, 1, now, "op1", "op3")); err != nil {
		t.Fatal(err)
	}
	r.mustReject(queued, ReasonApprovals) // revoked: final, not a wait
	if !r.set(r.guard).Revoked["carol"] {
		t.Fatal("carol is not revoked")
	}
	// A revoked name and key never come back.
	if err := r.apply(r.guard, r.change(ActionEnable, "carol", nil, 2, now, "op1", "op2")); err == nil {
		t.Fatal("a revoked approver was enabled")
	}
	r.mustSign(r.withdrawal("q2", addrUser, 100, 0, "bob"))
}

func TestApproverRegistryDisableAndEnable(t *testing.T) {
	r := newRegRig(t)
	now := r.clock()
	if err := r.apply(r.guard, r.change(ActionDisable, "bob", nil, 1, now, "op2", "op3")); err != nil {
		t.Fatal(err)
	}
	j := r.withdrawal("x1", addrUser, 100, 0, "bob")
	if d := r.run(j); d.Outcome != OutcomeRetry { // disabled is not final: the other side may have it enabled
		t.Fatalf("disabled approver: %s %q", d.Outcome, d.Reason)
	}
	if err := r.apply(r.guard, r.change(ActionEnable, "bob", nil, 2, now, "op2", "op3")); err != nil {
		t.Fatal(err)
	}
	r.mustSign(r.withdrawal("x2", addrUser, 100, 0, "bob"))
	// A dave (disabled in the config) can be enabled by operators.
	if err := r.apply(r.guard, r.change(ActionEnable, "dave", nil, 3, now, "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	r.mustSign(r.withdrawal("x3", addrUser, 100, 1, "dave"))
}

func TestApproverRegistryKeepsEnoughApprovers(t *testing.T) {
	r := newRegRig(t) // the highest tier needs 2 distinct approvers; alice, bob, carol and auto are enabled
	now := r.clock()
	for i, n := range []string{"alice", "bob"} {
		if err := r.apply(r.guard, r.change(ActionRevoke, n, nil, int64(i+1), now, "op1", "op2")); err != nil {
			t.Fatal(err)
		}
	}
	err := r.apply(r.guard, r.change(ActionRevoke, "carol", nil, 3, now, "op1", "op2")) // leaves auto only
	if err == nil || !strings.Contains(err.Error(), "highest approval tier needs 2") {
		t.Fatalf("revoke below the tier: %v", err)
	}
	if err := r.apply(r.guard, r.change(ActionDisable, "auto", nil, 3, now, "op1", "op2")); err == nil {
		t.Fatal("disable below the tier applied")
	}
	if r.rows(r.guard) != 2 {
		t.Fatal("a refused change was written")
	}
	// Two keys of one person are one approver for this rule.
	ap := r.enrolEntry("carol2")
	ap.Identity = "carol"
	if err := r.apply(r.guard, r.change(ActionEnrol, "carol2", ap, 3, now, "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(r.guard, r.change(ActionRevoke, "auto", nil, 4, now, "op1", "op2")); err == nil {
		t.Fatal("revoke leaving one person applied")
	}
	// ... and they count once when approving.
	in := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w-two", Asset: "ETH", To: addrUser.Hex(), Amount: "2000"}
	r.mustReject(r.job("two", in, r.ethTx(addrUser, 2000, 0), "carol", "carol2"), ReasonTier)
}

func TestApproverRegistryRouteAndFeeCapsUseTheEffectiveSet(t *testing.T) {
	r := newRegRig(t)
	r.cfg.Route = &RouteConfig{MinApprovers: 1, MaxAge: 10 * time.Minute}
	now := r.clock()
	ap := r.enrolEntry("erin")
	if err := r.apply(r.guard, r.change(ActionEnrol, "erin", ap, 1, now, "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(r.guard, r.change(ActionRevoke, "alice", nil, 2, now, "op1", "op2")); err != nil {
		t.Fatal(err)
	}
	set := r.set(r.guard)
	rc := SignRoute(r.keys["erin"], "erin", "B+C", 1, now)
	if _, err := verifyRoute(r.cfg, set.Approvers, rc); err != nil {
		t.Fatalf("a route change by an enrolled approver: %v", err)
	}
	if err := r.guard.ApplyRoute(context.Background(), r.cfg, rc, now); err != nil {
		t.Fatal(err)
	}
	ra := SignRoute(r.keys["alice"], "alice", "A+C", 2, now)
	if err := r.guard.ApplyRoute(context.Background(), r.cfg, ra, now); err == nil {
		t.Fatal("a route change by a revoked approver applied")
	}
}

// The gateway and a cosigner keep their own logs. While one has a change the other has not, a job is delayed, never failed.
func TestApproverRegistrySequenceMismatchDelaysNeverFails(t *testing.T) {
	r := newRegRig(t)
	now := r.clock()
	cosGuard := mustGuard(t, r.harness)
	cos := NewDecider(r.cfg, r.gw.codecs, cosGuard, ModeCosigner, r.clock)
	pub := r.signer.PublicKey()

	ap := r.enrolEntry("erin")
	enrol := r.change(ActionEnrol, "erin", ap, 1, now, "op1", "op2")
	if err := r.apply(r.guard, enrol); err != nil { // the gateway has it, the cosigner has not
		t.Fatal(err)
	}
	j := r.withdrawal("m1", addrUser, 100, 0, "erin")
	_, err := cos.Decide(t.Context(), j, pub)
	if _, refused := IsRejection(err); refused || !errors.Is(err, ErrApproverLag) {
		t.Fatalf("cosigner behind: err %v, want a retry (ErrApproverLag), not a refusal", err)
	}
	// Nothing was reserved or refused on the cosigner side; the job is judged again once the change arrives.
	if err := cosGuard.ApplyApproverChange(t.Context(), r.cfg, enrol, now, "cosigner"); err != nil {
		t.Fatal(err)
	}
	if _, err := cos.Decide(t.Context(), j, pub); err != nil {
		t.Fatalf("cosigner after the change: %v", err)
	}
	// An approval by somebody nobody knows is a wait only until the job expires; then it is the usual refusal.
	mallory := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w-mal", Asset: "ETH", To: addrUser.Hex(), Amount: "100", NotAfter: r.clock().Add(time.Hour).Unix()}
	r.keys["mallory"] = ed25519.PrivateKey(append([]byte(nil), r.keys["bob"]...))
	mj := r.job("mal", mallory, r.ethTx(addrUser, 100, 1), "mallory")
	if _, err := cos.Decide(t.Context(), mj, pub); !errors.Is(err, ErrApproverLag) {
		t.Fatalf("unknown approver before expiry: %v", err)
	}
	r.advance(2 * time.Hour)
	_, err = cos.Decide(t.Context(), mj, pub)
	if why, ok := IsRejection(err); !ok || !strings.HasPrefix(why, ReasonApprovals+":") {
		t.Fatalf("unknown approver after expiry: %v", err)
	}
}

func TestApproverRegistryConfigValidation(t *testing.T) {
	pub := func() string { p, _, _ := ed25519.GenerateKey(rand.Reader); return hex.EncodeToString(p) }
	ok := func(f OperatorsFile) error { _, err := f.build(map[string]string{}); return err }
	one := map[string]OperatorFile{"a": {pub()}}
	two := map[string]OperatorFile{"a": {pub()}, "b": {pub()}}
	if err := ok(OperatorsFile{Keys: one}); err != nil {
		t.Fatal(err)
	}
	if err := ok(OperatorsFile{Keys: two}); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]OperatorsFile{
		"none":                     {},
		"min 1 with two operators": {Keys: two, MinOperators: 1},
		"min above the keys":       {Keys: two, MinOperators: 3},
		"bad key":                  {Keys: map[string]OperatorFile{"a": {"zz"}}},
		"bad age":                  {Keys: two, MaxChangeAge: "soon"},
	} {
		if ok(f) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	k := pub()
	if _, err := (&OperatorsFile{Keys: map[string]OperatorFile{"a": {k}}}).build(map[string]string{}); err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(k)
	if _, err := (&OperatorsFile{Keys: map[string]OperatorFile{"a": {k}}}).build(map[string]string{string(raw): "alice"}); err == nil {
		t.Fatal("an operator with an approver's key was accepted")
	}
}

// A fee-cap change signed by an approver enrolled after start-up is accepted by the zone's running verifier (its bound view takes the effective
// approvers at every decision), and a revoked approver's signature stops counting without a restart.
func TestApproverRegistryFeeCapsViewFollowsTheEffectiveSet(t *testing.T) {
	b := feeCapsHarness(t)
	ctx, now := context.Background(), time.Now()
	oc := &OperatorConfig{Keys: map[string]ed25519.PublicKey{}, Min: 2, MaxAge: 10 * time.Minute}
	ops := map[string]ed25519.PrivateKey{}
	for _, n := range []string{"op1", "op2"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		ops[n], oc.Keys[n] = priv, pub
	}
	b.cfg.Operators = oc
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b.keys["erin"] = priv
	enrol := ApproverChange{Action: ActionEnrol, Name: "erin", Approver: &ApproverFile{PublicKey: hex.EncodeToString(pub), Enabled: true}, Seq: 1, SignedAt: now.Unix()}
	merged, _ := MergeApproverChanges(SignApproverChange(ops["op1"], "op1", enrol), SignApproverChange(ops["op2"], "op2", enrol))
	if err := b.guard.ApplyApproverChange(ctx, b.cfg, merged, now, "gateway"); err != nil {
		t.Fatal(err)
	}
	raised := btc.FeeCaps{MaxTxFeeSats: 100_000, MaxFeeRate: 300}
	if err := b.guard.ApplyFeeCaps(ctx, b.cfg, b.feeChange(raised, 1, now, "alice", "erin"), now, "gateway"); err != nil {
		t.Fatal(err)
	}
	// The running view reads the change: built under change 1, the dear payload signs.
	b.mustSignAll(b.jobs("w1", wdIntent("wi1", b.other, 100_000), b.dearPayload(1), "auto"))
	// Revoke erin: a later change signed by her and bob is refused, and the view stops counting her rows.
	rev := ApproverChange{Action: ActionRevoke, Name: "erin", Seq: 2, SignedAt: now.Unix()}
	mr, _ := MergeApproverChanges(SignApproverChange(ops["op1"], "op1", rev), SignApproverChange(ops["op2"], "op2", rev))
	if err := b.guard.ApplyApproverChange(ctx, b.cfg, mr, now, "gateway"); err != nil {
		t.Fatal(err)
	}
	lower := btc.FeeCaps{MaxTxFeeSats: 90_000, MaxFeeRate: 280}
	if err := b.guard.ApplyFeeCaps(ctx, b.cfg, b.feeChange(lower, 2, now, "bob", "erin"), now, "gateway"); err == nil {
		t.Fatal("a fee-cap change signed by a revoked approver applied")
	}
}
