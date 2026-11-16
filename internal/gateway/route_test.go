package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
)

// The operator-signed preferred pair (route.go): who may change it, what a change must carry, what the gateway does with rows it did not
// accept itself.

type routeRig struct {
	t     *testing.T
	g     *Guard
	cfg   *Config
	keys  map[string]ed25519.PrivateKey
	pool  interface{ Close() }
	exec  func(q string, a ...any) error
	audit func() []auditRow
}

func newRouteRig(t *testing.T, minApprovers int) *routeRig {
	t.Helper()
	pool := newGuardDB(t)
	g, err := OpenGuard(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Approvers: map[string]Approver{}, Route: &RouteConfig{MinApprovers: minApprovers, MaxAge: 10 * time.Minute}}
	keys := map[string]ed25519.PrivateKey{}
	for _, n := range []string{"alice", "bob", "carol", "dave"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[n] = priv
		cfg.Approvers[n] = Approver{Key: pub, Enabled: n != "dave"} // dave is disabled
	}
	h := &harness{t: t, guardDB: pool}
	return &routeRig{t: t, g: g, cfg: cfg, keys: keys, exec: func(q string, a ...any) error { _, err := pool.Exec(context.Background(), q, a...); return err },
		audit: h.auditRows}
}

func (r *routeRig) change(pair mpcsigner.Pair, seq int64, at time.Time, actors ...string) RouteChange {
	r.t.Helper()
	var parts []RouteChange
	for _, a := range actors {
		parts = append(parts, SignRoute(r.keys[a], a, pair, seq, at))
	}
	c, err := MergeRoute(parts...)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *routeRig) current() RouteSetting {
	r.t.Helper()
	c, _, err := r.g.CurrentRoute(context.Background(), r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func TestRouteDefaultIsAB(t *testing.T) {
	r := newRouteRig(t, 1)
	if c := r.current(); c.Pair != mpcsigner.PairAB || c.Seq != 0 {
		t.Fatalf("nothing set: %+v", c)
	}
}

func TestRouteSignedChangeAppliesAndIsAudited(t *testing.T) {
	r := newRouteRig(t, 2)
	ctx, now := context.Background(), time.Now()
	if err := r.g.ApplyRoute(ctx, r.cfg, r.change(mpcsigner.PairAC, 1, now, "alice", "bob"), now); err != nil {
		t.Fatal(err)
	}
	if c := r.current(); c.Pair != mpcsigner.PairAC || c.Seq != 1 {
		t.Fatalf("after the change: %+v", c)
	}
	var ev *auditRow
	for _, row := range r.audit() {
		if row.Type == EventRouteChanged {
			row := row
			ev = &row
		}
	}
	if ev == nil {
		t.Fatal("no audit event for the change")
	}
	if ev.Payload["from"] != "A+B" || ev.Payload["to"] != "A+C" || ev.Payload["seq"] != float64(1) {
		t.Fatalf("audit payload: %v", ev.Payload)
	}
	if a, _ := json.Marshal(ev.Payload["approvers"]); string(a) != `["alice","bob"]` {
		t.Fatalf("the audit event must name the approvers: %s", a)
	}
	if strings.Contains(string(routeJSON(ev.Payload)), "signature") {
		t.Fatal("the audit event holds signatures")
	}
	// the next change is audited too and records where it came from
	if err := r.g.ApplyRoute(ctx, r.cfg, r.change(mpcsigner.PairBC, 2, now, "bob", "carol"), now); err != nil {
		t.Fatal(err)
	}
	if c := r.current(); c.Pair != mpcsigner.PairBC || c.Seq != 2 {
		t.Fatalf("second change: %+v", c)
	}
}

func TestRouteRefusedChangesLeaveTheRouteAsItWas(t *testing.T) {
	r := newRouteRig(t, 2)
	ctx, now := context.Background(), time.Now()
	if err := r.g.ApplyRoute(ctx, r.cfg, r.change(mpcsigner.PairAC, 1, now, "alice", "bob"), now); err != nil {
		t.Fatal(err)
	}
	outsider := ed25519.NewKeyFromSeed(make([]byte, 32))
	forged := r.change(mpcsigner.PairBC, 2, now, "alice", "bob")
	forged.Signatures[1].Actor = "carol" // bob's signature under carol's name
	wrongPair := r.change(mpcsigner.PairBC, 2, now, "alice", "bob")
	wrongPair.Pair = "B+C"
	otherPair := r.change(mpcsigner.PairAB, 2, now, "alice", "bob")
	otherPair.Pair = "A+C" // signed for A+B, presented as A+C
	cases := map[string]RouteChange{
		"unsigned":                {Pair: "B+C", Seq: 2, SignedAt: now.Unix()},
		"one signature of two":    r.change(mpcsigner.PairBC, 2, now, "alice"),
		"the same approver twice": {Pair: "B+C", Seq: 2, SignedAt: now.Unix(), Signatures: append(r.change(mpcsigner.PairBC, 2, now, "alice").Signatures, r.change(mpcsigner.PairBC, 2, now, "alice").Signatures...)},
		"a disabled approver":     r.change(mpcsigner.PairBC, 2, now, "alice", "dave"),
		"signature under a name":  forged,
		"an unknown approver": func() RouteChange {
			c := r.change(mpcsigner.PairBC, 2, now, "alice")
			c.Signatures = append(c.Signatures, SignRoute(outsider, "mallory", mpcsigner.PairBC, 2, now).Signatures...)
			return c
		}(),
		"signed for another pair":      otherPair,
		"signed for another seq":       func() RouteChange { c := r.change(mpcsigner.PairBC, 2, now, "alice", "bob"); c.Seq = 3; return c }(),
		"signed for another time":      func() RouteChange { c := r.change(mpcsigner.PairBC, 2, now, "alice", "bob"); c.SignedAt++; return c }(),
		"an old sequence number":       r.change(mpcsigner.PairBC, 1, now, "alice", "bob"),
		"a stale signing time":         r.change(mpcsigner.PairBC, 2, now.Add(-time.Hour), "alice", "bob"),
		"a signing time in the future": r.change(mpcsigner.PairBC, 2, now.Add(time.Hour), "alice", "bob"),
		"a pair that does not exist":   func() RouteChange { c := r.change(mpcsigner.PairBC, 2, now, "alice", "bob"); c.Pair = "C+A"; return c }(),
		"signatures that are not hex":  {Pair: "B+C", Seq: 2, SignedAt: now.Unix(), Signatures: []RouteSignature{{Actor: "alice", Signature: "zz"}, {Actor: "bob", Signature: "zz"}}},
		// an approval is a signature of an intent hash; the core can obtain those. It must never count as a route signature.
		"approvals of other things": func() RouteChange {
			h := sha256.Sum256(RouteMessage(mpcsigner.PairBC, 2, now.Unix()))
			var s []RouteSignature
			for _, a := range []string{"alice", "bob"} {
				s = append(s, RouteSignature{Actor: a, Signature: hex.EncodeToString(ed25519.Sign(r.keys[a], h[:]))})
			}
			return RouteChange{Pair: "B+C", Seq: 2, SignedAt: now.Unix(), Signatures: s}
		}(),
	}
	_ = wrongPair
	for name, c := range cases {
		if err := r.g.ApplyRoute(ctx, r.cfg, c, now); err == nil {
			t.Errorf("%s: applied", name)
		}
		if cur := r.current(); cur.Pair != mpcsigner.PairAC || cur.Seq != 1 {
			t.Fatalf("%s: the route changed to %+v", name, cur)
		}
	}
	var n int
	for _, row := range r.audit() {
		if row.Type == EventRouteChanged {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d route-change audit events, want only the one applied", n)
	}
}

// Whoever can write the guard database but holds no approver key cannot move the route: the gateway verifies the signatures every time it
// reads, and rows that do not verify are skipped (and counted, so the gateway can alert).
func TestRouteRowsWithoutValidSignaturesAreIgnored(t *testing.T) {
	r := newRouteRig(t, 1)
	ctx, now := context.Background(), time.Now()
	if err := r.g.ApplyRoute(ctx, r.cfg, r.change(mpcsigner.PairAC, 1, now, "alice"), now); err != nil {
		t.Fatal(err)
	}
	if err := r.exec(`INSERT INTO mpc_route_changes (seq, pair, signed_at, signatures) VALUES (2, 'B+C', $1, '[]')`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	// a real row whose pair was edited afterwards? updates are blocked by the append-only trigger
	if err := r.exec(`UPDATE mpc_route_changes SET pair = 'B+C' WHERE seq = 1`); err == nil {
		t.Fatal("the table accepted an UPDATE")
	}
	if err := r.exec(`DELETE FROM mpc_route_changes WHERE seq = 2`); err == nil {
		t.Fatal("the table accepted a DELETE")
	}
	bogus := r.change(mpcsigner.PairBC, 3, now, "alice")
	bogus.Signatures[0].Signature = strings.Repeat("00", 64)
	sigs, _ := json.Marshal(bogus.Signatures)
	if err := r.exec(`INSERT INTO mpc_route_changes (seq, pair, signed_at, signatures) VALUES (3, 'B+C', $1, $2)`, now.Unix(), sigs); err != nil {
		t.Fatal(err)
	}
	// a valid row copied to a higher sequence number: the signature covers the sequence number
	valid := r.change(mpcsigner.PairBC, 4, now, "alice")
	vs, _ := json.Marshal(valid.Signatures)
	if err := r.exec(`INSERT INTO mpc_route_changes (seq, pair, signed_at, signatures) VALUES (5, 'B+C', $1, $2)`, now.Unix(), vs); err != nil {
		t.Fatal(err)
	}
	cur, skipped, err := r.g.CurrentRoute(ctx, r.cfg)
	if err != nil || cur.Pair != mpcsigner.PairAC || cur.Seq != 1 || skipped != 3 {
		t.Fatalf("current %+v skipped %d err %v: want A+C at 1 with the three forged rows skipped", cur, skipped, err)
	}
	// the preferred-pair source the router reads says the same, and reports the skipped rows
	var reported int
	src := r.g.PreferredSource(r.cfg, func(n int) { reported = n })
	if p, err := src(ctx); err != nil || p != mpcsigner.PairAC || reported != 3 {
		t.Fatalf("source: %q %v reported %d", p, err, reported)
	}
	// the operators can still change it: their sequence number only has to be higher than every row
	if err := r.g.ApplyRoute(ctx, r.cfg, r.change(mpcsigner.PairBC, 6, now, "alice"), now); err != nil {
		t.Fatal(err)
	}
	if cur := r.current(); cur.Pair != mpcsigner.PairBC || cur.Seq != 6 {
		t.Fatalf("after a real change: %+v", cur)
	}
}

// An approver key that was removed from the config (or disabled) no longer counts for rows it signed earlier: the gateway checks against its
// current config.
func TestRouteRowOfARemovedApproverStopsCounting(t *testing.T) {
	r := newRouteRig(t, 1)
	ctx, now := context.Background(), time.Now()
	if err := r.g.ApplyRoute(ctx, r.cfg, r.change(mpcsigner.PairBC, 1, now, "carol"), now); err != nil {
		t.Fatal(err)
	}
	a := r.cfg.Approvers["carol"]
	a.Enabled = false
	r.cfg.Approvers["carol"] = a
	if c := r.current(); c.Pair != mpcsigner.PairAB {
		t.Fatalf("a disabled approver's old change still counts: %+v", c)
	}
}

func TestRouteConfig(t *testing.T) {
	base := func(route string) string {
		return `{"approvers":{"alice":{"public_key":"` + strings.Repeat("11", 32) + `","enabled":true},"bob":{"public_key":"` + strings.Repeat("22", 32) + `","enabled":true}},
		"chains":{"x":{"family":"evm","evm":{"chain_id":1,"factory":"0x0000000000000000000000000000000000000001","sweep_destination":"0x0000000000000000000000000000000000000002","hot_addresses":{"p":"0x0000000000000000000000000000000000000003"},"cold_addresses":{},"tokens":{},"native_asset":"ETH","max_tx_fee_wei":"1"},
		"assets":{"ETH":{"per_tx_cap":"10","daily_cap":"100","tiers":[{"min_amount":"0","approvals":1}],"any_destination":true}},"withdrawals_per_hour":1}},
		"mpc_route":` + route + `}`
	}
	party := func(n string) string {
		return `{"name":"` + n + `","address":"127.0.0.1:1","cert_file":"c","key_file":"k","server_pin":"` + strings.Repeat("ab", 32) + `"}`
	}
	good := `{"parties":[` + party("A") + `,` + party("B") + `,` + party("C") + `]}`
	cfg, err := ParseConfig([]byte(base(good)))
	if err != nil {
		t.Fatal(err)
	}
	d := mpcsigner.DefaultThresholds()
	if cfg.Route.MinApprovers != 1 || cfg.Route.Probe.Thresholds != d || cfg.Route.Probe.Interval != 5*time.Second {
		t.Fatalf("defaults: %+v", cfg.Route)
	}
	custom := `{"parties":[` + party("A") + `,` + party("B") + `,` + party("C") + `],"probe_interval":"2s","fail_count":4,"fail_window":"20s","recover_count":9,"min_approvers":2}`
	cfg, err = ParseConfig([]byte(base(custom)))
	if err != nil || cfg.Route.MinApprovers != 2 || cfg.Route.Probe.Thresholds.FailCount != 4 || cfg.Route.Probe.Thresholds.RecoverCount != 9 ||
		cfg.Route.Probe.Thresholds.Window != 20*time.Second || cfg.Route.Probe.Interval != 2*time.Second {
		t.Fatalf("custom: %+v %v", cfg, err)
	}
	for name, bad := range map[string]string{
		"missing party":      `{"parties":[` + party("A") + `,` + party("B") + `]}`,
		"duplicate party":    `{"parties":[` + party("A") + `,` + party("A") + `,` + party("C") + `]}`,
		"too many approvers": `{"parties":[` + party("A") + `,` + party("B") + `,` + party("C") + `],"min_approvers":3}`,
		"window too short":   `{"parties":[` + party("A") + `,` + party("B") + `,` + party("C") + `],"fail_count":10,"fail_window":"10s"}`,
		"unknown field":      `{"parties":[` + party("A") + `,` + party("B") + `,` + party("C") + `],"fail_cuont":3}`,
		"not a duration":     `{"parties":[` + party("A") + `,` + party("B") + `,` + party("C") + `],"probe_interval":"soon"}`,
	} {
		if _, err := ParseConfig([]byte(base(bad))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func routeJSON(v any) []byte { b, _ := json.Marshal(v); return b }
