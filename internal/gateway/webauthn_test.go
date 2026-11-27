package gateway

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	"github.com/ws4charlie/quorum-vault/internal/webauthn"
	"github.com/ws4charlie/quorum-vault/internal/webauthn/webauthntest"
)

// SIMULATED: the authenticators are software (webauthntest): no hardware, no attestation, user verification is a flag the test sets.
const (
	waRP     = "approve.example.com"
	waOrigin = "https://approve.example.com"
)

// addWebAuthn enrols a simulated credential in the zone's config as approver name, of person identity.
func addWebAuthn(t *testing.T, cfg *Config, name, identity, alg string) *webauthntest.Authenticator {
	t.Helper()
	a := webauthntest.New(t, alg, waRP, waOrigin)
	k := &webauthn.Key{Alg: alg, CredentialID: a.CredentialID, RPID: waRP, Origins: []string{waOrigin}}
	if alg == webauthn.ES256 {
		k.ES256 = webauthntest.ES256Key(a)
	} else {
		k.Ed25519 = webauthntest.Ed25519Key(a)
	}
	cfg.Approvers[name] = Approver{Enabled: true, Identity: identity, WebAuthn: k}
	return a
}

// waJob builds a job of the intent and gives it the approvals made by mk over the intent exactly as the job carries it (the harness fills in the
// chain, partition and not_after).
func (h *harness) waJob(id string, in signjob.Intent, to int64, nonce uint64, m mk) signjob.Job {
	j := h.job(id, in, h.ethTx(addrUser, to, nonce))
	if m != nil {
		j.Approvals = m(mustIntent(j.Intent))
	}
	return j
}

func waApproval(actor string, a *webauthntest.Authenticator, in signjob.Intent, o webauthntest.Options) signjob.Approval {
	hash := in.Hash()
	return signjob.Approval{Actor: actor, WebAuthn: a.Assert(hash[:], o)}
}

func wdIn(id, requester string, amount string) signjob.Intent {
	return signjob.Intent{Kind: "withdrawal", RequestedBy: requester, ID: "w-" + id, Asset: "ETH", To: addrUser.Hex(), Amount: amount}
}

// mk makes the approvals of a job over its intent.
type mk func(signjob.Intent) []signjob.Approval

func wa(actor string, a *webauthntest.Authenticator, o webauthntest.Options) mk {
	return func(in signjob.Intent) []signjob.Approval { return []signjob.Approval{waApproval(actor, a, in, o)} }
}

func edKeys(h *harness, actors ...string) mk {
	return func(in signjob.Intent) []signjob.Approval { return h.approvals(in, actors...) }
}

func all(ms ...mk) mk {
	return func(in signjob.Intent) []signjob.Approval {
		var out []signjob.Approval
		for _, m := range ms {
			out = append(out, m(in)...)
		}
		return out
	}
}

func TestWebAuthnApprovalCounts(t *testing.T) {
	h := newHarness(t)
	es := addWebAuthn(t, h.cfg, "wa-es", "wa-es", webauthn.ES256)
	ed := addWebAuthn(t, h.cfg, "wa-ed", "wa-ed", webauthn.EdDSA)
	h.mustSign(h.waJob("ok1", wdIn("ok1", "req", "100"), 100, 0, wa("wa-es", es, webauthntest.Options{})))
	h.mustSign(h.waJob("ok2", wdIn("ok2", "req", "100"), 100, 1, wa("wa-ed", ed, webauthntest.Options{})))
	// Two people, one by passkey and one by Ed25519 key, reach the 2-approval tier.
	h.mustSign(h.waJob("ok3", wdIn("ok3", "req", "2000"), 2000, 2, all(wa("wa-es", es, webauthntest.Options{}), edKeys(h, "bob"))))
}

func TestWebAuthnApprovalRefusals(t *testing.T) {
	h := newHarness(t)
	a := addWebAuthn(t, h.cfg, "wa", "wa", webauthn.ES256)
	n := uint64(0)
	try := func(name string, m mk) {
		t.Helper()
		n++
		t.Logf("case: %s", name)
		h.mustReject(h.waJob(name, wdIn(name, "req", "100"), 100, n, m), ReasonApprovals)
	}
	try("wrong-origin", wa("wa", a, webauthntest.Options{Origin: "https://evil.example.com"}))
	try("wrong-rp", wa("wa", a, webauthntest.Options{RPID: "evil.example.com"}))
	try("no-uv", wa("wa", a, webauthntest.Options{NoUV: true}))
	try("no-up", wa("wa", a, webauthntest.Options{NoUP: true}))
	other := webauthntest.New(t, webauthn.ES256, waRP, waOrigin)
	other.CredentialID = a.CredentialID // the enrolled credential id under another key: only the signature is wrong
	try("wrong-key", wa("wa", other, webauthntest.Options{}))
	try("wrong-challenge", func(signjob.Intent) []signjob.Approval { // an assertion over another intent
		return []signjob.Approval{waApproval("wa", a, wdIn("something-else", "req", "100"), webauthntest.Options{})}
	})
	try("signature-field-too", func(in signjob.Intent) []signjob.Approval {
		ap := waApproval("wa", a, in, webauthntest.Options{})
		ap.Signature = make([]byte, 64)
		return []signjob.Approval{ap}
	})
	try("assertion-under-an-ed25519-approver", func(in signjob.Intent) []signjob.Approval {
		ap := waApproval("wa", a, in, webauthntest.Options{})
		ap.Actor = "alice"
		return []signjob.Approval{ap}
	})
	try("no-assertion-under-a-webauthn-approver", func(in signjob.Intent) []signjob.Approval {
		ap := h.approvals(in, "alice")[0]
		ap.Actor = "wa"
		return []signjob.Approval{ap}
	})
}

// An assertion over intent A does not count for intent B; the same assertion twice counts once.
func TestWebAuthnReplay(t *testing.T) {
	h := newHarness(t)
	a := addWebAuthn(t, h.cfg, "wa", "wa", webauthn.EdDSA)
	jA := h.waJob("ra", wdIn("ra", "req", "100"), 100, 0, wa("wa", a, webauthntest.Options{}))
	h.mustSign(jA)
	// The captured assertion is attached to another intent (another amount and id): its challenge is intent A's hash.
	jB := h.waJob("rb", wdIn("rb", "req", "500"), 500, 1, nil)
	jB.Approvals = jA.Approvals
	h.mustReject(jB, ReasonApprovals)
	// The same assertion twice, and two assertions of one credential, are one approver: a 2-approval amount is not reached.
	big := wdIn("rc", "req", "2000")
	h.mustReject(h.waJob("rc", big, 2000, 2, func(in signjob.Intent) []signjob.Approval {
		ap := waApproval("wa", a, in, webauthntest.Options{})
		return []signjob.Approval{ap, ap}
	}), ReasonTier)
	h.mustReject(h.waJob("rc2", big, 2000, 2, all(wa("wa", a, webauthntest.Options{}), wa("wa", a, webauthntest.Options{}))), ReasonTier) // a fresh assertion: another sign counter
}

// One person with an Ed25519 key and a WebAuthn key is one approver; and neither key may approve their own request.
func TestWebAuthnOnePersonTwoSchemesCountsOnce(t *testing.T) {
	h := newHarness(t)
	a := addWebAuthn(t, h.cfg, "carol-passkey", "carol", webauthn.ES256) // carol's Ed25519 key is "carol"
	big := wdIn("pp", "req", "2000")
	h.mustReject(h.waJob("pp", big, 2000, 0, all(wa("carol-passkey", a, webauthntest.Options{}), edKeys(h, "carol"))), ReasonTier)
	// With another person it passes.
	h.mustSign(h.waJob("pp2", big, 2000, 0, all(wa("carol-passkey", a, webauthntest.Options{}), edKeys(h, "bob"))))
	// Carol requests: neither her passkey nor her Ed25519 key may approve.
	own := wdIn("own", "carol", "100")
	h.mustReject(h.waJob("own", own, 100, 1, wa("carol-passkey", a, webauthntest.Options{})), ReasonRequester)
	h.mustReject(h.waJob("own2", own, 100, 1, edKeys(h, "carol")), ReasonRequester)
}

func TestWebAuthnBatchMember(t *testing.T) {
	b := newBatchHarness(t, nil)
	a := addWebAuthn(t, b.cfg, "wa", "wa", webauthn.ES256)
	ms := []bm{{id: "wm1", to: b.other, amount: 100_000}, {id: "wm2", to: b.cold, amount: 120_000}}
	bt := b.batchOf("wb", ms...)
	for i := range bt.Members {
		h := bt.Members[i].Intent.Hash()
		bt.Members[i].Approvals = []signjob.Approval{{Actor: "wa", WebAuthn: a.Assert(h[:], webauthntest.Options{})}}
	}
	ins := []btc.PayloadInput{btcIn(150, 0, 600_000, 1, 0), btcIn(151, 0, 600_000, 1, 0)}
	b.mustSignAll(b.batchJobs("wb", bt, b.batchPayload(ins, ms, 2_000)))
	// A member whose assertion lacks user verification refuses the whole batch.
	bt2 := b.batchOf("wb2", ms...)
	for i := range bt2.Members {
		h := bt2.Members[i].Intent.Hash()
		bt2.Members[i].Approvals = []signjob.Approval{{Actor: "wa", WebAuthn: a.Assert(h[:], webauthntest.Options{NoUV: i == 1})}}
	}
	ins2 := []btc.PayloadInput{btcIn(152, 0, 600_000, 1, 0), btcIn(153, 0, 600_000, 1, 0)}
	b.mustRefuse(b.batchJobs("wb2", bt2, b.batchPayload(ins2, ms, 2_000))[0], ReasonApprovals)
}

// Route changes are signed with Ed25519 keys only: a webauthn approver is skipped and nothing panics.
func TestRouteChangeIgnoresWebAuthnApprovers(t *testing.T) {
	h := newHarness(t)
	addWebAuthn(t, h.cfg, "wa", "wa", webauthn.ES256)
	c := RouteChange{Pair: string(mpcsigner.PairAB), Seq: 1, SignedAt: 1, Signatures: []RouteSignature{{Actor: "wa", Signature: "00"}}}
	if got, _ := verifyRoute(h.cfg, h.cfg.Approvers, c); len(got) != 0 {
		t.Fatalf("counted %v", got)
	}
}

func TestConfigWebAuthnApprovers(t *testing.T) {
	raw, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	a := webauthntest.New(t, webauthn.ES256, waRP, waOrigin)
	e := webauthntest.New(t, webauthn.EdDSA, waRP, waOrigin)
	entry := func(a *webauthntest.Authenticator, edit func(m map[string]any)) map[string]any {
		m := map[string]any{"scheme": "webauthn", "alg": a.Alg, "public_key": a.PublicKeyHex(), "credential_id": a.CredentialIDString(),
			"rp_id": waRP, "origins": []string{waOrigin}, "enabled": true, "identity": "alice"}
		if edit != nil {
			edit(m)
		}
		return m
	}
	parse := func(extra map[string]any) error {
		var m map[string]any
		json.Unmarshal(raw, &m)
		for k, v := range extra {
			m["approvers"].(map[string]any)[k] = v
		}
		b, _ := json.Marshal(m)
		_, err := ParseConfig(b)
		return err
	}
	if err := parse(map[string]any{"alice-passkey": entry(a, nil), "alice-key": entry(e, nil)}); err != nil {
		t.Fatalf("good config: %v", err)
	}
	bad := map[string]map[string]any{
		"unknown scheme":   {"x": entry(a, func(m map[string]any) { m["scheme"] = "pgp" })},
		"unknown alg":      {"x": entry(a, func(m map[string]any) { m["alg"] = "RS256" })},
		"no rp id":         {"x": entry(a, func(m map[string]any) { delete(m, "rp_id") })},
		"no origins":       {"x": entry(a, func(m map[string]any) { delete(m, "origins") })},
		"plain http":       {"x": entry(a, func(m map[string]any) { m["origins"] = []string{"http://approve.example.com"} })},
		"bad point":        {"x": entry(a, func(m map[string]any) { m["public_key"] = "04" })},
		"no credential id": {"x": entry(a, func(m map[string]any) { delete(m, "credential_id") })},
		"same credential":  {"x": entry(a, nil), "y": entry(a, nil)},
	}
	for name, extra := range bad {
		if err := parse(extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestConfigWebAuthnOrigins: an origin is exactly scheme://host[:port]; http only on an exact loopback host and only when QV_ENV is
// dev or test. On 0b9b109 a prefix check let http://localhost.evil.example through and accepted http in production.
func TestConfigWebAuthnOrigins(t *testing.T) {
	raw, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	a := webauthntest.New(t, webauthn.ES256, waRP, waOrigin)
	parse := func(origin string) error {
		var m map[string]any
		json.Unmarshal(raw, &m)
		m["approvers"].(map[string]any)["x"] = map[string]any{"scheme": "webauthn", "alg": a.Alg, "public_key": a.PublicKeyHex(),
			"credential_id": a.CredentialIDString(), "rp_id": waRP, "origins": []string{origin}, "enabled": true, "identity": "alice"}
		b, _ := json.Marshal(m)
		_, err := ParseConfig(b)
		return err
	}
	cases := []struct {
		origin    string
		dev, prod bool // accepted with QV_ENV=dev / with QV_ENV unset (production)
	}{
		{"https://a.example", true, true},
		{"https://a.example:8443", true, true},
		{"http://localhost:8080", true, false},
		{"http://localhost", true, false},
		{"http://127.0.0.1:8080", true, false},
		{"http://[::1]:8080", true, false},
		{"http://localhost.evil.example", false, false},
		{"http://localhost.evil.example:8080", false, false},
		{"http://localhostevil.example", false, false},
		{"http://a.example", false, false},
		{"https://a.example/path", false, false},
		{"https://a.example/", false, false},
		{"https://a.example?x=1", false, false},
		{"https://a.example#f", false, false},
		{"https://user@a.example", false, false},
		{"http://localhost/", false, false},
		{"ftp://a.example", false, false},
		{"a.example", false, false},
		{"https://", false, false},
	}
	for _, env := range []string{"dev", "test", "", "production", "Dev-typo"} {
		t.Run("QV_ENV="+env, func(t *testing.T) {
			t.Setenv("QV_ENV", env)
			loose := env == "dev" || env == "test"
			for _, c := range cases {
				want := c.prod
				if loose {
					want = c.dev
				}
				err := parse(c.origin)
				if got := err == nil; got != want {
					t.Errorf("origin %q: accepted=%v, want %v (err %v)", c.origin, got, want, err)
				}
				if err != nil && !strings.Contains(err.Error(), "origin") {
					t.Errorf("origin %q: error does not name the origin rule: %v", c.origin, err)
				}
			}
		})
	}
}
