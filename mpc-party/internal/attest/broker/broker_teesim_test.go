//go:build teesim

package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

func TestReleaseWorksAndOnlyTheEvidenceKeyOpensIt(t *testing.T) {
	r := newRig(t, rigOpts{})
	a := r.enclave("A")
	c := ctxOf("A", "ks1", attest.PurposeCreate, 1, 2)
	blobs, keys := a.newKeys(c)
	if len(blobs) != 2 || len(keys) != 2 || len(keys[0]) != 32 || bytes.Equal(keys[0], keys[1]) {
		t.Fatalf("newkey gave %d blobs, %d keys", len(blobs), len(keys))
	}
	rc := ctxOf("A", "ks1", attest.PurposeUnseal, 1, 2)
	req := a.prepare(rc, blobs, nil)
	resp, err := a.cl.Release(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_, got := a.open(req, resp, nil)
	if !bytes.Equal(got[0], keys[0]) || !bytes.Equal(got[1], keys[1]) {
		t.Fatal("released keys differ from the created ones")
	}
	for _, k := range resp.Keys { // nothing in the clear
		for _, key := range keys {
			if bytes.Contains(k.Sealed, key) {
				t.Fatal("a released key is in the clear")
			}
		}
	}
	// a release response replayed to another key (another enclave's private key) does not open
	other := r.enclave("A")
	ud := rc.UserData(req.Blobs, a.id.pin)
	if _, err := attest.OpenFrom(other.priv, attest.ResponseAAD(ud, req.Nonce, resp.Keys[0].Generation), resp.Keys[0].Sealed); err == nil {
		t.Fatal("a response opened under another enclave key")
	}
	// ... nor under the right key in another request's context (another nonce)
	if _, err := attest.OpenFrom(a.priv, attest.ResponseAAD(ud, []byte("another nonce"), resp.Keys[0].Generation), resp.Keys[0].Sealed); err == nil {
		t.Fatal("a response opened under another request's context")
	}
	if rec := r.lastRecord(); rec.Outcome != "released" || rec.Event != "release" || rec.Party != "A" || rec.Keyset != "ks1" ||
		rec.Measurement != hex.EncodeToString(r.meas["A"]) || rec.Nonce != hex.EncodeToString(req.Nonce) || len(rec.Generations) != 2 {
		t.Fatalf("audit record: %+v", rec)
	}
	// a blob does not open for another generation or keyset of the same party
	for _, bad := range []attest.RequestContext{ctxOf("A", "ks1", attest.PurposeUnseal, 3, 4), ctxOf("A", "ks2", attest.PurposeUnseal, 1, 2)} {
		_, err := a.cl.Release(context.Background(), a.prepare(bad, blobs, nil))
		wantRefusal(t, err, "hsm_failed")
	}
}

func TestEveryRefusalHasItsTestAndItsAuditRecord(t *testing.T) {
	r := newRig(t, rigOpts{})
	a, b := r.enclave("A"), r.enclave("B")
	bBlobs, _ := b.newKeys(ctxOf("B", "ks1", attest.PurposeCreate, 1))
	aBlobs, _ := a.newKeys(ctxOf("A", "ks1", attest.PurposeCreate, 1))
	cA := ctxOf("A", "ks1", attest.PurposeUnseal, 1)
	cB := ctxOf("B", "ks1", attest.PurposeUnseal, 1)

	type tc struct {
		name string
		rule string
		run  func() error
	}
	do := func(e *enclave, req attest.ReleaseRequest) error {
		_, err := e.cl.Release(context.Background(), req)
		return err
	}
	cases := []tc{
		{"wrong measurement", "allowlist:measurement_not_allowed", func() error {
			a.at.Fault = attest.FaultWrongPCR
			defer func() { a.at.Fault = attest.FaultNone }()
			return do(a, a.prepare(cA, aBlobs, nil))
		}},
		{"debug evidence", "verify:debug", func() error {
			a.at.Debug = true
			defer func() { a.at.Debug = false }()
			return do(a, a.prepare(cA, aBlobs, nil))
		}},
		{"bad signature", "verify:signature", func() error {
			a.at.Fault = attest.FaultBadSignature
			defer func() { a.at.Fault = attest.FaultNone }()
			return do(a, a.prepare(cA, aBlobs, nil))
		}},
		{"nonce inside the evidence is not the challenge", "verify:nonce", func() error {
			a.at.Fault = attest.FaultWrongNonce
			defer func() { a.at.Fault = attest.FaultNone }()
			return do(a, a.prepare(cA, aBlobs, nil))
		}},
		{"user_data mismatch", "verify:user_data", func() error {
			a.at.Fault = attest.FaultUserDataMismatch
			defer func() { a.at.Fault = attest.FaultNone }()
			return do(a, a.prepare(cA, aBlobs, nil))
		}},
		{"context changed after the evidence was made", "verify:user_data", func() error {
			req := a.prepare(cA, aBlobs, nil)
			req.Context.Keyset = "ks-other"
			return do(a, req)
		}},
		{"blob swapped after the evidence was made", "verify:user_data", func() error {
			req := a.prepare(cA, aBlobs, nil)
			req.Blobs = bBlobs
			return do(a, req)
		}},
		{"evidence of another TLS connection (other caller pin)", "verify:user_data", func() error {
			req := a.prepare(cA, aBlobs, nil)
			ev, err := a.at.Attest(req.Nonce, a.pub, cA.UserData(aBlobs, b.id.pin)) // bound to B's key, sent on A's connection
			if err != nil {
				t.Fatal(err)
			}
			req.Evidence = ev
			return do(a, req)
		}},
		{"nonce reused", "nonce:reused", func() error {
			req := a.prepare(cA, aBlobs, nil)
			if err := do(a, req); err != nil {
				t.Fatalf("first use: %v", err)
			}
			return do(a, req)
		}},
		{"nonce expired", "nonce:expired", func() error {
			req := a.prepare(cA, aBlobs, nil)
			r.clk.Advance(2 * time.Minute)
			return do(a, req)
		}},
		{"nonce never issued", "nonce:unknown", func() error {
			return do(a, a.prepare(cA, aBlobs, []byte("0123456789abcdef0123456789abcdef")))
		}},
		{"nonce issued to another caller", "nonce:wrong_caller", func() error {
			ch, err := b.cl.Challenge(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			return do(a, a.prepare(cA, aBlobs, ch.Nonce))
		}},
		{"evidence of A used for a request in B's name (A's connection)", "caller_not_party", func() error {
			return do(a, a.prepare(cB, bBlobs, nil))
		}},
		{"A's allowlisted evidence on B's connection for B's key", "allowlist:measurement_not_allowed", func() error {
			imp := r.enclave("B")
			imp.at.PCR0 = r.meas["A"] // an image that is allowed for A only
			return do(imp, imp.prepare(cB, bBlobs, nil))
		}},
		{"B's data key presented as A's", "hsm_failed", func() error {
			return do(a, a.prepare(cA, bBlobs, nil))
		}},
		{"purpose does not match the call", "bad_request", func() error {
			return do(a, a.prepare(ctxOf("A", "ks1", attest.PurposeCreate, 1), aBlobs, nil))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			wantRefusal(t, err, c.rule)
			rec := r.lastRecord()
			if rec.Outcome != "refused" || rec.Rule != c.rule || rec.Event != "release" || rec.Party == "" {
				t.Fatalf("audit record: %+v", rec)
			}
		})
	}
	if n, err := VerifyAudit(r.cfg.AuditLog); err != nil || n < len(cases) {
		t.Fatalf("audit chain: %d records, %v", n, err)
	}
}

func TestDebugEvidenceThroughAVerifierThatAllowsItIsStillRefusedByTheAllowlist(t *testing.T) {
	r := newRig(t, rigOpts{allowDebug: true})
	a := r.enclave("A")
	blobs, _ := a.newKeys(ctxOf("A", "ks1", attest.PurposeCreate, 1))
	a.at.Debug = true // all-zero measurements: the verifier lets it pass in this config, the allowlist rule must not
	_, err := a.cl.Release(context.Background(), a.prepare(ctxOf("A", "ks1", attest.PurposeUnseal, 1), blobs, nil))
	wantRefusal(t, err, "allowlist:debug")
}

func TestAllowlistWindowsAreEnforced(t *testing.T) {
	for _, tc := range []struct {
		name string
		from time.Duration
		to   time.Duration
		rule string
	}{
		{"entry expired", -48 * time.Hour, -time.Hour, "allowlist:expired"},
		{"entry not valid yet", time.Hour, 48 * time.Hour, "allowlist:not_yet_valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, rigOpts{entries: func(now time.Time, m map[string][]byte) []attest.AllowEntry {
				return []attest.AllowEntry{
					{Party: "A", Measurement: hex.EncodeToString(m["A"]), NotBefore: now.Add(tc.from), NotAfter: now.Add(tc.to)},
					{Party: "B", Measurement: hex.EncodeToString(m["B"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
				}
			}})
			a := r.enclave("A")
			// B is fine, so the key can be made; the refusal is A's window
			b := r.enclave("B")
			_, _ = b.newKeys(ctxOf("B", "k", attest.PurposeCreate, 1))
			_, err := a.cl.NewKey(context.Background(), a.prepare(ctxOf("A", "k", attest.PurposeCreate, 1), nil, nil))
			wantRefusal(t, err, tc.rule)
			if rec := r.lastRecord(); rec.Rule != tc.rule || rec.Event != "newkey" {
				t.Fatalf("audit: %+v", rec)
			}
		})
	}
}

func TestAllowlistTimeMovesWithTheClock(t *testing.T) {
	r := newRig(t, rigOpts{})
	a := r.enclave("A")
	blobs, _ := a.newKeys(ctxOf("A", "k", attest.PurposeCreate, 1))
	r.clk.Advance(30 * time.Hour) // entries end after 24h; the mock CA lasts 24h too, so the chain is the first to give out
	_, err := a.cl.Release(context.Background(), a.prepare(ctxOf("A", "k", attest.PurposeUnseal, 1), blobs, nil))
	if err == nil {
		t.Fatal("released after every window ended")
	}
}

func TestAllowlistReloadOverlapThenRevoke(t *testing.T) {
	r := newRig(t, rigOpts{})
	now := r.clk.Now()
	mA2 := attest.MeasureImage([]byte("party A binary v2"), []byte("cfg"))
	win := func(party string, m []byte) attest.AllowEntry {
		return attest.AllowEntry{Party: party, Measurement: hex.EncodeToString(m), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * time.Hour)}
	}
	v1, v2 := r.enclave("A"), r.enclave("A")
	v2.at.PCR0 = mA2
	blobs, _ := v1.newKeys(ctxOf("A", "k", attest.PurposeCreate, 1))
	rel := func(e *enclave) error {
		_, err := e.cl.Release(context.Background(), e.prepare(ctxOf("A", "k", attest.PurposeUnseal, 1), blobs, nil))
		return err
	}
	if err := rel(v1); err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, rel(v2), "allowlist:measurement_not_allowed") // v2 is not listed yet

	// overlap: both allowed, no restart
	r.writeList([]attest.AllowEntry{win("A", r.meas["A"]), win("A", mA2), win("B", r.meas["B"])}, 2, 2)
	if err := r.srv.Reload(); err != nil || r.srv.Sequence() != 2 {
		t.Fatalf("reload: %v seq %d", err, r.srv.Sequence())
	}
	if err := rel(v1); err != nil {
		t.Fatalf("v1 during overlap: %v", err)
	}
	if err := rel(v2); err != nil {
		t.Fatalf("v2 during overlap: %v", err)
	}
	if rec := r.lastRecord(); rec.Measurement != hex.EncodeToString(mA2) {
		t.Fatalf("audit does not name the measurement: %+v", rec)
	}

	// an under-signed list is refused and the previous one stays
	r.writeList([]attest.AllowEntry{win("A", mA2), win("B", r.meas["B"])}, 1, 3)
	if err := r.srv.Reload(); err == nil || r.srv.Sequence() != 2 {
		t.Fatalf("under-signed list: err %v seq %d", err, r.srv.Sequence())
	}
	if rec := r.lastRecord(); rec.Event != "allowlist_load" || rec.Outcome != "refused" || rec.Seq != 2 {
		t.Fatalf("audit: %+v", rec)
	}
	if err := rel(v1); err != nil {
		t.Fatalf("v1 after a refused reload: %v", err)
	}
	// a list that is not newer is refused (rollback to an older signed list)
	r.writeList([]attest.AllowEntry{win("A", r.meas["A"]), win("B", r.meas["B"])}, 2, 2)
	if err := r.srv.Reload(); err == nil {
		t.Fatal("a list with the same sequence replaced the one in force")
	}
	// garbage is refused
	os.WriteFile(r.cfg.AllowlistFile, []byte("{not json"), 0o600)
	if err := r.srv.Reload(); err == nil || r.srv.Sequence() != 2 {
		t.Fatalf("garbage: %v", err)
	}

	// revoke v1: only v2 remains
	r.writeList([]attest.AllowEntry{win("A", mA2), win("B", r.meas["B"])}, 2, 4)
	if err := r.srv.Reload(); err != nil || r.srv.Sequence() != 4 {
		t.Fatalf("revoke: %v", err)
	}
	wantRefusal(t, rel(v1), "allowlist:measurement_not_allowed")
	if err := rel(v2); err != nil {
		t.Fatalf("v2 after revoking v1: %v", err)
	}
}

func TestAllowlistWatchReloadsWithoutRestart(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.srv.set.reload = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.srv.Watch(ctx)
	now := r.clk.Now()
	r.writeList([]attest.AllowEntry{{Party: "A", Measurement: hex.EncodeToString(r.meas["A"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
		{Party: "B", Measurement: hex.EncodeToString(r.meas["B"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}, 3, 9)
	deadline := time.Now().Add(5 * time.Second)
	for r.srv.Sequence() != 9 {
		if time.Now().After(deadline) {
			t.Fatal("the watcher did not reload the list")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(r *rig)
	}{
		{"no trust roots file", func(r *rig) { os.Remove(r.cfg.TrustRoots) }},
		{"trust roots file without a certificate", func(r *rig) { os.WriteFile(r.cfg.TrustRoots, []byte("nothing"), 0o600) }},
		{"no allowlist file", func(r *rig) { os.Remove(r.cfg.AllowlistFile) }},
		{"allowlist signed by too few operators", func(r *rig) {
			r.writeList([]attest.AllowEntry{{Party: "A", Measurement: "aa", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}, 1, 1)
		}},
		{"unsigned allowlist", func(r *rig) {
			r.writeList([]attest.AllowEntry{{Party: "A", Measurement: "aa", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}, 0, 1)
		}},
		{"allowlist with a malformed entry", func(r *rig) {
			r.writeList([]attest.AllowEntry{{Party: "A", Measurement: "zz", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}}, 2, 1)
		}},
		{"PIN file readable by others", func(r *rig) { os.Chmod(r.cfg.PKCS11.PinFile, 0o644) }},
		{"unknown token", func(r *rig) { r.cfg.PKCS11.Token = "no-such-token" }},
		{"no callers", func(r *rig) { r.cfg.Parties = nil }},
		{"one caller key for two parties", func(r *rig) { r.cfg.Parties["B"] = r.cfg.Parties["A"] }},
		{"audit log with a broken chain", func(r *rig) {
			os.WriteFile(r.cfg.AuditLog, []byte(`{"time":"2026-01-01T00:00:00Z","event":"release","outcome":"refused","prev":"bad"}`+"\n"), 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, rigOpts{noStart: true})
			tc.break_(r)
			if srv, err := Open(r.cfg, Options{Now: r.clk.Now}); err == nil {
				srv.Close()
				t.Fatal("the broker started")
			}
		})
	}
}

func TestUnpinnedCallerCannotConnect(t *testing.T) {
	r := newRig(t, rigOpts{})
	stranger := newTLSID(t, r.dir, "stranger")
	if _, err := r.client(stranger).Challenge(context.Background()); err == nil {
		t.Fatal("an unpinned caller got a challenge")
	}
}

func TestRateLimitPerParty(t *testing.T) {
	r := newRig(t, rigOpts{rate: 1, burst: 3})
	a, b := r.enclave("A"), r.enclave("B")
	for i := 0; i < 3; i++ {
		if _, err := a.cl.Challenge(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	_, err := a.cl.Challenge(context.Background())
	wantRefusal(t, err, "rate_limited")
	if rec := r.lastRecord(); rec.Rule != "rate_limited" || rec.Party != "A" || rec.Outcome != "refused" {
		t.Fatalf("audit: %+v", rec)
	}
	if _, err := b.cl.Challenge(context.Background()); err != nil { // B has its own bucket
		t.Fatalf("party B limited by A: %v", err)
	}
	r.clk.Advance(2 * time.Minute) // refill
	if _, err := a.cl.Challenge(context.Background()); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

func TestNoReleaseWithoutAuditRecord(t *testing.T) {
	r := newRig(t, rigOpts{})
	a := r.enclave("A")
	blobs, _ := a.newKeys(ctxOf("A", "k", attest.PurposeCreate, 1))
	req := a.prepare(ctxOf("A", "k", attest.PurposeUnseal, 1), blobs, nil)
	r.srv.audit.Close() // the log can no longer be written
	resp, err := a.cl.Release(context.Background(), req)
	wantRefusal(t, err, "audit_failed")
	if len(resp.Keys) != 0 {
		t.Fatal("keys were returned without an audit record")
	}
}

func TestAuditHoldsNoSecretAndDetectsTampering(t *testing.T) {
	r := newRig(t, rigOpts{})
	a := r.enclave("A")
	blobs, keys := a.newKeys(ctxOf("A", "k", attest.PurposeCreate, 1))
	req := a.prepare(ctxOf("A", "k", attest.PurposeUnseal, 1), blobs, nil)
	resp, err := a.cl.Release(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(r.cfg.AuditLog)
	pin, _ := os.ReadFile(r.cfg.PKCS11.PinFile)
	for name, secret := range map[string][]byte{"data key": keys[0], "wrapped blob": blobs[0], "sealed key": resp.Keys[0].Sealed, "evidence": req.Evidence, "token PIN": pin} {
		for _, form := range []string{string(secret), hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret)} {
			if strings.Contains(string(raw), form) {
				t.Fatalf("the audit log holds the %s", name)
			}
		}
	}
	if _, err := VerifyAudit(r.cfg.AuditLog); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	lines[1] = strings.Replace(lines[1], `"released"`, `"refused"`, 1)
	os.WriteFile(r.cfg.AuditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if _, err := VerifyAudit(r.cfg.AuditLog); err == nil {
		t.Fatal("an edited audit line was not detected")
	}
	lines = append(lines[:1], lines[2:]...)
	os.WriteFile(r.cfg.AuditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if _, err := VerifyAudit(r.cfg.AuditLog); err == nil {
		t.Fatal("a removed audit line was not detected")
	}
}

func TestWrappingKeyIsNotExtractable(t *testing.T) {
	r := newRig(t, rigOpts{})
	h := r.srv.keys.(*HSM)
	key, blob, err := h.NewDataKey("A", "k", 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, key) {
		t.Fatal("the blob holds the key in the clear")
	}
	if got, err := h.Unwrap("A", "k", 1, blob); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := h.Unwrap("B", "k", 1, blob); err == nil {
		t.Fatal("B's wrapping key opened A's blob")
	}
	// the attribute that makes it so
	if !h.wrapKeyIsNonExtractable(t, "A") {
		t.Fatal("the wrapping key is extractable or not sensitive")
	}
}

func TestMockRootIsMarkedTestOnly(t *testing.T) {
	r := newRig(t, rigOpts{})
	if !strings.Contains(r.ca.Root.Subject.String(), testRootMarker) {
		t.Fatalf("the mock root's subject %q lacks %q: the production build could not recognise it", r.ca.Root.Subject, testRootMarker)
	}
	if !Simulation {
		t.Fatal("Simulation is false in a teesim build")
	}
}
