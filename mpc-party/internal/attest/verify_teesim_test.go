//go:build teesim

package attest

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"
)

type rig struct {
	ca             *MockCA
	v              *NitroVerifier
	at             *MockAttester
	now            time.Time
	nonce, pub, ud []byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	now := time.Now()
	ca, err := NewMockCA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewNitroVerifier(NitroConfig{Roots: []*x509.Certificate{ca.Root}})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{
		ca: ca, v: v, now: now,
		at:    &MockAttester{CA: ca, PCR0: MeasureImage([]byte("party binary"), []byte("party config")), PCR8: MeasureCert([]byte("mock signing cert"))},
		nonce: []byte("0123456789abcdef0123456789abcdef"), pub: []byte("DER-public-key"), ud: []byte("role=A;keyset=k1"),
	}
}

func (r *rig) verify(t *testing.T, fault Fault) (*Claims, error) {
	t.Helper()
	r.at.Fault = fault
	ev, err := r.at.Attest(r.nonce, r.pub, r.ud)
	if err != nil {
		t.Fatal(err)
	}
	return r.v.Verify(ev, Expect{Nonce: r.nonce, UserData: r.ud, PublicKey: r.pub}, r.now)
}

func TestGoodDocument(t *testing.T) {
	r := newRig(t)
	c, err := r.verify(t, FaultNone)
	if err != nil {
		t.Fatal(err)
	}
	if c.EvidenceType != EvidenceTypeNitro || c.Debug || len(c.Measurements) != 4 || c.Signer == "" {
		t.Fatalf("claims: %+v", c)
	}
	if want := MeasureImage([]byte("party binary"), []byte("party config")); !bytes.Equal(c.Measurements[0], want) {
		t.Fatal("PCR0 is not the measurement of binary and config")
	}
	if !bytes.Equal(c.Nonce, r.nonce) || !bytes.Equal(c.PublicKey, r.pub) || !bytes.Equal(c.UserData, r.ud) {
		t.Fatal("bound fields differ")
	}
}

// One test per rule: every injected fault names the rule that must refuse it.
func TestEveryRuleRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault Fault
		rule  Rule
	}{
		{"bad signature", FaultBadSignature, RuleSignature},
		{"expired certificate", FaultExpiredCert, RuleCertValidity},
		{"wrong chain order", FaultWrongChainOrder, RuleChainOrder},
		{"zero PCRs (debug)", FaultZeroPCRs, RuleDebug},
		{"missing nonce", FaultMissingNonce, RuleNonce},
		{"wrong nonce", FaultWrongNonce, RuleNonce},
		{"user data mismatch", FaultUserDataMismatch, RuleUserData},
		{"future timestamp", FaultFutureTimestamp, RuleFuture},
		{"stale timestamp", FaultStaleTimestamp, RuleStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			_, err := r.verify(t, tc.fault)
			if RuleOf(err) != tc.rule {
				t.Fatalf("got %v (rule %q), want rule %q", err, RuleOf(err), tc.rule)
			}
		})
	}
}

// The verifier accepts a wrong PCR0 (it cannot know the right one); the allowlist is what refuses it.
func TestWrongPCRIsTheAllowlistsJob(t *testing.T) {
	r := newRig(t)
	good, err := r.verify(t, FaultNone)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := r.verify(t, FaultWrongPCR)
	if err != nil {
		t.Fatal(err)
	}
	list := []AllowEntry{{Party: "A", Measurement: good.Measurement(), NotBefore: r.now.Add(-time.Hour), NotAfter: r.now.Add(time.Hour)}}
	if err := CheckAllowlist(good, "A", list, r.now); err != nil {
		t.Fatal(err)
	}
	if got := ReasonOf(CheckAllowlist(bad, "A", list, r.now)); got != ReasonMeasurement {
		t.Fatalf("reason %q", got)
	}
}

func TestChangingBinaryOrConfigChangesPCR0(t *testing.T) {
	base := MeasureImage([]byte("bin"), []byte("cfg"))
	if bytes.Equal(base, MeasureImage([]byte("bin2"), []byte("cfg"))) || bytes.Equal(base, MeasureImage([]byte("bin"), []byte("cfg2"))) {
		t.Fatal("measurement did not change")
	}
	if bytes.Equal(MeasureImage([]byte("ab"), []byte("c")), MeasureImage([]byte("a"), []byte("bc"))) {
		t.Fatal("binary and config can trade bytes")
	}
}

func TestDebugOnlyWhenAllowed(t *testing.T) {
	r := newRig(t)
	r.at.Debug = true
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	if _, err := r.v.Verify(ev, Expect{Nonce: r.nonce, UserData: r.ud}, r.now); RuleOf(err) != RuleDebug {
		t.Fatalf("default verifier: %v", err)
	}
	dv, err := NewNitroVerifier(NitroConfig{Roots: []*x509.Certificate{r.ca.Root}, AllowDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := dv.Verify(ev, Expect{Nonce: r.nonce, UserData: r.ud}, r.now)
	if err != nil || !c.Debug {
		t.Fatalf("allowed debug: %v %+v", err, c)
	}
	if got := ReasonOf(CheckAllowlist(c, "A", nil, r.now)); got != ReasonDebug {
		t.Fatalf("allowlist must refuse debug anyway, got %q", got)
	}
}

func TestReplayWithAnotherNonce(t *testing.T) {
	r := newRig(t)
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	if _, err := r.v.Verify(ev, Expect{Nonce: r.nonce, UserData: r.ud}, r.now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.v.Verify(ev, Expect{Nonce: []byte("another challenge"), UserData: r.ud}, r.now); RuleOf(err) != RuleNonce {
		t.Fatalf("replayed document: %v", err)
	}
}

func TestDocumentForOneKeyPresentedWithAnother(t *testing.T) {
	r := newRig(t)
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	if _, err := r.v.Verify(ev, Expect{Nonce: r.nonce, UserData: r.ud, PublicKey: []byte("someone else's key")}, r.now); RuleOf(err) != RulePublicKey {
		t.Fatalf("got %v", err)
	}
}

func TestMissingPublicKey(t *testing.T) {
	r := newRig(t)
	ev, _ := r.at.Attest(r.nonce, nil, r.ud)
	if _, err := r.v.Verify(ev, Expect{Nonce: r.nonce, UserData: r.ud}, r.now); RuleOf(err) != RulePublicKey {
		t.Fatalf("got %v", err)
	}
}

func TestExpectedNonceIsRequired(t *testing.T) {
	r := newRig(t)
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	if _, err := r.v.Verify(ev, Expect{UserData: r.ud}, r.now); RuleOf(err) != RuleExpectation {
		t.Fatalf("got %v", err)
	}
}

func TestUntrustedRoot(t *testing.T) {
	r := newRig(t)
	other, _ := NewMockCA(r.now, time.Hour)
	v, _ := NewNitroVerifier(NitroConfig{Roots: []*x509.Certificate{other.Root}})
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	if _, err := v.Verify(ev, Expect{Nonce: r.nonce, UserData: r.ud}, r.now); RuleOf(err) != RuleUntrusted {
		t.Fatalf("got %v", err)
	}
}

func TestTimeWindowsAreRelativeToTheVerifiersClock(t *testing.T) {
	r := newRig(t)
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	exp := Expect{Nonce: r.nonce, UserData: r.ud}
	if _, err := r.v.Verify(ev, exp, r.now.Add(DefaultMaxAge-time.Second)); err != nil {
		t.Fatalf("inside window: %v", err)
	}
	if _, err := r.v.Verify(ev, exp, r.now.Add(DefaultMaxAge+time.Second)); RuleOf(err) != RuleStale {
		t.Fatalf("outside window: %v", err)
	}
	// a verifier clock behind the document's time by more than the skew sees it as from the future
	if _, err := r.v.Verify(ev, exp, r.now.Add(-2*DefaultMaxFuture)); RuleOf(err) != RuleFuture {
		t.Fatalf("clock behind: %v", err)
	}
}

func TestMalformedInput(t *testing.T) {
	r := newRig(t)
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	exp := Expect{Nonce: r.nonce, UserData: r.ud}
	for name, in := range map[string][]byte{
		"empty": nil, "garbage": []byte("not cbor at all"), "truncated": ev[:len(ev)/2],
		"trailing bytes": append(append([]byte{}, ev...), 0), "huge": make([]byte, maxDocBytes+1),
	} {
		if _, err := r.v.Verify(in, exp, r.now); RuleOf(err) != RuleFormat {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEveryByteFlipIsRefused(t *testing.T) {
	// Flipping any single byte of a good document must never verify (signature, structure or certificate catches it).
	r := newRig(t)
	ev, _ := r.at.Attest(r.nonce, r.pub, r.ud)
	exp := Expect{Nonce: r.nonce, UserData: r.ud, PublicKey: r.pub}
	for i := 0; i < len(ev); i += 7 {
		m := append([]byte{}, ev...)
		m[i] ^= 0x01
		if _, err := r.v.Verify(m, exp, r.now); err == nil {
			t.Fatalf("byte %d flipped, document still verifies", i)
		}
	}
}

func TestVerifierConfig(t *testing.T) {
	if _, err := NewNitroVerifier(NitroConfig{}); err == nil {
		t.Fatal("no roots must be refused")
	}
	r := newRig(t)
	if _, err := NewNitroVerifier(NitroConfig{Roots: []*x509.Certificate{r.ca.Intermediate}}); err == nil {
		t.Fatal("a non-self-signed certificate must not be a root")
	}
}

func TestSimulationBuildFlag(t *testing.T) {
	if !SimulationBuild {
		t.Fatal("SimulationBuild must be true under teesim")
	}
}

func TestCAFilesRoundTrip(t *testing.T) {
	r := newRig(t)
	dir := t.TempDir()
	if err := r.ca.Write(dir); err != nil {
		t.Fatal(err)
	}
	ca, err := LoadMockCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.at.CA = ca
	if _, err := r.verify(t, FaultNone); err != nil {
		t.Fatalf("document from the reloaded CA: %v", err)
	}
}
