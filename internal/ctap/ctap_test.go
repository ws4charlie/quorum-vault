package ctap_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/ctap"
	"github.com/ws4charlie/quorum-vault/internal/ctap/ctaptest"
)

// All of this is SIMULATED: a software key and a stand-in for the libfido2 tools. No hardware key has been tried.

func mk(rp string, algs ...ctap.Alg) ctap.MakeRequest {
	r := ctap.MakeRequest{RPID: rp, UserName: "bob", UserID: []byte("bob-id"), Algs: algs}
	r.ClientDataHash = sha256.Sum256([]byte("enrol"))
	return r
}

func TestParseAttestationBothAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		alg     ctap.Alg
		keyLen  int
		keyHead string
	}{{ctap.ES256, 130, "04"}, {ctap.EdDSA, 64, ""}} {
		s := ctaptest.New()
		r := mk("approve.example", tc.alg)
		res, err := s.MakeCredential(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ctap.ParseAttestation(r, res)
		if err != nil {
			t.Fatalf("%s: %v", tc.alg.Name(), err)
		}
		if c.Alg != tc.alg || len(c.PublicKeyHex) != tc.keyLen || !strings.HasPrefix(c.PublicKeyHex, tc.keyHead) {
			t.Fatalf("%s: %+v", tc.alg.Name(), c)
		}
		a := c.Attestation
		if a.Type != "basic" || !strings.HasPrefix(a.SignatureCheck, "valid") || a.CertAAGUID == "" {
			t.Fatalf("attestation: %+v", a)
		}
	}
}

func TestParseAttestationRefusals(t *testing.T) {
	ctx := context.Background()
	s := ctaptest.New()
	r := mk("approve.example", ctap.ES256)
	res, _ := s.MakeCredential(ctx, r)

	if _, err := ctap.ParseAttestation(mk("other.example", ctap.ES256), res); err == nil || !strings.Contains(err.Error(), "relying party") {
		t.Fatalf("another rp id: %v", err)
	}
	if _, err := ctap.ParseAttestation(mk("approve.example", ctap.EdDSA), res); err == nil || !strings.Contains(err.Error(), "not asked for") {
		t.Fatalf("an algorithm that was not asked for: %v", err)
	}
	noUV := ctaptest.New()
	noUV.NoUV = true
	res2, _ := noUV.MakeCredential(ctx, r)
	if _, err := ctap.ParseAttestation(r, res2); err == nil || !strings.Contains(err.Error(), "did not verify the user") {
		t.Fatalf("no user verification: %v", err)
	}
	res3 := *res
	res3.CredentialID = []byte("another")
	if _, err := ctap.ParseAttestation(r, &res3); err == nil {
		t.Fatal("a credential id that differs from the authenticator data was accepted")
	}
	// A flipped attestation signature is reported, not hidden.
	res4 := *res
	res4.Signature = append([]byte{}, res.Signature...)
	res4.Signature[len(res4.Signature)-1] ^= 1
	c, err := ctap.ParseAttestation(r, &res4)
	if err != nil || c.Attestation.SignatureCheck != "INVALID" {
		t.Fatalf("bad attestation signature: %v %+v", err, c)
	}
	// No attestation at all.
	none := ctaptest.New()
	none.None = true
	res5, _ := none.MakeCredential(ctx, r)
	if c, err := ctap.ParseAttestation(r, res5); err != nil || c.Attestation.Type != "none" {
		t.Fatalf("none: %v %+v", err, c)
	}
}

func TestToolsTransport(t *testing.T) {
	ctx := context.Background()
	s := ctaptest.New()
	var log [][]string
	tools := &ctap.Tools{Run: ctaptest.ToolRun(s, &log)}

	r := mk("approve.example", ctap.EdDSA, ctap.ES256)
	res, err := tools.MakeCredential(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ctap.ParseAttestation(r, res)
	if err != nil || c.Alg != ctap.EdDSA {
		t.Fatalf("%v %+v", err, c)
	}
	if got := strings.Join(log[len(log)-1], " "); !strings.HasPrefix(got, "fido2-cred -M -v ioreg://4295000001 eddsa") {
		t.Fatalf("the tool was run as %q", got)
	}

	// A key that offers only ES256 (older firmware): EdDSA is tried first, refused, and ES256 is used.
	old := ctaptest.New()
	old.Algs = []ctap.Alg{ctap.ES256}
	res, err = (&ctap.Tools{Run: ctaptest.ToolRun(old, nil)}).MakeCredential(ctx, r)
	if err != nil || res.Alg != ctap.ES256 {
		t.Fatalf("fallback: %v %+v", err, res)
	}
	// A key that offers neither.
	none := ctaptest.New()
	none.Algs = nil
	if _, err = (&ctap.Tools{Run: ctaptest.ToolRun(none, nil)}).MakeCredential(ctx, r); err != ctap.ErrUnsupportedAlg {
		t.Fatalf("no algorithm: %v", err)
	}

	ar := ctap.AssertRequest{RPID: "approve.example", CredentialID: c.CredentialID, ClientDataHash: sha256.Sum256([]byte("cd"))}
	as, err := tools.GetAssertion(ctx, ar)
	if err != nil {
		t.Fatal(err)
	}
	if flags, err := ctap.ParseAssertion(ar, as); err != nil || flags&ctap.FlagUV == 0 || flags&ctap.FlagUP == 0 {
		t.Fatalf("flags %x %v", flags, err)
	}
	if got := strings.Join(log[len(log)-1], " "); got != "fido2-assert -G -v ioreg://4295000001" {
		t.Fatalf("the tool was run as %q", got)
	}
	// Authenticator data that is not one CBOR byte string is refused.
	bad := &ctap.Tools{Run: func(ctx context.Context, name string, args []string, in []byte) ([]byte, []byte, error) {
		out, e, err := ctaptest.ToolRun(s, nil)(ctx, name, args, in)
		ls := strings.Split(strings.TrimSpace(string(out)), "\n")
		ls[2] = "AAAA" // not a CBOR byte string
		return []byte(strings.Join(ls, "\n") + "\n"), e, err
	}, Device: "x"}
	if _, err := bad.GetAssertion(ctx, ar); err == nil {
		t.Fatal("garbage authenticator data was accepted")
	}
	// Two keys: the tool refuses to guess.
	two := &ctap.Tools{Run: func(ctx context.Context, name string, args []string, in []byte) ([]byte, []byte, error) {
		return []byte("/dev/hidraw1: vendor=0x1050\n/dev/hidraw2: vendor=0x1050\n"), nil, nil
	}}
	if _, err := two.GetAssertion(ctx, ar); err == nil || !strings.Contains(err.Error(), "2 security keys") {
		t.Fatalf("two keys: %v", err)
	}
}
