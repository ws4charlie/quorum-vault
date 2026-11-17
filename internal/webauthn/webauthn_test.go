package webauthn_test

import (
	"crypto/sha256"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/webauthn"
	"github.com/ws4charlie/quorum-vault/internal/webauthn/webauthntest"
)

// SIMULATED: every assertion here comes from a software authenticator (webauthntest), not hardware.
const (
	rp     = "approve.example.com"
	origin = "https://approve.example.com"
)

func keyOf(t *testing.T, a *webauthntest.Authenticator) *webauthn.Key {
	t.Helper()
	k := &webauthn.Key{Alg: a.Alg, CredentialID: a.CredentialID, RPID: rp, Origins: []string{origin}}
	switch a.Alg {
	case webauthn.ES256:
		k.ES256 = webauthntest.ES256Key(a)
	default:
		k.Ed25519 = webauthntest.Ed25519Key(a)
	}
	return k
}

func TestVerify(t *testing.T) {
	chal := sha256.Sum256([]byte("intent A"))
	other := sha256.Sum256([]byte("intent B"))
	for _, alg := range []string{webauthn.ES256, webauthn.EdDSA} {
		t.Run(alg, func(t *testing.T) {
			a := webauthntest.New(t, alg, rp, origin)
			k := keyOf(t, a)
			wrongKey := keyOf(t, webauthntest.New(t, alg, rp, origin))
			wrongKey.CredentialID = a.CredentialID // the same credential id under another key: only the signature is wrong
			cases := []struct {
				name string
				k    *webauthn.Key
				c    []byte
				o    webauthntest.Options
				ok   bool
			}{
				{"good", k, chal[:], webauthntest.Options{}, true},
				{"wrong challenge", k, other[:], webauthntest.Options{}, false},
				{"wrong origin", k, chal[:], webauthntest.Options{Origin: "https://evil.example.com"}, false},
				{"wrong rp id", k, chal[:], webauthntest.Options{RPID: "evil.example.com"}, false},
				{"user verification missing", k, chal[:], webauthntest.Options{NoUV: true}, false},
				{"user presence missing", k, chal[:], webauthntest.Options{NoUP: true}, false},
				{"wrong type", k, chal[:], webauthntest.Options{Type: "webauthn.create"}, false},
				{"cross-origin", k, chal[:], webauthntest.Options{CrossOrigin: true}, false},
				{"wrong key", wrongKey, chal[:], webauthntest.Options{}, false},
			}
			for _, c := range cases {
				err := webauthn.Verify(c.k, c.c, (*webauthn.Assertion)(a.Assert(chal[:], c.o)))
				if (err == nil) != c.ok {
					t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
				}
			}
			// The assertion was made for intent A: it does not verify for intent B (the replay case).
			if err := webauthn.Verify(k, other[:], (*webauthn.Assertion)(a.Assert(chal[:], webauthntest.Options{}))); err == nil {
				t.Error("an assertion over intent A verified for intent B")
			}
			// Another credential id is refused even with a valid signature.
			as := a.Assert(chal[:], webauthntest.Options{})
			as.CredentialID = []byte("another")
			if err := webauthn.Verify(k, chal[:], (*webauthn.Assertion)(as)); err == nil {
				t.Error("an unenrolled credential id verified")
			}
			// A flipped bit anywhere in the signed bytes breaks it.
			as = a.Assert(chal[:], webauthntest.Options{})
			as.AuthenticatorData[34] ^= 1 // the sign counter is signed
			if err := webauthn.Verify(k, chal[:], (*webauthn.Assertion)(as)); err == nil {
				t.Error("changed authenticator data verified")
			}
		})
	}
}

func TestSignCount(t *testing.T) {
	a := webauthntest.New(t, webauthn.EdDSA, rp, origin)
	a.SignCount = 6
	as := a.Assert(make([]byte, 32), webauthntest.Options{})
	if got := webauthn.SignCount(as.AuthenticatorData); got != 7 {
		t.Errorf("sign count %d", got)
	}
	if webauthn.SignCount(nil) != 0 {
		t.Error("short data")
	}
}
