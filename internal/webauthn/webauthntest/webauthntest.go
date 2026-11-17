// Package webauthntest is a software WebAuthn authenticator for tests. SIMULATED: it is not hardware, has no attestation, and its user
// presence and user verification are flags the test sets, not something a person did. It makes assertions the way an authenticator does (a signature
// over authenticatorData || SHA-256(clientDataJSON)), so the zone's verifier is tested against the real byte layout, not against its own helpers.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
	"github.com/ws4charlie/quorum-vault/internal/webauthn"
)

// Authenticator is one simulated credential.
type Authenticator struct {
	Alg          string
	CredentialID []byte
	RPID         string
	Origin       string
	SignCount    uint32
	es           *ecdsa.PrivateKey
	ed           ed25519.PrivateKey
}

// New makes a credential of the algorithm (webauthn.ES256 or webauthn.EdDSA) for the RP ID and origin.
func New(t testing.TB, alg, rpID, origin string) *Authenticator {
	t.Helper()
	a := &Authenticator{Alg: alg, RPID: rpID, Origin: origin, CredentialID: make([]byte, 16)}
	rand.Read(a.CredentialID)
	switch alg {
	case webauthn.ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		a.es = k
	case webauthn.EdDSA:
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		a.ed = k
	default:
		t.Fatalf("webauthntest: alg %q", alg)
	}
	return a
}

// PublicKeyHex is the key as the zone's config spells it.
func (a *Authenticator) PublicKeyHex() string {
	if a.es != nil {
		return hex.EncodeToString(elliptic.Marshal(elliptic.P256(), a.es.X, a.es.Y))
	}
	return hex.EncodeToString(a.ed.Public().(ed25519.PublicKey))
}

// CredentialIDString is the credential id as the config spells it (base64url).
func (a *Authenticator) CredentialIDString() string {
	return base64.RawURLEncoding.EncodeToString(a.CredentialID)
}

// Options say what to break in an assertion.
type Options struct {
	Type        string // default "webauthn.get"
	Origin      string // default the authenticator's
	RPID        string // default the authenticator's (the RP ID hash is made from it)
	NoUP, NoUV  bool
	CrossOrigin bool
}

// Assert signs the challenge (an intent hash) the way navigator.credentials.get would.
func (a *Authenticator) Assert(challenge []byte, o Options) *signjob.WebAuthnAssertion {
	if o.Type == "" {
		o.Type = "webauthn.get"
	}
	if o.Origin == "" {
		o.Origin = a.Origin
	}
	if o.RPID == "" {
		o.RPID = a.RPID
	}
	rp := sha256.Sum256([]byte(o.RPID))
	flags := byte(0x01 | 0x04)
	if o.NoUP {
		flags &^= 0x01
	}
	if o.NoUV {
		flags &^= 0x04
	}
	a.SignCount++
	ad := append(rp[:len(rp):len(rp)], flags, byte(a.SignCount>>24), byte(a.SignCount>>16), byte(a.SignCount>>8), byte(a.SignCount))
	cd, _ := json.Marshal(map[string]any{"type": o.Type, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": o.Origin, "crossOrigin": o.CrossOrigin})
	h := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), h[:]...)
	var sig []byte
	if a.es != nil {
		d := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, a.es, d[:])
	} else {
		sig = ed25519.Sign(a.ed, msg)
	}
	return &signjob.WebAuthnAssertion{CredentialID: a.CredentialID, AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
}

// ES256Key and Ed25519Key return the credential's public key, for tests that build a webauthn.Key by hand.
func ES256Key(a *Authenticator) *ecdsa.PublicKey { return &a.es.PublicKey }

// Ed25519Key is the public key of an EdDSA credential.
func Ed25519Key(a *Authenticator) ed25519.PublicKey { return a.ed.Public().(ed25519.PublicKey) }
