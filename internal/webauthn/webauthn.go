// Package webauthn verifies a WebAuthn assertion as an approval of one intent hash, using only the standard library and no network.
//
// It is deliberately small: the signing zone holds the enrolled public keys, RP ID and allowed origins in its own config, so it needs no
// attestation, no credential storage and no library that parses registrations. A maintained library (go-webauthn) is built for a relying party
// that runs registration and login; here that would add a large dependency tree to the zone for the one step it needs. The checks below are the
// assertion verification steps of WebAuthn Level 2 section 7.2 that apply when the challenge is the intent hash and the key is already enrolled.
// Tests use a software authenticator (see package tests): they are simulated, with no attestation and no real user verification.
package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Algorithm names, as the config spells them (COSE -7 and -8).
const (
	ES256 = "ES256"
	EdDSA = "EdDSA"
)

// Authenticator data flags.
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
)

// Key is one enrolled credential: what the zone trusts.
type Key struct {
	Alg          string // ES256 or EdDSA
	ES256        *ecdsa.PublicKey
	Ed25519      ed25519.PublicKey
	CredentialID []byte
	RPID         string
	Origins      []string
}

// Assertion is the response of navigator.credentials.get: everything the zone needs, nothing it must look up.
type Assertion struct {
	CredentialID      []byte `json:"credential_id"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}

// Verify reports whether a is a valid assertion by k over challenge (the intent hash): the credential is the enrolled one, clientDataJSON says
// "webauthn.get" with this challenge (base64url, no padding) and an allowed origin and is not cross-origin, the RP ID hash matches, user presence and
// user verification are set, and the signature verifies over authenticatorData || SHA-256(clientDataJSON) under the enrolled key.
func Verify(k *Key, challenge []byte, a *Assertion) error {
	if k == nil || a == nil {
		return errors.New("webauthn: no key or no assertion")
	}
	if !bytes.Equal(a.CredentialID, k.CredentialID) {
		return errors.New("webauthn: credential id is not the enrolled one")
	}
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return fmt.Errorf("webauthn: client data: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return fmt.Errorf("webauthn: type %q, want webauthn.get", cd.Type)
	}
	if cd.Challenge != base64.RawURLEncoding.EncodeToString(challenge) {
		return errors.New("webauthn: challenge is not this intent's hash")
	}
	if !slices.Contains(k.Origins, cd.Origin) {
		return fmt.Errorf("webauthn: origin %q is not allowed", cd.Origin)
	}
	if cd.CrossOrigin {
		return errors.New("webauthn: cross-origin assertion")
	}
	ad := a.AuthenticatorData
	if len(ad) < 37 {
		return errors.New("webauthn: authenticator data too short")
	}
	if rp := sha256.Sum256([]byte(k.RPID)); !bytes.Equal(ad[:32], rp[:]) {
		return errors.New("webauthn: rp id hash does not match")
	}
	if ad[32]&flagUP == 0 {
		return errors.New("webauthn: user presence flag not set")
	}
	if ad[32]&flagUV == 0 {
		return errors.New("webauthn: user verification flag not set")
	}
	cdh := sha256.Sum256(a.ClientDataJSON)
	msg := append(bytes.Clone(ad), cdh[:]...)
	switch k.Alg {
	case ES256:
		d := sha256.Sum256(msg)
		if k.ES256 == nil || !ecdsa.VerifyASN1(k.ES256, d[:], a.Signature) {
			return errors.New("webauthn: bad signature")
		}
	case EdDSA:
		if len(k.Ed25519) != ed25519.PublicKeySize || !ed25519.Verify(k.Ed25519, msg, a.Signature) {
			return errors.New("webauthn: bad signature")
		}
	default:
		return fmt.Errorf("webauthn: algorithm %q", k.Alg)
	}
	return nil
}

// SignCount is the authenticator's signature counter. The zone does not track it (see docs/signing-zone.md); it is exposed for logging.
func SignCount(authenticatorData []byte) uint32 {
	if len(authenticatorData) < 37 {
		return 0
	}
	return uint32(authenticatorData[33])<<24 | uint32(authenticatorData[34])<<16 | uint32(authenticatorData[35])<<8 | uint32(authenticatorData[36])
}
