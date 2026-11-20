package ctap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// Authenticator data flags (WebAuthn level 2, 6.1).
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagAT = 0x40
)

// Credential is a new credential, read from a key's make-credential answer. It holds what the zone's approver entry needs and what an operator
// compares by hand.
type Credential struct {
	Alg          Alg
	PublicKeyHex string // ES256: the 65-byte uncompressed point; EdDSA: the 32-byte key (the zone's config spelling)
	CredentialID []byte
	AAGUID       [16]byte
	SignCount    uint32
	Attestation  Attestation
}

// Attestation is what the key said about itself. Nothing here is checked against the FIDO Metadata Service: an operator compares AAGUID and the
// certificate by hand (docs/runbooks/webauthn-approver.md).
type Attestation struct {
	Format string // "packed", "none", "fido-u2f", ...
	// Type is "none" (no statement), "self" (signed by the new credential itself), "basic" (signed by a certificate the key carries) or "unknown".
	Type string
	// SignatureCheck is "valid" or "INVALID" for a statement this package can check (packed, ES256 attestation key or self attestation), else
	// "not checked" with the reason.
	SignatureCheck string
	CertSubject    string
	CertIssuer     string
	CertSerial     string
	CertSHA256     string // hex of the DER certificate
	CertAAGUID     string // the AAGUID the certificate itself claims (id-fido-gen-ce-aaguid), empty if none
	CertNotAfter   string
}

// ParseAttestation reads a make-credential answer for request r. It refuses an answer for another relying party, without user presence or user
// verification, without attested credential data, with another credential id than the one the key returned, or with a key of another algorithm than
// the request allowed.
func ParseAttestation(r MakeRequest, res *MakeResult) (*Credential, error) {
	ad := res.AuthData
	if len(ad) < 37 {
		return nil, errors.New("ctap: authenticator data too short")
	}
	if rp := sha256.Sum256([]byte(r.RPID)); !bytes.Equal(ad[:32], rp[:]) {
		return nil, errors.New("ctap: the key made the credential for another relying party id")
	}
	flags := ad[32]
	if flags&FlagUP == 0 {
		return nil, errors.New("ctap: the key did not report user presence")
	}
	if flags&FlagUV == 0 {
		return nil, errors.New("ctap: the key did not verify the user (no PIN or biometric): this credential would be refused by the zone, so it is not enrolled")
	}
	if flags&FlagAT == 0 || len(ad) < 55 {
		return nil, errors.New("ctap: no attested credential data")
	}
	c := &Credential{SignCount: binary.BigEndian.Uint32(ad[33:37])}
	copy(c.AAGUID[:], ad[37:53])
	n := int(binary.BigEndian.Uint16(ad[53:55]))
	if n == 0 || len(ad) < 55+n {
		return nil, errors.New("ctap: credential id length does not fit the data")
	}
	c.CredentialID = ad[55 : 55+n]
	if !bytes.Equal(c.CredentialID, res.CredentialID) {
		return nil, errors.New("ctap: the credential id in the authenticator data is not the one the key returned")
	}
	cr := &cborReader{b: ad[55+n:]}
	key, err := cr.item()
	if err != nil || key.kind != 5 {
		return nil, errors.New("ctap: credential public key is not a COSE key")
	}
	c.Alg, c.PublicKeyHex, err = coseKey(key)
	if err != nil {
		return nil, err
	}
	if !algAllowed(r.Algs, c.Alg) {
		return nil, fmt.Errorf("ctap: the key made a %s credential, which was not asked for", c.Alg.Name())
	}
	c.Attestation = attest(r, res)
	return c, nil
}

func algAllowed(list []Alg, a Alg) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// coseKey turns a COSE_Key into the zone's public key spelling and checks that the key is on its curve.
func coseKey(k cborItem) (Alg, string, error) {
	kty, _ := k.get(1)
	alg, _ := k.get(3)
	crv, _ := k.get(-1)
	x, _ := k.get(-2)
	switch {
	case kty.n == 2 && alg.n == int64(ES256) && crv.n == 1:
		y, _ := k.get(-3)
		if len(x.bytes) != 32 || len(y.bytes) != 32 {
			return 0, "", errors.New("ctap: ES256 key coordinates are not 32 bytes")
		}
		xx, yy := new(big.Int).SetBytes(x.bytes), new(big.Int).SetBytes(y.bytes)
		if !elliptic.P256().IsOnCurve(xx, yy) {
			return 0, "", errors.New("ctap: ES256 key is not on the P-256 curve")
		}
		return ES256, hex.EncodeToString(append([]byte{4}, append(x.bytes[:32:32], y.bytes...)...)), nil
	case kty.n == 1 && alg.n == int64(EdDSA) && crv.n == 6:
		if len(x.bytes) != ed25519.PublicKeySize {
			return 0, "", errors.New("ctap: EdDSA key is not 32 bytes")
		}
		return EdDSA, hex.EncodeToString(x.bytes), nil
	}
	return 0, "", fmt.Errorf("ctap: credential key type (kty %d, alg %d) is not one the signing zone verifies", kty.n, alg.n)
}

var oidFIDOAAGUID = []int{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

func attest(r MakeRequest, res *MakeResult) Attestation {
	a := Attestation{Format: res.Format}
	if res.Format == "none" || (len(res.Signature) == 0 && len(res.X5C) == 0) {
		a.Type, a.SignatureCheck = "none", "not checked (no attestation statement)"
		return a
	}
	if res.Format != "packed" {
		a.Type, a.SignatureCheck = "unknown", "not checked (format "+res.Format+")"
		return a
	}
	a.SignatureCheck = "not checked"
	if len(res.X5C) == 0 {
		a.Type = "self"
		a.SignatureCheck = "not checked (self attestation of this key type)"
		return a
	}
	a.Type = "basic"
	cert, err := x509.ParseCertificate(res.X5C)
	if err != nil {
		a.SignatureCheck = "INVALID (certificate does not parse)"
		return a
	}
	sum := sha256.Sum256(res.X5C)
	a.CertSubject, a.CertIssuer, a.CertSerial = cert.Subject.String(), cert.Issuer.String(), cert.SerialNumber.Text(16)
	a.CertSHA256, a.CertNotAfter = hex.EncodeToString(sum[:]), cert.NotAfter.UTC().Format("2006-01-02")
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidFIDOAAGUID) && len(e.Value) == 18 && e.Value[0] == 0x04 && e.Value[1] == 16 { // an OCTET STRING of 16 bytes
			a.CertAAGUID = hex.EncodeToString(e.Value[2:])
		}
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		d := sha256.Sum256(append(bytes.Clone(res.AuthData), r.ClientDataHash[:]...))
		if ecdsa.VerifyASN1(pub, d[:], res.Signature) {
			a.SignatureCheck = "valid (signed by the certificate above)"
		} else {
			a.SignatureCheck = "INVALID"
		}
	} else {
		a.SignatureCheck = "not checked (attestation key is not ECDSA)"
	}
	return a
}

// ParseAssertion checks an assertion answer for what the CLI can know before sending it on, and returns the flags so the caller can warn. It does not
// verify the signature: the CLI does not hold the public key, and the zone does that (internal/webauthn).
func ParseAssertion(r AssertRequest, res *AssertResult) (flags byte, err error) {
	ad := res.AuthData
	if len(ad) < 37 {
		return 0, errors.New("ctap: authenticator data too short")
	}
	if rp := sha256.Sum256([]byte(r.RPID)); !bytes.Equal(ad[:32], rp[:]) {
		return 0, errors.New("ctap: the key answered for another relying party id")
	}
	if len(res.Signature) == 0 {
		return 0, errors.New("ctap: the key returned no signature")
	}
	return ad[32], nil
}
