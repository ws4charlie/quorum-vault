// Package ctap is the approver CLI's side of a FIDO2 security key: the two operations it needs (make a credential, get an assertion), a strict
// reader of what the key returns, and one transport that drives the libfido2 command-line tools.
//
// Why the tools and not a Go CTAP2 stack or cgo (decision recorded for the YubiKey task):
//
//   - Code we must trust. Talking CTAP2 means HID framing, CBOR, PIN protocol v1/v2 (ECDH, AES-CBC, HMAC) and the key's quirks. libfido2 is Yubico's
//     reference library, used by OpenSSH for sk keys, and is packaged by every distribution and Homebrew. A new Go implementation would put that
//     whole stack into the approver's trusted code; the tools put none of it there. Our code only builds a request and reads three base64 lines.
//   - The PIN never enters this process. The tools read it from the terminal themselves (readpassphrase), so a bug or log line here cannot leak it.
//   - Build reproducibility. cgo against libfido2 makes the binary depend on the build machine's C toolchain and headers, and a different library
//     version per machine. With the tools, qv-approve is a static pure-Go binary (CGO_ENABLED=0) built the same everywhere; the approver machine
//     installs libfido2's tools from its own package manager, which an operator can pin and audit as one package.
//   - Supply chain. No new Go module is added (go-libfido2 and the pure-Go CTAP libraries are small projects with few maintainers).
//   - macOS and Linux. libfido2 supports both (hidraw on Linux, IOKit on macOS); a pure-Go HID layer would need cgo or a private IOKit binding on macOS.
//
// The cost is a process boundary and a text format that libfido2 documents (man fido2-cred, fido2-assert); the format is read strictly and every echo
// is compared with what was sent. The key is behind the Authenticator interface, so a software authenticator (package ctaptest, never linked into
// the binary) runs the same code path in tests.
package ctap

import (
	"context"
	"errors"
)

// Alg is a COSE algorithm number.
type Alg int

// The algorithms the signing zone verifies (internal/webauthn).
const (
	ES256 Alg = -7
	EdDSA Alg = -8
)

// Name is the algorithm as the zone's approver entry spells it.
func (a Alg) Name() string {
	switch a {
	case ES256:
		return "ES256"
	case EdDSA:
		return "EdDSA"
	}
	return ""
}

// MakeRequest asks for a new credential. User verification (PIN or biometric) and touch are always required: the interface has no switch for them.
type MakeRequest struct {
	RPID           string
	UserName       string
	UserID         []byte
	ClientDataHash [32]byte
	Algs           []Alg // preference order: the first one the key supports is used
}

// MakeResult is a key's answer to MakeRequest, with the authenticator data already unwrapped to its raw bytes.
type MakeResult struct {
	Alg          Alg
	Format       string // attestation statement format: "packed", "none", "fido-u2f", ...
	AuthData     []byte
	CredentialID []byte
	Signature    []byte // attestation signature (empty for "none")
	X5C          []byte // first attestation certificate, DER (empty when the format has none)
}

// AssertRequest asks for an assertion by a known credential. User verification and touch are always required.
type AssertRequest struct {
	RPID           string
	CredentialID   []byte
	ClientDataHash [32]byte
}

// AssertResult is a key's answer to AssertRequest.
type AssertResult struct {
	AuthData  []byte // raw authenticator data
	Signature []byte
}

// Authenticator is a security key.
type Authenticator interface {
	MakeCredential(ctx context.Context, r MakeRequest) (*MakeResult, error)
	GetAssertion(ctx context.Context, r AssertRequest) (*AssertResult, error)
}

// ErrUnsupportedAlg is returned by a transport when the key supports none of the requested algorithms.
var ErrUnsupportedAlg = errors.New("ctap: the key supports none of the requested algorithms")
