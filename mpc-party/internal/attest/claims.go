package attest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// EvidenceTypeNitro names the Nitro attestation document in Claims.EvidenceType.
const EvidenceTypeNitro = "aws-nitro"

// Claims is the normalised, verified content of a piece of evidence (modelled on the IETF EAT claim set, RFC 9711). Only a Verifier makes it,
// after every rule passed.
type Claims struct {
	EvidenceType string         // EvidenceTypeNitro
	ModuleID     string         // the enclave's identifier as reported by the platform
	Measurements map[int][]byte // PCR index -> value (Nitro: PCR0 image, PCR1 kernel and boot, PCR2 application, PCR8 EIF signing certificate)
	Signer       string         // lower-case hex of PCR8, the hash of the image signing certificate; empty when the image is unsigned (all zero)
	Debug        bool           // the enclave runs in debug mode (all-zero measurements); the verifier refuses it unless AllowDebug is set
	Nonce        []byte
	PublicKey    []byte // DER public key the enclave made for the relying party to encrypt to
	UserData     []byte
	Timestamp    time.Time // when the platform made the document
}

// Measurement returns the main measurement (PCR0, the image) as lower-case hex, or "" when absent.
func (c *Claims) Measurement() string {
	if v, ok := c.Measurements[0]; ok {
		return hex.EncodeToString(v)
	}
	return ""
}

// Attester makes evidence for a running party. publicKey is the DER public key the party made inside the TEE; nonce and userData are what the
// relying party asked the evidence to be bound to.
type Attester interface {
	Attest(nonce, publicKey, userData []byte) ([]byte, error)
}

// Expect is what the relying party knows about the request, so the evidence is bound to it.
type Expect struct {
	Nonce     []byte // the challenge the relying party issued; required, non-empty
	UserData  []byte // what the document must carry in user_data (nil and empty are the same: no user data)
	PublicKey []byte // when non-empty, the document's public_key must equal it (a document for one key is refused for another)
}

// Verifier checks evidence against the trust roots it was built with, the expectation and the time. It returns Claims or an *Error whose Rule
// says which rule failed (use RuleOf).
type Verifier interface {
	Verify(evidence []byte, expect Expect, now time.Time) (*Claims, error)
}

// Rule names the verification rule that failed.
type Rule string

const (
	RuleExpectation  Rule = "expectation"      // the caller gave no nonce
	RuleFormat       Rule = "format"           // not a well-formed COSE_Sign1 / CBOR document
	RuleAlgorithm    Rule = "algorithm"        // not ES384
	RuleMissingField Rule = "missing_field"    // a required field is absent or empty
	RuleSize         Rule = "size"             // a field is outside its documented length
	RuleChainOrder   Rule = "chain_order"      // cabundle is not root first, each signed by the one before
	RuleUntrusted    Rule = "untrusted_root"   // cabundle[0] is not a configured trust root
	RuleCertValidity Rule = "cert_validity"    // a certificate is outside its validity at the document's time
	RuleSignature    Rule = "signature"        // COSE signature does not verify under the leaf certificate
	RuleStale        Rule = "stale_timestamp"  // document older than the freshness window
	RuleFuture       Rule = "future_timestamp" // document from the future
	RuleDebug        Rule = "debug"            // debug-mode (all-zero) measurements
	RuleNonce        Rule = "nonce"            // nonce missing or different from the expected one
	RuleUserData     Rule = "user_data"        // user_data different from the expected one
	RulePublicKey    Rule = "public_key"       // public key missing or different from the expected one
)

// Error is a failed rule.
type Error struct {
	Rule   Rule
	Detail string
	Err    error
}

func (e *Error) Error() string {
	s := "attest: " + string(e.Rule) + ": " + e.Detail
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}
func (e *Error) Unwrap() error { return e.Err }

func fail(r Rule, format string, a ...any) *Error {
	return &Error{Rule: r, Detail: fmt.Sprintf(format, a...)}
}

// RuleOf returns the failed rule of err, or "" when err is not an *Error.
func RuleOf(err error) Rule {
	var e *Error
	if errors.As(err, &e) {
		return e.Rule
	}
	return ""
}
