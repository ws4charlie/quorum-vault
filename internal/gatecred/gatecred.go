// Package gatecred is the pure side of the Gate credential contract
// (docs/gate-credential.md): parse a credential, compute the exact bytes that
// were signed, verify the Ed25519 signature against a key set, check the clock
// and compare the credential with a payment that the caller has decoded from
// the bytes it is about to sign.
//
// It has no database, no network and no clock of its own. Replay records, the
// per-wallet caps and the Gate-governed mark need state and live in the zones
// (GC2). There is no switch here that turns a check off.
package gatecred

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"time"
)

// Version is the only credential format version this package accepts.
const Version = 1

// DomainPrefix is prepended to the canonical bytes before signing, so a
// signature over a credential can never be a signature over anything else.
const DomainPrefix = "qv-gate-credential-v1\n"

// Limits fixed by the contract.
const (
	MaxCredentialBytes = 4096
	MaxTimestamp       = 1<<53 - 1 // largest integer both sides can hold exactly
	DefaultSkew        = 30 * time.Second
	DefaultMaxTTL      = 10 * time.Minute
	MaxSkew            = 5 * time.Minute
	MaxTTLCeiling      = time.Hour
	NativeAsset        = "native"
)

// Code is a stable error code. Codes are part of the contract: never rename.
type Code string

const (
	CredentialMissing   Code = "credential_missing"
	CredentialMalformed Code = "credential_malformed"
	KIDUnknown          Code = "kid_unknown"
	SignatureInvalid    Code = "signature_invalid"
	AudienceMismatch    Code = "audience_mismatch"
	WalletMismatch      Code = "wallet_mismatch"
	TTLTooLong          Code = "ttl_too_long"
	NotYetValid         Code = "not_yet_valid"
	Expired             Code = "expired"
	PaymentMismatch     Code = "payment_mismatch"
	AuthorizationWindow Code = "authorization_window"

	// Codes below need state and are produced by the zones and the signing
	// API, not by this package. They are listed so the set is in one place.
	Replayed              Code = "replayed"
	WalletNotGateGoverned Code = "wallet_not_gate_governed"
	FastLaneCap           Code = "fast_lane_cap"
	PayloadInvalid        Code = "payload_invalid"
	ClientNotAuthorized   Code = "client_not_authorized"
	RequestInvalid        Code = "request_invalid"
)

// Error is a typed refusal. Field names the credential or payment field for
// credential_malformed and payment_mismatch; it is empty otherwise.
type Error struct {
	Code   Code
	Field  string
	Detail string
}

func (e *Error) Error() string {
	s := string(e.Code)
	if e.Field != "" {
		s += " (" + e.Field + ")"
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func fail(c Code, field, format string, a ...any) *Error {
	return &Error{Code: c, Field: field, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the code of err, or "" when err is not an *Error.
func CodeOf(err error) Code {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

// Credential is a parsed credential. Only Parse and the minter in
// gatecredtest build one; every field has passed the format rules.
type Credential struct {
	V              int64
	KID            string
	CredentialID   string
	ObligationID   string
	Audience       string
	WalletID       string
	Chain          string
	Asset          string
	Payee          string
	Amount         string
	IssuedAt       int64
	ExpiresAt      int64
	PolicyVersion  string
	DecisionReason string
	Sig            []byte // 64 bytes
}

// Payment is what the zone decoded from the bytes it is about to sign, in the
// canonical forms of the contract (lower-case hex, decimal amount).
type Payment struct {
	WalletID string // the wallet that pays
	Chain    string // CAIP-2, for example eip155:84532
	Asset    string // "native" or a lower-case token contract address
	Payee    string // lower-case address
	Amount   string // decimal string of integer minor units

	// For an EIP-3009 authorization only: its own validity window (Unix
	// seconds). Both nil for an ordinary transfer.
	ValidAfter  *int64
	ValidBefore *int64
}

// Config is the verifier's setting: this deployment's name, the Gate public
// keys by kid, and the two time limits.
type Config struct {
	Audience string
	Keys     map[string]ed25519.PublicKey
	Skew     time.Duration
	MaxTTL   time.Duration
}

// NewConfig validates a config; zero Skew and MaxTTL take the defaults.
// A node that cannot build a Config must not start.
func NewConfig(audience string, keys map[string]ed25519.PublicKey, skew, maxTTL time.Duration) (*Config, error) {
	if !reAudience.MatchString(audience) {
		return nil, fmt.Errorf("gatecred: audience %q is not 1-64 characters of [a-z0-9._-] starting with a letter or digit", audience)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("gatecred: no Gate public key configured")
	}
	cp := make(map[string]ed25519.PublicKey, len(keys))
	for kid, k := range keys {
		if !reKID.MatchString(kid) {
			return nil, fmt.Errorf("gatecred: kid %q is not 1-64 characters of [A-Za-z0-9._-]", kid)
		}
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("gatecred: key %q is %d bytes, want %d", kid, len(k), ed25519.PublicKeySize)
		}
		cp[kid] = append(ed25519.PublicKey(nil), k...)
	}
	if skew == 0 {
		skew = DefaultSkew
	}
	if maxTTL == 0 {
		maxTTL = DefaultMaxTTL
	}
	if skew < 0 || skew > MaxSkew {
		return nil, fmt.Errorf("gatecred: skew %s outside 0..%s", skew, MaxSkew)
	}
	if maxTTL < time.Second || maxTTL > MaxTTLCeiling {
		return nil, fmt.Errorf("gatecred: max ttl %s outside 1s..%s", maxTTL, MaxTTLCeiling)
	}
	return &Config{Audience: audience, Keys: cp, Skew: skew, MaxTTL: maxTTL}, nil
}

// Verify runs the pure checks in the contract's order and returns the parsed
// credential, or an *Error. raw is the credential exactly as received.
func (c *Config) Verify(raw []byte, p Payment, now time.Time) (*Credential, error) {
	cred, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	pub, ok := c.Keys[cred.KID]
	if !ok {
		return nil, fail(KIDUnknown, "kid", "no key %q", cred.KID)
	}
	if !ed25519.Verify(pub, cred.SignedBytes(), cred.Sig) {
		return nil, fail(SignatureInvalid, "", "signature does not match")
	}
	if cred.Audience != c.Audience {
		return nil, fail(AudienceMismatch, "audience", "credential is for %q", cred.Audience)
	}
	if cred.WalletID != p.WalletID {
		return nil, fail(WalletMismatch, "wallet_id", "credential is for another wallet")
	}
	if cred.ExpiresAt-cred.IssuedAt > int64(c.MaxTTL/time.Second) { // seconds, never multiplied: a huge span must not wrap
		return nil, fail(TTLTooLong, "expires_at", "lifetime %ds exceeds %s", cred.ExpiresAt-cred.IssuedAt, c.MaxTTL)
	}
	n := now.Unix()
	skew := int64(c.Skew / time.Second)
	if cred.IssuedAt > n+skew {
		return nil, fail(NotYetValid, "issued_at", "issued %ds in the future", cred.IssuedAt-n)
	}
	if n >= cred.ExpiresAt+skew {
		return nil, fail(Expired, "expires_at", "expired %ds ago", n-cred.ExpiresAt)
	}
	switch {
	case cred.Chain != p.Chain:
		return nil, fail(PaymentMismatch, "chain", "payload is on another chain")
	case cred.Asset != p.Asset:
		return nil, fail(PaymentMismatch, "asset", "payload moves another asset")
	case cred.Payee != p.Payee:
		return nil, fail(PaymentMismatch, "payee", "payload pays another address")
	case cred.Amount != p.Amount:
		return nil, fail(PaymentMismatch, "amount", "payload moves another amount")
	}
	if p.ValidAfter != nil || p.ValidBefore != nil {
		if p.ValidAfter == nil || p.ValidBefore == nil {
			return nil, fail(AuthorizationWindow, "", "validAfter and validBefore must both be given")
		}
		if *p.ValidAfter < cred.IssuedAt || *p.ValidBefore > cred.ExpiresAt || *p.ValidAfter >= *p.ValidBefore {
			return nil, fail(AuthorizationWindow, "", "authorization window %d..%d is not inside the credential's %d..%d",
				*p.ValidAfter, *p.ValidBefore, cred.IssuedAt, cred.ExpiresAt)
		}
	}
	return cred, nil
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
