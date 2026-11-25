// Package gatecredtest stands in for AgentGate in tests: it mints credentials
// signed with the TEST ONLY keys of testdata/gate-credential/vectors.json.
//
// It must never be linked into a production binary. gatecred's
// TestMinterNotInProductionBinaries fails if any package outside this
// directory imports it.
package gatecredtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/ws4charlie/quorum-vault/internal/gatecred"
)

// Key is a TEST ONLY Ed25519 key pair.
type Key struct {
	KID  string
	Seed string // the public string the key is derived from
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// SeedName is the public string that key n (1, 2, 3) derives from. The name
// says TEST ONLY on purpose: anyone can derive these keys, so a verifier that
// trusts one is not protecting anything.
func SeedName(n int) string { return "TEST-ONLY-qv-gate-credential-key-" + strconv.Itoa(n) }

// TestKey derives key n: seed = SHA-256(SeedName(n)); kid = "test-only-<n>".
func TestKey(n int) Key {
	name := SeedName(n)
	seed := sha256.Sum256([]byte(name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return Key{KID: "test-only-" + strconv.Itoa(n), Seed: name, Priv: priv, Pub: priv.Public().(ed25519.PublicKey)}
}

// Fields is a credential as loose name/value pairs (string or int64 values)
// so tests can build malformed ones too.
type Fields map[string]any

// FromCredential lists the fields of c (not the signature).
func FromCredential(c gatecred.Credential) Fields {
	return Fields{
		"v": c.V, "kid": c.KID, "credential_id": c.CredentialID, "obligation_id": c.ObligationID,
		"audience": c.Audience, "wallet_id": c.WalletID, "chain": c.Chain, "asset": c.Asset,
		"payee": c.Payee, "amount": c.Amount, "issued_at": c.IssuedAt, "expires_at": c.ExpiresAt,
		"policy_version": c.PolicyVersion, "decision_reason": c.DecisionReason,
	}
}

// Canonical encodes f as RFC 8785 JSON. It is written apart from gatecred's
// encoder (it leans on encoding/json for strings) so that the vectors check
// two implementations against each other.
func Canonical(f Fields) []byte {
	names := make([]string, 0, len(f))
	for k := range f {
		names = append(names, k)
	}
	sort.Strings(names)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonString(k))
		b.WriteByte(':')
		switch v := f[k].(type) {
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		case string:
			b.Write(jsonString(v))
		default:
			panic("gatecredtest: field values are string or int64")
		}
	}
	b.WriteByte('}')
	return b.Bytes()
}

func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		panic(err)
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

// SignedBytes is the domain prefix plus the canonical bytes.
func SignedBytes(f Fields) []byte { return append([]byte(gatecred.DomainPrefix), Canonical(f)...) }

// Sign signs f with k and returns the signature in base64url without padding.
func Sign(k Key, f Fields) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.Priv, SignedBytes(f)))
}

// Wire returns f plus its signature as the compact JSON object a client sends.
func Wire(k Key, f Fields) []byte { return WireWithSig(f, Sign(k, f)) }

// WireWithSig joins f and an already computed signature text.
func WireWithSig(f Fields, sig string) []byte {
	c := Canonical(f)
	return append(c[:len(c)-1:len(c)-1], []byte(`,"sig":`+string(jsonString(sig))+`}`)...)
}

// Mint signs c with k.
func Mint(k Key, c gatecred.Credential) []byte { return Wire(k, FromCredential(c)) }
