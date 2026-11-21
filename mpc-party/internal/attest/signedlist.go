package attest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// The signed allowlist: AllowEntry rows plus a sequence number, signed by operators with Ed25519. It follows the zone's signed settings
// (internal/gateway/approvers.go: a named operator key set, min_operators distinct valid signatures, a domain-tagged message, a rising
// sequence). That code lives in the root module, which this module may not import, so the few lines are repeated here.

// MaxAllowEntries bounds a list.
const MaxAllowEntries = 1000

// OperatorsFile is the operators section of a config (same shape as the gateway's).
type OperatorsFile struct {
	Keys         map[string]OperatorFile `json:"keys"`                    // operator name -> Ed25519 public key
	MinOperators int                     `json:"min_operators,omitempty"` // distinct operators a list needs; default 2 (1 with a single operator)
}

// OperatorFile is one operator.
type OperatorFile struct {
	PublicKey string `json:"public_key"` // 64 hex chars
}

// Operators is the validated operator key set.
type Operators struct {
	Keys map[string]ed25519.PublicKey
	Min  int
}

// Build validates the section.
func (o OperatorsFile) Build() (*Operators, error) {
	if len(o.Keys) == 0 {
		return nil, errors.New("attest: operators.keys is empty")
	}
	ops := &Operators{Keys: map[string]ed25519.PublicKey{}, Min: o.MinOperators}
	seen := map[string]string{}
	for name, k := range o.Keys {
		raw, err := hex.DecodeString(k.PublicKey)
		if name == "" || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("attest: operator %q: public_key must be %d hex bytes", name, ed25519.PublicKeySize)
		}
		if other, dup := seen[string(raw)]; dup {
			return nil, fmt.Errorf("attest: operators %q and %q share one public key", other, name)
		}
		seen[string(raw)] = name
		ops.Keys[name] = ed25519.PublicKey(raw)
	}
	if ops.Min == 0 {
		ops.Min = min(2, len(ops.Keys))
	}
	if ops.Min > len(ops.Keys) || ops.Min < 1 || (len(ops.Keys) > 1 && ops.Min < 2) {
		return nil, fmt.Errorf("attest: operators.min_operators %d: at least 2 (1 only with a single operator) and at most the %d configured operators", ops.Min, len(ops.Keys))
	}
	return ops, nil
}

// OperatorSignature is one operator's signature.
type OperatorSignature struct {
	Operator  string `json:"operator"`
	Signature string `json:"signature"` // hex
}

// SignedAllowlist is the file the broker loads.
type SignedAllowlist struct {
	Seq        int64               `json:"seq"`       // must rise with every list the broker accepts while running
	SignedAt   int64               `json:"signed_at"` // unix seconds, informational
	Entries    []AllowEntry        `json:"entries"`
	Signatures []OperatorSignature `json:"signatures"`
}

// canonEntry is the signed form of an entry: fixed field order, times as unix seconds, measurement in lower case.
type canonEntry struct {
	Party       string `json:"party"`
	Measurement string `json:"measurement"`
	NotBefore   int64  `json:"not_before"`
	NotAfter    int64  `json:"not_after"` // 0: no end
	Version     string `json:"version"`
	Status      string `json:"status"` // "active" or "revoked" ("" is signed as "active")
	// PCRs is left out when empty, so the signed bytes of a list without Nitro entries are what they were before T7-prep. A map marshals with sorted keys.
	PCRs map[string]string `json:"pcrs,omitempty"`
}

// AllowlistMessage is what the operators sign.
func AllowlistMessage(l SignedAllowlist) []byte {
	es := make([]canonEntry, len(l.Entries))
	for i, e := range l.Entries {
		var na int64
		if !e.NotAfter.IsZero() {
			na = e.NotAfter.Unix()
		}
		st := e.Status
		if st == "" {
			st = StatusActive
		}
		pcrs := map[string]string(nil)
		if len(e.PCRs) > 0 {
			pcrs = make(map[string]string, len(e.PCRs))
			for k, v := range e.PCRs {
				pcrs[k] = strings.ToLower(v)
			}
		}
		es[i] = canonEntry{e.Party, strings.ToLower(e.Measurement), e.NotBefore.Unix(), na, e.Version, st, pcrs}
	}
	body, _ := json.Marshal(struct {
		Seq      int64        `json:"seq"`
		SignedAt int64        `json:"signed_at"`
		Entries  []canonEntry `json:"entries"`
	}{l.Seq, l.SignedAt, es})
	return append([]byte("qv-attest-allowlist-v2\n"), body...)
}

// SignAllowlist adds (or replaces) one operator's signature over l.
func SignAllowlist(priv ed25519.PrivateKey, operator string, l SignedAllowlist) SignedAllowlist {
	sig := OperatorSignature{Operator: operator, Signature: hex.EncodeToString(ed25519.Sign(priv, AllowlistMessage(l)))}
	out := l
	out.Signatures = nil
	for _, s := range l.Signatures {
		if s.Operator != operator {
			out.Signatures = append(out.Signatures, s)
		}
	}
	out.Signatures = append(out.Signatures, sig)
	return out
}

// ValidEntries checks every entry the way CheckAllowlist does (a malformed list is refused whole) and the list bounds.
func ValidEntries(entries []AllowEntry) error {
	if len(entries) > MaxAllowEntries {
		return fmt.Errorf("attest: allowlist has %d entries, at most %d", len(entries), MaxAllowEntries)
	}
	for i, e := range entries {
		if _, ok := validEntry(e, partyRE.MatchString); !ok {
			return fmt.Errorf("attest: allowlist entry %d is malformed", i)
		}
	}
	return nil
}

// Verify returns the distinct operators whose signature over l is valid, and an error when there are fewer than o.Min or the list is malformed.
func (o *Operators) Verify(l SignedAllowlist) ([]string, error) {
	if o == nil {
		return nil, errors.New("attest: no operators configured")
	}
	if l.Seq < 1 {
		return nil, errors.New("attest: allowlist sequence must be at least 1")
	}
	if err := ValidEntries(l.Entries); err != nil {
		return nil, err
	}
	msg := AllowlistMessage(l)
	seen := map[string]bool{}
	var out []string
	for _, s := range l.Signatures {
		key, ok := o.Keys[s.Operator]
		if !ok || seen[s.Operator] {
			continue
		}
		sig, err := hex.DecodeString(s.Signature)
		if err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(key, msg, sig) {
			seen[s.Operator] = true
			out = append(out, s.Operator)
		}
	}
	sort.Strings(out)
	if len(out) < o.Min {
		return nil, fmt.Errorf("attest: allowlist has %d valid signatures of distinct configured operators, %d needed", len(out), o.Min)
	}
	return out, nil
}

// ParseSignedAllowlist reads the JSON form (unknown fields refused).
func ParseSignedAllowlist(data []byte) (SignedAllowlist, error) {
	var l SignedAllowlist
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return l, fmt.Errorf("attest: allowlist: %w", err)
	}
	return l, nil
}

// LoadSignedAllowlist reads and verifies the file. It returns the list only when enough operators signed it.
func LoadSignedAllowlist(path string, ops *Operators) (*SignedAllowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attest: allowlist: %w", err)
	}
	l, err := ParseSignedAllowlist(data)
	if err != nil {
		return nil, err
	}
	if _, err := ops.Verify(l); err != nil {
		return nil, err
	}
	return &l, nil
}

// ParseOperatorKey reads an Ed25519 private key file body: hex of the 32-byte seed or of the 64-byte key.
func ParseOperatorKey(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	switch {
	case err != nil:
		return nil, errors.New("attest: operator key is not hex")
	case len(b) == ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case len(b) == ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("attest: operator key must be %d or %d bytes", ed25519.SeedSize, ed25519.PrivateKeySize)
}

// Window formats an entry's validity for display.
func (e AllowEntry) Window() string {
	until := "no end"
	if !e.NotAfter.IsZero() {
		until = e.NotAfter.UTC().Format(time.RFC3339)
	}
	return e.NotBefore.UTC().Format(time.RFC3339) + " .. " + until
}

// Counts splits the entries at time now: allowing now, outside their window, and revoked.
func (l SignedAllowlist) Counts(now time.Time) (active, expiredOrFuture, revoked int) {
	for _, e := range l.Entries {
		switch {
		case e.Revoked():
			revoked++
		case now.Before(e.NotBefore) || (!e.NotAfter.IsZero() && now.After(e.NotAfter)):
			expiredOrFuture++
		default:
			active++
		}
	}
	return
}
