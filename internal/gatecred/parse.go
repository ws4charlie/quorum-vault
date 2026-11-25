package gatecred

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	reKID      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	reAudience = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reUUID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reChain    = regexp.MustCompile(`^eip155:[1-9][0-9]{0,31}$`)
	reAddress  = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	reAmount   = regexp.MustCompile(`^[1-9][0-9]{0,77}$`)
	reInt      = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
)

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// The fields of a credential, in the order of the contract's table. "sig" is
// the envelope field and is not signed.
var fieldNames = []string{
	"v", "kid", "credential_id", "obligation_id", "audience", "wallet_id", "chain", "asset",
	"payee", "amount", "issued_at", "expires_at", "policy_version", "decision_reason",
}

var intFields = map[string]bool{"v": true, "issued_at": true, "expires_at": true}

// opaque reports whether s may be an opaque field: 1..max bytes of valid UTF-8
// with no control character (U+0000-U+001F). The bytes are kept as given; no
// normalisation is ever applied.
func opaque(s string, max int) bool {
	if len(s) < 1 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 {
			return false
		}
	}
	return true
}

// escapesAreSound refuses a lone UTF-16 surrogate written as a \u escape: the
// JSON decoder would silently turn it into U+FFFD, a different string from the
// one the sender signed.
func escapesAreSound(raw []byte) bool {
	hex4 := func(i int) (int, bool) {
		if i+4 > len(raw) {
			return 0, false
		}
		n := 0
		for _, c := range raw[i : i+4] {
			switch {
			case c >= '0' && c <= '9':
				n = n<<4 | int(c-'0')
			case c >= 'a' && c <= 'f':
				n = n<<4 | int(c-'a'+10)
			case c >= 'A' && c <= 'F':
				n = n<<4 | int(c-'A'+10)
			default:
				return 0, false
			}
		}
		return n, true
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 < len(raw) && raw[i+1] == 'u' {
			n, ok := hex4(i + 2)
			if !ok {
				return false
			}
			i += 5
			switch {
			case n >= 0xdc00 && n <= 0xdfff:
				return false // low surrogate without a high one
			case n >= 0xd800 && n <= 0xdbff:
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				m, ok := hex4(i + 3)
				if !ok || m < 0xdc00 || m > 0xdfff {
					return false
				}
				i += 6
			}
			continue
		}
		i++ // skip the escaped character
	}
	return true
}

// printable reports whether s is 1..max characters of printable ASCII (0x20-0x7e).
func printable(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Parse reads a credential strictly: one JSON object, exactly the contract's
// fields and "sig", no duplicate or unknown names, every value of the right
// JSON type and format. Empty input is credential_missing; anything else that
// is wrong is credential_malformed with the field named when one is to blame.
func Parse(raw []byte) (*Credential, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, fail(CredentialMissing, "", "no credential")
	}
	if len(raw) > MaxCredentialBytes {
		return nil, fail(CredentialMalformed, "", "credential is %d bytes, limit %d", len(raw), MaxCredentialBytes)
	}
	if !utf8.Valid(raw) {
		return nil, fail(CredentialMalformed, "", "not valid UTF-8")
	}
	if !escapesAreSound(raw) {
		return nil, fail(CredentialMalformed, "", "unpaired surrogate escape")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fail(CredentialMalformed, "", "not a JSON object")
	}
	vals := map[string]any{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fail(CredentialMalformed, "", "bad JSON: %v", err)
		}
		key, _ := kt.(string)
		if _, dup := vals[key]; dup {
			return nil, fail(CredentialMalformed, key, "duplicate field")
		}
		vt, err := dec.Token()
		if err != nil {
			return nil, fail(CredentialMalformed, key, "bad JSON: %v", err)
		}
		switch vt.(type) {
		case string, json.Number:
		default:
			return nil, fail(CredentialMalformed, key, "value must be a string or an integer")
		}
		vals[key] = vt
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, fail(CredentialMalformed, "", "unterminated JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail(CredentialMalformed, "", "data after the JSON object")
	}

	known := map[string]bool{"sig": true}
	for _, f := range fieldNames {
		known[f] = true
	}
	var unknown []string
	for k := range vals {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fail(CredentialMalformed, unknown[0], "unknown field")
	}
	for _, f := range append(append([]string(nil), fieldNames...), "sig") {
		if _, ok := vals[f]; !ok {
			return nil, fail(CredentialMalformed, f, "missing field")
		}
	}

	str := func(f string) (string, *Error) {
		s, ok := vals[f].(string)
		if !ok {
			return "", fail(CredentialMalformed, f, "must be a string")
		}
		return s, nil
	}
	num := func(f string) (int64, *Error) {
		n, ok := vals[f].(json.Number)
		if !ok {
			return 0, fail(CredentialMalformed, f, "must be an integer")
		}
		if !reInt.MatchString(n.String()) {
			return 0, fail(CredentialMalformed, f, "must be a plain non-negative integer")
		}
		v, err := n.Int64()
		if err != nil || v > MaxTimestamp {
			return 0, fail(CredentialMalformed, f, "integer out of range")
		}
		return v, nil
	}

	c := &Credential{}
	var e *Error
	for _, f := range fieldNames {
		if intFields[f] {
			var v int64
			if v, e = num(f); e != nil {
				return nil, e
			}
			switch f {
			case "v":
				c.V = v
			case "issued_at":
				c.IssuedAt = v
			case "expires_at":
				c.ExpiresAt = v
			}
			continue
		}
		var s string
		if s, e = str(f); e != nil {
			return nil, e
		}
		switch f {
		case "kid":
			c.KID = s
		case "credential_id":
			c.CredentialID = s
		case "obligation_id":
			c.ObligationID = s
		case "audience":
			c.Audience = s
		case "wallet_id":
			c.WalletID = s
		case "chain":
			c.Chain = s
		case "asset":
			c.Asset = s
		case "payee":
			c.Payee = s
		case "amount":
			c.Amount = s
		case "policy_version":
			c.PolicyVersion = s
		case "decision_reason":
			c.DecisionReason = s
		}
	}
	sigText, e := str("sig")
	if e != nil {
		return nil, e
	}
	if err := c.checkFormats(); err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(sigText)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fail(CredentialMalformed, "sig", "must be 64 bytes in base64url without padding")
	}
	c.Sig = sig
	return c, nil
}

// checkFormats applies the format and limit of each field.
func (c *Credential) checkFormats() *Error {
	bad := func(f, why string) *Error { return fail(CredentialMalformed, f, "%s", why) }
	switch {
	case c.V != Version:
		return bad("v", "unsupported version")
	case !reKID.MatchString(c.KID):
		return bad("kid", "must be 1-64 characters of [A-Za-z0-9._-]")
	case !reUUID.MatchString(c.CredentialID):
		return bad("credential_id", "must be a lower-case UUID")
	case !opaque(c.ObligationID, 128):
		return bad("obligation_id", "must be 1-128 bytes of UTF-8 without control characters")
	case !reAudience.MatchString(c.Audience):
		return bad("audience", "must be 1-64 characters of [a-z0-9._-]")
	case !reUUID.MatchString(c.WalletID):
		return bad("wallet_id", "must be a lower-case UUID")
	case !reChain.MatchString(c.Chain):
		return bad("chain", "must be eip155:<decimal chain id>")
	case c.Asset != NativeAsset && !reAddress.MatchString(c.Asset):
		return bad("asset", `must be "native" or a lower-case 0x address`)
	case !reAddress.MatchString(c.Payee):
		return bad("payee", "must be a lower-case 0x address")
	case !reAmount.MatchString(c.Amount):
		return bad("amount", "must be a decimal integer of at least 1, no sign, no leading zero")
	case c.IssuedAt < 1:
		return bad("issued_at", "must be at least 1")
	case c.ExpiresAt <= c.IssuedAt:
		return bad("expires_at", "must be after issued_at")
	case !opaque(c.PolicyVersion, 64):
		return bad("policy_version", "must be 1-64 bytes of UTF-8 without control characters")
	case !opaque(c.DecisionReason, 256):
		return bad("decision_reason", "must be 1-256 bytes of UTF-8 without control characters")
	}
	if a, ok := new(big.Int).SetString(c.Amount, 10); !ok || a.Cmp(maxUint256) > 0 {
		return bad("amount", "exceeds 2^256-1")
	}
	return nil
}

// Canonical returns the credential without "sig" in RFC 8785 form. Member names
// are ASCII, so sorting by UTF-16 code unit is sorting by byte. Numbers are
// non-negative integers below 2^53, written in decimal. Strings follow the
// RFC: escape the quote, the backslash and the controls; everything else
// (including non-ASCII and characters above the BMP) is written as UTF-8.
func (c *Credential) Canonical() []byte {
	strs := map[string]string{
		"kid": c.KID, "credential_id": c.CredentialID, "obligation_id": c.ObligationID,
		"audience": c.Audience, "wallet_id": c.WalletID, "chain": c.Chain, "asset": c.Asset,
		"payee": c.Payee, "amount": c.Amount, "policy_version": c.PolicyVersion,
		"decision_reason": c.DecisionReason,
	}
	ints := map[string]int64{"v": c.V, "issued_at": c.IssuedAt, "expires_at": c.ExpiresAt}
	names := append([]string(nil), fieldNames...)
	sort.Strings(names)
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"` + n + `":`)
		if intFields[n] {
			b.WriteString(itoa(ints[n]))
		} else {
			b.WriteString(quote(strs[n]))
		}
	}
	b.WriteByte('}')
	return []byte(b.String())
}

func quote(s string) string {
	const hexd = "0123456789abcdef"
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexd[c>>4])
				b.WriteByte(hexd[c&15])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// SignedBytes is what Gate signs: the domain prefix, then the canonical bytes.
func (c *Credential) SignedBytes() []byte {
	return append([]byte(DomainPrefix), c.Canonical()...)
}

// Wire returns the credential as sent: the canonical object plus "sig".
func (c *Credential) Wire() []byte {
	canon := c.Canonical()
	sig := base64.RawURLEncoding.EncodeToString(c.Sig)
	return append(canon[:len(canon)-1:len(canon)-1], []byte(`,"sig":"`+sig+`"}`)...)
}
