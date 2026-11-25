package gatecredtest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ws4charlie/quorum-vault/internal/gatecred"
)

// Fixed values of the vectors. Everything here is public test data.
const (
	VectorsNow      int64 = 1790000000
	VectorsAudience       = "qv-test"
	VectorsWallet         = "7c1f0a52-3b8e-4d6a-9f21-5e0b7a4c8d13"
	VectorsChain          = "eip155:84532"
	VectorsPayee          = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
	VectorsToken          = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
)

type VKey struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
	Seed      string `json:"seed_string,omitempty"`
}

type VConfig struct {
	Audience   string `json:"audience"`
	SkewSecs   int64  `json:"skew_seconds"`
	MaxTTLSecs int64  `json:"max_ttl_seconds"`
	Keys       []VKey `json:"keys"`
}

type VPayment struct {
	WalletID    string `json:"wallet_id"`
	Chain       string `json:"chain"`
	Asset       string `json:"asset"`
	Payee       string `json:"payee"`
	Amount      string `json:"amount"`
	ValidAfter  *int64 `json:"valid_after,omitempty"`
	ValidBefore *int64 `json:"valid_before,omitempty"`
	// PayloadDigest: hex SHA-256 of the payload bytes the zone would sign.
	// Not compared by the pure verifier; a checker's replay record keeps it.
	PayloadDigest string `json:"payload_digest,omitempty"`
}

type VExpect struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Field string `json:"field,omitempty"`
}

type VCase struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Credential  *string `json:"credential"`
	// CredentialHex replaces Credential when the bytes are not valid UTF-8
	// (a JSON file cannot hold them as text); Credential is then null.
	CredentialHex string   `json:"credential_hex,omitempty"`
	SignedBytes   string   `json:"signed_bytes_hex,omitempty"`
	Payment       VPayment `json:"payment"`
	Now           *int64   `json:"now,omitempty"`
	Expect        VExpect  `json:"expect"`
	// Then lists the results of further uses of the same credential after the
	// first one, in order. Only a checker with a used-credential store can
	// produce them.
	Then []VReuse `json:"then_expect_on_reuse,omitempty"`
}

type Vectors struct {
	TestOnly     string   `json:"TEST_ONLY"`
	Format       string   `json:"format"`
	DomainPrefix string   `json:"domain_prefix"`
	KeyDerive    string   `json:"key_derivation"`
	Config       VConfig  `json:"config"`
	Now          int64    `json:"now"`
	Cases        []VCase  `json:"cases"`
	Notes        []string `json:"notes"`
}

// VReuse is a later presentation of the same credential, optionally with
// another payment description (default: the same one).
type VReuse struct {
	Payment *VPayment `json:"payment,omitempty"`
	VExpect
}

func ok() VExpect                              { return VExpect{OK: true} }
func refuse(c gatecred.Code, f string) VExpect { return VExpect{Code: string(c), Field: f} }

func basePayment() VPayment {
	return VPayment{WalletID: VectorsWallet, Chain: VectorsChain, Asset: "native", Payee: VectorsPayee, Amount: "1000000000000000"}
}

func baseFields(kid string) Fields {
	return Fields{
		"v": int64(1), "kid": kid,
		"credential_id": "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a01",
		"obligation_id": "obl-2026-09-21-0001", "audience": VectorsAudience,
		"wallet_id": VectorsWallet, "chain": VectorsChain, "asset": "native",
		"payee": VectorsPayee, "amount": "1000000000000000",
		"issued_at": VectorsNow - 10, "expires_at": VectorsNow + 590,
		"policy_version": "policy-v12", "decision_reason": "within daily budget; tool call approved by rule r-7",
	}
}

func (f Fields) with(kv ...any) Fields {
	g := Fields{}
	for k, v := range f {
		g[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(g, kv[i].(string))
		} else {
			g[kv[i].(string)] = kv[i+1]
		}
	}
	return g
}

func i64(n int64) *int64 { return &n }

// Generate returns the exact bytes of testdata/gate-credential/vectors.json.
func Generate() ([]byte, error) {
	k1, k2, k3 := TestKey(1), TestKey(2), TestKey(3)
	pk := func(k Key) string { return base64.RawURLEncoding.EncodeToString(k.Pub) }
	v := Vectors{
		TestOnly:     "TEST ONLY. Every key in this file is derived from a public string and signs nothing real. Never configure these keys anywhere that matters.",
		Format:       "qv-gate-credential-vectors/1",
		DomainPrefix: gatecred.DomainPrefix,
		KeyDerive:    "Ed25519 seed = SHA-256 of the ASCII bytes of seed_string (RFC 8032 seed form). Only public keys are listed; derive the signing key with that rule to mint more cases. Key 3 is deliberately not in config.keys.",
		Config: VConfig{
			Audience: VectorsAudience, SkewSecs: 30, MaxTTLSecs: 600,
			Keys: []VKey{{KID: k1.KID, PublicKey: pk(k1), Seed: k1.Seed}, {KID: k2.KID, PublicKey: pk(k2), Seed: k2.Seed}},
		},
		Now: VectorsNow,
		Notes: []string{
			"credential is the exact text received (a JSON object); null means no credential was sent.",
			"signed_bytes_hex is what the verifier computes from the parsed credential: domain_prefix, then the RFC 8785 form of every field except sig. It is present when the credential parses (even if the signature is wrong).",
			"payment is what the zone decoded from the bytes it would sign; compare by exact string equality.",
			"now is the case's clock; when absent use the top-level now.",
			"then_expect_on_reuse: present the same credential again after its first use was accepted, with the entry's payment if it has one (else the case's). A pure verifier runs the pure checks; if they pass and the credential_id was already used, the result is replayed. The checker records credential_id (and the payload digest) at first use and refuses any later use whatever the payload, once the payment check has passed. The zone never returns a stored result for a repeat; only GC4's API layer does, for an identical request.",
			"credential_hex: when present, the exact bytes of the credential (not valid UTF-8, so they cannot sit in this file as text); credential is then null.",
			"Opaque fields (obligation_id, policy_version, decision_reason) are UTF-8 kept byte for byte, with no normalisation; control characters U+0000-U+001F and invalid UTF-8 are refused; limits are in bytes.",
			"The codes wallet_not_gate_governed, fast_lane_cap, client_not_authorized and payload_invalid depend on zone state or the request and have no vector here.",
		},
	}
	add := func(c VCase) { v.Cases = append(v.Cases, c) }
	// valid builds a case whose credential parses; the signature may be bad.
	build := func(name, desc string, f Fields, sig func(Fields) string, p VPayment, e VExpect) VCase {
		w := string(WireWithSig(f, sig(f)))
		return VCase{Name: name, Description: desc, Credential: &w, SignedBytes: hex.EncodeToString(SignedBytes(f)), Payment: p, Expect: e}
	}
	by := func(k Key) func(Fields) string { return func(f Fields) string { return Sign(k, f) } }
	good := baseFields(k1.KID)
	tok := good.with("asset", VectorsToken, "amount", "2500000", "credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a02")
	tokPay := basePayment()
	tokPay.Asset, tokPay.Amount = VectorsToken, "2500000"

	add(build("valid_evm_native", "Native transfer, key 1.", good, by(k1), basePayment(), ok()))
	add(build("valid_evm_token", "Token transfer: asset is the token contract, payee the recipient of transfer(), amount its value.", tok, by(k1), tokPay, ok()))
	e3 := tok.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a03")
	p3 := tokPay
	p3.ValidAfter, p3.ValidBefore = i64(VectorsNow-10), i64(VectorsNow+300)
	add(build("valid_eip3009", "EIP-3009 transferWithAuthorization: asset=verifyingContract, payee=to, amount=value, window inside the credential's.", e3, by(k1), p3, ok()))
	add(build("valid_second_key", "Signed by key 2 (rotation: both keys active).", good.with("kid", k2.KID, "credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a04"), by(k2), basePayment(), ok()))
	add(build("valid_ttl_exactly_max", "Lifetime of exactly 600 s is accepted.", good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a05", "issued_at", VectorsNow-10, "expires_at", VectorsNow+590), by(k1), basePayment(), ok()))
	c := build("valid_issued_at_skew_edge", "issued_at is exactly now+30 s: inside the skew.", good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a06", "issued_at", VectorsNow+30, "expires_at", VectorsNow+630), by(k1), basePayment(), ok())
	add(c)
	c = build("valid_expired_within_skew", "now is expires_at+29 s: still inside the skew.", good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a07", "issued_at", VectorsNow-600, "expires_at", VectorsNow-29), by(k1), basePayment(), ok())
	add(c)
	// Same credential as valid_evm_native, in another byte layout: reordered fields, spaces, an escaped letter.
	w := string(Wire(k1, good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a08")))
	re := `{ "sig" : ` + w[strings.Index(w, `"sig":`)+6:len(w)-1] + `, "decision_reason":"within daily budget; tool call approved by rule r-7", "payee":"` + VectorsPayee + `", "kid":"test-only-1", "v":1, "amount":"1000000000000000", "asset":"native", "chain":"` + VectorsChain + `", "credential_id":"0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a08", "obligation_id":"obl-2026-09-21-0001", "policy_version":"policy-v\u0031\u0032" , "audience":"` + VectorsAudience + `", "wallet_id":"` + VectorsWallet + `", "issued_at":` + "1789999990" + `, "expires_at":1790000590 }`
	add(VCase{Name: "valid_other_byte_layout", Description: "Same credential with fields in another order, spaces around tokens and an escaped digit (\\u0031): valid, because the signature covers the canonical form, not the received text.",
		Credential: &re, SignedBytes: hex.EncodeToString(SignedBytes(good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a08"))), Payment: basePayment(), Expect: ok()})

	id := func(n string) string { return "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e" + n }
	for _, u := range []struct{ name, desc, reason, id string }{
		{"valid_decision_reason_non_ascii", "decision_reason with non-ASCII letters (kept byte for byte, no normalisation).", "caf\u00e9 \u5ba1\u6279\u901a\u8fc7 \u00fcber", "1f01"},
		{"valid_decision_reason_outside_bmp", "decision_reason with characters above U+FFFF (a 4-byte UTF-8 sequence, a surrogate pair if escaped).", "ok \U0001F600 \U0001D4B3", "1f02"},
		{"valid_decision_reason_quote_backslash", "decision_reason with a quote and a backslash: the canonical form escapes both.", `say "yes" to C:\pay\x <a&b>`, "1f03"},
		{"valid_decision_reason_line_separator", "decision_reason with U+2028 and U+007F: RFC 8785 writes them as they are (Go's encoding/json would escape U+2028).", "a\u2028b\u007fc", "1f04"},
		{"valid_decision_reason_decomposed", "decision_reason in decomposed form (e + U+0301): not normalised, so it differs from the composed form byte for byte.", "cafe\u0301", "1f05"},
	} {
		add(build(u.name, u.desc, good.with("credential_id", id(u.id), "decision_reason", u.reason, "obligation_id", "obl-\u00e9-1", "policy_version", "v\u00e9"), by(k1), basePayment(), ok()))
	}
	escaped := string(Wire(k1, good.with("credential_id", id("1f06"), "decision_reason", "ok \U0001F600")))
	escaped = strings.Replace(escaped, "\U0001F600", `\ud83d\ude00`, 1)
	add(VCase{Name: "valid_surrogate_pair_escape", Description: "The same non-BMP character written as the escape pair \\ud83d\\ude00: valid, equal to the character itself.", Credential: &escaped, SignedBytes: hex.EncodeToString(SignedBytes(good.with("credential_id", id("1f06"), "decision_reason", "ok \U0001F600"))), Payment: basePayment(), Expect: ok()})

	// Signature cases.
	f := good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1b01")
	sigBytes, _ := base64.RawURLEncoding.DecodeString(Sign(k1, f))
	sigBytes[0] ^= 0x01
	add(build("bad_signature", "One bit of the signature flipped.", f, func(Fields) string { return base64.RawURLEncoding.EncodeToString(sigBytes) }, basePayment(), refuse(gatecred.SignatureInvalid, "")))
	orig := good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1b02")
	tampered := orig.with("amount", "9000000000000000")
	tp := basePayment()
	tp.Amount = "9000000000000000"
	add(build("amount_tampered_after_signing", "Signed for 1000000000000000, then the amount was edited (the payment matches the edit): the signature fails.", tampered, func(Fields) string { return Sign(k1, orig) }, tp, refuse(gatecred.SignatureInvalid, "")))
	add(build("kid_claims_wrong_key", "Signed by key 2 but names key 1.", good.with("credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1b03"), by(k2), basePayment(), refuse(gatecred.SignatureInvalid, "")))
	add(build("unknown_kid", "Signed by key 3, which is not in the key set.", good.with("kid", k3.KID, "credential_id", "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1b04"), by(k3), basePayment(), refuse(gatecred.KIDUnknown, "kid")))

	// Binding and time cases (all correctly signed).
	sg := func(name, desc string, f Fields, p VPayment, e VExpect) { add(build(name, desc, f, by(k1), p, e)) }
	sg("audience_mismatch", "Credential names another deployment.", good.with("audience", "qv-prod", "credential_id", id("1c01")), basePayment(), refuse(gatecred.AudienceMismatch, "audience"))
	wp := basePayment()
	wp.WalletID = "aaaaaaaa-0000-4000-8000-000000000001"
	sg("wallet_mismatch", "The payment is from another wallet than the credential names.", good.with("credential_id", id("1c02")), wp, refuse(gatecred.WalletMismatch, "wallet_id"))
	sg("ttl_too_long", "Lifetime 601 s, limit 600 s.", good.with("credential_id", id("1c03"), "issued_at", VectorsNow-10, "expires_at", VectorsNow+591), basePayment(), refuse(gatecred.TTLTooLong, "expires_at"))
	sg("ttl_overflow", "Lifetime of about 10^10 s: a verifier that multiplies seconds into nanoseconds in 64 bits wraps and accepts it.", good.with("credential_id", id("1c06"), "issued_at", VectorsNow-10, "expires_at", int64(11790000000)), basePayment(), refuse(gatecred.TTLTooLong, "expires_at"))
	sg("future_dated", "issued_at is now+31 s, one second past the skew.", good.with("credential_id", id("1c04"), "issued_at", VectorsNow+31, "expires_at", VectorsNow+631), basePayment(), refuse(gatecred.NotYetValid, "issued_at"))
	sg("expired", "now is expires_at+30 s: the skew is used up.", good.with("credential_id", id("1c05"), "issued_at", VectorsNow-600, "expires_at", VectorsNow-30), basePayment(), refuse(gatecred.Expired, "expires_at"))
	mm := func(name, field string, mut func(*VPayment)) {
		p := basePayment()
		mut(&p)
		sg(name, "The payload decoded by the zone differs in "+field+".", good.with("credential_id", id("1d"+map[string]string{"chain": "01", "asset": "02", "payee": "03", "amount": "04"}[field])), p, refuse(gatecred.PaymentMismatch, field))
	}
	mm("payment_chain_mismatch", "chain", func(p *VPayment) { p.Chain = "eip155:8453" })
	mm("payment_asset_mismatch", "asset", func(p *VPayment) { p.Asset = VectorsToken })
	mm("payment_payee_mismatch", "payee", func(p *VPayment) { p.Payee = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc" })
	mm("payment_amount_mismatch", "amount", func(p *VPayment) { p.Amount = "1000000000000001" })
	e3b := e3.with("credential_id", id("1e01"))
	pw := p3
	pw.ValidAfter = i64(VectorsNow - 11)
	sg("authorization_starts_before_credential", "EIP-3009 validAfter is one second before issued_at.", e3b, pw, refuse(gatecred.AuthorizationWindow, ""))
	pw2 := p3
	pw2.ValidBefore = i64(VectorsNow + 591)
	sg("authorization_ends_after_credential", "EIP-3009 validBefore is one second after expires_at.", e3b.with("credential_id", id("1e02")), pw2, refuse(gatecred.AuthorizationWindow, ""))

	// Missing and malformed.
	add(VCase{Name: "credential_absent", Description: "No credential sent.", Credential: nil, Payment: basePayment(), Expect: refuse(gatecred.CredentialMissing, "")})
	empty := ""
	add(VCase{Name: "credential_empty_string", Description: "Empty credential text.", Credential: &empty, Payment: basePayment(), Expect: refuse(gatecred.CredentialMissing, "")})
	mal := func(name, desc string, w string, field string) {
		add(VCase{Name: name, Description: desc, Credential: &w, Payment: basePayment(), Expect: refuse(gatecred.CredentialMalformed, field)})
	}
	malSigned := func(name, desc string, f Fields, field string) {
		// correctly signed with key 1: the refusal is for the format, not the signature
		w := string(Wire(k1, f))
		c := VCase{Name: name, Description: desc, Credential: &w, Payment: basePayment(), Expect: refuse(gatecred.CredentialMalformed, field)}
		add(c)
	}
	mal("not_json", "Text that is not JSON.", "credential", "")
	mal("json_array", "A JSON array.", "[]", "")
	mal("trailing_data", "A valid credential followed by more text.", string(Wire(k1, good.with("credential_id", id("2a01"))))+" {}", "")
	dup := string(Wire(k1, good.with("credential_id", id("2a02"))))
	dup = dup[:len(dup)-1] + `,"amount":"1"}`
	mal("duplicate_field", "A field name appears twice (the second amount would win in many parsers).", dup, "amount")
	malSigned("unknown_field", "A correctly signed credential with an extra field: refused, never ignored.", good.with("credential_id", id("2b01"), "note", "hello"), "note")
	malSigned("missing_field", "A correctly signed credential without decision_reason.", good.with("credential_id", id("2b02"), "decision_reason", nil), "decision_reason")
	nosig := string(WireWithSig(good.with("credential_id", id("2b03")), ""))
	nosig = strings.Replace(nosig, `,"sig":""`, "", 1)
	mal("missing_signature", "No sig field.", nosig, "sig")
	pad := string(WireWithSig(good.with("credential_id", id("2b04")), Sign(k1, good.with("credential_id", id("2b04")))+"=="))
	mal("signature_with_padding", "Signature in base64 with padding: refused, not tolerated.", pad, "sig")
	mal("signature_wrong_length", "Signature of 63 bytes.", string(WireWithSig(good.with("credential_id", id("2b05")), base64.RawURLEncoding.EncodeToString(make([]byte, 63)))), "sig")
	malSigned("version_2", "v is 2, which this contract does not define.", good.with("credential_id", id("2c01"), "v", int64(2)), "v")
	malSigned("amount_zero", "amount \"0\".", good.with("credential_id", id("2c02"), "amount", "0"), "amount")
	malSigned("amount_leading_zero", "amount \"01000\".", good.with("credential_id", id("2c03"), "amount", "01000"), "amount")
	malSigned("amount_negative", "amount \"-5\".", good.with("credential_id", id("2c04"), "amount", "-5"), "amount")
	malSigned("amount_decimal_point", "amount \"1.5\".", good.with("credential_id", id("2c05"), "amount", "1.5"), "amount")
	malSigned("amount_above_uint256", "amount is 2^256 (one more than the largest value).", good.with("credential_id", id("2c06"), "amount", "115792089237316195423570985008687907853269984665640564039457584007913129639936"), "amount")
	malSigned("amount_is_number", "amount sent as a JSON number.", good.with("credential_id", id("2c07"), "amount", int64(1000)), "amount")
	malSigned("payee_checksum_case", "payee in mixed (EIP-55) case: the contract wants lower case only.", good.with("credential_id", id("2c08"), "payee", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), "payee")
	malSigned("payee_short", "payee with 39 hex digits.", good.with("credential_id", id("2c09"), "payee", VectorsPayee[:41]), "payee")
	malSigned("asset_bad", "asset \"NATIVE\".", good.with("credential_id", id("2c0a"), "asset", "NATIVE"), "asset")
	malSigned("chain_leading_zero", "chain \"eip155:084532\".", good.with("credential_id", id("2c0b"), "chain", "eip155:084532"), "chain")
	malSigned("chain_other_namespace", "chain from a namespace this version does not define.", good.with("credential_id", id("2c0c"), "chain", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"), "chain")
	malSigned("credential_id_upper_case", "credential_id in upper case.", good.with("credential_id", strings.ToUpper(id("2c0d"))), "credential_id")
	malSigned("expires_before_issued", "expires_at not after issued_at.", good.with("credential_id", id("2c0e"), "issued_at", VectorsNow, "expires_at", VectorsNow), "expires_at")
	malSigned("time_as_string", "issued_at sent as a string.", good.with("credential_id", id("2c0f"), "issued_at", "1789999990"), "issued_at")
	malSigned("decision_reason_control_character", "decision_reason holds a raw control character (U+0001).", good.with("credential_id", id("2c10"), "decision_reason", "a\x01b"), "decision_reason")
	malSigned("decision_reason_newline", "decision_reason holds a line feed (written as \\n in the text).", good.with("credential_id", id("2c13"), "decision_reason", "line one\nline two"), "decision_reason")
	malSigned("obligation_id_too_long_in_bytes", "obligation_id of 43 three-byte characters = 129 bytes: limits count bytes.", good.with("credential_id", id("2c14"), "obligation_id", strings.Repeat("\u4e2d", 43)), "obligation_id")
	bad8 := []byte(string(Wire(k1, good.with("credential_id", id("2c15"), "decision_reason", "XX"))))
	bad8 = bytes.Replace(bad8, []byte("XX"), []byte{0xc3, 0x28}, 1)
	add(VCase{Name: "decision_reason_invalid_utf8", Description: "decision_reason holds the bytes C3 28, which are not valid UTF-8 (see credential_hex).", CredentialHex: hex.EncodeToString(bad8), Payment: basePayment(), Expect: refuse(gatecred.CredentialMalformed, "")})
	lone := string(Wire(k1, good.with("credential_id", id("2c16"), "decision_reason", "XXXXXX")))
	lone = strings.Replace(lone, "XXXXXX", `\ud800`, 1)
	mal("decision_reason_lone_surrogate_escape", "decision_reason written with the escape \\ud800 alone, which is not a character.", lone, "")
	malSigned("kid_bad_character", "kid with a space.", good.with("credential_id", id("2c11"), "kid", "test only"), "kid")
	w2 := string(Wire(k1, good.with("credential_id", id("2c12"))))
	w2 = strings.Replace(w2, `"issued_at":1789999990`, `"issued_at":1.78999999e9`, 1)
	mal("time_as_float", "issued_at written as 1.78999999e9.", w2, "issued_at")

	// Replay: a pair of uses of one credential.
	r := build("replay_pair", "The same credential presented twice: the first use is accepted, the second is refused as replayed.", good.with("credential_id", id("3a01")), by(k1), basePayment(), ok())
	r.Then = []VReuse{{VExpect: refuse(gatecred.Replayed, "")}}
	add(r)
	// Same decoded payment, different bytes to sign (for example another nonce or fee).
	dA, dB := "aa"+strings.Repeat("00", 31), "bb"+strings.Repeat("00", 31)
	pA, pB := basePayment(), basePayment()
	pA.PayloadDigest, pB.PayloadDigest = dA, dB
	r3 := build("replay_same_credential_other_payload", "First use with payload digest A is accepted and records credential_id with A. A second use with payload B that decodes to the same payment passes every pure check and is refused as replayed: the checker refuses any later use of a recorded credential_id, whatever the payload.", good.with("credential_id", id("3a03")), by(k1), pA, ok())
	r3.Then = []VReuse{{Payment: &pB, VExpect: refuse(gatecred.Replayed, "")}}
	add(r3)
	pC := basePayment()
	pC.Amount, pC.PayloadDigest = "1000000000000001", dB
	r4 := build("replay_same_credential_other_amount", "A second use whose payload decodes to another amount fails the payment check first (payment_mismatch); the replay record is only reached by a payload that decodes to the credential's payment.", good.with("credential_id", id("3a04")), by(k1), pA, ok())
	r4.Then = []VReuse{{Payment: &pC, VExpect: refuse(gatecred.PaymentMismatch, "amount")}}
	add(r4)

	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
