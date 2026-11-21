package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Limits and defaults. The field lengths come from the document layout in [NSM-API] ("Attestation document specification"): module_id and
// digest are text; pcrs holds 1 to 32 entries (index 0..31) of 32, 48 or 64 bytes; certificate and each cabundle entry are 1..1024 bytes,
// cabundle has at least one entry; public_key and user_data are at most 1024 bytes, nonce at most 512.
const (
	maxDocBytes      = 32 << 10 // our own bound on the input; real documents are about 5 KB
	maxPCRs          = 32
	maxCertBytes     = 1024
	maxCABundle      = 16 // our bound; real bundles hold 4 certificates
	maxPublicKey     = 1024
	maxUserData      = 1024
	maxNonce         = 512
	nitroDigest      = "SHA384" // [NSM-API]: the only digest, used for the PCRs
	coseAlgES384     = -35      // [COSE] RFC 9053 table: ECDSA w/ SHA-384
	coseHeaderAlg    = 1        // [COSE] RFC 9052 table 3: label of "alg"
	coseTagSign1     = 18       // [COSE] RFC 9052 table 1: CBOR tag of COSE_Sign1
	es384SigBytes    = 96       // [COSE] RFC 9053 2.1: r and s, each as a fixed-length 48-byte integer, concatenated
	DefaultMaxAge    = 5 * time.Minute
	DefaultMaxFuture = time.Minute
)

// nitroDoc is the payload of the COSE_Sign1 ([NSM-API]: "Attestation document specification"). Optional fields are CBOR null when absent.
type nitroDoc struct {
	ModuleID    string            `cbor:"module_id"`
	Digest      string            `cbor:"digest"`
	Timestamp   uint64            `cbor:"timestamp"` // milliseconds since the Unix epoch
	PCRs        map[uint64][]byte `cbor:"pcrs"`
	Certificate []byte            `cbor:"certificate"` // DER, the leaf that signed the document
	CABundle    [][]byte          `cbor:"cabundle"`    // DER certificates, root first ([AWS-DOC]: "the CA bundle ... ordered root first")
	PublicKey   []byte            `cbor:"public_key"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
}

// coseSign1 is [COSE] RFC 9052 4.2: [protected (bstr), unprotected (map), payload (bstr), signature (bstr)].
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

var (
	strictDec cbor.DecMode
	encMode   cbor.EncMode
)

func init() {
	var err error
	// Strict decoding: no duplicate map keys, no indefinite-length items, bounded nesting and sizes.
	strictDec, err = cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  8,
		MaxArrayElements: 64,
		MaxMapPairs:      64,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	encMode, err = cbor.EncOptions{}.EncMode()
	if err != nil {
		panic(err)
	}
}

// sigStructure is the data ES384 signs: [COSE] RFC 9052 4.4, Sig_structure for COSE_Sign1:
// ["Signature1", body_protected, external_aad (empty), payload].
func sigStructure(protected, payload []byte) ([]byte, error) {
	return encMode.Marshal([]any{"Signature1", protected, []byte{}, payload})
}

// NitroConfig configures the verifier. All fields are config data supplied by the caller; nothing is compiled in.
type NitroConfig struct {
	Roots         []*x509.Certificate // trust roots: the vendor root in production (AWS_NitroEnclaves_Root-G1), a test root in simulation
	MaxAge        time.Duration       // how old a document may be at verification time; default DefaultMaxAge
	MaxFutureSkew time.Duration       // how far ahead of the verifier's clock a document may be; default DefaultMaxFuture
	AllowDebug    bool                // accept debug-mode (all-zero PCR) documents. Never set it in production.
}

// NitroVerifier verifies AWS Nitro attestation documents. It makes no network call and has no switch that skips a rule. Revocation (CRL/OCSP)
// is not checked and stays off: the Nitro PKI is verified offline against its root (research/TEE.md, Q2).
type NitroVerifier struct {
	roots []*x509.Certificate
	cfg   NitroConfig
}

var _ Verifier = (*NitroVerifier)(nil)

// NewNitroVerifier checks the configuration and returns the verifier.
func NewNitroVerifier(cfg NitroConfig) (*NitroVerifier, error) {
	if len(cfg.Roots) == 0 {
		return nil, errors.New("attest: no trust roots configured")
	}
	for i, r := range cfg.Roots {
		if r == nil || !r.IsCA || r.CheckSignatureFrom(r) != nil {
			return nil, fmt.Errorf("attest: trust root %d is not a self-signed CA certificate", i)
		}
	}
	if cfg.MaxAge < 0 || cfg.MaxFutureSkew < 0 {
		return nil, errors.New("attest: negative time window")
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.MaxFutureSkew == 0 {
		cfg.MaxFutureSkew = DefaultMaxFuture
	}
	return &NitroVerifier{roots: append([]*x509.Certificate(nil), cfg.Roots...), cfg: cfg}, nil
}

// ParseRootsPEM reads PEM trust roots (a file the operator mounts), for NitroConfig.Roots.
func ParseRootsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attest: trust root: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("attest: no certificate in the root file")
	}
	return out, nil
}

// Verify checks evidence ([AWS-DOC] "Validating the attestation document": syntactic, certificate chain, COSE signature) plus our own rules:
// freshness, debug mode, nonce, user data and public key. It returns the claims or an *Error naming the first rule that failed.
func (v *NitroVerifier) Verify(evidence []byte, expect Expect, now time.Time) (*Claims, error) {
	if len(expect.Nonce) == 0 {
		return nil, fail(RuleExpectation, "an expected nonce is required")
	}
	claims, err := v.authenticate(evidence, now)
	if err != nil {
		return nil, err
	}
	// 7. Binding to the request. [NSM-API]: nonce is the relying party's replay defence, public_key what the response is encrypted to,
	//    user_data protocol-defined content. All three are compared in constant time.
	if len(claims.Nonce) == 0 {
		return nil, fail(RuleNonce, "document has no nonce")
	}
	if !ctEqual(claims.Nonce, expect.Nonce) {
		return nil, fail(RuleNonce, "nonce differs from the expected one")
	}
	if !ctEqual(claims.UserData, expect.UserData) {
		return nil, fail(RuleUserData, "user_data differs from the expected one")
	}
	if len(claims.PublicKey) == 0 {
		return nil, fail(RulePublicKey, "document has no public_key")
	}
	if len(expect.PublicKey) > 0 && !ctEqual(claims.PublicKey, expect.PublicKey) {
		return nil, fail(RulePublicKey, "public_key differs from the expected one")
	}
	return claims, nil
}

// authenticate runs every rule that is about the document itself, not about the request: envelope, algorithm, fields, certificate chain to the
// configured root, signature, freshness, debug mode. It stays unexported on purpose: only Verify (which then checks the binding) is the API,
// and a document that passed authenticate alone is not yet evidence for anything. In-package tests use it to check a real AWS document that
// carries no nonce or public key.
func (v *NitroVerifier) authenticate(evidence []byte, now time.Time) (*Claims, error) {
	if len(evidence) == 0 || len(evidence) > maxDocBytes {
		return nil, fail(RuleFormat, "document is %d bytes (allowed 1..%d)", len(evidence), maxDocBytes)
	}

	// 1. COSE_Sign1 envelope and algorithm.
	s, err := parseSign1(evidence)
	if err != nil {
		return nil, err
	}
	var doc nitroDoc
	if err := strictDec.Unmarshal(s.Payload, &doc); err != nil {
		return nil, &Error{Rule: RuleFormat, Detail: "payload", Err: err}
	}

	// 2. Required fields and sizes ([NSM-API] document specification).
	if err := checkFields(&doc); err != nil {
		return nil, err
	}
	ts := time.UnixMilli(int64(doc.Timestamp))

	// 3. Certificate chain. [AWS-DOC]: cabundle is ordered root first; the leaf in "certificate" is signed by the last bundle entry; the root
	//    must be the trusted vendor root, compared by content, not by name.
	leaf, err := verifyChain(&doc, v.roots, ts)
	if err != nil {
		return nil, err
	}

	// 4. COSE signature under the leaf's P-384 key.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, fail(RuleAlgorithm, "leaf certificate key is not ECDSA P-384")
	}
	if err := verifySign1(pub, s.Protected, s.Payload, s.Signature); err != nil {
		return nil, err
	}

	// 5. Freshness (our rule: a document is a statement about now; [AWS-DOC] leaves the window to the relying party).
	if ts.After(now.Add(v.cfg.MaxFutureSkew)) {
		return nil, fail(RuleFuture, "document time %s is ahead of now %s", ts.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if now.Sub(ts) > v.cfg.MaxAge {
		return nil, fail(RuleStale, "document time %s is older than %s", ts.UTC().Format(time.RFC3339), v.cfg.MaxAge)
	}

	claims := &Claims{
		EvidenceType: EvidenceTypeNitro,
		ModuleID:     doc.ModuleID,
		Measurements: make(map[int][]byte, len(doc.PCRs)),
		Nonce:        doc.Nonce,
		PublicKey:    doc.PublicKey,
		UserData:     doc.UserData,
		Timestamp:    ts,
	}
	for i, p := range doc.PCRs {
		claims.Measurements[int(i)] = p
	}
	// 6. Debug mode. [AWS-DOC]/nitro-cli: an enclave started with --debug-mode gets all-zero PCR0..PCR2 in its documents, so a debug (or
	//    simulated) enclave cannot pass for a production one. PCR0 is required, so absence is not "debug".
	claims.Debug = allZero(doc.PCRs[0]) && allZeroIfPresent(doc.PCRs, 1) && allZeroIfPresent(doc.PCRs, 2)
	if p8 := doc.PCRs[8]; len(p8) > 0 && !allZero(p8) {
		claims.Signer = fmt.Sprintf("%x", p8)
	}
	if claims.Debug && !v.cfg.AllowDebug {
		return nil, fail(RuleDebug, "debug-mode document (all-zero PCRs)")
	}

	return claims, nil
}

// parseSign1 decodes the COSE_Sign1 envelope and checks the protected algorithm is ES384. [AWS-DOC]: the document is a CBOR-encoded
// COSE_Sign1; NSM output carries tag 18, some tools omit it. Nothing but that optional tag may precede the array.
func parseSign1(evidence []byte) (*coseSign1, error) {
	b := evidence
	if b[0] == 0xC0|coseTagSign1 { // major type 6, value 18
		b = b[1:]
	}
	if len(b) == 0 || b[0] != 0x84 { // definite array of 4
		return nil, fail(RuleFormat, "not a COSE_Sign1 (tag 18 or untagged array of four)")
	}
	var s coseSign1
	if err := strictDec.Unmarshal(b, &s); err != nil {
		return nil, &Error{Rule: RuleFormat, Detail: "not a COSE_Sign1 array", Err: err}
	}
	if len(s.Unprotected) == 0 || s.Unprotected[0]>>5 != 5 { // major type 5: map
		return nil, fail(RuleFormat, "unprotected header is not a map")
	}
	var prot map[int64]any
	if err := strictDec.Unmarshal(s.Protected, &prot); err != nil {
		return nil, &Error{Rule: RuleFormat, Detail: "protected header", Err: err}
	}
	// [AWS-DOC]/[NSM-API]: the signing algorithm is ECDSA w/ SHA-384 (alg -35); nothing else is accepted.
	if alg, ok := prot[coseHeaderAlg]; !ok || fmt.Sprint(alg) != fmt.Sprint(coseAlgES384) {
		return nil, fail(RuleAlgorithm, "protected alg is %v, want %d (ES384)", alg, coseAlgES384)
	}
	return &s, nil
}

// verifySign1 checks an ES384 COSE_Sign1 signature ([COSE] RFC 9052 4.4 Sig_structure, RFC 9053 2.1) with no payload rules, so a published
// test vector can drive it.
func verifySign1(pub *ecdsa.PublicKey, protected, payload, sig []byte) error {
	if len(sig) != es384SigBytes {
		return fail(RuleSignature, "signature is %d bytes, want %d", len(sig), es384SigBytes)
	}
	tbs, err := sigStructure(protected, payload)
	if err != nil {
		return &Error{Rule: RuleFormat, Detail: "sig_structure", Err: err}
	}
	h := sha512.Sum384(tbs)
	r := new(big.Int).SetBytes(sig[:es384SigBytes/2])
	sv := new(big.Int).SetBytes(sig[es384SigBytes/2:])
	if !ecdsa.Verify(pub, h[:], r, sv) {
		return fail(RuleSignature, "ES384 signature does not verify")
	}
	return nil
}

func checkFields(d *nitroDoc) error {
	if d.ModuleID == "" {
		return fail(RuleMissingField, "module_id")
	}
	if d.Digest != nitroDigest {
		return fail(RuleMissingField, "digest is %q, want %q", d.Digest, nitroDigest)
	}
	if d.Timestamp == 0 || d.Timestamp > 1<<62 {
		return fail(RuleMissingField, "timestamp")
	}
	if len(d.PCRs) < 1 || len(d.PCRs) > maxPCRs {
		return fail(RuleSize, "pcrs has %d entries, want 1..%d", len(d.PCRs), maxPCRs)
	}
	for i, p := range d.PCRs {
		if i >= maxPCRs {
			return fail(RuleSize, "pcr index %d, want 0..%d", i, maxPCRs-1)
		}
		if n := len(p); n != 32 && n != 48 && n != 64 {
			return fail(RuleSize, "pcr %d is %d bytes, want 32, 48 or 64", i, n)
		}
	}
	if _, ok := d.PCRs[0]; !ok {
		return fail(RuleMissingField, "pcr 0 (the image measurement)")
	}
	if n := len(d.Certificate); n < 1 || n > maxCertBytes {
		return fail(RuleSize, "certificate is %d bytes, want 1..%d", n, maxCertBytes)
	}
	if n := len(d.CABundle); n < 1 || n > maxCABundle {
		return fail(RuleSize, "cabundle has %d certificates, want 1..%d", n, maxCABundle)
	}
	for i, c := range d.CABundle {
		if n := len(c); n < 1 || n > maxCertBytes {
			return fail(RuleSize, "cabundle[%d] is %d bytes, want 1..%d", i, n, maxCertBytes)
		}
	}
	if len(d.PublicKey) > maxPublicKey {
		return fail(RuleSize, "public_key is %d bytes, max %d", len(d.PublicKey), maxPublicKey)
	}
	if len(d.UserData) > maxUserData {
		return fail(RuleSize, "user_data is %d bytes, max %d", len(d.UserData), maxUserData)
	}
	if len(d.Nonce) > maxNonce {
		return fail(RuleSize, "nonce is %d bytes, max %d", len(d.Nonce), maxNonce)
	}
	return nil
}

// verifyChain checks cabundle[0] is a configured root, every following certificate is signed by the one before it, the leaf by the last one,
// every certificate is valid at the document's own time, and (as a backstop for CA flags and path length) that Go's verifier agrees.
func verifyChain(d *nitroDoc, roots []*x509.Certificate, at time.Time) (*x509.Certificate, error) {
	bundle := make([]*x509.Certificate, len(d.CABundle))
	for i, der := range d.CABundle {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &Error{Rule: RuleFormat, Detail: fmt.Sprintf("cabundle[%d]", i), Err: err}
		}
		bundle[i] = c
	}
	leaf, err := x509.ParseCertificate(d.Certificate)
	if err != nil {
		return nil, &Error{Rule: RuleFormat, Detail: "certificate", Err: err}
	}
	isRoot := func(c *x509.Certificate) bool {
		for _, r := range roots {
			if bytes.Equal(r.Raw, c.Raw) {
				return true
			}
		}
		return false
	}
	if !isRoot(bundle[0]) {
		for _, c := range bundle[1:] {
			if isRoot(c) {
				return nil, fail(RuleChainOrder, "the trusted root is not first in cabundle")
			}
		}
		return nil, fail(RuleUntrusted, "cabundle[0] is not a configured trust root")
	}
	for i := 1; i < len(bundle); i++ {
		if err := bundle[i].CheckSignatureFrom(bundle[i-1]); err != nil {
			return nil, &Error{Rule: RuleChainOrder, Detail: fmt.Sprintf("cabundle[%d] is not signed by cabundle[%d]", i, i-1), Err: err}
		}
	}
	if err := leaf.CheckSignatureFrom(bundle[len(bundle)-1]); err != nil {
		return nil, &Error{Rule: RuleChainOrder, Detail: "certificate is not signed by the last cabundle entry", Err: err}
	}
	for i, c := range append(append([]*x509.Certificate{}, bundle...), leaf) {
		if at.Before(c.NotBefore) || at.After(c.NotAfter) {
			name := fmt.Sprintf("cabundle[%d]", i)
			if i == len(bundle) {
				name = "certificate"
			}
			return nil, fail(RuleCertValidity, "%s is valid %s..%s, document time is %s", name,
				c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
		}
	}
	pool, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	for _, c := range bundle[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, &Error{Rule: RuleChainOrder, Detail: "chain does not verify", Err: err}
	}
	return leaf, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return len(b) > 0
}

func allZeroIfPresent(m map[uint64][]byte, i uint64) bool {
	v, ok := m[i]
	return !ok || allZero(v)
}

func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
