//go:build teesim

// Package kmsfake is a fake AWS KMS for tests: it speaks the JSON 1.1 protocol of Decrypt and GenerateDataKey, checks the SigV4 signature, verifies the
// attestation document with the real NitroVerifier (trust root = a test root), evaluates the condition semantics of the key policy that
// deploy/cloud/aws/modules/nitro-enclave-key writes, and answers with a correctly formed CiphertextForRecipient. Simulation builds only (-tags teesim): the
// production party does not contain it (TestProductionPartyHasNoKMSFake).
//
// What it cannot prove: that AWS KMS evaluates the conditions this way. The semantics come from the AWS documentation
// (https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html, read 2026-11-20): kms:RecipientAttestation:ImageSha384 is PCR0;
// kms:RecipientAttestation:PCR<n> is a lower-case hex string; StringEqualsIgnoreCase compares them; a request without a valid attestation document does not
// satisfy the condition, so it is denied. The first real call is item "KMS condition evaluation" of docs/runbooks/nitro-first-run.md.
package kmsfake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// Policy is the PCR condition set of the key policy: every entry must equal (case-insensitively) the PCR of the document. PCRs maps a PCR index to
// its lower-case hex value; index 0 is kms:RecipientAttestation:ImageSha384 as well. An empty Policy is refused by New: a key policy with no PCR
// condition would let any enclave (or any caller with the role) use the key, which is the mistake the Terraform tests also refuse.
type Policy struct {
	PCRs map[int]string
}

// Call is one request the fake saw.
type Call struct {
	Op      string
	PCR0    string
	Allowed bool
	Reason  string // "" when allowed, else the exception name
}

// Fake is the server. Create with New, close with Close.
type Fake struct {
	URL         string
	KeyID       string
	AccessKeyID string
	Secret      string
	Token       string
	Verifier    *attest.NitroVerifier
	Now         func() time.Time
	Indefinite  bool // emit BER with indefinite lengths, as KMS does (default true in New)

	mu     sync.Mutex
	policy Policy
	master cipher.AEAD
	calls  []Call
	srv    *httptest.Server
}

// New starts a fake KMS that trusts documents verified by v and applies policy.
func New(keyID string, v *attest.NitroVerifier, policy Policy) (*Fake, error) {
	if len(policy.PCRs) == 0 {
		return nil, errors.New("kmsfake: a key policy without a PCR condition is refused")
	}
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	blk, _ := aes.NewCipher(mk)
	g, _ := cipher.NewGCM(blk)
	f := &Fake{KeyID: keyID, AccessKeyID: "AKIAFAKEFAKEFAKEFAKE", Secret: randHex(20), Token: randHex(24), Verifier: v, Now: time.Now, Indefinite: true, policy: policy, master: g}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	f.URL = f.srv.URL
	return f, nil
}

func randHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

// SetCreds sets the credentials the fake accepts (tests that give the same environment credentials to several fakes).
func (f *Fake) SetCreds(accessKeyID, secret, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.AccessKeyID, f.Secret, f.Token = accessKeyID, secret, token
}

// Close stops the server.
func (f *Fake) Close() { f.srv.Close() }

// SetPolicy replaces the PCR conditions (a key-policy change).
func (f *Fake) SetPolicy(p Policy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy = p
}

// Calls returns what the fake saw.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

func (f *Fake) record(c Call) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

func deny(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || r.Method != http.MethodPost || r.URL.Path != "/" {
		deny(w, 400, "InvalidRequest", "bad request")
		return
	}
	if !f.checkSigV4(r, body) {
		f.record(Call{Op: r.Header.Get("X-Amz-Target"), Reason: "InvalidSignatureException"})
		deny(w, 400, "InvalidSignatureException", "signature mismatch")
		return
	}
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	var in struct {
		KeyID             string            `json:"KeyId"`
		CiphertextBlob    []byte            `json:"CiphertextBlob"`
		KeySpec           string            `json:"KeySpec"`
		EncryptionContext map[string]string `json:"EncryptionContext"`
		Recipient         *struct {
			AttestationDocument string `json:"AttestationDocument"`
			KeyEncryptionAlg    string `json:"KeyEncryptionAlgorithm"`
		} `json:"Recipient"`
	}
	if err := json.Unmarshal(body, &in); err != nil || (op != "Decrypt" && op != "GenerateDataKey") {
		deny(w, 400, "ValidationException", "bad body or operation")
		return
	}
	call := Call{Op: op}
	refuse := func(status int, typ, msg string) {
		call.Reason = typ
		f.record(call)
		deny(w, status, typ, msg)
	}
	if in.KeyID != f.KeyID {
		refuse(400, "NotFoundException", "key not found")
		return
	}
	// the key policy: every statement here carries PCR conditions, so a request without a valid attestation document does not satisfy them
	if in.Recipient == nil || in.Recipient.AttestationDocument == "" {
		refuse(400, "AccessDeniedException", "no attestation document: the PCR conditions of the key policy are not satisfied")
		return
	}
	if in.Recipient.KeyEncryptionAlg != "RSAES_OAEP_SHA_256" {
		refuse(400, "ValidationException", "KeyEncryptionAlgorithm")
		return
	}
	doc, err := base64.StdEncoding.DecodeString(in.Recipient.AttestationDocument)
	if err != nil {
		refuse(400, "ValidationException", "attestation document is not base64")
		return
	}
	claims, err := f.Verifier.AuthenticateOnly(doc, f.Now())
	if err != nil {
		refuse(400, "AccessDeniedException", "attestation document: "+err.Error())
		return
	}
	call.PCR0 = claims.Measurement()
	f.mu.Lock()
	pol := f.policy
	f.mu.Unlock()
	for _, idx := range sortedKeys(pol.PCRs) {
		got, ok := claims.Measurements[idx]
		if !ok || !strings.EqualFold(hex.EncodeToString(got), pol.PCRs[idx]) {
			refuse(400, "AccessDeniedException", "kms:RecipientAttestation:PCR"+itoa(idx)+" does not match the key policy")
			return
		}
	}
	pub, err := x509.ParsePKIXPublicKey(claims.PublicKey)
	rpub, ok := pub.(*rsa.PublicKey)
	if err != nil || !ok || rpub.N.BitLen() < 2048 {
		refuse(400, "ValidationException", "the document's public key is not RSA of at least 2048 bits")
		return
	}
	aad := ctxAAD(in.KeyID, in.EncryptionContext)
	var out map[string]any
	switch op {
	case "Decrypt":
		if len(in.CiphertextBlob) < 12+16 {
			refuse(400, "InvalidCiphertextException", "blob")
			return
		}
		pt, err := f.master.Open(nil, in.CiphertextBlob[:12], in.CiphertextBlob[12:], aad)
		if err != nil {
			refuse(400, "InvalidCiphertextException", "the blob does not open under this encryption context")
			return
		}
		env, err := Envelope(rpub, pt, f.Indefinite)
		if err != nil {
			refuse(500, "KMSInternalException", err.Error())
			return
		}
		out = map[string]any{"KeyId": f.KeyID, "CiphertextForRecipient": env, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}
	case "GenerateDataKey":
		if in.KeySpec != "AES_256" {
			refuse(400, "ValidationException", "KeySpec")
			return
		}
		dk := make([]byte, 32)
		_, _ = rand.Read(dk)
		nonce := make([]byte, 12)
		_, _ = rand.Read(nonce)
		blob := f.master.Seal(nonce, nonce, dk, aad)
		env, err := Envelope(rpub, dk, f.Indefinite)
		if err != nil {
			refuse(500, "KMSInternalException", err.Error())
			return
		}
		out = map[string]any{"KeyId": f.KeyID, "CiphertextBlob": blob, "CiphertextForRecipient": env} // no Plaintext: the document was given
	}
	call.Allowed = true
	f.record(call)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func sortedKeys(m map[int]string) []int {
	var k []int
	for i := range m {
		k = append(k, i)
	}
	sort.Ints(k)
	return k
}

func ctxAAD(keyID string, c map[string]string) []byte {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b := []byte("kmsfake\n" + keyID + "\n")
	for _, k := range keys {
		b = append(b, k+"="+c[k]+"\n"...)
	}
	return b
}

// checkSigV4 recomputes the signature from the request as AWS documents it (canonical request over the headers named in SignedHeaders, string to sign, derived key).
func (f *Fake) checkSigV4(r *http.Request, body []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || r.Header.Get("X-Amz-Security-Token") != f.Token {
		return false
	}
	parts := map[string]string{}
	for _, p := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ", ") {
		if k, v, ok := strings.Cut(p, "="); ok {
			parts[k] = v
		}
	}
	cred := strings.Split(parts["Credential"], "/")
	if len(cred) != 5 || cred[0] != f.AccessKeyID || cred[3] != "kms" || cred[4] != "aws4_request" {
		return false
	}
	date := r.Header.Get("X-Amz-Date")
	t, err := time.Parse("20060102T150405Z", date)
	if err != nil || t.Format("20060102") != cred[1] || f.Now().Sub(t) > 5*time.Minute || t.Sub(f.Now()) > 5*time.Minute {
		return false
	}
	names := strings.Split(parts["SignedHeaders"], ";")
	need := map[string]bool{"host": false, "x-amz-date": false, "content-type": false, "x-amz-target": false, "x-amz-security-token": false}
	var canon strings.Builder
	for _, n := range names {
		v := r.Host
		if n != "host" {
			v = strings.TrimSpace(r.Header.Get(n))
		}
		if _, ok := need[n]; ok {
			need[n] = true
		}
		canon.WriteString(n + ":" + v + "\n")
	}
	for _, ok := range need {
		if !ok {
			return false
		}
	}
	bh := sha256.Sum256(body)
	creq := "POST\n/\n\n" + canon.String() + "\n" + parts["SignedHeaders"] + "\n" + hex.EncodeToString(bh[:])
	ch := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + strings.Join(cred[1:], "/") + "\n" + hex.EncodeToString(ch[:])
	mac := func(k []byte, s string) []byte { h := hmac.New(sha256.New, k); h.Write([]byte(s)); return h.Sum(nil) }
	k := mac(mac(mac(mac([]byte("AWS4"+f.Secret), cred[1]), cred[2]), cred[3]), cred[4])
	return hmac.Equal([]byte(hex.EncodeToString(mac(k, sts))), []byte(parts["Signature"]))
}
