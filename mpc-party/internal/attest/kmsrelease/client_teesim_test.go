//go:build teesim

package kmsrelease_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease/kmsfake"
)

type rig struct {
	ca   *attest.MockCA
	att  *attest.MockAttester
	kms  *kmsfake.Fake
	cl   *kmsrelease.Client
	pcr0 []byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ca, err := attest.NewMockCA(time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewNitroVerifier(attest.NitroConfig{Roots: []*x509.Certificate{ca.Root}})
	if err != nil {
		t.Fatal(err)
	}
	pcr0 := attest.MeasureImage([]byte("party image"), []byte("deployment config"))
	pcr8 := attest.MeasureCert([]byte("mock signing cert"))
	k, err := kmsfake.New("key-1", v, kmsfake.Policy{PCRs: map[int]string{0: hex.EncodeToString(pcr0), 8: hex.EncodeToString(pcr8)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	cl, err := kmsrelease.New(kmsrelease.Config{KeyID: "key-1", Region: "eu-central-1", Endpoint: k.URL,
		Creds: kmsrelease.StaticCreds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.Secret, SessionToken: k.Token}})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{ca: ca, att: &attest.MockAttester{CA: ca, PCR0: pcr0, PCR8: pcr8}, kms: k, cl: cl, pcr0: pcr0}
}

func (r *rig) evidence(t *testing.T) (doc []byte, open func(aad, sealed []byte) ([]byte, error)) {
	t.Helper()
	pub, open, err := r.cl.NewRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := r.cl.Challenge(context.Background())
	doc, err = r.att.Attest(ch.Nonce, pub, []byte("user data"))
	if err != nil {
		t.Fatal(err)
	}
	return doc, open
}

func rc(purpose string, gens ...uint64) attest.RequestContext {
	return attest.RequestContext{Party: "A", Keyset: "k1", Generations: gens, Purpose: purpose}
}

func TestNewKeyThenReleaseRoundTrip(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	doc, open := r.evidence(t)
	made, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1, 2)})
	if err != nil || len(made.Keys) != 2 {
		t.Fatalf("%v %+v", err, made)
	}
	keys := map[uint64][]byte{}
	for _, k := range made.Keys {
		pt, err := open(nil, k.Sealed)
		if err != nil || len(pt) != 32 || len(k.Blob) == 0 {
			t.Fatalf("gen %d: %v len %d", k.Generation, err, len(pt))
		}
		keys[k.Generation] = pt
	}
	if bytes.Equal(keys[1], keys[2]) {
		t.Fatal("two generations got the same key")
	}
	// a restart: a new enclave key, a new document, the stored blobs
	doc2, open2 := r.evidence(t)
	rel, err := r.cl.Release(ctx, attest.ReleaseRequest{Evidence: doc2, Context: rc(attest.PurposeUnseal, 1, 2), Blobs: [][]byte{made.Keys[0].Blob, made.Keys[1].Blob}})
	if err != nil || len(rel.Keys) != 2 {
		t.Fatal(err)
	}
	for _, k := range rel.Keys {
		pt, err := open2(nil, k.Sealed)
		if err != nil || !bytes.Equal(pt, keys[k.Generation]) {
			t.Fatalf("gen %d came back different: %v", k.Generation, err)
		}
	}
	// the answer is encrypted to the first enclave key only: another enclave key cannot read it
	if _, err := open(nil, rel.Keys[0].Sealed); err == nil {
		t.Fatal("a response opened under another enclave's key")
	}
}

func refusal(t *testing.T, err error, want string) {
	t.Helper()
	var re *kmsrelease.RefusedError
	if !errors.As(err, &re) || re.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

func TestKMSRefusals(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		fault attest.Fault
		debug bool
	}{
		{"wrong PCR0", attest.FaultWrongPCR, false},
		{"debug document", attest.FaultNone, true},
		{"bad signature", attest.FaultBadSignature, false},
		{"expired certificate", attest.FaultExpiredCert, false},
		{"stale document", attest.FaultStaleTimestamp, false},
		{"wrong chain order", attest.FaultWrongChainOrder, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.att.Fault, r.att.Debug = tc.fault, tc.debug
			doc, _ := r.evidence(t)
			_, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)})
			refusal(t, err, "AccessDeniedException")
		})
	}
	t.Run("document from another root", func(t *testing.T) {
		r := newRig(t)
		other, _ := attest.NewMockCA(time.Now(), time.Hour)
		r.att.CA = other
		doc, _ := r.evidence(t)
		_, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)})
		refusal(t, err, "AccessDeniedException")
	})
	t.Run("signing certificate differs (PCR8)", func(t *testing.T) {
		r := newRig(t)
		r.att.PCR8 = attest.MeasureCert([]byte("another cert"))
		doc, _ := r.evidence(t)
		_, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)})
		refusal(t, err, "AccessDeniedException")
	})
	t.Run("a document without PCR8 when the policy names it", func(t *testing.T) {
		r := newRig(t)
		r.att.PCR8 = nil
		doc, _ := r.evidence(t)
		_, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)})
		refusal(t, err, "AccessDeniedException")
	})
	t.Run("blob of another generation, keyset or party does not open", func(t *testing.T) {
		r := newRig(t)
		doc, _ := r.evidence(t)
		made, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 3)})
		if err != nil {
			t.Fatal(err)
		}
		blob := made.Keys[0].Blob
		for name, c := range map[string]attest.RequestContext{
			"generation": rc(attest.PurposeUnseal, 4),
			"keyset":     {Party: "A", Keyset: "k2", Generations: []uint64{3}, Purpose: attest.PurposeUnseal},
			"party":      {Party: "B", Keyset: "k1", Generations: []uint64{3}, Purpose: attest.PurposeUnseal},
		} {
			d, _ := r.evidence(t)
			_, err := r.cl.Release(ctx, attest.ReleaseRequest{Evidence: d, Context: c, Blobs: [][]byte{blob}})
			if err == nil {
				t.Fatalf("a blob of generation 3 opened as another %s", name)
			}
			refusal(t, err, "InvalidCiphertextException")
		}
	})
	t.Run("a key-policy change revokes the image at once", func(t *testing.T) {
		r := newRig(t)
		doc, _ := r.evidence(t)
		if _, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)}); err != nil {
			t.Fatal(err)
		}
		r.kms.SetPolicy(kmsfake.Policy{PCRs: map[int]string{0: strings.Repeat("ab", 48)}})
		doc, _ = r.evidence(t)
		_, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)})
		refusal(t, err, "AccessDeniedException")
	})
	t.Run("policy values compare without regard to case", func(t *testing.T) {
		r := newRig(t)
		r.kms.SetPolicy(kmsfake.Policy{PCRs: map[int]string{0: strings.ToUpper(hex.EncodeToString(r.pcr0))}})
		doc, _ := r.evidence(t)
		if _, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wrong credentials", func(t *testing.T) {
		r := newRig(t)
		cl, _ := kmsrelease.New(kmsrelease.Config{KeyID: "key-1", Region: "eu-central-1", Endpoint: r.kms.URL,
			Creds: kmsrelease.StaticCreds{AccessKeyID: r.kms.AccessKeyID, SecretAccessKey: "not the secret", SessionToken: r.kms.Token}})
		doc, _ := r.evidence(t)
		_, err := cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)})
		refusal(t, err, "InvalidSignatureException")
	})
	t.Run("another key id", func(t *testing.T) {
		r := newRig(t)
		cl, _ := kmsrelease.New(kmsrelease.Config{KeyID: "key-2", Region: "eu-central-1", Endpoint: r.kms.URL,
			Creds: kmsrelease.StaticCreds{AccessKeyID: r.kms.AccessKeyID, SecretAccessKey: r.kms.Secret, SessionToken: r.kms.Token}})
		doc, _ := r.evidence(t)
		_, err := cl.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc(attest.PurposeCreate, 1)})
		refusal(t, err, "NotFoundException")
	})
	t.Run("no attestation document at all", func(t *testing.T) {
		r := newRig(t)
		_, err := r.cl.NewKey(ctx, attest.ReleaseRequest{Context: rc(attest.PurposeCreate, 1)})
		if err == nil {
			t.Fatal("a request without evidence was sent")
		}
		// and the fake itself denies a raw request with no Recipient: the PCR conditions are not satisfied
		resp := rawCall(t, r, `{"KeyId":"key-1","KeySpec":"AES_256"}`)
		if !strings.Contains(resp, "AccessDeniedException") {
			t.Fatalf("raw call without recipient: %s", resp)
		}
	})
	t.Run("a policy without a PCR condition cannot be made", func(t *testing.T) {
		if _, err := kmsfake.New("k", nil, kmsfake.Policy{}); err == nil {
			t.Fatal("empty policy accepted")
		}
	})
}

func rawCall(t *testing.T, r *rig, body string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", r.kms.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.GenerateDataKey")
	kmsrelease.SignRequest(req, []byte(body), kmsrelease.Creds{AccessKeyID: r.kms.AccessKeyID, SecretAccessKey: r.kms.Secret, SessionToken: r.kms.Token}, "eu-central-1", "kms", time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return b.String()
}

func TestEndpointMustBeHTTPS(t *testing.T) {
	creds := kmsrelease.StaticCreds{AccessKeyID: "a", SecretAccessKey: "b"}
	for _, ep := range []string{"http://kms.example.com", "ftp://x", "https://kms.example.com/path", "kms.example.com"} {
		if _, err := kmsrelease.New(kmsrelease.Config{KeyID: "k", Region: "r", Endpoint: ep, Creds: creds}); err == nil {
			t.Fatalf("%q accepted", ep)
		}
	}
	for _, ep := range []string{"", "https://kms-fips.us-east-1.amazonaws.com", "http://127.0.0.1:9"} {
		if _, err := kmsrelease.New(kmsrelease.Config{KeyID: "k", Region: "r", Endpoint: ep, Creds: creds}); err != nil {
			t.Fatalf("%q: %v", ep, err)
		}
	}
}

// ---- the CMS layer on its own ----

func TestEnvelopeForms(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, indef := range []bool{true, false} {
		for _, n := range []int{1, 15, 16, 32, 33, 300} {
			pt := bytes.Repeat([]byte{0x5a}, n)
			env, err := kmsfake.Envelope(&k.PublicKey, pt, indef)
			if err != nil {
				t.Fatal(err)
			}
			got, err := kmsrelease.OpenEnvelope(k, env)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("indefinite=%v n=%d: %v", indef, n, err)
			}
		}
	}
}

func TestEnvelopeRefusals(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	env, _ := kmsfake.Envelope(&k.PublicKey, bytes.Repeat([]byte{1}, 32), true)
	if _, err := kmsrelease.OpenEnvelope(other, env); err == nil {
		t.Fatal("opened under another key")
	}
	for n := 0; n < len(env); n++ {
		if _, err := kmsrelease.OpenEnvelope(k, env[:n]); err == nil {
			t.Fatalf("truncated to %d accepted", n)
		}
	}
	for _, b := range [][]byte{nil, {0x30, 0x80}, bytes.Repeat([]byte{0x30, 0x80}, 50), {0x30, 0x03, 0x06, 0x01, 0x00}, make([]byte, 70000)} {
		if _, err := kmsrelease.OpenEnvelope(k, b); err == nil {
			t.Fatalf("%x accepted", b[:min(len(b), 8)])
		}
	}
}

// Cross-check with an independent implementation: OpenSSL writes the CMS the way KMS does (streamed, so BER with indefinite lengths; RSAES-OAEP SHA-256; AES-256-CBC;
// subject key identifier recipient). The test is skipped only where there is no openssl; CI's image has it.
func TestEnvelopeFromOpenSSL(t *testing.T) {
	ssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl on PATH")
	}
	dir := t.TempDir()
	run := func(stdin []byte, args ...string) []byte {
		cmd := exec.Command(ssl, args...)
		cmd.Dir = dir
		cmd.Stdin = bytes.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Skipf("this openssl cannot make the test CMS (%v): %s", err, out)
		}
		return out
	}
	run(nil, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-subj", "/CN=t", "-days", "1")
	secret := bytes.Repeat([]byte("data key"), 4)
	run(secret, "cms", "-encrypt", "-binary", "-aes-256-cbc", "-recip", "c.pem", "-keyid", "-keyopt", "rsa_padding_mode:oaep",
		"-keyopt", "rsa_oaep_md:sha256", "-outform", "DER", "-stream", "-out", "e.der")
	der, err := os.ReadFile(filepath.Join(dir, "e.der"))
	if err != nil {
		t.Fatal(err)
	}
	kp, err := os.ReadFile(filepath.Join(dir, "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	priv := parseRSAKey(t, kp)
	got, err := kmsrelease.OpenEnvelope(priv, der)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("OpenSSL CMS not opened: %v", err)
	}
}
