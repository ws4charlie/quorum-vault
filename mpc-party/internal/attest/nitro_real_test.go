package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// Tests of the production verifier on a document a real Nitro enclave made (testdata/nitro/README.md: source and licence). The document's
// certificates were valid for three hours on 2022-11-09, so every check runs at the document's own time.

var realDocTime = time.UnixMilli(1668034320696)

func readB64(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/nitro/" + name)
	if err != nil {
		t.Fatal(err)
	}
	out, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func realVerifier(t *testing.T) *NitroVerifier {
	t.Helper()
	v, err := NewProductionNitroVerifier()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNitroRootPin(t *testing.T) {
	root, err := NitroRootG1()
	if err != nil {
		t.Fatal(err)
	}
	if root.Subject.CommonName != "aws.nitro-enclaves" || root.NotAfter.Year() != 2049 {
		t.Fatalf("unexpected root: %s until %s", root.Subject, root.NotAfter)
	}
	// the fingerprint AWS prints, with colons and upper case, is the same pin
	if err := CheckFingerprint(root.Raw, "64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B"); err != nil {
		t.Fatal(err)
	}
	if err := CheckFingerprint(root.Raw, strings.Repeat("00", 32)); err == nil {
		t.Fatal("a wrong fingerprint was accepted")
	}
	if err := CheckFingerprint(root.Raw, "zz"); err == nil {
		t.Fatal("a malformed fingerprint was accepted")
	}
}

// The root of a real document is, byte for byte, the pinned certificate: the pin and the world agree.
func TestRealDocumentChain(t *testing.T) {
	var doc nitroDoc
	s, err := parseSign1(readB64(t, "aws-real-document-2022.b64"))
	if err != nil {
		t.Fatal(err)
	}
	if err := strictDec.Unmarshal(s.Payload, &doc); err != nil {
		t.Fatal(err)
	}
	root, _ := NitroRootG1()
	if !bytes.Equal(doc.CABundle[0], root.Raw) {
		t.Fatal("cabundle[0] of a real AWS document is not the pinned root")
	}
	if len(doc.CABundle) != 4 {
		t.Fatalf("cabundle has %d certificates, a real bundle holds 4", len(doc.CABundle))
	}
}

func TestRealDocumentAuthenticates(t *testing.T) {
	c, err := realVerifier(t).authenticate(readB64(t, "aws-real-document-2022.b64"), realDocTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if c.EvidenceType != EvidenceTypeNitro || c.Debug || c.ModuleID != "i-04fd167167daacf3b-enc01845e97d0b3eb4e" {
		t.Fatalf("claims: %+v", c)
	}
	if got := c.Measurement(); !strings.HasPrefix(got, "22f9e1c94920") || len(got) != 96 {
		t.Fatalf("PCR0 %s", got)
	}
	if len(c.Measurements) != 16 || len(c.UserData) != 32 || c.Signer != "" {
		t.Fatalf("pcrs %d, user data %d, signer %q (an unsigned image has no PCR8)", len(c.Measurements), len(c.UserData), c.Signer)
	}
	if !c.Timestamp.Equal(realDocTime) {
		t.Fatalf("timestamp %s", c.Timestamp)
	}
}

// A real document carries no nonce: it can never pass as evidence for a request, whatever else is right.
func TestRealDocumentIsNotEvidenceForARequest(t *testing.T) {
	_, err := realVerifier(t).Verify(readB64(t, "aws-real-document-2022.b64"), Expect{Nonce: []byte("n")}, realDocTime.Add(time.Minute))
	if RuleOf(err) != RuleNonce {
		t.Fatalf("want the nonce rule, got %v", err)
	}
}

func TestRealDocumentRefusals(t *testing.T) {
	doc := readB64(t, "aws-real-document-2022.b64")
	at := realDocTime.Add(time.Minute)

	t.Run("wrong root", func(t *testing.T) {
		other := selfSignedCA(t)
		v, err := NewNitroVerifier(NitroConfig{Roots: []*x509.Certificate{other}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.authenticate(doc, at); RuleOf(err) != RuleUntrusted {
			t.Fatalf("want untrusted_root, got %v", err)
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		if _, err := realVerifier(t).authenticate(readB64(t, "aws-real-document-2022-badsig.b64"), at); RuleOf(err) != RuleSignature {
			t.Fatalf("want signature, got %v", err)
		}
	})
	t.Run("one flipped bit anywhere in the signature", func(t *testing.T) {
		s, _ := parseSign1(doc)
		for i := 0; i < len(s.Signature); i += 7 {
			bad := bytes.Replace(doc, s.Signature, flip(s.Signature, i), 1)
			if _, err := realVerifier(t).authenticate(bad, at); RuleOf(err) != RuleSignature {
				t.Fatalf("bit %d: want signature, got %v", i, err)
			}
		}
	})
	t.Run("changed payload", func(t *testing.T) {
		s, _ := parseSign1(doc)
		// the module id is text inside the payload; changing one letter keeps the CBOR valid and the signature wrong
		bad := bytes.Replace(doc, []byte("i-04fd167167daacf3b"), []byte("i-14fd167167daacf3b"), 1)
		if bytes.Equal(bad, doc) || !bytes.Contains(s.Payload, []byte("i-04fd167167daacf3b")) {
			t.Fatal("test setup")
		}
		if _, err := realVerifier(t).authenticate(bad, at); RuleOf(err) != RuleSignature {
			t.Fatalf("want signature, got %v", err)
		}
	})
	t.Run("document older than the freshness window", func(t *testing.T) {
		if _, err := realVerifier(t).authenticate(doc, realDocTime.Add(DefaultMaxAge+time.Second)); RuleOf(err) != RuleStale {
			t.Fatalf("want stale_timestamp, got %v", err)
		}
	})
	t.Run("document from the future", func(t *testing.T) {
		if _, err := realVerifier(t).authenticate(doc, realDocTime.Add(-2*time.Minute)); RuleOf(err) != RuleFuture {
			t.Fatalf("want future_timestamp, got %v", err)
		}
	})
	t.Run("expired certificates", func(t *testing.T) {
		// a document whose own time lies after the leaf's end: the chain rule refuses before freshness is looked at
		var d nitroDoc
		s, _ := parseSign1(doc)
		if err := strictDec.Unmarshal(s.Payload, &d); err != nil {
			t.Fatal(err)
		}
		d.Timestamp = uint64(realDocTime.Add(4 * time.Hour).UnixMilli())
		payload, _ := encMode.Marshal(d)
		if _, err := realVerifier(t).authenticate(rewrap(t, s, payload), realDocTime.Add(4*time.Hour)); RuleOf(err) != RuleCertValidity {
			t.Fatalf("want cert_validity, got %v", err)
		}
	})
	t.Run("truncated at every length", func(t *testing.T) {
		v := realVerifier(t)
		for n := 0; n < len(doc); n++ {
			if _, err := v.authenticate(doc[:n], at); err == nil {
				t.Fatalf("a document cut to %d of %d bytes was accepted", n, len(doc))
			} else if RuleOf(err) == "" {
				t.Fatalf("cut to %d: error is not a rule: %v", n, err)
			}
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := realVerifier(t).authenticate(append(append([]byte(nil), doc...), 0), at); err == nil {
			t.Fatal("trailing garbage accepted")
		}
	})
	t.Run("not CBOR", func(t *testing.T) {
		for _, b := range [][]byte{{0xff}, []byte("{}"), bytes.Repeat([]byte{0x9f}, 100), {0xd2, 0x84}} {
			if _, err := realVerifier(t).authenticate(b, at); RuleOf(err) == "" {
				t.Fatalf("%x: %v", b, err)
			}
		}
	})
}

// Every documented size limit refuses: the limits are checked before any signature work. The real document's signature is kept, so only the size
// rule can be what fires.
func TestRealDocumentOversizedFields(t *testing.T) {
	doc := readB64(t, "aws-real-document-2022.b64")
	s, _ := parseSign1(doc)
	var base nitroDoc
	if err := strictDec.Unmarshal(s.Payload, &base); err != nil {
		t.Fatal(err)
	}
	big := func(n int) []byte { return bytes.Repeat([]byte{7}, n) }
	for _, tc := range []struct {
		name string
		mut  func(d *nitroDoc)
		rule Rule
	}{
		{"public_key 1025 bytes", func(d *nitroDoc) { d.PublicKey = big(maxPublicKey + 1) }, RuleSize},
		{"user_data 1025 bytes", func(d *nitroDoc) { d.UserData = big(maxUserData + 1) }, RuleSize},
		{"nonce 513 bytes", func(d *nitroDoc) { d.Nonce = big(maxNonce + 1) }, RuleSize},
		{"certificate 1025 bytes", func(d *nitroDoc) { d.Certificate = big(maxCertBytes + 1) }, RuleSize},
		{"cabundle entry 1025 bytes", func(d *nitroDoc) { d.CABundle = append([][]byte{big(maxCertBytes + 1)}, d.CABundle[1:]...) }, RuleSize},
		{"cabundle 17 entries", func(d *nitroDoc) {
			for len(d.CABundle) <= maxCABundle {
				d.CABundle = append(d.CABundle, d.CABundle[0])
			}
		}, RuleSize},
		{"empty cabundle", func(d *nitroDoc) { d.CABundle = nil }, RuleSize},
		{"33 pcrs", func(d *nitroDoc) { d.PCRs[32] = big(48) }, RuleSize},
		{"pcr of 47 bytes", func(d *nitroDoc) { d.PCRs[5] = big(47) }, RuleSize},
		{"pcr of 65 bytes", func(d *nitroDoc) { d.PCRs[5] = big(65) }, RuleSize},
		{"no pcr 0", func(d *nitroDoc) { delete(d.PCRs, 0) }, RuleMissingField},
		{"no module id", func(d *nitroDoc) { d.ModuleID = "" }, RuleMissingField},
		{"digest other than SHA384", func(d *nitroDoc) { d.Digest = "SHA256" }, RuleMissingField},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.PCRs = map[uint64][]byte{}
			for k, v := range base.PCRs {
				d.PCRs[k] = v
			}
			tc.mut(&d)
			payload, err := encMode.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := realVerifier(t).authenticate(rewrap(t, s, payload), realDocTime.Add(time.Minute)); RuleOf(err) != tc.rule {
				t.Fatalf("want %s, got %v", tc.rule, err)
			}
		})
	}
	t.Run("whole document over 32 KiB", func(t *testing.T) {
		if _, err := realVerifier(t).authenticate(make([]byte, maxDocBytes+1), realDocTime); RuleOf(err) != RuleFormat {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRealDocumentPCR0IsNotDebug(t *testing.T) {
	c, _ := realVerifier(t).authenticate(readB64(t, "aws-real-document-2022.b64"), realDocTime.Add(time.Minute))
	zero, _ := hex.DecodeString(strings.Repeat("00", 48))
	if bytes.Equal(c.Measurements[0], zero) || !bytes.Equal(c.Measurements[3], zero) {
		t.Fatal("PCR0 must be non-zero and PCR3 zero in this document")
	}
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 1 << (i % 8)
	return out
}

// rewrap puts a new payload under the old envelope and signature: the result has a valid shape and an invalid signature.
func rewrap(t *testing.T, s *coseSign1, payload []byte) []byte {
	t.Helper()
	body, err := encMode.Marshal(coseSign1{Protected: s.Protected, Unprotected: []byte{0xA0}, Payload: payload, Signature: s.Signature})
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0xC0 | coseTagSign1}, body...)
}

func selfSignedCA(t *testing.T) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "some other root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}
