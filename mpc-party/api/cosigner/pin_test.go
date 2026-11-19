package cosigner_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
)

// Fixed vector, carried identically by every module that computes pins: the pin of the Ed25519 key with seed 32 x 0x01 is the
// SHA-256 of its DER SubjectPublicKeyInfo, whatever certificate wraps it.
const vectorPin = "fd110d301d2f077de1414b8f99f441b1403fab207b2052fbd2c065e4ee8e7dc2"

func issue(t *testing.T, key crypto.Signer, serial int64, from, to time.Time) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "p"}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPinFixedVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	a := issue(t, key, 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	b := issue(t, key, 2, time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour))
	pa, err := wire.PinOf(a.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if pb, _ := wire.PinOf(b.Raw); pa != pb {
		t.Fatalf("same key, new certificate: the pin changed (%s vs %s)", pa, pb)
	}
	if pa.String() != vectorPin {
		t.Fatalf("pin = %s, want the fixed vector %s", pa, vectorPin)
	}
	if wire.CertFingerprint(a.Raw) == pa {
		t.Fatal("the whole-certificate fingerprint must differ from the key pin")
	}
}

func verify(t *testing.T, c *x509.Certificate, pins ...string) error {
	t.Helper()
	m, err := wire.ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	return wire.VerifyPinned(m, time.Now)([][]byte{c.Raw}, nil)
}

func pinOf(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	return wire.PinOfCert(c).String()
}

func TestVerifyPinnedRenewalRotationExpiryOldScheme(t *testing.T) {
	now := time.Now()
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c1 := issue(t, k1, 1, now.Add(-time.Hour), now.Add(time.Hour))
	renewed := issue(t, k1, 2, now.Add(-time.Minute), now.Add(48*time.Hour))
	rotated := issue(t, k2, 3, now.Add(-time.Minute), now.Add(time.Hour))
	expired := issue(t, k1, 4, now.Add(-3*time.Hour), now.Add(-2*time.Hour))

	if err := verify(t, c1, pinOf(t, c1)); err != nil {
		t.Fatalf("pinned certificate refused: %v", err)
	}
	if err := verify(t, renewed, pinOf(t, c1)); err != nil {
		t.Fatalf("same key, new certificate: refused with no config change: %v", err)
	}
	if err := verify(t, rotated, pinOf(t, c1)); err == nil {
		t.Fatal("a new key was accepted before its pin was added")
	}
	if err := verify(t, rotated, pinOf(t, c1), pinOf(t, rotated)); err != nil {
		t.Fatalf("rotation: two pins configured, the new key refused: %v", err)
	}
	if err := verify(t, c1, pinOf(t, c1), pinOf(t, rotated)); err != nil {
		t.Fatalf("rotation: two pins configured, the old key refused: %v", err)
	}
	if err := verify(t, expired, pinOf(t, expired)); err == nil || !strings.Contains(err.Error(), "validity") {
		t.Fatalf("expired certificate with a pinned key: %v", err)
	}
	// an old-style pin (SHA-256 of the whole certificate) left in a config
	old := wire.CertFingerprint(c1.Raw).String()
	err := verify(t, c1, old)
	if err == nil || !strings.Contains(err.Error(), "SPKI") || !strings.Contains(err.Error(), "certificate fingerprint") ||
		!strings.Contains(err.Error(), pinOf(t, c1)) {
		t.Fatalf("old-style pin: want the scheme message naming the SPKI pin to use, got %v", err)
	}
	if err := verify(t, c1, pinOf(t, rotated)); err == nil || strings.Contains(err.Error(), "old scheme") {
		t.Fatalf("a plain mismatch must not claim an old-style pin: %v", err)
	}
}

// The documented one-liner prints the same pin as the code.
func TestOpensslOneLinerMatchesCode(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := issue(t, k, 7, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	f := filepath.Join(t.TempDir(), "c.pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", `openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1`, "sh", f).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != pinOf(t, c) {
		t.Fatalf("openssl one-liner %s, code %s", got, pinOf(t, c))
	}
}
