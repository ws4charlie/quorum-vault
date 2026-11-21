package broker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

func writeCert(t *testing.T, path string, ends ...time.Time) {
	t.Helper()
	var out []byte
	for i, end := range ends {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "t"}, NotBefore: end.Add(-48 * time.Hour), NotAfter: end}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertMetrics(t *testing.T) {
	now := time.Now().Truncate(time.Second) // certificate times have second resolution
	var b bytes.Buffer
	writeCertMetricsFor(&b, now.Add(10*24*time.Hour).Unix(), now.Add(300*24*time.Hour).Unix(), now)
	out := b.String()
	for _, want := range []string{`{kind="leaf"} 864000`, `{kind="trust_root"} 25920000`} { // 10 days; 300 days
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in:\n%s", want, out)
		}
	}
	// a kind that is not loaded writes no line
	b.Reset()
	writeCertMetricsFor(&b, 0, now.Add(300*24*time.Hour).Unix(), now)
	if strings.Contains(b.String(), `kind="leaf"`) || !strings.Contains(b.String(), `kind="trust_root"`) {
		t.Errorf("leaf not loaded:\n%s", b.String())
	}
}

// The metric reports the material the broker loaded, not the file now: a replaced file the broker has not loaded must not hide an expiring active certificate.
func TestCertMetricsFollowLoadedMaterial(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)
	roots := filepath.Join(dir, "roots.pem")
	writeCert(t, roots, now.Add(300*24*time.Hour), now.Add(900*24*time.Hour))
	pemb, _ := os.ReadFile(roots)
	cs, err := attest.ParseRootsPEM(pemb)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	s.rootEnd.Store(soonestNotAfter(cs))
	writeCert(t, roots, now.Add(5000*24*time.Hour)) // the file is replaced after the broker loaded it
	var b bytes.Buffer
	s.writeCertMetrics(&b)
	if !strings.Contains(b.String(), `{kind="trust_root"} 2`) || strings.Contains(b.String(), `{kind="trust_root"} 4`) { // about 300 days (2.59e7 s), not 5000 days
		t.Errorf("want the loaded root's end:\n%s", b.String())
	}
}
