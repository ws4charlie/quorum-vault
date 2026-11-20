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
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second) // certificate times have second resolution
	leaf, roots := filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "roots.pem")
	writeCert(t, leaf, now.Add(10*24*time.Hour))
	writeCert(t, roots, now.Add(900*24*time.Hour), now.Add(300*24*time.Hour)) // the soonest counts
	var b bytes.Buffer
	writeCertMetricsFor(&b, leaf, roots, now)
	out := b.String()
	for _, want := range []string{`{kind="leaf"} 864000`, `{kind="trust_root"} 25920000`} { // 10 days; the soonest root, 300 days
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in:\n%s", want, out)
		}
	}
	// an unreadable file writes no line for its kind
	b.Reset()
	writeCertMetricsFor(&b, filepath.Join(dir, "missing.pem"), roots, now)
	if strings.Contains(b.String(), `kind="leaf"`) || !strings.Contains(b.String(), `kind="trust_root"`) {
		t.Errorf("missing file:\n%s", b.String())
	}
}
