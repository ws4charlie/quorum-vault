package pki_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// Every long-running service takes its TLS identity through pki.Flags, so a missing, expired or wrong-zone certificate stops it at start with the same
// message, and a future service cannot forget it.
func TestEveryServiceTakesItsIdentityThroughPKIFlags(t *testing.T) {
	for _, svc := range []string{"qv-core", "qv-worker", "qv-relay", "qv-anchor-archiver", "qv-gateway", "qv-cosigner"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "cmd", svc, "main.go"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "pki.Flags(") {
			t.Errorf("%s does not take its TLS identity through pki.Flags", svc)
		}
	}
}

// qv-relay, started with an expired certificate or none, stops with a clear message before it touches anything.
func TestRelayRefusesToStartWithoutAUsableCertificate(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "qv-relay")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/qv-relay").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	root := t.TempDir()
	past := time.Now().Add(-48 * time.Hour)
	if err := pki.Init(root, 72*time.Hour, past); err != nil {
		t.Fatal(err)
	}
	if err := pki.IssueAll(root, time.Hour, past); err != nil {
		t.Fatal(err)
	}
	d := pki.Dir(root, pki.ZoneBusiness, "relay")
	run := func(env []string, args ...string) string {
		cmd := exec.Command(bin, append([]string{"-dsn", "postgres://x@127.0.0.1:1/x?sslmode=verify-full", "-brokers", "127.0.0.1:1"}, args...)...)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("qv-relay started but should have refused:\n%s", out)
		}
		return string(out)
	}
	if out := run(nil); !strings.Contains(out, "TLS is required") {
		t.Errorf("no certificate: %s", out)
	}
	if out := run([]string{"QV_ALLOW_PLAINTEXT=1"}); !strings.Contains(out, "TLS is required") {
		t.Errorf("the plain-text switch without QV_ENV=dev: %s", out)
	}
	if out := run(nil, "-tls-cert", d+"/tls.crt", "-tls-key", d+"/tls.key", "-tls-ca", d+"/ca.crt"); !strings.Contains(out, "expired at") || !strings.Contains(out, "docs/runbooks/certificates.md") {
		t.Errorf("expired certificate: %s", out)
	}
	if out := run(nil, "-tls-cert", d+"/tls.crt", "-tls-key", d+"/tls.key", "-tls-ca", d+"/ca.crt", "-metrics-listen", "0.0.0.0:9102"); !strings.Contains(out, "expired at") {
		t.Errorf("the certificate is checked before anything is opened: %s", out)
	}
}
