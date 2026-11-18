package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// build compiles qv-core once for the start-up refusals below.
func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "qv-core")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func start(t *testing.T, bin string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"-config", "/nonexistent.json", "-dsn", "postgres://x@127.0.0.1:1/x", "-dev-actor-header"}, args...)...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatal("qv-core did not stop")
	}
	if err == nil {
		t.Fatalf("qv-core started but should have refused:\n%s", out)
	}
	return string(out)
}

func TestStartRefusals(t *testing.T) {
	bin := build(t)
	root := t.TempDir()
	past := time.Now().Add(-48 * time.Hour)
	if err := pki.Init(root, 72*time.Hour, past); err != nil {
		t.Fatal(err)
	}
	if err := pki.IssueAll(root, time.Hour, past); err != nil { // valid for an hour, two days ago
		t.Fatal(err)
	}
	d := pki.Dir(root, pki.ZoneBusiness, "core")
	files := []string{"-tls-cert", d + "/tls.crt", "-tls-key", d + "/tls.key", "-tls-ca", d + "/ca.crt"}

	// no TLS in a production environment (QV_ENV unset), even with the plain-text switch
	for _, env := range [][]string{{}, {"QV_ALLOW_PLAINTEXT=1"}, {"QV_ENV=prod", "QV_ALLOW_PLAINTEXT=1"}} {
		out := start(t, bin, env, "-dev-actor-header=false", "-oidc-issuer", "https://idp.example")
		if !strings.Contains(out, "TLS is required") && !strings.Contains(out, "refused in production") {
			t.Fatalf("env %v: %s", env, out)
		}
	}
	// an expired certificate: a clear message, and no listening
	out := start(t, bin, []string{"QV_ENV=dev"}, files...)
	if !strings.Contains(out, "expired at") || !strings.Contains(out, "docs/runbooks/certificates.md") {
		t.Fatalf("expired certificate: %s", out)
	}
}
