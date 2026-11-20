package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The production binary has no software authenticator, and builds without cgo (the transport is the libfido2 tools, not a C library).
func TestBinaryHasNoSoftwareAuthenticator(t *testing.T) {
	deps, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"ctaptest", "webauthntest", "/testing", "authtest"} {
		if strings.Contains(string(deps), bad) {
			t.Errorf("qv-approve depends on a package with %q in its path", bad)
		}
	}
	bin := filepath.Join(t.TempDir(), "qv-approve")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build with CGO_ENABLED=0: %v\n%s", err, out)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"ctaptest", "SIMULATED authenticator attestation", "software authenticator"} {
		if bytes.Contains(b, []byte(bad)) {
			t.Errorf("the binary contains %q", bad)
		}
	}
	// It does have the real transport.
	if !bytes.Contains(b, []byte("fido2-assert")) {
		t.Error("the binary does not drive fido2-assert")
	}
}
