package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `mpc-party tls-init` holds the new TLS private key in plain memory, so it applies the same process hardening as a running party (core dumps off,
// mlockall on Linux) before it reads anything: the log line is there even when the config does not exist.
func TestTLSInitIsHardenedBeforeItDoesAnything(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mpc-party")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, _ := exec.Command(bin, "tls-init", "-config", filepath.Join(t.TempDir(), "missing.json")).CombinedOutput()
	if !strings.Contains(string(out), "hardening: core dumps disabled") {
		t.Fatalf("tls-init did not apply the process hardening:\n%s", out)
	}
}
