package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

// The HSM mode reads the token PIN like qv-gateway does: from a file, and from the environment only in dev or test. The PIN is read before the PKCS#11
// library is loaded, so the refusal needs no token.
func TestHSMKeysReadThePINLikeTheGateway(t *testing.T) {
	cfg := &gateway.Config{Signers: map[string]gateway.SignerFile{"p": {Backend: "hsm", Token: "tok"}}}
	t.Setenv("QV_HSM_PIN_FILE", "")

	t.Setenv("QV_ENV", "")
	t.Setenv("QV_HSM_PIN", "1234")
	if _, _, err := newHSMKeys(cfg, "p"); err == nil || !strings.Contains(err.Error(), "QV_HSM_PIN_FILE") {
		t.Fatalf("the PIN in the environment, no QV_ENV: %v", err)
	}
	t.Setenv("QV_ENV", "production")
	t.Setenv("QV_HSM_PIN", "1234")
	if _, _, err := newHSMKeys(cfg, "p"); err == nil || !strings.Contains(err.Error(), "refused in production") {
		t.Fatalf("the PIN in the environment in production: %v", err)
	}

	// A file with a loose mode is refused; one with mode 0400 is read (the token then fails to open, which is past the PIN).
	t.Setenv("QV_HSM_PIN", "")
	f := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(f, []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QV_HSM_PIN_FILE", f)
	if _, _, err := newHSMKeys(cfg, "p"); err == nil || strings.Contains(err.Error(), "load pkcs11") {
		t.Fatalf("a world-readable PIN file: %v", err)
	}
	if err := os.Chmod(f, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newHSMKeys(cfg, "p"); err != nil && strings.Contains(err.Error(), "QV_HSM_PIN") {
		t.Fatalf("a PIN file with mode 0400 was not accepted: %v", err)
	}
}
