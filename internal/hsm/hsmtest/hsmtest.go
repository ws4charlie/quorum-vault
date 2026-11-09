// Package hsmtest opens SoftHSM tokens for tests from the repo-local config
// written by scripts/setup-softhsm.sh (run `make setup` first).
//
// If the library, the config or the token is missing the test is skipped,
// unless QV_REQUIRE_HSM=1 (CI and every hand's verification), then it fails.
package hsmtest

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

// ErrNoPIN says where the PIN comes from. There is no default PIN anywhere.
var ErrNoPIN = errors.New("QV_HSM_PIN is not set: run `make dev-env` (it writes random PINs to .env)")

// LookupPIN returns the user PIN of the test tokens: QV_HSM_PIN from the environment, else from the .env at the repo root (written by
// `make dev-env`). It returns ErrNoPIN when neither has one.
func LookupPIN() (string, error) {
	if p := os.Getenv("QV_HSM_PIN"); p != "" {
		return p, nil
	}
	b, err := os.ReadFile(filepath.Join(repoRoot(), ".env"))
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "QV_HSM_PIN="); ok && v != "" {
				return v, nil
			}
		}
	}
	return "", ErrNoPIN
}

func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(f), "..", "..", ".."))
}

// PIN returns the user PIN (see LookupPIN). Without one the test is skipped, or fails under QV_REQUIRE_HSM=1, with a message naming `make dev-env`.
func PIN(t testing.TB) string {
	t.Helper()
	p, err := LookupPIN()
	if err != nil {
		unavailable(t, "%v", err)
	}
	return p
}

// Lib loads the PKCS#11 library from hsm.DefaultLibPath and closes it on cleanup.
func Lib(t testing.TB) *hsm.Lib {
	t.Helper()
	path := hsm.DefaultLibPath()
	if _, err := os.Stat(path); err != nil {
		unavailable(t, "pkcs11 library %s not found (install SoftHSM2 or set QV_PKCS11_LIB)", path)
	}
	if os.Getenv("SOFTHSM2_CONF") == "" && hsm.RepoSoftHSMConf() == "" {
		unavailable(t, "no SoftHSM config: run `make setup` (scripts/setup-softhsm.sh) or set SOFTHSM2_CONF")
	}
	lib, err := hsm.LoadLib(path)
	if err != nil {
		unavailable(t, "load pkcs11 library: %v", err)
	}
	t.Cleanup(func() { lib.Close() })
	return lib
}

// Token opens the token with the given label (logged in with PIN(t)) and closes
// it on cleanup.
func Token(t testing.TB, label string) *hsm.Token {
	t.Helper()
	lib := Lib(t)
	tok, err := lib.OpenToken(label, PIN(t))
	if errors.Is(err, hsm.ErrTokenNotFound) {
		unavailable(t, "%v: run `make setup`", err)
	}
	if err != nil {
		t.Fatalf("hsmtest: open token %q: %v", label, err)
	}
	t.Cleanup(func() { tok.Close() })
	return tok
}

func unavailable(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_HSM") == "1" {
		t.Fatalf("hsmtest (QV_REQUIRE_HSM=1): "+format, args...)
	}
	t.Skipf("hsmtest: "+format, args...)
}
