// Package hsmtest opens SoftHSM tokens for tests from the repo-local config
// written by scripts/setup-softhsm.sh (run `make setup` first).
//
// If the library, the config or the token is missing the test is skipped,
// unless QV_REQUIRE_HSM=1 (CI and every hand's verification), then it fails.
package hsmtest

import (
	"errors"
	"os"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

// DefaultPIN is the documented dev-only user PIN (see .env.example).
const DefaultPIN = "user-dev-1234"

// PIN returns QV_HSM_PIN or DefaultPIN.
func PIN() string {
	if p := os.Getenv("QV_HSM_PIN"); p != "" {
		return p
	}
	return DefaultPIN
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

// Token opens the token with the given label (logged in with PIN()) and closes
// it on cleanup.
func Token(t testing.TB, label string) *hsm.Token {
	t.Helper()
	lib := Lib(t)
	tok, err := lib.OpenToken(label, PIN())
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
