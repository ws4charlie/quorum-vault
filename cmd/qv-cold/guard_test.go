package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// The production guard of the cold signer, the same rule as qv-gateway and qv-rekey: with QV_ENV unset (production) a SoftHSM module is
// refused and a PIN in an environment variable is refused, before any key is made or used; with QV_ENV=dev SoftHSM works with one warning line.
func TestColdRefusesSoftHSMInProduction(t *testing.T) {
	hsmtest.Token(t, "qv-cold") // skips (or fails under QV_REQUIRE_HSM) when the token is missing
	pin := hsmtest.PIN(t)
	pinFile := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(pinFile, []byte(pin+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	keygen := func() (string, string, error) {
		var out, errb bytes.Buffer
		err := run([]string{"keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_COLD_TEST_PIN"}, &out, &errb)
		return out.String(), errb.String(), err
	}

	t.Run("production, PIN file, SoftHSM: refused", func(t *testing.T) {
		t.Setenv("QV_ENV", "") // unset is production
		t.Setenv("QV_COLD_TEST_PIN", "")
		t.Setenv(hsm.PINFileEnv, pinFile)
		out, _, err := keygen()
		if err == nil || !strings.Contains(err.Error(), "is SoftHSM") || !strings.Contains(err.Error(), "refused in production") {
			t.Fatalf("keygen in production on SoftHSM: err %v, want the SoftHSM refusal", err)
		}
		if out != "" {
			t.Fatalf("a refused keygen wrote a key:\n%s", out)
		}
	})
	t.Run("production, PIN in the environment: refused", func(t *testing.T) {
		t.Setenv("QV_ENV", "production")
		t.Setenv("QV_COLD_TEST_PIN", pin)
		t.Setenv(hsm.PINFileEnv, "")
		out, _, err := keygen()
		if err == nil || !strings.Contains(err.Error(), "$QV_COLD_TEST_PIN is refused in production") {
			t.Fatalf("keygen in production with an environment PIN: err %v, want the PIN refusal", err)
		}
		if out != "" {
			t.Fatalf("a refused keygen wrote a key:\n%s", out)
		}
	})
	t.Run("dev, SoftHSM: works with a warning", func(t *testing.T) {
		t.Setenv("QV_ENV", "dev")
		t.Setenv("QV_COLD_TEST_PIN", pin)
		t.Setenv(hsm.PINFileEnv, "")
		out, errOut, err := keygen()
		if err != nil {
			t.Fatalf("keygen in dev: %v\n%s", err, errOut)
		}
		if !strings.Contains(out, `"key_id"`) {
			t.Fatalf("keygen in dev printed no key:\n%s", out)
		}
		if n := strings.Count(errOut, "WARNING: the PKCS#11 module is SoftHSM"); n != 1 {
			t.Fatalf("dev keygen printed the SoftHSM warning %d times, want once:\n%s", n, errOut)
		}
	})
}
