package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// startHSM does what run does with the PIN: read it from the environment as a service does, then log in. Everything that would be shown to an
// operator (the returned error and every log line) is captured.
func startHSM(t *testing.T, cfg *gateway.Config) (shown string, err error) {
	t.Helper()
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(old)
	pin, err := hsmServicePIN(cfg)
	if err == nil {
		var closeAll func()
		_, _, closeAll, err = openHSMSigners(cfg, pin)
		if closeAll != nil {
			closeAll()
		}
	}
	if err != nil {
		logs.WriteString(err.Error()) // main logs exactly this on stop
	}
	return logs.String(), err
}

func pinFile(t *testing.T, pin string, mode os.FileMode) string {
	f := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(f, []byte(pin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chmod(f, mode)
	return f
}

// The PIN never appears in what a start prints, with a wrong PIN or the right one, from a file or the environment.
func TestStartNeverShowsPIN(t *testing.T) {
	good := hsmtest.PIN(t)
	hsmtest.Lib(t) // skipped without SoftHSM
	const wrong = "wrong-pin-0451"
	// The key is not valid hex: a login that works then stops at the key, which is all this test needs (the full path is in the e2e groups).
	cfg := &gateway.Config{Signers: map[string]gateway.SignerFile{"hot": {Token: "quorumvault", KeyID: "zz", PublicKey: "zz"}}}
	t.Setenv("QV_ENV", "test")

	for _, c := range []struct {
		name, pin, wantErr string
		fromFile           bool
	}{
		{"wrong PIN, file", wrong, "CKR_PIN", true},
		{"wrong PIN, environment", wrong, "CKR_PIN", false},
		{"right PIN, file", good, "hex", true},
		{"right PIN, environment", good, "hex", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("QV_HSM_PIN", "")
			t.Setenv("QV_HSM_PIN_FILE", "")
			if c.fromFile {
				t.Setenv("QV_HSM_PIN_FILE", pinFile(t, c.pin, 0o440))
			} else {
				t.Setenv("QV_HSM_PIN", c.pin)
			}
			shown, err := startHSM(t, cfg)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, c.wantErr)
			}
			for _, p := range []string{c.pin, wrong, good} {
				if p != "" && strings.Contains(shown, p) {
					t.Errorf("the PIN is in the output of the start: %s", shown)
				}
			}
		})
	}
}

// A production start refuses the environment form, names the file option and does not print the PIN.
func TestProductionRefusesPINInEnvironment(t *testing.T) {
	cfg := &gateway.Config{Signers: map[string]gateway.SignerFile{"hot": {Token: "quorumvault"}}}
	for _, qvEnv := range []string{"", "production", "staging"} {
		t.Setenv("QV_ENV", qvEnv)
		t.Setenv("QV_HSM_PIN_FILE", "")
		t.Setenv("QV_HSM_PIN", "env-pin-7731")
		shown, err := startHSM(t, cfg)
		if err == nil || !strings.Contains(err.Error(), "QV_HSM_PIN_FILE") {
			t.Fatalf("QV_ENV=%q: err = %v", qvEnv, err)
		}
		if strings.Contains(shown, "env-pin-7731") {
			t.Errorf("QV_ENV=%q: PIN in the output: %s", qvEnv, shown)
		}
	}
	// the same config as JSON, as LoadConfig would read it: an MPC-only zone needs no PIN at all
	var mpcOnly gateway.Config
	json.Unmarshal([]byte(`{"signers":{"hot":{"backend":"mpc"}}}`), &mpcOnly)
	if pin, err := hsmServicePIN(&mpcOnly); err != nil || pin != "" {
		t.Fatalf("a zone without HSM signers needs no PIN: %q, %v", pin, err)
	}
}
