package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S4: in production (QV_ENV unset, or not dev or test) the PKCS#11 sealer takes its PIN from pin_file only, as the gateway does
// (internal/hsm/pin.go). The refusal comes before the PIN is read and before the module is loaded. Development and tests keep pin_env.
func TestPKCS11PinEnvRefusedInProduction(t *testing.T) {
	t.Setenv("QV_S4_PIN", "1234")
	for _, env := range []string{"", "production", "staging", " Prod "} {
		t.Setenv("QV_ENV", env)
		for _, prov := range []string{ProviderSoftHSM, ProviderCloudHSM} { // "" is refused first (TestPKCS11EmptyProviderRefusedInProduction)
			_, err := NewPKCS11Sealer(SealerConfig{Type: "pkcs11", Provider: prov, Token: "t", PinEnv: "QV_S4_PIN", Lib: "/nonexistent"})
			if err == nil || !strings.Contains(err.Error(), "pin_env is refused in production") {
				t.Errorf("QV_ENV=%q provider=%q: want the pin_env refusal, got %v", env, prov, err)
			}
		}
	}
	// Development and tests: pin_env is read as before (the start then fails later, on the missing library).
	for _, env := range []string{"dev", "test", " TEST "} {
		t.Setenv("QV_ENV", env)
		for _, prov := range []string{"", ProviderSoftHSM} {
			_, err := NewPKCS11Sealer(SealerConfig{Type: "pkcs11", Provider: prov, Token: "t", PinEnv: "QV_S4_PIN", Lib: "/nonexistent"})
			if err == nil || !strings.Contains(err.Error(), "library") {
				t.Errorf("QV_ENV=%q provider=%q: want the old path (library error), got %v", env, prov, err)
			}
		}
	}
}

// S4: attester nitro with the KMS release must reach KMS and the instance credentials over vsock in production; port 0 (network KMS, AWS_*
// credentials) is a test setup and is refused at start instead of being fallen back to. Development and tests keep it.
func TestKMSNitroWithoutVsockRefusedInProduction(t *testing.T) {
	kms := func(port, creds uint32) SealerConfig {
		return SealerConfig{Type: "attested", Attester: AttesterConfig{Type: "nitro"},
			Release: ReleaseConfig{Type: "kms", KMS: KMSConfig{KeyID: "k", Region: "r", VsockPort: port, CredsVsockPort: creds}}}
	}
	for _, env := range []string{"", "production"} {
		t.Setenv("QV_ENV", env)
		for name, tc := range map[string]struct {
			c    SealerConfig
			want string
		}{
			"no kms vsock":   {kms(0, 8001), "vsock_port is required"},
			"no creds vsock": {kms(8000, 0), "creds_vsock_port is required"},
			"neither":        {kms(0, 0), "vsock_port is required"},
		} {
			err := tc.c.validateAttested()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("QV_ENV=%q %s: want %q, got %v", env, name, tc.want, err)
			}
		}
		if err := kms(8000, 8001).validateAttested(); err != nil {
			t.Errorf("QV_ENV=%q: both vsock ports set: %v", env, err)
		}
	}
	for _, env := range []string{"dev", "test"} {
		t.Setenv("QV_ENV", env)
		if err := kms(0, 0).validateAttested(); err != nil {
			t.Errorf("QV_ENV=%s: the test setup (network KMS, AWS_* credentials) must still be accepted: %v", env, err)
		}
	}
}

// S4 fix1: in production the provider must be named; an empty one used to select the SoftHSM profile silently (process-made IV, pin_env) for any
// module that does not call itself SoftHSM. Development and tests keep the empty default.
func TestPKCS11EmptyProviderRefusedInProduction(t *testing.T) {
	pin := writePINFile(t, "1234")
	for _, env := range []string{"", "production", "staging"} {
		t.Setenv("QV_ENV", env)
		for _, prov := range []string{"", "  "} {
			_, err := NewPKCS11Sealer(SealerConfig{Type: "pkcs11", Provider: prov, Token: "t", PinFile: pin, Lib: "/nonexistent"})
			if err == nil || !strings.Contains(err.Error(), "provider is required in production") {
				t.Errorf("QV_ENV=%q provider=%q: want the provider refusal, got %v", env, prov, err)
			}
		}
		// Named providers pass this check (and fail later, on the missing library).
		for _, prov := range []string{ProviderSoftHSM, ProviderCloudHSM} {
			p := pin
			if prov == ProviderCloudHSM {
				p = writePINFile(t, "user:pw")
			}
			_, err := NewPKCS11Sealer(SealerConfig{Type: "pkcs11", Provider: prov, Token: "t", PinFile: p, Lib: "/nonexistent"})
			if err == nil || !strings.Contains(err.Error(), "library") {
				t.Errorf("QV_ENV=%q provider=%q: want the library error, got %v", env, prov, err)
			}
		}
	}
	for _, env := range []string{"dev", "test"} {
		t.Setenv("QV_ENV", env)
		_, err := NewPKCS11Sealer(SealerConfig{Type: "pkcs11", Token: "t", PinFile: pin, Lib: "/nonexistent"})
		if err == nil || !strings.Contains(err.Error(), "library") {
			t.Errorf("QV_ENV=%s: the empty provider (SoftHSM profile) must still be accepted: %v", env, err)
		}
	}
}

func writePINFile(t *testing.T, pin string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(p, []byte(pin), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}
