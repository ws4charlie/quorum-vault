//go:build teesim

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/teetest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// `backup export` and `backup restore` open the store, so with the attested sealer they must prove themselves to the broker like a start: the simulated
// attester measures the running binary and the config file named by -config (no pcr0, no measure_* in the config). SIMULATED enclave.
func TestBackupCommandsReachTheBrokerWithTheDefaultMeasurement(t *testing.T) {
	env := testenv.NewEnv(t)
	cfg := env.Config(t, "A", "127.0.0.1:1", "127.0.0.1:0", "")
	rig := teetest.New(t, []teetest.PartyCert{{Role: "A", CertFile: cfg.CertFile, KeyFile: cfg.KeyFile, Pin: env.CertA.Pin}})
	cfg.Sealer = server.SealerConfig{Type: server.AttestedSealerType, BrokerURL: rig.URL, BrokerPins: []string{rig.Pin},
		BrokerCertFile: cfg.CertFile, BrokerKeyFile: cfg.KeyFile, Attester: server.AttesterConfig{Type: "mock", CADir: rig.CADir}}
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(t.TempDir(), "party-A.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable() // this test binary is the "party image"
	m, err := attest.MeasureFiles(exe, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rig.SetAllowlist(attest.AllowEntry{Party: "A", Measurement: hex.EncodeToString(m), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})

	pub := filepath.Join(t.TempDir(), "rec.pub")
	os.WriteFile(pub, []byte("x"), 0o600)
	err = cmdExport([]string{"-config", cfgPath, "-keyset", "none", "-recovery-public", pub, "-out", filepath.Join(t.TempDir(), "b.json")})
	if err == nil || !strings.Contains(err.Error(), "has no current generation") { // past the sealer: it got its keys
		t.Fatalf("export: %v", err)
	}
	err = cmdRestore([]string{"-config", cfgPath, "-recovery-private", pub, "-file", filepath.Join(t.TempDir(), "missing.json")})
	if err == nil || strings.Contains(err.Error(), "sealer cannot get its keys") || strings.Contains(err.Error(), "measure_config") {
		t.Fatalf("restore: %v", err)
	}
	released := 0
	for _, r := range rig.Audit() {
		if r.Outcome == "released" && r.Measurement == hex.EncodeToString(m) {
			released++
		}
	}
	if released < 2 {
		t.Fatalf("the broker released keys to the measured image %d times, want one per command", released)
	}
}
