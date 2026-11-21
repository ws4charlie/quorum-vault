//go:build !teesim

package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

func goRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("go", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// The production party contains no mock attester and no test root, and a party configured with the attested sealer refuses to start in it (the
// Nitro attester does not exist yet), with a message that says so. It never falls back to another sealer.
func TestProductionPartyHasNoMockAndRefusesTheAttestedSealerWithoutAttester(t *testing.T) {
	deps := goRun(t, "list", "-deps", "-f", "{{.ImportPath}} {{join .GoFiles \" \"}}", ".")
	for _, line := range strings.Split(deps, "\n") {
		if strings.Contains(line, "quorum-vault") && strings.Contains(line, "mock") {
			t.Fatalf("a production dependency holds a mock file: %s", line)
		}
	}
	bin := filepath.Join(t.TempDir(), "mpc-party")
	goRun(t, "build", "-o", bin, ".")
	syms := goRun(t, "tool", "nm", bin)
	for _, bad := range []string{"MockAttester", "MockCA", "LoadMockCA", "NewMockCA", "MeasureImage", "QV mock Nitro root", "teetest"} {
		if strings.Contains(syms, bad) {
			t.Fatalf("the production binary contains %s", bad)
		}
	}
	if !strings.Contains(syms, "AttestedSealer") {
		t.Fatal("symbol check found no attested sealer: the check itself is broken")
	}

	env := testenv.NewEnv(t)
	cfg := env.Config(t, "A", "127.0.0.1:1", "127.0.0.1:0", "")
	cfg.Authorizer = server.AuthorizerConfig{Type: "deny-all"}
	cfg.Sealer = server.SealerConfig{Type: "attested", BrokerURL: "https://127.0.0.1:1", BrokerPins: []string{env.CertA.Pin},
		Attester: server.AttesterConfig{Type: "mock", CADir: "/nonexistent", PCR0: strings.Repeat("00", 48)}}
	path := env.WriteConfig(t, cfg, "attested.json")
	cmd := exec.Command(bin, "-config", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("a production party started with the attested sealer and no attester")
	}
	if !strings.Contains(stderr.String(), "attester \"mock\" is not available in this build") {
		t.Fatalf("unclear refusal: %s", stderr.String())
	}
}
