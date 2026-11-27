package mpcstack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The builds the harnesses ask GoBuild for (e2e/btc, e2e/sol, e2e/custody harness_test.go; Build, BuildTeeSim, BuildPartyAdmin; e2e/mpcsign and
// e2e/solsign stack_test.go; e2e/custody load_test.go), as (workdir relative to the root, package, tags).
var harnessBuilds = [][3]string{
	{".", modulePath + "cmd/qv-worker", "devauth"},
	{".", modulePath + "cmd/qv-core", ""}, {".", modulePath + "cmd/qv-gateway", ""}, {".", modulePath + "cmd/qv-cold", ""},
	{".", modulePath + "cmd/qv-btc-xpub", ""}, {".", modulePath + "cmd/qv-fee-caps", ""}, {".", modulePath + "cmd/qv-approvers", ""},
	{".", modulePath + "cmd/qv-keysets", ""}, {".", modulePath + "cmd/qv-rekey", ""}, {".", modulePath + "cmd/qv-relay", ""},
	{".", modulePath + "cmd/qv-guardian", ""}, {".", modulePath + "cmd/qv-approval-web", ""}, {".", modulePath + "cmd/qv-sol-nonces", ""},
	{".", modulePath + "loadtest/cmd/qv-load", ""},
	{"mpc-party", "./cmd/mpc-party", ""}, {".", "./cmd/qv-cosigner", ""}, {"mpc-party", "./cmd/qv-party-admin", ""},
	{"mpc-party", "./cmd/mpc-party", "teesim"}, {"mpc-party", "./cmd/qv-attest-broker", "teesim"},
	{"mpc-party", "./internal/attest/cmd/qv-attest-ca", "teesim"},
}

func TestPrebuiltKeys(t *testing.T) {
	root := RepoRoot()
	for _, c := range []struct{ workdir, pkg, tags, want string }{
		{root, modulePath + "cmd/qv-worker", "devauth", "cmd_qv-worker@devauth"},
		{filepath.Join(root, "mpc-party"), "./cmd/mpc-party", "teesim", "mpc-party_cmd_mpc-party@teesim"},
		{"../../mpc-party", "./cmd/mpc-party", "", "mpc-party_cmd_mpc-party"}, // e2e/mpcsign's spelling, from this package's directory
		{"../..", "./cmd/qv-gateway", "", "cmd_qv-gateway"},
		{root, "./cmd/a", "x,y", "cmd_a@x+y"},
	} {
		got, err := PrebuiltKey(c.workdir, c.pkg, c.tags)
		if err != nil || got != c.want {
			t.Errorf("PrebuiltKey(%s, %s, %q) = %q, %v; want %q", c.workdir, c.pkg, c.tags, got, err, c.want)
		}
	}
	for _, bad := range []string{"example.com/x", "../../../outside"} {
		if _, err := PrebuiltKey(root, bad, ""); err == nil {
			t.Errorf("PrebuiltKey(%s): want an error", bad)
		}
	}
}

// ci/e2e-prebuild.sh makes every binary a harness asks for (in CI a missing one fails the job: QV_E2E_PREBUILT_STRICT=1).
func TestThePrebuildScriptMakesEveryHarnessBuild(t *testing.T) {
	root := RepoRoot()
	b, err := os.ReadFile(filepath.Join(root, "ci", "e2e-prebuild.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := map[string]bool{}
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, `BUILDS="`):
			in = true
		case in && line == `"`:
			in = false
		case in && strings.TrimSpace(line) != "":
			f := strings.Fields(line)
			tags := f[2]
			if tags == "-" {
				tags = ""
			}
			k, err := PrebuiltKey(filepath.Join(root, f[0]), f[1], tags)
			if err != nil {
				t.Fatal(err)
			}
			script[k] = true
		}
	}
	for _, h := range harnessBuilds {
		k, err := PrebuiltKey(filepath.Join(root, h[0]), h[1], h[2])
		if err != nil {
			t.Fatal(err)
		}
		if !script[k] {
			t.Errorf("ci/e2e-prebuild.sh does not build %s (a harness asks for it)", k)
		}
	}
}

func TestGoBuildCopiesAPrebuiltBinaryOrRefusesInStrictMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cmd_qv-core"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QV_E2E_PREBUILT", dir)
	t.Setenv("QV_E2E_PREBUILT_STRICT", "1")
	out := filepath.Join(t.TempDir(), "qv-core")
	if err := GoBuild(RepoRoot(), out, modulePath+"cmd/qv-core", ""); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err != nil || st.Mode()&0o100 == 0 {
		t.Fatalf("the copy is not an executable: %v %v", st, err)
	}
	if err := GoBuild(RepoRoot(), filepath.Join(t.TempDir(), "x"), modulePath+"cmd/qv-cold", ""); err == nil || !strings.Contains(err.Error(), "ci/e2e-prebuild.sh") {
		t.Fatalf("strict mode: a missing prebuilt binary must be an error naming ci/e2e-prebuild.sh, got %v", err)
	}
}
