//go:build !teesim

package broker

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func goCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// The production broker contains no mock code and no test root: not in its files, not in its dependencies' files, and not as a symbol of the
// compiled binary (the pattern of attest.TestProductionBuildHasNoMock, applied to the whole program).
func TestProductionBrokerHasNoMock(t *testing.T) {
	deps := goCmd(t, ".", "list", "-deps", "-f", "{{.ImportPath}} {{join .GoFiles \" \"}}", "../../../cmd/qv-attest-broker")
	for _, line := range strings.Split(deps, "\n") {
		if strings.Contains(line, "quorum-vault") && strings.Contains(line, "mock") {
			t.Fatalf("a production dependency holds a mock file: %s", line)
		}
	}
	bin := filepath.Join(t.TempDir(), "broker")
	goCmd(t, ".", "build", "-o", bin, "../../../cmd/qv-attest-broker")
	syms := goCmd(t, ".", "tool", "nm", bin)
	for _, bad := range []string{"MockAttester", "MockCA", "NewMockCA", "LoadMockCA", "MeasureImage", "QV mock Nitro root"} {
		if strings.Contains(syms, bad) {
			t.Fatalf("the production binary contains %s", bad)
		}
	}
	if !strings.Contains(syms, "NitroVerifier") || !strings.Contains(syms, "checkBuildPolicy") {
		t.Fatal("symbol check found no verifier or policy: the check itself is broken")
	}
}
