//go:build !teesim

package attest

import (
	"os/exec"
	"strings"
	"testing"
)

func goCmd(t *testing.T, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	out, err := exec.Command("go", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// The production build has neither the mock attester nor the test root: not in the file list, and not in the compiled package.
func TestProductionBuildHasNoMock(t *testing.T) {
	if SimulationBuild {
		t.Fatal("SimulationBuild is true in a build without the teesim tag")
	}
	files := goCmd(t, "list", "-f", "{{join .GoFiles \" \"}}", ".")
	if strings.Contains(files, "mock") {
		t.Fatalf("production file list holds a mock file: %s", files)
	}
	if !strings.Contains(goCmd(t, "list", "-tags", "teesim", "-f", "{{join .GoFiles \" \"}}", "."), "mock_teesim.go") {
		t.Fatal("the teesim build does not hold the mock: this test would prove nothing")
	}
	// symbols of the compiled package archive (includes unreferenced ones)
	archive := strings.TrimSpace(goCmd(t, "list", "-export", "-f", "{{.Export}}", "."))
	syms := goCmd(t, "tool", "nm", archive)
	for _, bad := range []string{"MockAttester", "MockCA", "NewMockCA", "LoadMockCA", "MeasureImage"} {
		if strings.Contains(syms, bad) {
			t.Fatalf("production package contains symbol %s", bad)
		}
	}
	if !strings.Contains(syms, "NitroVerifier") {
		t.Fatal("symbol check found no NitroVerifier: the check itself is broken")
	}
}

// The verifier tests need the mock, so they are tagged. Run them from the plain `go test ./...` too, so CI covers them without a second command.
func TestVerifierRulesUnderTeesim(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	goCmd(t, "test", "-count=1", "-tags", "teesim", ".")
}

// The test CA tool refuses to run in a production build.
func TestCATooIsInertWithoutTag(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	out, err := exec.Command("go", "run", "./cmd/qv-attest-ca", "-dir", t.TempDir()).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "without -tags teesim") {
		t.Fatalf("expected refusal, got %v: %s", err, out)
	}
}
