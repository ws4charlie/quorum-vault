//go:build !devauth

package workflow

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// In a default (production) build a failpoint in the environment does nothing: no exit, no hook.
func TestProductionBuildIgnoresFailpoints(t *testing.T) {
	t.Setenv("QV_FAILPOINT", "withdrawal.after_build")
	called := false
	FailHook = func(string) { called = true }
	t.Cleanup(func() { FailHook = nil })
	Hit("withdrawal", "after_build") // would exit the test binary if it were armed
	if called {
		t.Fatal("the hook ran in a production build")
	}
	if Armed() != "" {
		t.Fatalf("Armed() = %q in a production build", Armed())
	}
}

// The default qv-worker binary does not even contain the failpoint's exit path.
func TestDefaultWorkerBinaryHasNoFailpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "qv-worker")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/ws4charlie/quorum-vault/cmd/qv-worker").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("failpoint reached: killing the process")) {
		t.Fatal("the default qv-worker contains the failpoint code")
	}
	devBin := filepath.Join(t.TempDir(), "qv-worker-dev")
	if out, err := exec.Command("go", "build", "-tags", "devauth", "-o", devBin, "github.com/ws4charlie/quorum-vault/cmd/qv-worker").CombinedOutput(); err != nil {
		t.Fatalf("build -tags devauth: %v\n%s", err, out)
	}
	if db, _ := os.ReadFile(devBin); !bytes.Contains(db, []byte("failpoint reached: killing the process")) {
		t.Fatal("the devauth build lacks the failpoint (the check above would prove nothing)")
	}
}
