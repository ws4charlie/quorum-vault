package cbmpc

import (
	"os/exec"
	"strings"
	"testing"
)

// The module must never import go-ethereum: its cgo libsecp256k1 collides with cb-mpc's vendored copy at link time.
func TestModuleDoesNotDependOnGoEthereum(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-test", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "go-ethereum") || (strings.Contains(l, "quorum-vault/internal") && !strings.Contains(l, "mpc-party")) {
			t.Fatalf("forbidden dependency in mpc-party: %s", l)
		}
	}
	mod, err := exec.Command("go", "list", "-m", "all").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m: %v\n%s", err, mod)
	}
	if strings.Contains(string(mod), "go-ethereum") {
		t.Fatalf("go-ethereum is in the module graph of mpc-party:\n%s", mod)
	}
}
