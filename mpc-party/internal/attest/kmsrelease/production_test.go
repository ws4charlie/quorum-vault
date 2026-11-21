//go:build !teesim

package kmsrelease_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The fake KMS (and with it the mock attester and the test root) is not in the production party: it is not among its dependencies.
func TestProductionPartyHasNoKMSFake(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	out, err := exec.Command("go", "list", "-deps", "../../../cmd/mpc-party").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := string(out)
	if !strings.Contains(deps, "internal/attest/kmsrelease") {
		t.Fatal("the party does not link the KMS release: this test would prove nothing")
	}
	for _, bad := range []string{"kmsfake", "net/http/httptest"} {
		if strings.Contains(deps, bad) {
			t.Fatalf("the production party depends on %s", bad)
		}
	}
}
