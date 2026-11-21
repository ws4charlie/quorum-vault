//go:build linux && !teesim

package server

import (
	"strings"
	"testing"
)

// The production party carries the Nitro attester and no other: "mock" does not exist in it, so sealer.type attested with attester.type mock
// refuses to start, and "nitro" outside an enclave refuses (no /dev/nsm) instead of falling back.
func TestProductionAttesterFactories(t *testing.T) {
	if _, ok := attesterFactories["nitro"]; !ok {
		t.Fatal("the production build has no nitro attester")
	}
	if len(attesterFactories) != 1 {
		t.Fatalf("production attesters: %d, want only nitro", len(attesterFactories))
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "a")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "b")
	cfg := SealerConfig{Type: AttestedSealerType, Release: ReleaseConfig{Type: "kms", KMS: KMSConfig{KeyID: "k", Region: "r"}}}
	cfg.Attester.Type = "mock"
	if _, err := NewSealerForRole("A", cfg); err == nil || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("mock attester: %v", err)
	}
	cfg.Attester.Type = "nitro"
	if _, err := NewSealerForRole("A", cfg); err == nil || !strings.Contains(err.Error(), "/dev/nsm") {
		t.Fatalf("nitro attester outside an enclave: %v", err)
	}
}
