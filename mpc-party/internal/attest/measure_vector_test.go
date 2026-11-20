//go:build teesim

package attest

import (
	"encoding/hex"
	"testing"
)

// The release tooling (deploy/images/measure-release.py) computes the measurement without Go. This vector is pinned in both places: if
// MeasureImage changes, the script's selftest and this test fail together, and no release measurement silently differs from what a party computes.
func TestMeasureImageVectorMatchesReleaseScript(t *testing.T) {
	const want = "d62171b1221a665b8e6c97d1be0c04a63f997fc5f96736ef7d22e224fc1bde82e02b6e9d6739b8326b32032b1949bf85"
	if got := hex.EncodeToString(MeasureImage([]byte("qv-binary"), []byte(`{"role":"A"}`))); got != want {
		t.Fatalf("MeasureImage vector: got %s, want %s (update deploy/images/measure-release.py too)", got, want)
	}
}
