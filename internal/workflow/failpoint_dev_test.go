//go:build devauth

package workflow

import "testing"

// With -tags devauth the failpoint fires, through FailHook in a test (the process would exit otherwise).
func TestDevBuildFiresTheFailpoint(t *testing.T) {
	t.Setenv("QV_FAILPOINT", "sweep.after_job")
	var got string
	FailHook = func(p string) { got = p }
	t.Cleanup(func() { FailHook = nil })
	Hit("withdrawal", "after_job") // another point: nothing
	if got != "" {
		t.Fatalf("fired for the wrong point: %q", got)
	}
	Hit("sweep", "after_job")
	if got != "sweep.after_job" {
		t.Fatalf("hook got %q", got)
	}
	if Armed() != "sweep.after_job" {
		t.Fatalf("Armed() = %q", Armed())
	}
}
