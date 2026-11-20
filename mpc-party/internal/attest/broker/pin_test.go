package broker

import (
	"os"
	"path/filepath"
	"testing"
)

// A Secret volume under fsGroup is group-readable (0440): the broker accepts it. Anything the group can write or execute, and anything for others, is refused.
func TestReadPINFileModes(t *testing.T) {
	for mode, ok := range map[os.FileMode]bool{
		0o400: true, 0o600: true, 0o440: true, 0o640: true,
		0o660: false, 0o620: false, 0o450: false, 0o644: false, 0o444: false, 0o604: false, 0o750: false, 0o777: false,
	} {
		f := filepath.Join(t.TempDir(), "pin")
		if err := os.WriteFile(f, []byte("1234\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		pin, err := ReadPIN("", f)
		if ok && (err != nil || pin != "1234") {
			t.Errorf("mode %04o refused: %q, %v", mode, pin, err)
		}
		if !ok && err == nil {
			t.Errorf("mode %04o accepted", mode)
		}
	}
}
