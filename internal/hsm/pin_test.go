package hsm

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two tests below are byte-for-byte the tests of the party's pin_file rule (mpc-party/internal/server/k8s_internal_test.go: TestPINFileModes and
// TestPINFileThroughSymlink). The party is another Go module and keeps its own copy of the rule; if one changes, change the other.

func TestPINFileModes(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		ok   bool
		warn bool // the group-readable acceptance is logged
	}{
		{0o400, true, false}, {0o600, true, false}, {0o500, true, false},
		{0o440, true, true}, {0o640, true, true}, {0o460, false, false}, {0o660, false, false},
		{0o410, false, false}, {0o750, false, false}, {0o470, false, false}, // group execute or write
		{0o404, false, false}, {0o604, false, false}, {0o644, false, false}, {0o444, false, false}, {0o441, false, false}, {0o646, false, false}, {0o666, false, false}, {0o777, false, false},
	}
	for _, c := range cases {
		var logs bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		f := filepath.Join(t.TempDir(), "pin")
		os.WriteFile(f, []byte("123456\n"), 0o600)
		os.Chmod(f, c.mode)
		pin, err := ReadPIN("", f)
		slog.SetDefault(old)
		if c.ok {
			if err != nil || pin != "123456" {
				t.Errorf("mode %04o: refused: %v", c.mode, err)
			}
		} else {
			if err == nil {
				t.Errorf("mode %04o: accepted", c.mode)
			} else if strings.Contains(err.Error(), "123456") {
				t.Errorf("mode %04o: PIN in the error", c.mode)
			}
		}
		if got := strings.Contains(logs.String(), "group-readable"); got != c.warn {
			t.Errorf("mode %04o: group-readable log = %v, want %v (%s)", c.mode, got, c.warn, logs.String())
		}
		if c.warn && !strings.Contains(logs.String(), fmt.Sprintf("mode=%04o", uint32(c.mode))) {
			t.Errorf("mode %04o: the log must name the accepted mode: %s", c.mode, logs.String())
		}
		if strings.Contains(logs.String(), "123456") {
			t.Errorf("mode %04o: PIN in the log", c.mode)
		}
	}
}

// A symlinked file, as a Kubernetes Secret volume mounts it (file -> ..data/file), is judged by the file it points at.
func TestPINFileThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	os.WriteFile(real, []byte("9999"), 0o440)
	os.Chmod(real, 0o440)
	link := filepath.Join(dir, "pin")
	os.Symlink(real, link)
	if pin, err := ReadPIN("", link); err != nil || pin != "9999" {
		t.Fatalf("%v", err)
	}
	os.Chmod(real, 0o660)
	if _, err := ReadPIN("", link); err == nil {
		t.Fatal("a group-writable target must be refused through the link too")
	}
}

// ---- the service's PIN: file in production, environment only in dev and test

func TestServicePIN(t *testing.T) {
	write := func(mode os.FileMode, content string) string {
		f := filepath.Join(t.TempDir(), "pin")
		os.WriteFile(f, []byte(content), 0o600)
		os.Chmod(f, mode)
		return f
	}
	cases := []struct {
		name, qvEnv, env, file string
		want, errHas           string
	}{
		{"file, production", "", "", write(0o440, "s3cret-pin\n"), "s3cret-pin", ""},
		{"file, QV_ENV=production", "production", "", write(0o400, "s3cret-pin"), "s3cret-pin", ""},
		{"file, dev", "dev", "", write(0o600, "s3cret-pin\r\n"), "s3cret-pin", ""},
		{"file with a bad mode", "", "", write(0o644, "s3cret-pin"), "", "mode 0644"},
		{"empty file", "", "", write(0o400, "\n"), "", "empty"},
		{"missing file", "", "", filepath.Join(t.TempDir(), "none"), "", "PIN file"},
		{"environment, unset QV_ENV", "", "s3cret-pin", "", "", PINFileEnv},
		{"environment, QV_ENV=staging", "staging", "s3cret-pin", "", "", PINFileEnv},
		{"environment, QV_ENV=prod", "prod", "s3cret-pin", "", "", "refused in production"},
		{"environment, dev", "dev", "s3cret-pin", "", "s3cret-pin", ""},
		{"environment, test", " TEST ", "s3cret-pin", "", "s3cret-pin", ""},
		{"both", "dev", "s3cret-pin", write(0o400, "decoy-pin-9"), "", "both"},
		{"none, production", "", "", "", "", PINFileEnv},
		{"none, dev", "dev", "", "", "", PINFileEnv},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("QV_ENV", c.qvEnv)
			t.Setenv(PINEnv, c.env)
			t.Setenv(PINFileEnv, c.file)
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			pin, err := ServicePIN()
			slog.SetDefault(old)
			if c.errHas == "" {
				if err != nil || pin != c.want {
					t.Fatalf("pin %q, err %v; want %q", pin, err, c.want)
				}
				if c.env != "" && os.Getenv(PINEnv) != "" {
					t.Error("the PIN stays in the process environment after the read")
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), c.errHas) {
					t.Fatalf("err %v, want it to contain %q", err, c.errHas)
				}
				if pin != "" {
					t.Error("a PIN is returned with an error")
				}
			}
			for _, s := range []string{"s3cret-pin", "decoy-pin-9"} {
				if err != nil && strings.Contains(err.Error(), s) || strings.Contains(logs.String(), s) {
					t.Errorf("the PIN is in an error or a log line: %v %s", err, logs.String())
				}
			}
		})
	}
}
