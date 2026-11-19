package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

// ---- one process per data directory

func TestDataLockSecondProcessRefusedThenAllowedAfterRelease(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "party")
	first, err := acquireDataLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := acquireDataLock(dir)
	if err == nil {
		second.release()
		t.Fatal("a second holder of the same data directory was allowed")
	}
	if !strings.Contains(err.Error(), "in use by another mpc-party process") || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("the message must say what is wrong: %v", err)
	}
	// a different directory is independent
	other, err := acquireDataLock(filepath.Join(t.TempDir(), "party2"))
	if err != nil {
		t.Fatal(err)
	}
	other.release()
	first.release()
	first.release() // twice is fine
	third, err := acquireDataLock(dir)
	if err != nil {
		t.Fatalf("after the first released: %v", err)
	}
	third.release()
}

// The lock belongs to the process: when the holder is killed without any cleanup, the next one starts at once (no stale lock file to remove).
func TestDataLockIsReleasedWhenTheHolderIsKilled(t *testing.T) {
	if os.Getenv("QV_LOCK_HELPER_DIR") != "" { // child: take the lock, say so, wait to be killed
		l, err := acquireDataLock(os.Getenv("QV_LOCK_HELPER_DIR"))
		if err != nil {
			os.Stdout.WriteString("FAIL " + err.Error() + "\n")
			os.Exit(3)
		}
		_ = l
		os.Stdout.WriteString("LOCKED\n")
		time.Sleep(time.Minute)
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDataLockIsReleasedWhenTheHolderIsKilled$")
	cmd.Env = append(os.Environ(), "QV_LOCK_HELPER_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	buf := make([]byte, 64)
	n, _ := io.ReadAtLeast(out, buf, 6)
	if !strings.HasPrefix(string(buf[:n]), "LOCKED") {
		t.Fatalf("helper: %q", buf[:n])
	}
	if l, err := acquireDataLock(dir); err == nil {
		l.release()
		t.Fatal("a live process in another PID holds the lock; this one must be refused")
	}
	cmd.Process.Kill() // kill -9: no deferred cleanup runs
	cmd.Wait()
	l, err := acquireDataLock(dir)
	if err != nil {
		t.Fatalf("after the holder was killed: %v", err)
	}
	l.release()
}

// ---- pin_file mode

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

// ---- SoftHSM in production

func TestSoftHSMDetectionAndProductionRefusal(t *testing.T) {
	soft := pkcs11.Info{ManufacturerID: "SoftHSM", LibraryDescription: "Implementation of PKCS11"}
	softTok := &pkcs11.TokenInfo{ManufacturerID: "SoftHSM project", Model: "SoftHSM v2"}
	cloud := pkcs11.Info{ManufacturerID: "Amazon Web Services", LibraryDescription: "CloudHSM"}
	if !isSoftHSM(soft, nil) || !isSoftHSM(cloud, softTok) || isSoftHSM(cloud, &pkcs11.TokenInfo{ManufacturerID: "Amazon", Model: "CloudHSM"}) || isSoftHSM(pkcs11.Info{}, nil) {
		t.Fatal("detection by what the module reports")
	}
	// the file name does not decide: a SoftHSM module under another name is still SoftHSM, a real one named softhsm is judged by its report
	if err := refuseSoftHSM(soft, nil, "/usr/lib/libcloudhsm_pkcs11.so"); err == nil {
		t.Fatal("QV_ENV unset: SoftHSM under another file name must be refused")
	}
	if err := refuseSoftHSM(cloud, nil, "/opt/softhsm/lib.so"); err != nil {
		t.Fatalf("a real HSM must pass whatever the file is called: %v", err)
	}
	for env, refused := range map[string]bool{"": true, "production": true, "prod": true, "staging": true, "dev": false, "test": false, "DEV": false, " test ": false} {
		t.Setenv("QV_ENV", env)
		err := refuseSoftHSM(soft, softTok, "/x/libsofthsm2.so")
		if (err != nil) != refused {
			t.Errorf("QV_ENV=%q: err=%v, refused should be %v", env, err, refused)
		}
		if err != nil && !strings.Contains(err.Error(), "refused in production") {
			t.Errorf("QV_ENV=%q: unclear message %v", env, err)
		}
	}
}

// ---- probes and metrics

func TestHealthHandler(t *testing.T) {
	cert := selfSigned(t, "party-a", time.Hour)
	s := &Server{cfg: &Config{Role: "A"}, cert: cert, fails: newFailStats("A")}
	h := s.HealthHandler()
	get := func(method, path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		b, _ := io.ReadAll(rec.Result().Body)
		return rec.Code, string(b)
	}
	if code, _ := get("GET", "/livez"); code != 200 {
		t.Fatalf("livez %d", code)
	}
	if code, _ := get("GET", "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before Start: %d", code)
	}
	s.started.Store(true)
	if code, body := get("GET", "/readyz"); code != 200 || strings.TrimSpace(body) != "ok" {
		t.Fatalf("readyz after Start: %d %q", code, body)
	}
	if err := s.Ready(time.Now().Add(2 * time.Hour)); err == nil {
		t.Fatal("an expired certificate must make the party not ready")
	}
	for _, p := range []string{"/", "/metrics", "/debug/pprof/", "/readyz/x"} {
		if code, _ := get("GET", p); code != 404 {
			t.Errorf("%s: %d, want 404", p, code)
		}
	}
	if code, _ := get("POST", "/livez"); code != 405 {
		t.Errorf("POST: %d", code)
	}
	s.stopMu.Lock()
	s.stopped = true // Shutdown began
	s.stopMu.Unlock()
	if code, body := get("GET", "/readyz"); code != 503 || strings.Contains(body, "stopping") {
		t.Fatalf("readyz while stopping: %d %q (no detail allowed)", code, body)
	}
	if code, _ := get("GET", "/livez"); code != 200 {
		t.Fatalf("livez while stopping: %d", code)
	}
}

// The party's certificate expiry is on its metrics under the shared name, for the shared alert rule.
func TestPartyMetricsHaveCertExpiry(t *testing.T) {
	cert := selfSigned(t, "party-b", 48*time.Hour)
	s := &Server{cfg: &Config{Role: "B"}, cert: cert, fails: newFailStats("B")}
	var b strings.Builder
	s.WriteMetrics(&b)
	if !strings.Contains(b.String(), `qv_tls_cert_seconds_to_expiry{name="mpc-party-b",zone="signing",kind="leaf"} 1`) { // 172800 - a few seconds
		t.Fatalf("no expiry metric:\n%s", b.String())
	}
}

func selfSigned(t *testing.T, name string, valid time.Duration) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(valid)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
