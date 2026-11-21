package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

func src(t *testing.T, root, zone, service string) *pki.Source {
	t.Helper()
	d := pki.Dir(root, zone, service)
	s, err := pki.NewSource(pki.SourceConfig{Name: "qv-cosigner", Zone: zone, CertFile: filepath.Join(d, "tls.crt"), KeyFile: filepath.Join(d, "tls.key"), CAFile: filepath.Join(d, "ca.crt")})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCosignerIdentityFollowsTheCertificate(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	if err := pki.Init(root, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := pki.IssueAll(root, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"b", "c"} {
		ts, ls := src(t, root, pki.ZoneSigning, "cosigner-"+role), src(t, root, pki.ZoneBusiness, "cosigner-link-"+role)
		got, err := cosignerIdentity(ts, ls)
		if err != nil || got != role {
			t.Fatalf("role %s: got %q, %v", role, got, err)
		}
		if ts.Name() != "qv-cosigner-"+role || ls.Name() != "qv-cosigner-link-"+role {
			t.Errorf("metrics names: %s, %s", ts.Name(), ls.Name())
		}
	}
	// B's signing certificate with C's link certificate, and the other way: refused
	if _, err := cosignerIdentity(src(t, root, pki.ZoneSigning, "cosigner-b"), src(t, root, pki.ZoneBusiness, "cosigner-link-c")); err == nil || !strings.Contains(err.Error(), "cosigner-link-b") {
		t.Errorf("B with C's link: %v", err)
	}
	// a non-cosigner certificate of the signing zone, and the retired shared name's shape
	for _, other := range []string{"gateway", "cosigner-socket", "admin"} {
		if _, err := cosignerIdentity(src(t, root, pki.ZoneSigning, other), src(t, root, pki.ZoneBusiness, "cosigner-link-b")); err == nil {
			t.Errorf("a %s certificate was accepted as a cosigner", other)
		}
	}
	// plain text development switch: no sources, no role
	if r, err := cosignerIdentity(nil, nil); err != nil || r != "" {
		t.Errorf("plain text: %q %v", r, err)
	}
}

// A reload that brings the other cosigner's certificate is refused and the process keeps its own.
func TestCosignerKeepsItsNameOnReload(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	if err := pki.Init(root, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := pki.IssueAll(root, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	// work on a copy of B's files and swap C's certificate in
	b := pki.Dir(root, pki.ZoneSigning, "cosigner-b")
	c := pki.Dir(root, pki.ZoneSigning, "cosigner-c")
	cp := t.TempDir()
	for _, f := range []string{"tls.crt", "tls.key", "ca.crt"} {
		copyFile(t, filepath.Join(b, f), filepath.Join(cp, f))
	}
	ts, err := pki.NewSource(pki.SourceConfig{Name: "x", Zone: pki.ZoneSigning, CertFile: filepath.Join(cp, "tls.crt"), KeyFile: filepath.Join(cp, "tls.key"), CAFile: filepath.Join(cp, "ca.crt")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.HoldName("cosigner-b"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"tls.crt", "tls.key"} {
		copyFile(t, filepath.Join(c, f), filepath.Join(cp, f))
	}
	if err := ts.Reload(); err == nil || !strings.Contains(err.Error(), "holds the name") {
		t.Fatalf("a reload with C's certificate: %v", err)
	}
	if ts.Service() != "cosigner-b" {
		t.Errorf("the process changed identity: %s", ts.Service())
	}
}

func TestVerifyNeedsASource(t *testing.T) {
	for args, want := range map[string]bool{"-dsn x": false, "-source cosigner-b": true, "--source=cosigner-c": true, "-source": false, "-source=": false} {
		if got := hasSourceFlag(strings.Fields(args)); got != want {
			t.Errorf("%q: %v", args, got)
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
