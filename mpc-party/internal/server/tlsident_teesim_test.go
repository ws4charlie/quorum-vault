//go:build teesim

package server_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// SIMULATED enclave: the TLS key of a party is made inside the party, sealed under the party's local data key and never on disk in the clear.
func TestSealedTLSKeyIsMadeInsideSealedAndLoadsAfterRestart(t *testing.T) {
	r := newAttRig(t)
	dir := t.TempDir()
	cfg := &server.Config{Role: "A", DataDir: dir, TLSSealed: true, Sealer: r.sealerConfig("A", "")}
	pin, created, err := server.TLSInit(context.Background(), cfg, time.Hour)
	if err != nil || !created {
		t.Fatalf("tls-init: created=%v err=%v", created, err)
	}
	// no private key in the clear anywhere in the data directory
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Errorf("%s holds a private key in the clear", p)
		}
		return nil
	})
	if _, err := os.Stat(filepath.Join(dir, "tls-key.sealed.json")); err != nil {
		t.Fatal(err)
	}
	// run again: same pin, nothing changes
	pin2, created, err := server.TLSInit(context.Background(), cfg, time.Hour)
	if err != nil || created || pin2 != pin {
		t.Fatalf("second tls-init: pin %v vs %v created=%v err=%v", pin2, pin, created, err)
	}
	// a restart: a new sealer asks the broker again, opens the key, and the certificate's pin is the exported one
	fs, _, err := r.store("A", dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := fs.LoadTLSIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := server.PinOf(cert.Certificate[0])
	if err != nil || got != pin {
		t.Fatalf("pin of the loaded certificate %v, exported %v (%v)", got, pin, err)
	}
	// the sealed file moved to another party's directory does not open (associated data names the role)
	dirB := t.TempDir()
	b, _ := os.ReadFile(filepath.Join(dir, "tls-key.sealed.json"))
	os.WriteFile(filepath.Join(dirB, "tls-key.sealed.json"), b, 0o600)
	c, _ := os.ReadFile(filepath.Join(dir, "tls-cert.pem"))
	os.WriteFile(filepath.Join(dirB, "tls-cert.pem"), c, 0o600)
	fsB, _, err := r.store("B", dirB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fsB.LoadTLSIdentity(context.Background()); err == nil {
		t.Fatal("party B opened party A's sealed TLS key")
	}
	// a flipped byte does not open
	b[len(b)/2] ^= 1
	os.WriteFile(filepath.Join(dir, "tls-key.sealed.json"), b, 0o600)
	fs2, _, err := r.store("A", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs2.LoadTLSIdentity(context.Background()); err == nil {
		t.Fatal("a corrupted sealed key opened")
	}
}

func TestSealedTLSRequiresAttestedSealerAndNoKeyFiles(t *testing.T) {
	c := &server.Config{TLSSealed: true, CertFile: "a", KeyFile: "b"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "tls_sealed") {
		t.Fatalf("validate: %v", err)
	}
}
