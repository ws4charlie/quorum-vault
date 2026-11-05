package server_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

func pkcs11Sealer(t *testing.T, token string) *server.PKCS11Sealer {
	t.Helper()
	pin := testenv.HSMEnv(t)
	t.Setenv("QV_TEST_PIN", pin)
	s, err := server.NewPKCS11Sealer(server.SealerConfig{Type: "pkcs11", Token: token, PinEnv: "QV_TEST_PIN"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPKCS11SealerRoundTripAndBinding(t *testing.T) {
	a := pkcs11Sealer(t, "qv-party-1")
	b := pkcs11Sealer(t, "qv-party-2")
	aad := []byte("qv-mpc-party|keyset|v2|A|ks|1|ecdsa")
	secret := bytes.Repeat([]byte("share"), 200)
	sealed, err := a.Seal(aad, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("share")) {
		t.Fatal("plaintext visible in the envelope")
	}
	got, err := a.Open(aad, sealed)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %v", err)
	}
	// the envelope of a different token (party B's own key), a different AAD (role, keyset, generation), and flipped bytes
	for name, f := range map[string]func() error{
		"other party's token": func() error { _, e := b.Open(aad, sealed); return e },
		"other role":          func() error { _, e := a.Open([]byte("qv-mpc-party|keyset|v2|B|ks|1|ecdsa"), sealed); return e },
		"other keyset":        func() error { _, e := a.Open([]byte("qv-mpc-party|keyset|v2|A|other|1|ecdsa"), sealed); return e },
		"other generation":    func() error { _, e := a.Open([]byte("qv-mpc-party|keyset|v2|A|ks|2|ecdsa"), sealed); return e },
		"tampered ciphertext": func() error { x := append([]byte(nil), sealed...); x[len(x)/2] ^= 1; _, e := a.Open(aad, x); return e },
		"garbage":             func() error { _, e := a.Open(aad, []byte("not json")); return e },
	} {
		if err := f(); err == nil {
			t.Errorf("%s: opened", name)
		} else if _, ok := err.(*server.UnavailableError); ok {
			t.Errorf("%s: reported as an outage instead of a failed open: %v", name, err)
		}
	}
}

func TestPKCS11SealerRefusesToStart(t *testing.T) {
	pin := testenv.HSMEnv(t)
	t.Setenv("QV_TEST_PIN", pin)
	t.Setenv("QV_TEST_BADPIN", "definitely-wrong")
	dir := t.TempDir()
	loose := filepath.Join(dir, "pin-loose")
	os.WriteFile(loose, []byte(pin), 0o644)
	tight := filepath.Join(dir, "pin-tight")
	os.WriteFile(tight, []byte(pin+"\n"), 0o400)
	cases := map[string]struct {
		c    server.SealerConfig
		want string
	}{
		"missing token": {server.SealerConfig{Token: "no-such-token", PinEnv: "QV_TEST_PIN"}, "not found"},
		// (a wrong PIN is tested in e2e: PKCS#11 does not re-check the PIN once the process is logged in to the slot)
		"no PIN source":    {server.SealerConfig{Token: "qv-party-1"}, "pin_env or pin_file"},
		"both PIN sources": {server.SealerConfig{Token: "qv-party-1", PinEnv: "QV_TEST_PIN", PinFile: tight}, "exactly one"},
		"unset env":        {server.SealerConfig{Token: "qv-party-1", PinEnv: "QV_TEST_UNSET"}, "empty or unset"},
		"loose PIN file":   {server.SealerConfig{Token: "qv-party-1", PinFile: loose}, "chmod 0400"},
		"missing library":  {server.SealerConfig{Token: "qv-party-1", PinEnv: "QV_TEST_PIN", Lib: "/nonexistent/lib.so"}, "library"},
	}
	for name, c := range cases {
		_, err := server.NewPKCS11Sealer(c.c)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
	// A 0400 PIN file works.
	if _, err := server.NewPKCS11Sealer(server.SealerConfig{Token: "qv-party-1", PinFile: tight}); err != nil {
		t.Fatalf("0400 pin file: %v", err)
	}
	// The PIN never appears in an error message.
	for name, c := range cases {
		if _, err := server.NewPKCS11Sealer(c.c); err != nil && strings.Contains(err.Error(), pin) {
			t.Errorf("%s: PIN in error message", name)
		}
	}
}

// The production build contains no insecure sealer: only pkcs11 is accepted by NewSealer here (this test binary is built
// without -tags devauth).
func TestProductionBuildHasNoInsecureSealer(t *testing.T) {
	_, err := server.NewSealer(server.SealerConfig{Type: server.InsecureSealerType, KeyFile: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("insecure sealer accepted or wrong error: %v", err)
	}
}

// Sealed files on disk: swapping blobs between parties and between generations is refused; a copied data directory does not
// open under another token; nothing readable is stored.
func TestFileStoreSealedBlobsAreBound(t *testing.T) {
	ctx := context.Background()
	sealA, sealB := pkcs11Sealer(t, "qv-party-1"), pkcs11Sealer(t, "qv-party-2")
	dirA, dirB := t.TempDir(), t.TempDir()
	stA, err := server.NewFileStore(dirA, "A", sealA)
	if err != nil {
		t.Fatal(err)
	}
	stB, _ := server.NewFileStore(dirB, "B", sealB)
	k1, k2 := dkgPairForTest(t)
	defer k1.Wipe()
	defer k2.Wipe()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(stA.PutCandidate(ctx, "ks", 1, k1))
	must(stA.Promote(ctx, "ks", 1))
	must(stB.PutCandidate(ctx, "ks", 1, k2))
	must(stB.Promote(ctx, "ks", 1))
	// a second generation on A (the same key material is enough for the binding test)
	must(stA.PutCandidate(ctx, "ks", 2, k1))
	must(stA.Promote(ctx, "ks", 2))

	if ks, err := stA.GetKeyset(ctx, "ks", 2); err != nil {
		t.Fatal(err)
	} else {
		ks.Wipe()
	}
	// no share bytes in the files
	blob, _ := k1.Bytes()
	defer cbmpc.WipeBytes(blob)
	filepath.Walk(dirA, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			raw, _ := os.ReadFile(p)
			if bytes.Contains(raw, blob[:64]) {
				t.Errorf("%s contains plaintext keyset bytes", p)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s has mode %v", p, fi.Mode().Perm())
			}
		}
		return nil
	})
	// B's file placed in A's directory (swap between parties)
	raw, _ := os.ReadFile(filepath.Join(dirB, "keysets", "ks", "g1.json"))
	os.WriteFile(filepath.Join(dirA, "keysets", "ks", "g1.json"), raw, 0o600)
	if _, err := stA.GetKeyset(ctx, "ks", 1); err == nil {
		t.Fatal("A opened B's blob")
	}
	// generation 1's blob renamed to generation 2 (swap between generations)
	g1, _ := os.ReadFile(filepath.Join(dirB, "keysets", "ks", "g1.json"))
	_ = g1
	a1, _ := os.ReadFile(filepath.Join(dirA, "keysets", "ks", "g2.json"))
	os.WriteFile(filepath.Join(dirA, "keysets", "ks", "g1.json"), a1, 0o600)
	if _, err := stA.GetKeyset(ctx, "ks", 1); err == nil {
		t.Fatal("generation 2's blob opened as generation 1")
	}
	// the data directory of A opened by B's token (a copied disk on another setup)
	stOther, _ := server.NewFileStore(dirA, "A", sealB)
	if _, err := stOther.GetKeyset(ctx, "ks", 2); err == nil {
		t.Fatal("a different token opened A's sealed keyset")
	}
	// a tampered file
	p := filepath.Join(dirA, "keysets", "ks", "g2.json")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	os.WriteFile(p, b, 0o600)
	if _, err := stA.GetKeyset(ctx, "ks", 2); err == nil {
		t.Fatal("tampered file opened")
	}
}
