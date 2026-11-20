package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func runCLI(args ...string) (int, string) {
	var out, errw bytes.Buffer
	code := run(args, &out, &errw)
	return code, out.String() + errw.String()
}

func keyFile(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "op.key")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, pub
}

func TestSignWritesAFileThatVerifiesAndRefusesBadInput(t *testing.T) {
	kf, pub := keyFile(t)
	out := filepath.Join(t.TempDir(), "a.json")
	if code, msg := runCLI("sign", "-key", kf, "-op", "refresh", "-keyset", "hot-0", "-out", out); code != 0 {
		t.Fatalf("sign: %s", msg)
	}
	f, err := admin.ReadFile(out)
	if err != nil || f.Op != "refresh" || f.Keyset != "hot-0" || f.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("file %+v, %v", f, err)
	}
	if age := f.Age(time.Now()); age < 0 || age > 5*time.Second {
		t.Fatalf("age %s", age)
	}
	for _, bad := range [][]string{{"-op", "freeze", "-keyset", "k"}, {"-op", "dkg", "-keyset", "a b"}, {"-op", "dkg"}} {
		if code, _ := runCLI(append([]string{"sign", "-key", kf}, bad...)...); code == 0 {
			t.Fatalf("sign %v succeeded", bad)
		}
	}
}

// The sending commands refuse before any network call, and name what to do.
func TestSendRefusesLocally(t *testing.T) {
	kf, _ := keyFile(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	runCLI("sign", "-key", kf, "-op", "refresh", "-keyset", "k", "-out", good)
	old, _ := adminFile(t, kf, "refresh", "k", time.Now().Add(-time.Hour))
	dkgFile, _ := adminFile(t, kf, "dkg", "k", time.Now())
	damaged := filepath.Join(dir, "damaged.json")
	b, _ := os.ReadFile(good)
	os.WriteFile(damaged, []byte(strings.Replace(string(b), `"keyset": "k"`, `"keyset": "j"`, 1)), 0o600)
	// no certificate and an address nobody listens on: a refusal that comes from the file never needs them
	net := []string{"-party", "A=127.0.0.1:1@" + strings.Repeat("ab", 32), "-cert", "/nonexistent.crt", "-key", "/nonexistent.key"}
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no file":      {append([]string{"refresh"}, net...), "-auth is required"},
		"wrong op":     {append([]string{"refresh", "-auth", dkgFile}, net...), "not for refresh"},
		"expired":      {append([]string{"refresh", "-auth", old}, net...), "outside the"},
		"damaged":      {append([]string{"refresh", "-auth", damaged}, net...), "signature does not match"},
		"no parties":   {[]string{"refresh", "-auth", good}, "-party"},
		"other keyset": {append([]string{"refresh", "-auth", good, "-keyset", "other"}, net...), "for keyset other: nothing was sent"},
		"missing file": {append([]string{"unfreeze", "-auth", filepath.Join(dir, "none")}, net...), "no such file"},
	} {
		code, msg := runCLI(c.args...)
		if code == 0 || !strings.Contains(msg, c.want) {
			t.Errorf("%s: exit %d, %q (want %q)", name, code, msg, c.want)
		}
	}
}

func adminFile(t *testing.T, keyPath, op, keyset string, at time.Time) (string, admin.File) {
	t.Helper()
	priv, err := admin.ReadKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := admin.NewFile(priv, op, keyset, at)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), op+".json")
	if err := os.WriteFile(p, f.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, f
}

func TestCompareFindsEveryDisagreement(t *testing.T) {
	ks := func(gen uint64, frozen bool, pub string) *pb.KeysetStatus {
		return &pb.KeysetStatus{KeysetId: "k", Generation: gen, Resolved: true, Frozen: frozen, PublicKey: []byte(pub)}
	}
	h := func(k ...*pb.KeysetStatus) *pb.HealthResponse { return &pb.HealthResponse{Keysets: k} }
	if bad := compare([]view{{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h(ks(2, false, "p"))}}, ""); len(bad) != 0 {
		t.Fatalf("agreeing parties: %v", bad)
	}
	for name, vs := range map[string][]view{
		"generation": {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h(ks(1, false, "p"))}},
		"frozen":     {{name: "A", health: h(ks(2, true, "p"))}, {name: "B", health: h(ks(2, false, "p"))}},
		"public key": {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h(ks(2, false, "q"))}},
		"missing":    {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h()}},
		"down":       {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", err: os.ErrDeadlineExceeded}},
	} {
		if bad := compare(vs, ""); len(bad) == 0 {
			t.Errorf("%s: no disagreement found", name)
		}
	}
}
