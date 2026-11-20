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
	if bad := compare([]view{{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h(ks(2, false, "p"))}}, "", false); len(bad) != 0 {
		t.Fatalf("agreeing parties: %v", bad)
	}
	for name, vs := range map[string][]view{
		"generation": {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h(ks(1, false, "p"))}},
		"frozen":     {{name: "A", health: h(ks(2, true, "p"))}, {name: "B", health: h(ks(2, false, "p"))}},
		"public key": {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h(ks(2, false, "q"))}},
		"missing":    {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", health: h()}},
		"down":       {{name: "A", health: h(ks(2, false, "p"))}, {name: "B", err: os.ErrDeadlineExceeded}},
	} {
		if bad := compare(vs, "", false); len(bad) == 0 {
			t.Errorf("%s: no disagreement found", name)
		}
	}
}

func TestCompareOnlyTheTargetKeysetAndUnfreezeIgnoresTheFlag(t *testing.T) {
	mk := func(id string, gen uint64, frozen bool) *pb.KeysetStatus {
		return &pb.KeysetStatus{KeysetId: id, Generation: gen, Resolved: true, Frozen: frozen, PublicKey: []byte("p")}
	}
	h := func(k ...*pb.KeysetStatus) *pb.HealthResponse { return &pb.HealthResponse{Keysets: k} }
	// "bad" is in disagreement (generations differ, one unresolved); "good" is healthy
	vs := []view{
		{name: "A", health: h(mk("good", 3, false), mk("bad", 2, false))},
		{name: "B", health: h(mk("good", 3, false), &pb.KeysetStatus{KeysetId: "bad", Generation: 1, PublicKey: []byte("p")})},
	}
	if bad := compare(vs, "good", false); len(bad) != 0 {
		t.Fatalf("an unrelated keyset blocks the healthy one: %v", bad)
	}
	if bad := compare(vs, "fresh", false); len(bad) != 0 {
		t.Fatalf("an unrelated keyset blocks a keyset that does not exist yet: %v", bad)
	}
	if bad := compare(vs, "bad", false); len(bad) == 0 {
		t.Fatal("the keyset's own disagreement was not found")
	}
	// one party frozen, the others not: unfreeze goes on, a refresh does not
	fz := []view{{name: "A", health: h(mk("k", 2, true))}, {name: "B", health: h(mk("k", 2, false))}, {name: "C", health: h(mk("k", 2, false))}}
	if bad := compare(fz, "k", true); len(bad) != 0 {
		t.Fatalf("unfreeze refused for partly frozen parties: %v", bad)
	}
	if bad := compare(fz, "k", false); len(bad) == 0 {
		t.Fatal("a partly frozen keyset passes for other operations")
	}
	// generation still has to agree on unfreeze
	fz[1] = view{name: "B", health: h(mk("k", 1, false))}
	if bad := compare(fz, "k", true); len(bad) == 0 {
		t.Fatal("unfreeze ignores a generation mismatch")
	}
}

// The co-signing flow: one operator makes the request, two of three admins sign it, anyone verifies it against the party configuration, and
// every refusal that needs no party happens before one is contacted.
func TestCoSigningFlow(t *testing.T) {
	dir := t.TempDir()
	k1, p1 := keyFile(t)
	k2, p2 := keyFile(t)
	_, p3 := keyFile(t)
	keys := []string{"-admin-key", hex.EncodeToString(p1), "-admin-key", hex.EncodeToString(p2), "-admin-key", hex.EncodeToString(p3)}
	f := filepath.Join(dir, "req.json")
	if code, msg := runCLI("request", "-op", "dkg", "-keyset", "ks", "-scheme", "ecdsa-2of3", "-domain", "prod", "-out", f); code != 0 {
		t.Fatalf("request: %s", msg)
	}
	verify := func(extra ...string) (int, string) {
		return runCLI(append([]string{"verify", "-in", f, "-domain", "prod"}, append(keys, extra...)...)...)
	}
	if code, msg := verify("-threshold", "2"); code == 0 || !strings.Contains(msg, "0 signatures") && !strings.Contains(msg, "no signatures") && !strings.Contains(msg, "0 signature(s), 2 needed") {
		t.Fatalf("an unsigned request verified: %s", msg)
	}
	if code, msg := runCLI("sign", "-key", k1, "-in", f); code != 0 {
		t.Fatalf("sign 1: %s", msg)
	}
	if code, msg := runCLI("sign", "-key", k1, "-in", f); code == 0 || !strings.Contains(msg, "already signed") {
		t.Fatalf("the same admin signed twice: %d %s", code, msg)
	}
	if code, msg := verify("-threshold", "2"); code == 0 || !strings.Contains(msg, "1 signature(s), 2 needed") {
		t.Fatalf("one of two verified: %s", msg)
	}
	if code, msg := verify("-threshold", "1"); code != 0 {
		t.Fatalf("one of one refused: %s", msg)
	}
	// signing does not change what is signed
	before, _ := readReq(f)
	if code, msg := runCLI("sign", "-key", k2, "-in", f); code != 0 {
		t.Fatalf("sign 2: %s", msg)
	}
	after, _ := readReq(f)
	if before.BodyHash != after.BodyHash || before.Nonce != after.Nonce || before.IssuedUnix != after.IssuedUnix || len(after.Signatures) != 2 {
		t.Fatal("signing changed the request")
	}
	if code, msg := verify("-threshold", "2"); code != 0 || !strings.Contains(msg, "OK") {
		t.Fatalf("two of three refused: %s", msg)
	}
	if code, msg := runCLI("verify", "-in", f, "-admin-key", hex.EncodeToString(p1), "-admin-key", hex.EncodeToString(p3), "-threshold", "2", "-domain", "prod"); code == 0 || !strings.Contains(msg, "not a configured admin key") {
		t.Fatalf("a signer that the party does not know: %s", msg)
	}
	if code, msg := runCLI("verify", "-in", f, "-domain", "staging", "-threshold", "2", "-admin-key", hex.EncodeToString(p1), "-admin-key", hex.EncodeToString(p2)); code == 0 || !strings.Contains(msg, "domain") {
		t.Fatalf("another domain: %s", msg)
	}
	// an edited file is caught
	raw, _ := os.ReadFile(f)
	edited := filepath.Join(dir, "edited.json")
	os.WriteFile(edited, []byte(strings.Replace(string(raw), "SCHEME_ECDSA_2OF3", "SCHEME_ED25519_2OF3", 1)), 0o600)
	if code, msg := runCLI(append([]string{"verify", "-in", edited, "-domain", "prod", "-threshold", "2"}, keys...)...); code == 0 {
		t.Fatalf("an edited request verified: %s", msg)
	}
	// a signer cannot sign a file that has expired
	old := filepath.Join(dir, "old.json")
	if code, msg := runCLI("request", "-op", "refresh", "-keyset", "ks", "-domain", "prod", "-valid-for", "1s", "-out", old); code != 0 {
		t.Fatal(msg)
	}
	if code, msg := runCLI("sign", "-key", k1, "-in", old); code != 0 {
		t.Fatal(msg)
	}
	time.Sleep(1200 * time.Millisecond)
	if code, msg := runCLI("sign", "-key", k2, "-in", old); code == 0 || !strings.Contains(msg, "expired") {
		t.Fatalf("signing an expired request: %s", msg)
	}

	// send: every refusal below happens before any network call (no certificate, nobody listens)
	net := []string{"-party", "A=127.0.0.1:1@" + strings.Repeat("ab", 32), "-cert", "/nonexistent.crt", "-key", "/nonexistent.key"}
	pol := append([]string{"-domain", "prod"}, keys...)
	one := filepath.Join(dir, "one.json")
	runCLI("request", "-op", "dkg", "-keyset", "ks", "-scheme", "ecdsa-2of3", "-domain", "prod", "-out", one)
	runCLI("sign", "-key", k1, "-in", one)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"too few signatures":  {append(append([]string{"dkg", "-auth", one, "-threshold", "2"}, pol...), net...), "1 signature(s), 2 needed"},
		"no policy given":     {append([]string{"dkg", "-auth", f}, net...), "say what the parties need"},
		"wrong operation":     {append(append([]string{"refresh", "-auth", f, "-threshold", "2"}, pol...), net...), "not for refresh"},
		"other keyset":        {append(append([]string{"dkg", "-auth", f, "-threshold", "2", "-keyset", "zz"}, pol...), net...), "nothing was sent"},
		"scheme differs":      {append(append([]string{"dkg", "-auth", f, "-threshold", "2", "-scheme", "ed25519-2of3"}, pol...), net...), "the file decides"},
		"keys and config mix": {append(append([]string{"dkg", "-auth", f, "-threshold", "2", "-config", "x.json"}, pol...), net...), "not both"},
		"expired file":        {append(append([]string{"refresh", "-auth", old, "-threshold", "1"}, pol...), net...), "expired"},
	} {
		if code, msg := runCLI(c.args...); code == 0 || !strings.Contains(msg, c.want) {
			t.Errorf("%s: exit %d, %q (want %q)", name, code, msg, c.want)
		}
	}
}

func TestVerifyReadsPartyConfigs(t *testing.T) {
	dir := t.TempDir()
	k1, p1 := keyFile(t)
	k2, p2 := keyFile(t)
	cfg := func(name string, threshold int, domain string) string {
		p := filepath.Join(dir, name)
		b := `{"admin_keys":["` + hex.EncodeToString(p1) + `","` + hex.EncodeToString(p2) + `"],"admin_threshold":` + string(rune('0'+threshold)) + `,"admin_domain":"` + domain + `"}`
		os.WriteFile(p, []byte(b), 0o600)
		return p
	}
	f := filepath.Join(dir, "r.json")
	runCLI("request", "-op", "unfreeze", "-keyset", "ks", "-out", f)
	runCLI("sign", "-key", k1, "-in", f)
	if code, msg := runCLI("verify", "-in", f, "-config", cfg("a.json", 2, "")); code == 0 || !strings.Contains(msg, "1 signature(s), 2 needed") {
		t.Fatalf("one of two: %s", msg)
	}
	runCLI("sign", "-key", k2, "-in", f)
	if code, msg := runCLI("verify", "-in", f, "-config", cfg("a.json", 2, ""), "-config", cfg("b.json", 2, "")); code != 0 {
		t.Fatalf("two of two on two parties: %s", msg)
	}
	// the strictest party decides: a party still configured for a domain refuses
	if code, msg := runCLI("verify", "-in", f, "-config", cfg("a.json", 2, ""), "-config", cfg("c.json", 2, "prod")); code == 0 || !strings.Contains(msg, "a party 2 of 2 would refuse") {
		t.Fatalf("one party of two configured differently: %s", msg)
	}
}

func readReq(path string) (admin.Request, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return admin.Request{}, err
	}
	return admin.ParseRequest(raw)
}

func TestPubkeyPrintsWhatTheKeyFileHolds(t *testing.T) {
	kf, pub := keyFile(t)
	code, msg := runCLI("pubkey", "-key", kf)
	if code != 0 || strings.TrimSpace(msg) != hex.EncodeToString(pub) {
		t.Fatalf("%d %q", code, msg)
	}
}
