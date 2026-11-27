package gatecred_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
)

const vectorsPath = "../../testdata/gate-credential/vectors.json"

func loadVectors(t testing.TB) gatecredtest.Vectors {
	t.Helper()
	b, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v gatecredtest.Vectors
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func configOf(t testing.TB, v gatecredtest.Vectors) *gatecred.Config {
	t.Helper()
	keys := map[string]ed25519.PublicKey{}
	for _, k := range v.Config.Keys {
		pub, err := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys[k.KID] = pub
	}
	cfg, err := gatecred.NewConfig(v.Config.Audience, keys,
		time.Duration(v.Config.SkewSecs)*time.Second, time.Duration(v.Config.MaxTTLSecs)*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func paymentOf(p gatecredtest.VPayment) gatecred.Payment {
	return gatecred.Payment{WalletID: p.WalletID, Chain: p.Chain, Asset: p.Asset, Payee: p.Payee, Amount: p.Amount,
		ValidAfter: p.ValidAfter, ValidBefore: p.ValidBefore}
}

func check(t *testing.T, err error, want gatecredtest.VExpect, used map[string]bool, id string) {
	t.Helper()
	// The pure package has no replay store; this stands in for the zone's:
	// the replay check comes after the pure checks (step 12).
	if err == nil && used[id] {
		err = &gatecred.Error{Code: gatecred.Replayed}
	}
	if want.OK {
		if err != nil {
			t.Fatalf("want ok, got %v", err)
		}
		return
	}
	var ge *gatecred.Error
	if !errors.As(err, &ge) {
		t.Fatalf("want %s, got %v", want.Code, err)
	}
	if string(ge.Code) != want.Code || ge.Field != want.Field {
		t.Fatalf("want %s (%s), got %s (%s): %s", want.Code, want.Field, ge.Code, ge.Field, ge.Detail)
	}
}

// Every case of the shared vectors file passes through the verifier.
func TestVectors(t *testing.T) {
	v := loadVectors(t)
	cfg := configOf(t, v)
	if len(v.Cases) < 60 {
		t.Fatalf("only %d cases", len(v.Cases))
	}
	names := map[string]bool{}
	for _, c := range v.Cases {
		c := c
		if names[c.Name] {
			t.Fatalf("duplicate case name %s", c.Name)
		}
		names[c.Name] = true
		t.Run(c.Name, func(t *testing.T) {
			now := v.Now
			if c.Now != nil {
				now = *c.Now
			}
			var raw []byte
			if c.Credential != nil {
				raw = []byte(*c.Credential)
			}
			if c.Substitute != nil {
				with, herr := hex.DecodeString(c.Substitute.With)
				if herr != nil || bytes.Count(raw, []byte(c.Substitute.Find)) != 1 {
					t.Fatalf("bad substitute: %v", herr)
				}
				raw = bytes.Replace(raw, []byte(c.Substitute.Find), with, 1)
			}
			cred, err := cfg.Verify(raw, paymentOf(c.Payment), time.Unix(now, 0))
			check(t, err, c.Expect, nil, "")
			used := map[string]bool{}
			if err == nil && len(c.Then) > 0 {
				used[cred.CredentialID] = true
				for _, then := range c.Then {
					p := c.Payment
					if then.Payment != nil {
						p = *then.Payment
					}
					_, err2 := cfg.Verify(raw, paymentOf(p), time.Unix(now, 0))
					check(t, err2, then.VExpect, used, cred.CredentialID)
				}
			}
			// signed bytes: present exactly when the credential parses
			parsed, perr := gatecred.Parse(raw)
			if c.SignedBytes == "" {
				if perr == nil {
					t.Fatalf("parses but no signed_bytes_hex")
				}
				return
			}
			if perr != nil {
				t.Fatalf("signed_bytes_hex given but parse fails: %v", perr)
			}
			if got := hex.EncodeToString(parsed.SignedBytes()); got != c.SignedBytes {
				t.Fatalf("signed bytes\n got %s\nwant %s", got, c.SignedBytes)
			}
		})
	}
	// every stateless code of the contract appears at least once
	seen := map[string]bool{}
	for _, c := range v.Cases {
		seen[c.Expect.Code] = true
		for _, th := range c.Then {
			seen[th.Code] = true
		}
	}
	for _, code := range []gatecred.Code{gatecred.CredentialMissing, gatecred.CredentialMalformed, gatecred.KIDUnknown,
		gatecred.SignatureInvalid, gatecred.AudienceMismatch, gatecred.WalletMismatch, gatecred.TTLTooLong,
		gatecred.NotYetValid, gatecred.Expired, gatecred.PaymentMismatch, gatecred.AuthorizationWindow, gatecred.Replayed} {
		if !seen[string(code)] {
			t.Errorf("no vector for %s", code)
		}
	}
	for _, f := range []string{"chain", "asset", "payee", "amount"} {
		found := false
		for _, c := range v.Cases {
			found = found || (c.Expect.Code == "payment_mismatch" && c.Expect.Field == f)
		}
		if !found {
			t.Errorf("no payment_mismatch vector for %s", f)
		}
	}
}

// The committed file is exactly what the generator writes, and the keys in it
// are the ones derived from the public seed strings.
func TestVectorsFileIsGeneratedOutput(t *testing.T) {
	want, err := gatecredtest.Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/gate-credential/vectors.json differs from the generator: run `make gate-vectors`")
	}
	raw := string(got)
	for _, forbidden := range []string{"PRIVATE KEY", `"private_key"`, `"seed_hex"`} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("vectors file mentions %q: it must hold public keys only", forbidden)
		}
	}
	if !strings.Contains(raw, "TEST ONLY") {
		t.Fatal("vectors file is not marked TEST ONLY")
	}
}

// The verifier's encoder and the minter's (written apart) agree byte for byte,
// and a parsed credential encodes back to the same wire object.
func TestRoundTrip(t *testing.T) {
	k := gatecredtest.TestKey(1)
	c := gatecred.Credential{
		V: 1, KID: k.KID, CredentialID: "11111111-2222-4333-8444-555555555555", ObligationID: `ob"l\1`,
		Audience: "qv-test", WalletID: gatecredtest.VectorsWallet, Chain: "eip155:1", Asset: "native",
		Payee: gatecredtest.VectorsPayee, Amount: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
		IssuedAt: 1, ExpiresAt: 1<<53 - 1, PolicyVersion: "p", DecisionReason: `a "quoted" back\slash <&>`,
	}
	wire := gatecredtest.Mint(k, c)
	got, err := gatecred.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.SignedBytes(), gatecredtest.SignedBytes(gatecredtest.FromCredential(c))) {
		t.Fatalf("encoders disagree:\n%s\n%s", got.SignedBytes(), gatecredtest.SignedBytes(gatecredtest.FromCredential(c)))
	}
	if !bytes.Equal(got.Wire(), wire) {
		t.Fatalf("wire round trip:\n%s\n%s", got.Wire(), wire)
	}
	again, err := gatecred.Parse(got.Wire())
	if err != nil || !bytes.Equal(again.SignedBytes(), got.SignedBytes()) {
		t.Fatalf("second parse: %v", err)
	}
}

func TestKeysMatchSeeds(t *testing.T) {
	v := loadVectors(t)
	for _, k := range v.Config.Keys {
		var n int
		for i := 1; i <= 2; i++ {
			if gatecredtest.TestKey(i).KID == k.KID {
				n = i
			}
		}
		if n == 0 {
			t.Fatalf("unexpected kid %s", k.KID)
		}
		tk := gatecredtest.TestKey(n)
		if k.Seed != tk.Seed || k.PublicKey != base64.RawURLEncoding.EncodeToString(tk.Pub) {
			t.Fatalf("key %s does not match its seed string", k.KID)
		}
		if !strings.Contains(k.Seed, "TEST-ONLY") {
			t.Fatalf("seed %q is not marked TEST ONLY", k.Seed)
		}
	}
}

func TestNewConfigRefusesBadSettings(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ok := map[string]ed25519.PublicKey{"k1": pub}
	cases := []struct {
		name string
		aud  string
		keys map[string]ed25519.PublicKey
		skew time.Duration
		ttl  time.Duration
	}{
		{"empty audience", "", ok, 0, 0},
		{"upper-case audience", "QV", ok, 0, 0},
		{"no keys", "qv", nil, 0, 0},
		{"bad kid", "qv", map[string]ed25519.PublicKey{"a b": pub}, 0, 0},
		{"short key", "qv", map[string]ed25519.PublicKey{"k": pub[:31]}, 0, 0},
		{"huge skew", "qv", ok, time.Hour, 0},
		{"negative skew", "qv", ok, -time.Second, 0},
		{"huge ttl", "qv", ok, 0, 2 * time.Hour},
	}
	for _, c := range cases {
		if _, err := gatecred.NewConfig(c.aud, c.keys, c.skew, c.ttl); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	cfg, err := gatecred.NewConfig("qv", ok, 0, 0)
	if err != nil || cfg.Skew != 30*time.Second || cfg.MaxTTL != 10*time.Minute {
		t.Fatalf("defaults: %v %+v", err, cfg)
	}
}

// Never trust a payment description the zone did not give: a zero Payment
// must not match a credential.
func TestEmptyPaymentNeverMatches(t *testing.T) {
	v := loadVectors(t)
	cfg := configOf(t, v)
	raw := []byte(*v.Cases[0].Credential)
	if _, err := cfg.Verify(raw, gatecred.Payment{}, time.Unix(v.Now, 0)); gatecred.CodeOf(err) != gatecred.WalletMismatch {
		t.Fatalf("got %v", err)
	}
}

// Fuzz: the parser never panics, and whatever it accepts is in canonical
// formats and re-encodes to a credential that parses to the same bytes.
func FuzzParse(f *testing.F) {
	v := loadVectors(f)
	for _, c := range v.Cases {
		if c.Credential != nil {
			f.Add([]byte(*c.Credential))
		}
	}
	for _, r := range []string{"caf\u00e9 \U0001F600", `\ud83d\ude00`, `\ud800`, `\udc00x`, "a\u2028b", "\x01", "\xc3\x28", `"\\`} {
		w := string(gatecredtest.WireWithSig(gatecredtest.Fields{"v": int64(1), "decision_reason": "X"}, "s"))
		f.Add([]byte(strings.Replace(w, "X", r, 1)))
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":1,"v":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := gatecred.Parse(raw)
		if err != nil {
			if gatecred.CodeOf(err) == "" {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		again, err := gatecred.Parse(c.Wire())
		if err != nil {
			t.Fatalf("accepted credential does not re-parse: %v", err)
		}
		if !bytes.Equal(again.SignedBytes(), c.SignedBytes()) {
			t.Fatal("re-encoding changed the signed bytes")
		}
		if !bytes.Equal(c.SignedBytes(), gatecredtest.SignedBytes(gatecredtest.FromCredential(*c))) {
			t.Fatal("two encoders disagree")
		}
		if !utf8.ValidString(c.DecisionReason) || strings.ContainsAny(c.DecisionReason, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x1f") {
			t.Fatalf("accepted a bad decision_reason %q", c.DecisionReason)
		}
		if len(c.Sig) != ed25519.SignatureSize || c.V != 1 || c.ExpiresAt <= c.IssuedAt {
			t.Fatalf("accepted a credential that breaks the rules: %+v", c)
		}
	})
}

// The test minter is test code: no package outside its own directory may
// import it, so no production binary can contain it.
func TestMinterNotInProductionBinaries(t *testing.T) {
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	dir := strings.TrimSpace(string(root))
	// 1. the dependency closure of every command, of the root module
	deps, err := exec.Command("go", "list", "-C", dir, "-deps", "-f", "{{.ImportPath}}", "./cmd/...").Output()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/...: %v", err)
	}
	for _, p := range strings.Fields(string(deps)) {
		if strings.Contains(p, "gatecredtest") {
			t.Fatalf("a command depends on %s", p)
		}
	}
	// 2. every non-test package of the module: only the minter's own packages import it
	out, err := exec.Command("go", "list", "-C", dir, "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list ./...: %v", err)
	}
	const mod = "github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], mod) {
			continue
		}
		for _, imp := range f[1:] {
			if strings.HasPrefix(imp, mod) {
				t.Errorf("%s imports the test minter: only _test.go files may", f[0])
			}
		}
	}
	// 3. mpc-party is its own module: nothing there may name it at all
	_ = filepath.Join
	err = filepath.Walk(filepath.Join(dir, "mpc-party"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte("gatecredtest")) {
			t.Errorf("%s names gatecredtest", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A sig is accepted only when every byte is in the base64url alphabet. Go's strict decoder skips CR and LF, so before this check a valid
// signature with "\n" appended parsed and verified (Greptile on PR 158).
func TestSigRefusesBytesOutsideAlphabet(t *testing.T) {
	k := gatecredtest.TestKey(1)
	f := gatecredtest.FromCredential(gatecred.Credential{
		V: 1, KID: k.KID, CredentialID: "11111111-2222-4333-8444-555555555555", ObligationID: "o",
		Audience: "qv-test", WalletID: gatecredtest.VectorsWallet, Chain: "eip155:1", Asset: "native",
		Payee: gatecredtest.VectorsPayee, Amount: "1", IssuedAt: 1, ExpiresAt: 2, PolicyVersion: "p", DecisionReason: "r",
	})
	sig := gatecredtest.Sign(k, f)
	if _, err := gatecred.Parse(gatecredtest.WireWithSig(f, sig)); err != nil {
		t.Fatalf("valid credential: %v", err)
	}
	for name, s := range map[string]string{
		"line feed at end": sig + "\n", "line feed inside": sig[:43] + "\n" + sig[43:], "carriage return": sig[:43] + "\r" + sig[43:],
		"CRLF": sig + "\r\n", "space": sig[:43] + " " + sig[43:], "tab": sig + "\t", "one =": sig + "=", "two =": sig + "==",
		"plus": "+" + sig[1:], "slash": "/" + sig[1:], "63 bytes": base64.RawURLEncoding.EncodeToString(make([]byte, 63)),
		"65 bytes": base64.RawURLEncoding.EncodeToString(make([]byte, 65)),
	} {
		_, err := gatecred.Parse(gatecredtest.WireWithSig(f, s))
		var ge *gatecred.Error
		if !errors.As(err, &ge) || ge.Code != gatecred.CredentialMalformed || ge.Field != "sig" {
			t.Errorf("%s: want credential_malformed (sig), got %v", name, err)
		}
	}
	// The unused low bits of the last character must be zero: one encoding per signature.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, sig[len(sig)-1])
	if i%16 != 0 {
		t.Fatalf("last character %q has non-zero low bits", sig[len(sig)-1])
	}
	other := alphabet[i+1]
	if _, ok := gatecred.DecodeBase64URL(sig[:len(sig)-1]+string(other), 64); ok {
		t.Error("non-zero trailing bits accepted")
	}
}
