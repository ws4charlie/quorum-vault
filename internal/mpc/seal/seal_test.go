package seal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/mpc/seal"
)

var secret = []byte(`{"Xi":12345,"ShareID":67890,"note":"pretend save data"}`)

func aad(keyRef string, party int) []byte {
	return []byte(keyRef + "|party-" + string(rune('0'+party)))
}

func TestSealOpenRoundTrip(t *testing.T) {
	ctx := context.Background()
	tok := hsmtest.Token(t, "qv-party-1")
	env, err := seal.Seal(ctx, tok, secret, aad("w-v1", 1))
	if err != nil {
		t.Fatal(err)
	}
	// Long markers only: a short one such as "Xi" appears in random base64 by chance.
	if bytes.Contains(env, []byte("ShareID")) || bytes.Contains(env, []byte("pretend save data")) {
		t.Fatalf("envelope leaks plaintext: %s", env)
	}
	var e map[string]any
	if err := json.Unmarshal(env, &e); err != nil || e["v"] != float64(1) || e["iv"] == nil || e["ct"] == nil {
		t.Fatalf("envelope format: %s (%v)", env, err)
	}
	pt, err := seal.Open(ctx, tok, env, aad("w-v1", 1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, secret) {
		t.Fatalf("round trip mismatch: %q", pt)
	}
	// Two seals of the same plaintext differ (fresh IV each time).
	env2, err := seal.Seal(ctx, tok, secret, aad("w-v1", 1))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(env, env2) {
		t.Fatal("two seals produced identical envelopes: IV reused")
	}
}

// (b) A copied sealed file is useless without its own token.
func TestCopiedShareWithOtherTokenFails(t *testing.T) {
	ctx := context.Background()
	t1 := hsmtest.Token(t, "qv-party-1")
	t2 := hsmtest.Token(t, "qv-party-2")
	if _, err := seal.Seal(ctx, t2, []byte("x"), []byte("x")); err != nil { // make sure party-2 has a wrap key too
		t.Fatal(err)
	}
	dir := t.TempDir()
	env, err := seal.Seal(ctx, t1, secret, aad("w-v1", 1))
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "party-1.sealed")
	if err := seal.WriteFile(src, env); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(src); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("sealed file mode: %v %v", fi.Mode(), err)
	}
	copied, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := seal.WriteFile(filepath.Join(dir, "stolen", "party-2.sealed"), copied); err != nil {
		t.Fatal(err)
	}
	// The thief controls party-2's token and presents the exact AAD.
	pt, err := seal.Open(ctx, t2, copied, aad("w-v1", 1))
	if err == nil || !errors.Is(err, seal.ErrOpen) {
		t.Fatalf("party-2 token opened party-1's share: pt=%q err=%v", pt, err)
	}
	t.Logf("expected failure: %v", err)
}

// (c) Any flipped bit fails GCM authentication.
func TestTamperedEnvelopeFails(t *testing.T) {
	ctx := context.Background()
	tok := hsmtest.Token(t, "qv-party-1")
	env, err := seal.Seal(ctx, tok, secret, aad("w-v1", 1))
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		V      int
		IV, CT []byte
	}
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mut  func()
	}{
		{"ciphertext", func() { e.CT[0] ^= 1 }},
		{"tag", func() { e.CT[len(e.CT)-1] ^= 0x80 }},
		{"iv", func() { e.IV[3] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var orig struct {
				V      int
				IV, CT []byte
			}
			json.Unmarshal(env, &orig)
			e = orig
			tc.mut()
			bad, _ := json.Marshal(map[string]any{"v": e.V, "iv": e.IV, "ct": e.CT})
			if pt, err := seal.Open(ctx, tok, bad, aad("w-v1", 1)); !errors.Is(err, seal.ErrOpen) {
				t.Fatalf("tampered %s opened: pt=%q err=%v", tc.name, pt, err)
			}
		})
	}
	// Truncation is rejected too.
	if _, err := seal.Open(ctx, tok, env[:len(env)/2], aad("w-v1", 1)); !errors.Is(err, seal.ErrOpen) {
		t.Fatalf("truncated envelope: %v", err)
	}
	// And the untouched envelope still opens (session pool is not poisoned).
	if _, err := seal.Open(ctx, tok, env, aad("w-v1", 1)); err != nil {
		t.Fatalf("untouched envelope after failures: %v", err)
	}
}

// (d) Right token, wrong AAD (other keyRef or other party id) fails.
func TestWrongAADFails(t *testing.T) {
	ctx := context.Background()
	tok := hsmtest.Token(t, "qv-party-1")
	env, err := seal.Seal(ctx, tok, secret, aad("wallet-a-v1", 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range [][]byte{aad("wallet-a-v2", 1), aad("wallet-b-v1", 1), aad("wallet-a-v1", 2), nil} {
		if pt, err := seal.Open(ctx, tok, env, a); !errors.Is(err, seal.ErrOpen) {
			t.Fatalf("opened with AAD %q: pt=%q err=%v", a, pt, err)
		}
	}
}

// (e) The wrap key's value cannot be read out of the token.
func TestWrapKeyNotExtractable(t *testing.T) {
	ctx := context.Background()
	for _, label := range []string{"qv-party-1", "qv-party-2", "qv-party-3"} {
		t.Run(label, func(t *testing.T) {
			tok := hsmtest.Token(t, label)
			checkWrapKey(t, ctx, tok)
		})
	}
}

func checkWrapKey(t *testing.T, ctx context.Context, tok *hsm.Token) {
	err := tok.WithSession(ctx, func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		h, err := seal.EnsureKey(p, s)
		if err != nil {
			return err
		}
		attrs, err := p.GetAttributeValue(s, h, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, nil),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		})
		if err != nil {
			return err
		}
		want := []byte{1, 0, 1}
		for i, w := range want {
			if len(attrs[i].Value) != 1 || attrs[i].Value[0] != w {
				t.Errorf("attr %#x = %v, want %d", attrs[i].Type, attrs[i].Value, w)
			}
		}
		if n := bytesToUint(attrs[3].Value); n != 32 {
			t.Errorf("CKA_VALUE_LEN = %d, want 32", n)
		}
		v, err := p.GetAttributeValue(s, h, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
		var pe pkcs11.Error
		if err == nil || !errors.As(err, &pe) || uint(pe) != pkcs11.CKR_ATTRIBUTE_SENSITIVE {
			t.Errorf("reading CKA_VALUE: value=%v err=%v, want CKR_ATTRIBUTE_SENSITIVE", v, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func bytesToUint(b []byte) uint64 { // CK_ULONG in host (little-endian on arm64/amd64) order
	var n uint64
	for i := len(b) - 1; i >= 0; i-- {
		n = n<<8 | uint64(b[i])
	}
	return n
}
