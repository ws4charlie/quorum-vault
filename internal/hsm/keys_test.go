package hsm_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// newKey generates a key pair with a fresh random CKA_ID and destroys both
// halves on cleanup, so test runs do not pile up objects in the token.
func newKey(t *testing.T, tok *hsm.Token, curve domain.Curve) (id, pub []byte) {
	t.Helper()
	id = make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	pub, err := tok.GenerateECKeyPair(context.Background(), curve, fmt.Sprintf("qv-test-%x", id[:4]), id)
	if err != nil {
		t.Fatalf("GenerateECKeyPair(%s): %v", curve, err)
	}
	t.Cleanup(func() { destroyAll(tok, id) })
	return id, pub
}

func destroyAll(tok *hsm.Token, id []byte) {
	tok.WithSession(context.Background(), func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		if err := p.FindObjectsInit(s, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, id)}); err != nil {
			return err
		}
		hs, _, _ := p.FindObjects(s, 10)
		p.FindObjectsFinal(s)
		for _, h := range hs {
			p.DestroyObject(s, h)
		}
		return nil
	})
}

func TestGenerateSecp256k1(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	_, pub := newKey(t, tok, domain.CurveSecp256k1)
	if len(pub) != 65 || pub[0] != 0x04 {
		t.Fatalf("pub = %X, want 65-byte uncompressed point", pub)
	}
	if _, err := signer.ParseUncompressed(pub); err != nil {
		t.Fatalf("pub not on secp256k1: %v", err)
	}
}

func TestPrivateKeyNotExportable(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	id, _ := newKey(t, tok, domain.CurveSecp256k1)
	err := tok.WithSession(context.Background(), func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		if err := p.FindObjectsInit(s, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return err
		}
		hs, _, err := p.FindObjects(s, 1)
		p.FindObjectsFinal(s)
		if err != nil || len(hs) != 1 {
			return fmt.Errorf("find private key: %v (%d)", err, len(hs))
		}
		h := hs[0]

		_, err = p.GetAttributeValue(s, h, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
		var ck pkcs11.Error
		if !errors.As(err, &ck) || uint(ck) != pkcs11.CKR_ATTRIBUTE_SENSITIVE {
			t.Errorf("reading CKA_VALUE: err = %v, want CKR_ATTRIBUTE_SENSITIVE", err)
		}

		attrs, err := p.GetAttributeValue(s, h, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, nil),
		})
		if err != nil {
			return err
		}
		want := map[uint]bool{pkcs11.CKA_EXTRACTABLE: false, pkcs11.CKA_SENSITIVE: true, pkcs11.CKA_TOKEN: true}
		for _, a := range attrs {
			got := len(a.Value) == 1 && a.Value[0] == 1
			if got != want[a.Type] {
				t.Errorf("attribute 0x%X = %v, want %v", a.Type, got, want[a.Type])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignECDSAVerifiesLowS(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	id, pubBytes := newKey(t, tok, domain.CurveSecp256k1)
	pub, err := signer.ParseUncompressed(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ { // ~half of raw signatures are high-S; 20 runs exercise the flip
		digest := sha256.Sum256([]byte(fmt.Sprintf("msg %d", i)))
		r, s, err := tok.SignECDSA(context.Background(), id, digest)
		if err != nil {
			t.Fatal(err)
		}
		sig := signer.Signature{R: r, S: s}
		if !signer.Verify(pub, digest, sig) {
			t.Fatalf("signature %d does not verify", i)
		}
		if n := signer.NormalizeLowS(sig); n.S.Cmp(s) != 0 {
			t.Fatalf("signature %d is high-S", i)
		}
	}
}

// TestSignP256 proves the generic EC path on the standard curve too.
func TestSignP256(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	id, pubBytes := newKey(t, tok, domain.CurveP256)
	x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes) //nolint:staticcheck // fine for a test
	if x == nil {
		t.Fatal("pub is not a P-256 point")
	}
	digest := sha256.Sum256([]byte("p256"))
	r, s, err := tok.SignECDSA(context.Background(), id, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s) {
		t.Fatal("P-256 signature does not verify")
	}
}

func TestDestroyPrivateKey(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	ctx := context.Background()
	id, _ := newKey(t, tok, domain.CurveSecp256k1)
	if err := tok.DestroyPrivateKey(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tok.SignECDSA(ctx, id, [32]byte{1}); !errors.Is(err, hsm.ErrKeyNotFound) {
		t.Fatalf("sign after destroy: err = %v, want ErrKeyNotFound", err)
	}
	if err := tok.DestroyPrivateKey(ctx, id); !errors.Is(err, hsm.ErrKeyNotFound) {
		t.Fatalf("second destroy: err = %v, want ErrKeyNotFound", err)
	}
	if ok, err := tok.HasObject(ctx, pkcs11.CKO_PUBLIC_KEY, id); err != nil || !ok {
		t.Fatalf("public key still present = %v, %v; want true", ok, err)
	}
	if ok, err := tok.HasObject(ctx, pkcs11.CKO_PRIVATE_KEY, id); err != nil || ok {
		t.Fatalf("private key present = %v, %v; want false", ok, err)
	}
}
