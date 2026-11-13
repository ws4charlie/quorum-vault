package hsm_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// The pinned SoftHSM (2.6 and later) generates Ed25519 keys and signs with CKM_EDDSA: the signature verifies with crypto/ed25519, the private key stays
// on the token, and a destroyed key signs no more. This is what a Solana pool's cold key relies on.
func TestEd25519KeyAndSignature(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	id := make([]byte, 16)
	rand.Read(id)
	pub, err := tok.GenerateEd25519KeyPair(context.Background(), fmt.Sprintf("qv-test-ed-%x", id[:4]), id)
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	t.Cleanup(func() { destroyAll(tok, id) })
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key of %d bytes", len(pub))
	}
	msg := []byte("a Solana message, not a digest")
	sig, err := tok.SignEd25519(context.Background(), id, msg)
	if err != nil {
		t.Fatalf("SignEd25519: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("the token's signature does not verify with crypto/ed25519")
	}
	if ed25519.Verify(pub, append(msg, 0), sig) {
		t.Fatal("verifies over another message")
	}
	// Ed25519 is deterministic: the same message, the same signature
	again, _ := tok.SignEd25519(context.Background(), id, msg)
	if string(again) != string(sig) {
		t.Fatal("two signatures of one message differ")
	}
	if err := tok.DestroyPrivateKey(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := tok.SignEd25519(context.Background(), id, msg); err == nil {
		t.Fatal("a destroyed key signed")
	}
	_ = hsm.ErrKeyNotFound
}
