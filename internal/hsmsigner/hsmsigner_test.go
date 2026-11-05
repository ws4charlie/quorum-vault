package hsmsigner_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

func TestGenerateAndSign(t *testing.T) {
	ctx := context.Background()
	tok := hsmtest.Token(t, "quorumvault")
	gen := hsmsigner.NewGenerator(tok)
	if gen.Backend() != domain.BackendHSM {
		t.Fatalf("backend = %s", gen.Backend())
	}
	k, err := gen.Generate(ctx, "wallet-x", 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tok.DestroyPrivateKey(ctx, k.HSMKeyID) })
	if k.HSMLabel != "qv-wallet-x-v3" || len(k.HSMKeyID) != 16 || k.Curve != domain.CurveSecp256k1 {
		t.Fatalf("key = %+v", k)
	}
	pub, err := signer.ParseUncompressed(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if want := crypto.PubkeyToAddress(*pub).Hex(); k.Address != want || !strings.HasPrefix(k.Address, "0x") {
		t.Fatalf("address = %s, want %s", k.Address, want)
	}

	s, err := hsmsigner.New(tok, k)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("tx"))
	res, err := s.SignDigest(ctx, digest, signer.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Verify(s.PublicKey(), digest, res.Sig) {
		t.Fatal("signature does not verify")
	}
	if len(res.Participants) != 1 || res.Participants[0] != "hsm:quorumvault" {
		t.Fatalf("participants = %v", res.Participants)
	}
	// Ethereum recovery: the address recovered from (r, s, v) is the key's.
	sig := make([]byte, 65)
	res.Sig.R.FillBytes(sig[:32])
	res.Sig.S.FillBytes(sig[32:64])
	found := false
	for v := byte(0); v < 2; v++ {
		sig[64] = v
		if rec, err := crypto.SigToPub(digest[:], sig); err == nil && crypto.PubkeyToAddress(*rec).Hex() == k.Address {
			found = true
		}
	}
	if !found {
		t.Fatal("no recovery id recovers the key's address")
	}

	if err := gen.(interface {
		DestroyKey(context.Context, domain.Key) error
	}).DestroyKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignDigest(ctx, digest, signer.SignOptions{}); err == nil {
		t.Fatal("signed after DestroyKey")
	}
}

func TestNewRefusesNonHSMKey(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	_, err := hsmsigner.New(tok, domain.Key{ID: "k", Backend: domain.BackendMPC, HSMKeyID: []byte{1}})
	if err == nil {
		t.Fatal("accepted an MPC key")
	}
}
