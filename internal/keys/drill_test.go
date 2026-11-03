package keys

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// TestRotationDrill runs the whole HSM key lifecycle against SoftHSM and
// Postgres: create -> bind request -> rotate (drain) -> retire (destroy).
func TestRotationDrill(t *testing.T) {
	ctx := context.Background()
	tok := hsmtest.Token(t, "quorumvault")
	r, aud, pool := newRegistry(t, hsmsigner.NewGenerator(tok))

	// sign authorizes like the orchestrator will, then signs in the HSM.
	sign := func(k domain.Key, req domain.SignRequest) error {
		k, err := r.Get(ctx, k.ID)
		if err != nil {
			return err
		}
		if err := r.AuthorizeSign(k, req); err != nil {
			return err
		}
		s, err := hsmsigner.New(tok, k)
		if err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(req.ID))
		res, err := s.SignDigest(ctx, digest, signer.SignOptions{})
		if err != nil {
			return err
		}
		if !signer.Verify(s.PublicKey(), digest, res.Sig) {
			return errors.New("signature does not verify")
		}
		return nil
	}

	w, v1, err := r.CreateWallet(ctx, "alice", "hsm-cold", domain.TierCold, domain.BackendHSM)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tok.DestroyPrivateKey(ctx, v1.HSMKeyID) })
	if v1.Curve != domain.CurveSecp256k1 || v1.HSMLabel != fmt.Sprintf("qv-%s-v1", w.ID) || len(v1.HSMKeyID) != 16 || v1.Purpose != "signing" {
		t.Fatalf("v1 = %+v", v1)
	}
	oldReq := insertRequest(t, pool, v1)
	if err := sign(v1, oldReq); err != nil {
		t.Fatalf("v1 signs its request while active: %v", err)
	}

	v2, demoted, err := r.Rotate(ctx, "alice", w.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tok.DestroyPrivateKey(ctx, v2.HSMKeyID) })
	if demoted.ID != v1.ID || demoted.State != domain.KeyStateSignOnly || v2.Version != 2 || v2.State != domain.KeyStateActive {
		t.Fatalf("rotate: new %+v old %+v", v2, demoted)
	}
	if v2.Address == v1.Address {
		t.Fatal("rotation kept the same address")
	}

	if err := sign(v1, oldReq); err != nil {
		t.Fatalf("sign_only v1 must still sign the old request: %v", err)
	}
	newReqOnV1 := insertRequest(t, pool, v1) // a request bound to v1 created after the rotation
	if err := sign(v1, newReqOnV1); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("sign_only v1 signing a new request: err = %v, want ErrKeyNotUsable", err)
	}
	newReq := insertRequest(t, pool, v2)
	if err := sign(v1, newReq); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("v1 signing a request bound to v2: err = %v, want ErrKeyNotUsable", err)
	}

	retired, err := r.Retire(ctx, "alice", v1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retired.State != domain.KeyStateRetired {
		t.Fatalf("retired = %+v", retired)
	}
	if err := sign(v1, oldReq); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("retired v1: err = %v, want ErrKeyNotUsable", err)
	}
	// Even bypassing the registry, the token can no longer sign with v1.
	if _, _, err := tok.SignECDSA(ctx, v1.HSMKeyID, [32]byte{1}); !errors.Is(err, hsm.ErrKeyNotFound) {
		t.Fatalf("HSM sign with destroyed v1: err = %v, want ErrKeyNotFound", err)
	}
	if ok, err := tok.HasObject(ctx, pkcs11.CKO_PUBLIC_KEY, v1.HSMKeyID); err != nil || !ok {
		t.Fatalf("v1 public key kept = %v, %v", ok, err)
	}
	if err := sign(v2, newReq); err != nil {
		t.Fatalf("v2 signs: %v", err)
	}

	want := []string{
		domain.EventWalletCreated, domain.EventKeyGenerated, // create
		domain.EventKeyGenerated, domain.EventKeyStateChanged, domain.EventKeyRotated, // rotate
		domain.EventKeyStateChanged, domain.EventKeyDestroyed, // retire
	}
	if got := aud.types(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("audit = %v, want %v", got, want)
	}
	rot := payload(t, aud.evs[4])
	if rot["old_key_id"] != v1.ID || rot["new_key_id"] != v2.ID {
		t.Fatalf("key.rotated payload = %v", rot)
	}
	if d := payload(t, aud.evs[6]); d["hsm_label"] != v1.HSMLabel || aud.evs[6].KeyID != v1.ID {
		t.Fatalf("key.destroyed = %+v %v", aud.evs[6], d)
	}
}
