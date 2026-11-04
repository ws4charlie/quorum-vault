package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func newVerifier(t *testing.T) (*adminVerifier, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, err := newAdminVerifier(&Config{AdminKeys: []string{hex.EncodeToString(pub)}, AdminMaxAgeSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	return v, priv
}

func TestAdminSignatureChecks(t *testing.T) {
	v, priv := newVerifier(t)
	now := time.Now()
	if _, err := v.check("refresh", "ks", SignAdmin(priv, "refresh", "ks", now)); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	// a signature is good once
	a := SignAdmin(priv, "dkg", "ks", now)
	if _, err := v.check("dkg", "ks", a); err != nil {
		t.Fatal(err)
	}
	if _, err := v.check("dkg", "ks", a); err == nil {
		t.Error("replayed signature accepted")
	}
	// wrong operation or keyset
	if _, err := v.check("refresh", "ks", SignAdmin(priv, "dkg", "ks", now.Add(time.Second))); err == nil {
		t.Error("signature for another op accepted")
	}
	if _, err := v.check("refresh", "other", SignAdmin(priv, "refresh", "ks", now.Add(2*time.Second))); err == nil {
		t.Error("signature for another keyset accepted")
	}
	// stale and future timestamps
	if _, err := v.check("refresh", "ks", SignAdmin(priv, "refresh", "ks", now.Add(-10*time.Minute))); err == nil {
		t.Error("stale timestamp accepted")
	}
	if _, err := v.check("refresh", "ks", SignAdmin(priv, "refresh", "ks", now.Add(10*time.Minute))); err == nil {
		t.Error("future timestamp accepted")
	}
	// a key that is not configured, a tampered signature, missing auth
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := v.check("refresh", "ks", SignAdmin(other, "refresh", "ks", now.Add(3*time.Second))); err == nil {
		t.Error("unconfigured key accepted")
	}
	bad := SignAdmin(priv, "refresh", "ks", now.Add(4*time.Second))
	bad.Signature[0] ^= 1
	if _, err := v.check("refresh", "ks", bad); err == nil {
		t.Error("tampered signature accepted")
	}
	if _, err := v.check("refresh", "ks", nil); err == nil {
		t.Error("missing auth accepted")
	}
	// the claimed key must be the signing key: substituting a configured public key under another key's signature fails
	forged := SignAdmin(other, "refresh", "ks", now.Add(5*time.Second))
	forged.PublicKey = priv.Public().(ed25519.PublicKey)
	if _, err := v.check("refresh", "ks", forged); err == nil {
		t.Error("signature by another key under a configured public key accepted")
	}
}

func TestFreezeSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	f, err := newFileFreeze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if frozen, _ := f.Frozen("ks"); frozen {
		t.Fatal("frozen at start")
	}
	if err := f.Freeze("ks", "tampering seen"); err != nil {
		t.Fatal(err)
	}
	f2, err := newFileFreeze(dir) // a restart
	if err != nil {
		t.Fatal(err)
	}
	if frozen, why := f2.Frozen("ks"); !frozen || why != "tampering seen" {
		t.Fatalf("freeze lost across restart: %v %q", frozen, why)
	}
	if err := f2.Unfreeze("ks"); err != nil {
		t.Fatal(err)
	}
	f3, _ := newFileFreeze(dir)
	if frozen, _ := f3.Frozen("ks"); frozen {
		t.Fatal("unfreeze did not persist")
	}
	if err := f3.Freeze("../escape", "x"); err == nil {
		t.Error("path traversal accepted as keyset id")
	}
}
