package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if _, err := v.check("refresh", "ks", nil, SignAdmin(priv, "refresh", "ks", now)); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	// a signature is good once
	a := SignAdmin(priv, "dkg", "ks", now)
	if _, err := v.check("dkg", "ks", nil, a); err != nil {
		t.Fatal(err)
	}
	if _, err := v.check("dkg", "ks", nil, a); err == nil {
		t.Error("replayed signature accepted")
	}
	// wrong operation or keyset
	if _, err := v.check("refresh", "ks", nil, SignAdmin(priv, "dkg", "ks", now.Add(time.Second))); err == nil {
		t.Error("signature for another op accepted")
	}
	if _, err := v.check("refresh", "other", nil, SignAdmin(priv, "refresh", "ks", now.Add(2*time.Second))); err == nil {
		t.Error("signature for another keyset accepted")
	}
	// stale and future timestamps
	if _, err := v.check("refresh", "ks", nil, SignAdmin(priv, "refresh", "ks", now.Add(-10*time.Minute))); err == nil {
		t.Error("stale timestamp accepted")
	}
	if _, err := v.check("refresh", "ks", nil, SignAdmin(priv, "refresh", "ks", now.Add(10*time.Minute))); err == nil {
		t.Error("future timestamp accepted")
	}
	// a key that is not configured, a tampered signature, missing auth
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := v.check("refresh", "ks", nil, SignAdmin(other, "refresh", "ks", now.Add(3*time.Second))); err == nil {
		t.Error("unconfigured key accepted")
	}
	bad := SignAdmin(priv, "refresh", "ks", now.Add(4*time.Second))
	bad.Signature[0] ^= 1
	if _, err := v.check("refresh", "ks", nil, bad); err == nil {
		t.Error("tampered signature accepted")
	}
	if _, err := v.check("refresh", "ks", nil, nil); err == nil {
		t.Error("missing auth accepted")
	}
	// the claimed key must be the signing key: substituting a configured public key under another key's signature fails
	forged := SignAdmin(other, "refresh", "ks", now.Add(5*time.Second))
	forged.PublicKey = priv.Public().(ed25519.PublicKey)
	if _, err := v.check("refresh", "ks", nil, forged); err == nil {
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

func newDurableVerifier(t *testing.T, dir string, pub ed25519.PublicKey) *adminVerifier {
	v, err := newAdminVerifier(&Config{AdminKeys: []string{hex.EncodeToString(pub)}, AdminMaxAgeSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	v.persistOn(nil, dir)
	return v
}

// A recorded request is spent even if the party died before acting on it (the record comes first), and a restart reloads it.
func TestAdminSeenSurvivesRestartAndCrashBeforeAct(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := newDurableVerifier(t, dir, pub)
	a := SignAdmin(priv, "refresh", "ks", time.Now().Add(time.Minute)) // ahead of the start: only the file can refuse a replay
	if _, err := v.check("refresh", "ks", nil, a); err != nil {
		t.Fatal(err)
	}
	// "crash" here: check returned, the operation never ran. A new process:
	v2 := newDurableVerifier(t, dir, pub)
	if _, err := v2.check("refresh", "ks", nil, a); err == nil {
		t.Fatal("a request recorded before a crash was accepted again")
	}
	if _, err := v2.check("refresh", "ks", nil, SignAdmin(priv, "refresh", "ks", time.Now().Add(61*time.Second))); err != nil {
		t.Fatalf("a fresh request after the restart: %v", err)
	}
}

// Entries leave the file once their timestamp is two windows old.
func TestAdminSeenPruned(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := newDurableVerifier(t, dir, pub)
	t0 := time.Now()
	v.now = func() time.Time { return t0 }
	if _, err := v.check("refresh", "ks", nil, SignAdmin(priv, "refresh", "ks", t0)); err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return t0.Add(11 * time.Minute) }
	if _, err := v.check("refresh", "ks", nil, SignAdmin(priv, "refresh", "ks", t0.Add(11*time.Minute))); err != nil {
		t.Fatal(err)
	}
	var d adminSeenDoc
	raw, err := os.ReadFile(filepath.Join(dir, adminSeenFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &d); err != nil || len(d.Seen) != 1 {
		t.Fatalf("want 1 entry after pruning, got %d (%v)", len(d.Seen), err)
	}
}

// Start-time rule: a request signed before this process started is refused, with or without the file; an unwritable file refuses (and does not spend).
func TestAdminStartTimeAndWriteFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := newDurableVerifier(t, t.TempDir(), pub)
	v.start = time.Now().Add(2 * time.Second)
	if _, err := v.check("refresh", "ks", nil, SignAdmin(priv, "refresh", "ks", time.Now())); err == nil || !strings.Contains(err.Error(), "older than this party's start") {
		t.Fatalf("request before the start accepted: %v", err)
	}
	bad := newDurableVerifier(t, filepath.Join(t.TempDir(), "missing", "dir"), pub)
	a := SignAdmin(priv, "refresh", "ks", time.Now().Add(time.Minute))
	if _, err := bad.check("refresh", "ks", nil, a); err == nil {
		t.Fatal("accepted although the record could not be written")
	}
	if len(bad.seen) != 0 {
		t.Fatal("a refused request was remembered")
	}
}
