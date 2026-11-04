package backup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/backup"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

func both[T any](fa, fb func(cbmpc.Transport) (T, error)) (ra, rb T, ea, eb error) {
	a, b := cbmpc.NewMemPair()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ra, ea = fa(a)
		if ea != nil {
			a.Close()
		}
	}()
	go func() {
		defer wg.Done()
		rb, eb = fb(b)
		if eb != nil {
			b.Close()
		}
	}()
	wg.Wait()
	return
}

func dkg(t *testing.T, alg cbmpc.Alg) (*cbmpc.Keyset, *cbmpc.Keyset) {
	ctx := context.Background()
	k1, k2, e1, e2 := both(
		func(tr cbmpc.Transport) (*cbmpc.Keyset, error) { return cbmpc.DKG(ctx, tr, cbmpc.P1, alg) },
		func(tr cbmpc.Transport) (*cbmpc.Keyset, error) { return cbmpc.DKG(ctx, tr, cbmpc.P2, alg) })
	if e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	return k1, k2
}

func refresh(t *testing.T, k1, k2 *cbmpc.Keyset) (*cbmpc.Keyset, *cbmpc.Keyset) {
	ctx := context.Background()
	n1, n2, e1, e2 := both(
		func(tr cbmpc.Transport) (*cbmpc.Keyset, error) { return k1.Refresh(ctx, tr) },
		func(tr cbmpc.Transport) (*cbmpc.Keyset, error) { return k2.Refresh(ctx, tr) })
	if e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	return n1, n2
}

func selfTest(t *testing.T, k1, k2 *cbmpc.Keyset) []byte {
	ctx := context.Background()
	p1, _, e1, e2 := both(
		func(tr cbmpc.Transport) ([]byte, error) { return k1.SelfTest(ctx, tr) },
		func(tr cbmpc.Transport) ([]byte, error) { return k2.SelfTest(ctx, tr) })
	if e1 != nil || e2 != nil {
		t.Fatalf("restored shares do not work together: %v %v", e1, e2)
	}
	return p1
}

// Both parties, ECDSA and Ed25519, each after a refresh: export, verify (public only), restore, sign.
func TestExportVerifyRestoreBothParties(t *testing.T) {
	priv, pub, err := backup.GenRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []cbmpc.Alg{cbmpc.ECDSA, cbmpc.Ed25519} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			k1, k2 := dkg(t, alg)
			for i := 0; i < 3; i++ { // several refreshes: P1's exact share can exceed q
				k1, k2 = refresh(t, k1, k2)
			}
			root, _ := k1.RootPublicKey()
			f1, err := backup.Export(k1, "ks", 4, "A", pub)
			if err != nil {
				t.Fatal(err)
			}
			f2, err := backup.Export(k2, "ks", 4, "B", pub)
			if err != nil {
				t.Fatal(err)
			}
			// the file round-trips through bytes and verifies with public data only
			for _, f := range []*backup.File{f1, f2} {
				p, err := backup.Parse(f.Marshal())
				if err != nil {
					t.Fatal(err)
				}
				if err := backup.Verify(p, pub); err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(f.Marshal(), []byte("PRIVATE")) {
					t.Fatal("secret marker in the backup")
				}
			}
			// P1 lost, P2 alive
			r1, err := backup.Restore(f1, priv)
			if err != nil {
				t.Fatal(err)
			}
			selfTest(t, r1, k2)
			// P2 lost, P1 alive
			r2, err := backup.Restore(f2, priv)
			if err != nil {
				t.Fatal(err)
			}
			selfTest(t, k1, r2)
			// both lost
			selfTest(t, r1, r2)
			rr, _ := r1.RootPublicKey()
			if !bytes.Equal(rr, root) {
				t.Fatal("root key changed by restore")
			}
		})
	}
}

func TestBackupNegatives(t *testing.T) {
	priv, pub, _ := backup.GenRecoveryKey()
	priv2, pub2, _ := backup.GenRecoveryKey()
	k1, k2 := dkg(t, cbmpc.ECDSA)
	f1, err := backup.Export(k1, "ks", 1, "A", pub)
	if err != nil {
		t.Fatal(err)
	}
	f2, _ := backup.Export(k2, "ks", 1, "B", pub)
	clone := func(f *backup.File) *backup.File { p, _ := backup.Parse(f.Marshal()); return p }

	expect := func(name string, err error, contains string) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), contains) {
			t.Errorf("%s: unclear error %q (want it to contain %q)", name, err, contains)
		}
	}

	// wrong recovery key
	_, err = backup.Restore(f1, priv2)
	expect("restore with another recovery key", err, "not the recovery key")
	expect("verify against another recovery public key", backup.Verify(f1, pub2), "recovery key")

	// tampered PVE ciphertext
	t1 := clone(f1)
	t1.PVE[len(t1.PVE)/2] ^= 1
	expect("tampered PVE", backup.Verify(t1, pub), "does not verify")
	_, err = backup.Restore(t1, priv)
	if err == nil {
		t.Error("tampered PVE restored")
	}
	// tampered stripped blob
	t2 := clone(f1)
	t2.Stripped.CT[len(t2.Stripped.CT)/2] ^= 1
	_, err = backup.Restore(t2, priv)
	expect("tampered stripped blob", err, "does not decrypt")
	t2b := clone(f1)
	t2b.Stripped.WrappedKey[10] ^= 1
	_, err = backup.Restore(t2b, priv)
	expect("tampered wrapped key", err, "cannot unwrap")
	// header edits: generation, role, keyset id, root key
	for name, mut := range map[string]func(f *backup.File){
		"generation": func(f *backup.File) { f.Generation = 2 },
		"role":       func(f *backup.File) { f.Role = "B" },
		"keyset id":  func(f *backup.File) { f.KeysetID = "other" },
		"root key":   func(f *backup.File) { f.RootPublicKey = strings.Repeat("0", len(f.RootPublicKey)) },
	} {
		c := clone(f1)
		mut(c)
		// (the root key is covered by the stripped blob's AAD, which only the recovery private key can check; the other
		// header fields are part of the PVE label, which anyone can check)
		if name != "root key" && backup.Verify(c, pub) == nil {
			t.Errorf("edited %s: verify accepted", name)
		}
		if _, err := backup.Restore(c, priv); err == nil {
			t.Errorf("edited %s: restore accepted", name)
		}
	}
	// A's backup presented as B's slot content / B's PVE with A's stripped blob
	x := clone(f1)
	x.PVE = f2.PVE
	if _, err := backup.Restore(x, priv); err == nil {
		t.Error("mixed A stripped blob with B PVE restored")
	}
	// file-level: unknown fields, version, truncation
	var m map[string]any
	json.Unmarshal(f1.Marshal(), &m)
	m["extra"] = 1
	raw, _ := json.Marshal(m)
	if _, err := backup.Parse(raw); err == nil {
		t.Error("unknown field accepted")
	}
	m2 := map[string]any{}
	json.Unmarshal(f1.Marshal(), &m2)
	m2["v"] = 99
	raw, _ = json.Marshal(m2)
	if _, err := backup.Parse(raw); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("version: %v", err)
	}
	if _, err := backup.Parse(f1.Marshal()[:100]); err == nil {
		t.Error("truncated file accepted")
	}
	// garbage keys never crash
	if _, err := backup.Restore(f1, []byte("garbage")); err == nil {
		t.Error("garbage private key accepted")
	}
	if err := backup.Verify(f1, []byte("garbage")); err == nil {
		t.Error("garbage public key accepted")
	}
}
