package cbmpc

import (
	"bytes"
	"context"
	"testing"
)

type backup struct {
	stripped []byte
	ct       []byte
	pubX     []byte
	pubK     []byte
	reduced  bool
}

func takeBackup(t *testing.T, ks *Keyset, ek, label []byte) backup {
	t.Helper()
	sp, err := ks.Split()
	must(t, err)
	defer sp.Wipe()
	ct, err := sp.PVEExport(ek, label)
	must(t, err)
	// Anyone can verify the ciphertext against the public points, with no secret.
	must(t, PVEVerify(ks.Alg(), ek, ct, label, sp.PubX, sp.PubK))
	return backup{stripped: secretBytes(t, sp.Stripped), ct: ct, pubX: sp.PubX, pubK: sp.PubK, reduced: sp.XReduced}
}

func restore(t *testing.T, alg Alg, role Role, b backup, dk *Secret, ek, label []byte) (*Keyset, error) {
	t.Helper()
	sp, err := NewKeysetSplit(alg, role, append([]byte(nil), b.stripped...), b.pubX, b.pubK)
	must(t, err)
	defer sp.Wipe()
	x, k, err := PVERestore(alg, dk, ek, b.ct, label)
	if err != nil {
		return nil, err
	}
	sp.X, sp.K = x, k
	return Join(sp)
}

func refreshN(t *testing.T, k1, k2 *Keyset, want func(sp *KeysetSplit) bool) (*Keyset, *Keyset) {
	t.Helper()
	ctx := ctx5(t)
	for i := 0; i < 40; i++ {
		var n1, n2 *Keyset
		e1, e2 := both(
			func(tr Transport) (err error) { n1, err = k1.Refresh(ctx, tr); return },
			func(tr Transport) (err error) { n2, err = k2.Refresh(ctx, tr); return })
		must(t, e1)
		must(t, e2)
		t.Cleanup(func() { n1.Wipe(); n2.Wipe() })
		k1, k2 = n1, n2
		sp, err := k1.Split()
		must(t, err)
		ok := want == nil || want(sp)
		sp.Wipe()
		if ok {
			return k1, k2
		}
	}
	t.Fatal("refresh never produced the wanted state")
	return nil, nil
}

// PVE export, destroy, restore, sign: for both parties, for fresh and refreshed keysets, ECDSA and Ed25519.
func TestBackupRestoreBothParties(t *testing.T) {
	type scenario struct {
		name string
		alg  Alg
		// prep returns the keysets to back up
		prep func(t *testing.T, k1, k2 *Keyset) (*Keyset, *Keyset)
	}
	fresh := func(t *testing.T, k1, k2 *Keyset) (*Keyset, *Keyset) { return k1, k2 }
	scenarios := []scenario{
		{"ecdsa-fresh", ECDSA, fresh},
		{"ecdsa-after-refresh", ECDSA, func(t *testing.T, k1, k2 *Keyset) (*Keyset, *Keyset) { return refreshN(t, k1, k2, nil) }},
		// the case SECURE_USAGE.md warns about: P1's exact share exceeds q, PVE only sees x mod q
		{"ecdsa-after-refresh-x-over-q", ECDSA, func(t *testing.T, k1, k2 *Keyset) (*Keyset, *Keyset) {
			return refreshN(t, k1, k2, func(sp *KeysetSplit) bool { return sp.XReduced })
		}},
		{"ed25519-fresh", Ed25519, fresh},
		{"ed25519-after-refresh", Ed25519, func(t *testing.T, k1, k2 *Keyset) (*Keyset, *Keyset) { return refreshN(t, k1, k2, nil) }},
	}
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			ctx := ctx5(t)
			k1, k2 := dkgPair(t, sc.alg)
			k1, k2 = sc.prep(t, k1, k2)
			ek, dk, err := GeneratePVEKeys()
			must(t, err)
			defer dk.Wipe()
			h, path := []uint32{9, 9}, []uint32{4}
			s1, s2 := derivePair(t, k1, k2, h, path)
			wantPub, _ := s1.PublicKey()
			_ = s2
			labels := [2][]byte{BackupLabel("ks-1", sc.alg, P1), BackupLabel("ks-1", sc.alg, P2)}
			bk := [2]backup{takeBackup(t, k1, ek, labels[0]), takeBackup(t, k2, ek, labels[1])}
			if sc.name == "ecdsa-after-refresh-x-over-q" && !bk[0].reduced {
				t.Fatal("scenario did not produce x >= q")
			}
			if len(bk[0].ct) < 10000 {
				t.Fatalf("suspiciously small PVE ciphertext: %d", len(bk[0].ct))
			}

			check := func(name string, r1, r2 *Keyset) {
				t.Helper()
				defer func() {
					if r1 != k1 {
						r1.Wipe()
					}
					if r2 != k2 {
						r2.Wipe()
					}
				}()
				rp, _ := r1.RootPublicKey()
				op, _ := k1.RootPublicKey()
				if !bytes.Equal(rp, op) {
					t.Fatalf("%s: restored root key differs", name)
				}
				c1, c2 := derivePair(t, r1, r2, h, path)
				got, _ := c1.PublicKey()
				if !bytes.Equal(got, wantPub) {
					t.Fatalf("%s: restored keyset derives another key", name)
				}
				d := digest32(5)
				sig, e1, e2 := signPair(ctx, c1, c2, d)
				must(t, e1)
				must(t, e2)
				if sc.alg == ECDSA {
					verifyECDSA(t, got, d, sig)
				} else {
					verifyEd25519(t, got, d, sig)
				}
			}

			// P1 lost, P2 alive
			r1, err := restore(t, sc.alg, P1, bk[0], dk, ek, labels[0])
			must(t, err)
			check("P1 restored", r1, k2)
			// P2 lost, P1 alive
			r2, err := restore(t, sc.alg, P2, bk[1], dk, ek, labels[1])
			must(t, err)
			check("P2 restored", k1, r2)
			// both lost
			a, err := restore(t, sc.alg, P1, bk[0], dk, ek, labels[0])
			must(t, err)
			b, err := restore(t, sc.alg, P2, bk[1], dk, ek, labels[1])
			must(t, err)
			check("both restored", a, b)

			// Negative cases: nothing may restore silently into the wrong slot or from tampered data.
			if _, err := restore(t, sc.alg, P1, bk[0], dk, ek, labels[1]); err == nil {
				t.Fatal("restore with the wrong label succeeded")
			}
			if err := PVEVerify(sc.alg, ek, bk[0].ct, labels[1], bk[0].pubX, bk[0].pubK); err == nil || !IsCryptographic(err) {
				t.Fatalf("verify with wrong label: want cryptographic error, got %v", err)
			}
			if err := PVEVerify(sc.alg, ek, bk[0].ct, labels[0], bk[1].pubX, bk[1].pubK); err == nil {
				t.Fatal("verify against the other party's public points succeeded")
			}
			bad := append([]byte(nil), bk[0].ct...)
			bad[len(bad)/2] ^= 1
			if err := PVEVerify(sc.alg, ek, bad, labels[0], bk[0].pubX, bk[0].pubK); err == nil {
				t.Fatal("tampered ciphertext verified")
			}
			// P1's PVE ciphertext with P2's stripped blob (wrong slot): refused.
			cross := bk[1]
			cross.ct = bk[0].ct
			if _, err := restore(t, sc.alg, P2, cross, dk, ek, labels[0]); err == nil {
				t.Fatal("cross-slot restore succeeded")
			}
		})
	}
}

// A backup taken before a refresh must not restore a share of the refreshed key: PVE and stripped blob of different
// versions do not combine, and a pre-refresh backup restores a share that no longer pairs with the refreshed peer.
func TestBackupVersionMixing(t *testing.T) {
	ctx := ctx5(t)
	k1, k2 := dkgPair(t, ECDSA)
	ek, dk, err := GeneratePVEKeys()
	must(t, err)
	defer dk.Wipe()
	l := BackupLabel("ks-2", ECDSA, P1)
	old := takeBackup(t, k1, ek, l)
	n1, n2 := refreshN(t, k1, k2, func(sp *KeysetSplit) bool { return sp.XReduced })
	cur := takeBackup(t, n1, ek, l)

	// stripped (new) + ciphertext (old): the scalar no longer matches the public point recorded with the new backup.
	mix := cur
	mix.ct = old.ct
	if _, err := restore(t, ECDSA, P1, mix, dk, ek, l); err == nil {
		t.Fatal("mixed-version backup restored")
	}
	// stripped (old) + ciphertext (new)
	mix = old
	mix.ct = cur.ct
	mix.pubX, mix.pubK = cur.pubX, cur.pubK
	if _, err := restore(t, ECDSA, P1, mix, dk, ek, l); err == nil {
		t.Fatal("mixed-version backup restored (old stripped, new ct)")
	}
	// A consistent OLD backup restores fine as a keyset, but it is a share of the pre-refresh sharing: with the refreshed
	// peer it cannot sign (this is why backups must be re-taken after every refresh, README).
	r, err := restore(t, ECDSA, P1, old, dk, ek, l)
	must(t, err)
	defer r.Wipe()
	h := []uint32{3}
	var x1, x2 *SignKey
	e1, e2 := both(
		func(tr Transport) (err error) { x1, err = r.Derive(ctx, tr, h, []uint32{0}); return },
		func(tr Transport) (err error) { x2, err = n2.Derive(ctx, tr, h, []uint32{0}); return })
	if e1 == nil && e2 == nil {
		sig, a, b := signPair(ctx, x1, x2, digest32(1))
		if a == nil && b == nil || sig != nil {
			t.Fatal("old backup + refreshed peer produced a signature")
		}
	}
	_ = n1
}

func TestJoinRejectsInconsistentParts(t *testing.T) {
	k1, _ := dkgPair(t, ECDSA)
	sp, err := k1.Split()
	must(t, err)
	defer sp.Wipe()
	// swapped scalars
	bad := &KeysetSplit{Alg: ECDSA, Role: P1, Stripped: sp.Stripped, X: sp.K, K: sp.X, PubX: sp.PubX, PubK: sp.PubK}
	if _, err := Join(bad); err == nil || !IsCryptographic(err) {
		t.Fatalf("swapped scalars: want cryptographic error, got %v", err)
	}
	// wrong curve/alg
	bad = &KeysetSplit{Alg: Ed25519, Role: P1, Stripped: sp.Stripped, X: sp.X, K: sp.K, PubX: make([]byte, 32), PubK: make([]byte, 32)}
	if _, err := Join(bad); err == nil {
		t.Fatal("ecdsa stripped blob joined as ed25519")
	}
	// wiped input
	sp2, _ := k1.Split()
	sp2.X.Wipe()
	if _, err := Join(sp2); err == nil {
		t.Fatal("join with wiped scalar succeeded")
	}
	sp2.Wipe()
	_ = context.Background
}
