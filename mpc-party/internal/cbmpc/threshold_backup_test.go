package cbmpc

import (
	"bytes"
	"testing"
)

type tbackup struct {
	public, ct, pubX []byte
}

func takeTBackup(t *testing.T, k *TKey, ek, label []byte) tbackup {
	t.Helper()
	sp, err := k.Split()
	must(t, err)
	defer sp.Wipe()
	ct, err := sp.PVEExport(ek, label)
	must(t, err)
	must(t, TPVEVerify(ek, ct, label, sp.PubX)) // anyone can check it with no secret
	return tbackup{public: sp.Public, ct: ct, pubX: sp.PubX}
}

func restoreT(self Member, b tbackup, dk *Secret, ek, label []byte) (*TKey, error) {
	x, err := TRestoreScalar(dk, ek, b.ct, label)
	if err != nil {
		return nil, err
	}
	defer x.Wipe()
	return TJoin(self, b.public, x, b.pubX)
}

func TestThresholdBackupRestoreEachMember(t *testing.T) {
	ctx := ctx5(t)
	ks := tDKG(t)
	ek, dk, err := GeneratePVEKeys()
	must(t, err)
	defer dk.Wipe()
	for lost := Member(0); lost < NumMembers; lost++ {
		label := TBackupLabel("ks-1", lost, 1)
		b := takeTBackup(t, ks[lost], ek, label)
		if bytes.Contains(b.public, secretBytes(t, ks[lost].Secret)[len(secretBytes(t, ks[lost].Secret))-32:]) {
			t.Fatal("public blob still contains the scalar")
		}
		rk, err := restoreT(lost, b, dk, ek, label)
		must(t, err)
		if !bytes.Equal(secretBytes(t, rk.Secret), secretBytes(t, ks[lost].Secret)) {
			t.Fatal("restored share differs from the original")
		}
		// sign with the restored share and the two others: every pair that involves it
		set := ks
		set[lost] = rk
		for _, pr := range allPairs {
			if pr[0] != lost && pr[1] != lost {
				continue
			}
			d := digest32(byte(lost) + 9)
			sig, ea, eb := tSign(ctx, set, pr[0], pr[1], pr[0], d)
			must(t, ea)
			must(t, eb)
			verifyECDSA(t, ks[0].PublicKey(), d, sig)
		}
		rk.Wipe()
	}
}

// Backups are per generation: the backup of generation 1 does not fit generation 2, and a lost member is brought back
// by restore, refresh, self-test (the documented procedure).
func TestThresholdBackupPerGeneration(t *testing.T) {
	ctx := ctx5(t)
	g1 := tDKG(t)
	ek, dk, err := GeneratePVEKeys()
	must(t, err)
	defer dk.Wipe()
	l1, l2 := TBackupLabel("ks-1", 1, 1), TBackupLabel("ks-1", 1, 2)
	b1 := takeTBackup(t, g1[1], ek, l1)

	g2 := tRefresh(t, g1)
	b2 := takeTBackup(t, g2[1], ek, l2)

	// the old ciphertext does not verify under the new generation's label or the new share point
	if err := TPVEVerify(ek, b1.ct, l2, b1.pubX); !IsCryptographic(err) {
		t.Fatalf("old ct under the new label: want cryptographic, got %v", err)
	}
	if err := TPVEVerify(ek, b1.ct, l1, b2.pubX); !IsCryptographic(err) {
		t.Fatalf("old ct against the new share point: want cryptographic, got %v", err)
	}
	// decrypting with the wrong label fails
	if _, err := TRestoreScalar(dk, ek, b1.ct, l2); err == nil || IsInternal(err) {
		t.Fatalf("wrong label: want cryptographic, got %v", err)
	}
	// a generation-1 scalar cannot be attached to the generation-2 public blob
	x1, err := TRestoreScalar(dk, ek, b1.ct, l1)
	must(t, err)
	defer x1.Wipe()
	if _, err := TJoin(1, b2.public, x1, b2.pubX); err == nil {
		t.Fatal("generation-1 scalar attached to generation-2 blob")
	}
	// and a generation-1 share does not sign with generation-2 shares
	old1, err := restoreT(1, b1, dk, ek, l1)
	must(t, err)
	defer old1.Wipe()
	mixed := g2
	mixed[1] = old1
	if sig, _, _ := tSign(ctx, mixed, 0, 1, 0, digest32(1)); sig != nil {
		t.Fatal("restored old-generation share signed with new shares")
	}
	// Procedure: member 1 lost its share at generation 2. Restore its generation-2 backup, refresh all three, self-test.
	r2, err := restoreT(1, b2, dk, ek, l2)
	must(t, err)
	set := g2
	set[1] = r2
	g3 := tRefresh(t, set)
	r2.Wipe()
	for i, e := range tSelfTest(ctx, g3, []byte("ks-1|g3")) {
		if e != nil {
			t.Fatalf("self-test after restore+refresh, member %d: %v", i, e)
		}
	}
	if !bytes.Equal(g3[0].PublicKey(), g1[0].PublicKey()) {
		t.Fatal("public key changed")
	}
}

func TestThresholdBackupRejectsDamage(t *testing.T) {
	ks := tDKG(t)
	ek, dk, err := GeneratePVEKeys()
	must(t, err)
	defer dk.Wipe()
	label := TBackupLabel("ks-1", 0, 1)
	b := takeTBackup(t, ks[0], ek, label)
	other := takeTBackup(t, ks[2], ek, TBackupLabel("ks-1", 2, 1))
	ek2, dk2, err := GeneratePVEKeys()
	must(t, err)
	defer dk2.Wipe()
	// damaged ciphertext
	for _, mut := range []func([]byte) []byte{
		func(c []byte) []byte { c[len(c)/2] ^= 1; return c },
		func(c []byte) []byte { return c[:len(c)-1] },
		func(c []byte) []byte { return nil },
	} {
		ct := mut(append([]byte(nil), b.ct...))
		if err := TPVEVerify(ek, ct, label, b.pubX); err == nil || IsInternal(err) && !isLayout(err) && len(ct) > 0 {
			t.Errorf("damaged ct verified or misclassified: %v", err)
		}
		// Decrypt alone does not check the proof (verify first, like the 2-party path); a scalar that comes out of a
		// damaged ciphertext must still be refused by the join, which checks x*G against the share point.
		if x, err := TRestoreScalar(dk, ek, ct, label); err == nil {
			if k, err := TJoin(0, b.public, x, b.pubX); err == nil {
				if !bytes.Equal(secretBytes(t, k.Secret), secretBytes(t, ks[0].Secret)) {
					t.Error("damaged ct joined into a different share")
				}
				k.Wipe()
			}
			x.Wipe()
		}
	}
	// another member's ciphertext / another share point
	if err := TPVEVerify(ek, other.ct, label, b.pubX); err == nil {
		t.Error("member 2's ciphertext verified for member 0")
	}
	// another recovery key
	if x, err := TRestoreScalar(dk2, ek, b.ct, label); err == nil {
		x.Wipe()
		t.Error("decrypted with the wrong recovery key")
	}
	if err := TPVEVerify(ek2, b.ct, label, b.pubX); err == nil {
		t.Error("verified against another recovery public key")
	}
	// join: wrong scalar, wrong member, damaged public blob
	x, err := TRestoreScalar(dk, ek, other.ct, TBackupLabel("ks-1", 2, 1))
	must(t, err)
	defer x.Wipe()
	if _, err := TJoin(0, b.public, x, b.pubX); err == nil {
		t.Error("another member's scalar accepted")
	}
	x0, err := TRestoreScalar(dk, ek, b.ct, label)
	must(t, err)
	defer x0.Wipe()
	if _, err := TJoin(1, b.public, x0, b.pubX); err == nil {
		t.Error("member 0's share joined as member 1")
	}
	pb := append([]byte(nil), b.public...)
	pb[len(pb)/2] ^= 1
	if k, err := TJoin(0, pb, x0, b.pubX); err == nil {
		if !bytes.Equal(k.SharePoint(), ks[0].SharePoint()) || !bytes.Equal(k.PublicKey(), ks[0].PublicKey()) {
			t.Error("damaged public blob joined into a different key")
		}
		k.Wipe()
	}
}
