package cbmpc

import (
	"bytes"
	"testing"
)

// Backup and restore of 2-of-3 Ed25519 shares (P8-1): the same single-recipient PVE as the ECDSA shares, on the
// ed25519 curve.

func edLabel(self Member, gen uint64) []byte { return TBackupLabelAlg(Ed25519, "sol-1", self, gen) }

func restoreEd(self Member, b tbackup, dk *Secret, ek, label []byte) (*TKey, error) {
	x, err := TRestoreScalarAlg(Ed25519, dk, ek, b.ct, label)
	if err != nil {
		return nil, err
	}
	defer x.Wipe()
	return TJoin(self, b.public, x, b.pubX)
}

func TestEdThresholdBackupRestoreEachMember(t *testing.T) {
	ctx := ctx5(t)
	ks := tDKGAlg(t, Ed25519)
	ek, dk, err := GeneratePVEKeys()
	must(t, err)
	defer dk.Wipe()
	for lost := Member(0); lost < NumMembers; lost++ {
		label := edLabel(lost, 1)
		b := takeTBackup(t, ks[lost], ek, label)
		if len(b.pubX) != 32 {
			t.Fatalf("share point is %d bytes", len(b.pubX))
		}
		sb := secretBytes(t, ks[lost].Secret)
		if bytes.Contains(b.public, sb[len(sb)-32:]) {
			t.Fatal("public blob still contains the scalar")
		}
		rk, err := restoreEd(lost, b, dk, ek, label)
		must(t, err)
		if rk.Alg() != Ed25519 || !bytes.Equal(secretBytes(t, rk.Secret), sb) {
			t.Fatal("restored share differs from the original")
		}
		set := ks
		set[lost] = rk
		for _, pr := range allPairs {
			if pr[0] != lost && pr[1] != lost {
				continue
			}
			m := edMsg(90, byte(lost)+9)
			sig, ea, eb := tSign(ctx, set, pr[0], pr[1], pr[0], m)
			must(t, ea)
			must(t, eb)
			verifyEd25519(t, ks[0].PublicKey(), m, sig)
		}
		rk.Wipe()
	}
}

func TestEdThresholdBackupPerGeneration(t *testing.T) {
	ctx := ctx5(t)
	g1 := tDKGAlg(t, Ed25519)
	ek, dk, err := GeneratePVEKeys()
	must(t, err)
	defer dk.Wipe()
	l1, l2 := edLabel(1, 1), edLabel(1, 2)
	b1 := takeTBackup(t, g1[1], ek, l1)
	g2 := tRefresh(t, g1)
	b2 := takeTBackup(t, g2[1], ek, l2)
	if err := TPVEVerify(ek, b1.ct, l2, b1.pubX); !IsCryptographic(err) {
		t.Fatalf("old ct under the new label: want cryptographic, got %v", err)
	}
	if err := TPVEVerify(ek, b1.ct, l1, b2.pubX); !IsCryptographic(err) {
		t.Fatalf("old ct against the new share point: want cryptographic, got %v", err)
	}
	if _, err := TRestoreScalarAlg(Ed25519, dk, ek, b1.ct, l2); err == nil || IsInternal(err) {
		t.Fatalf("wrong label: want cryptographic, got %v", err)
	}
	x1, err := TRestoreScalarAlg(Ed25519, dk, ek, b1.ct, l1)
	must(t, err)
	defer x1.Wipe()
	if _, err := TJoin(1, b2.public, x1, b2.pubX); err == nil {
		t.Fatal("generation-1 scalar attached to generation-2 blob")
	}
	old1, err := restoreEd(1, b1, dk, ek, l1)
	must(t, err)
	defer old1.Wipe()
	mixed := g2
	mixed[1] = old1
	if sig, _, _ := tSign(ctx, mixed, 0, 1, 0, edMsg(8, 1)); sig != nil {
		t.Fatal("restored old-generation share signed with new shares")
	}
	// procedure: restore the lost member's generation-2 backup, refresh all three, self-test
	r2, err := restoreEd(1, b2, dk, ek, l2)
	must(t, err)
	set := g2
	set[1] = r2
	g3 := tRefresh(t, set)
	r2.Wipe()
	for i, e := range tSelfTest(ctx, g3, []byte("sol-1|g3")) {
		if e != nil {
			t.Fatalf("self-test after restore+refresh, member %d: %v", i, e)
		}
	}
	if !bytes.Equal(g3[0].PublicKey(), g1[0].PublicKey()) {
		t.Fatal("public key changed")
	}
}

func TestEdThresholdBackupRejectsDamageAndOtherScheme(t *testing.T) {
	ks := tDKGAlg(t, Ed25519)
	ec := tDKG(t)
	ek, dk, err := GeneratePVEKeys()
	must(t, err)
	defer dk.Wipe()
	label := edLabel(0, 1)
	b := takeTBackup(t, ks[0], ek, label)
	other := takeTBackup(t, ks[2], ek, edLabel(2, 1))
	ecb := takeTBackup(t, ec[0], ek, TBackupLabel("ks-1", 0, 1))
	ek2, dk2, err := GeneratePVEKeys()
	must(t, err)
	defer dk2.Wipe()
	for _, mut := range []func([]byte) []byte{
		func(c []byte) []byte { c[len(c)/2] ^= 1; return c },
		func(c []byte) []byte { return c[:len(c)-1] },
		func(c []byte) []byte { return nil },
	} {
		ct := mut(append([]byte(nil), b.ct...))
		if err := TPVEVerify(ek, ct, label, b.pubX); err == nil || IsInternal(err) && !isLayout(err) && len(ct) > 0 {
			t.Errorf("damaged ct verified or misclassified: %v", err)
		}
		if x, err := TRestoreScalarAlg(Ed25519, dk, ek, ct, label); err == nil {
			if k, err := TJoin(0, b.public, x, b.pubX); err == nil {
				if !bytes.Equal(secretBytes(t, k.Secret), secretBytes(t, ks[0].Secret)) {
					t.Error("damaged ct joined into a different share")
				}
				k.Wipe()
			}
			x.Wipe()
		}
	}
	if err := TPVEVerify(ek, other.ct, label, b.pubX); err == nil {
		t.Error("member 2's ciphertext verified for member 0")
	}
	if x, err := TRestoreScalarAlg(Ed25519, dk2, ek, b.ct, label); err == nil {
		x.Wipe()
		t.Error("decrypted with the wrong recovery key")
	}
	if err := TPVEVerify(ek2, b.ct, label, b.pubX); err == nil {
		t.Error("verified against another recovery public key")
	}
	// the other scheme: an ECDSA backup does not verify against an Ed25519 point, nor restore into an Ed25519 slot
	if err := TPVEVerify(ek, ecb.ct, label, b.pubX); err == nil {
		t.Error("ECDSA ciphertext verified for an Ed25519 share point")
	}
	if x, err := TRestoreScalarAlg(Ed25519, dk, ek, ecb.ct, TBackupLabel("ks-1", 0, 1)); err == nil {
		// the scalar may decrypt (same recovery key), but it must not attach to the Ed25519 blob
		if _, err := TJoin(0, b.public, x, b.pubX); err == nil {
			t.Error("ECDSA scalar attached to an Ed25519 share")
		}
		x.Wipe()
	}
	if bytes.Equal(edLabel(0, 1), TBackupLabel("sol-1", 0, 1)) {
		t.Error("labels of the two schemes are equal")
	}
	x0, err := TRestoreScalarAlg(Ed25519, dk, ek, b.ct, label)
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
