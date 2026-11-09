package cbmpc

/*
#include <stdlib.h>
#include <string.h>
#include "shim.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Backup of one member's share of a 2-of-3 key, per generation (E23-1, and P8-1 for Ed25519: eddsa_mp shares have the same
// shape, so the code is shared and the curve follows the key's Alg).
//
// ecdsa_mp has no Paillier key in its shares: a share is one scalar x_i (in [0, q) exactly, no "x over q" case as in
// the 2-party P1) plus public points. So the backup is simpler than the 2-party one: PVE of the single scalar x_i
// against the public point Q_i = x_i*G (the same single-recipient RSA-OAEP PVE the 2-party path uses, with n = 1), and
// the "public blob" (the share with x wiped: Q, all Qi, the name; no secret). cb-mpc's access-structure PVE
// (pve_batch_ac, for sharing a secret ACROSS recipients) is not used: each member's backup goes to the same offline
// recovery key, so single-recipient PVE is the right tool and the one already reviewed.

// TKeySplit is a share taken apart for backup.
type TKeySplit struct {
	Self Member
	Alg  Alg
	// Public is the share blob with x wiped. It holds no secret (Qis, Q, names) and is useless for signing until X is
	// attached again; still seal it like the share, it is cheap.
	Public []byte
	X      *Secret // x_i, 32 bytes big-endian
	PubX   []byte  // Q_i, 33 bytes (ECDSA) or 32 bytes (Ed25519)
}

// Wipe wipes the secret scalar.
func (s *TKeySplit) Wipe() {
	if s != nil {
		s.X.Wipe()
	}
}

// Split takes the share apart for backup. The share stays valid.
func (k *TKey) Split() (*TKeySplit, error) {
	op := top(k.alg, "backup.split")
	var pp, xp *C.uint8_t
	var pn C.size_t
	err := k.use(func(p *C.uint8_t, n C.size_t) error {
		return local(op, func() C.int { return C.qv_t_split(C.int(k.alg), p, n, &pp, &pn, &xp) })
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return &TKeySplit{Self: k.self, Alg: k.alg, Public: takeBytes(pp, pn), X: takeSecret(xp, 32), PubX: k.SharePoint()}, nil
}

// TBackupLabel binds a PVE ciphertext to a keyset, a member and a generation, so that it cannot be restored into
// another slot or an older generation's place.
func TBackupLabel(keysetID string, self Member, generation uint64) []byte {
	return TBackupLabelAlg(ECDSA, keysetID, self, generation)
}

// TBackupLabelAlg is TBackupLabel for either scheme; the scheme is part of the label, so an Ed25519 backup cannot be
// restored into an ECDSA slot or the other way round.
func TBackupLabelAlg(alg Alg, keysetID string, self Member, generation uint64) []byte {
	scheme := "tecdsa"
	if alg == Ed25519 {
		scheme = "teddsa"
	}
	return []byte(fmt.Sprintf("qv-cbmpc-backup|v1|%s|%s|%s|g%d", scheme, keysetID, self, generation))
}

// PVEExport encrypts x_i to the offline recovery key ek with a proof anyone can check against PubX (TPVEVerify).
func (s *TKeySplit) PVEExport(ek, label []byte) ([]byte, error) {
	op := top(s.Alg, "pve.export")
	if len(ek) == 0 || len(label) == 0 {
		return nil, badArg(op, "ek and label are required")
	}
	if s.X == nil {
		return nil, badArg(op, "split has no scalar")
	}
	var cp *C.uint8_t
	var cn C.size_t
	err := s.X.use(func(xp *C.uint8_t, _ C.size_t) error {
		return local(op, func() C.int {
			return C.qv_pve_encrypt(s.Alg.curve(), bptr(ek), C.size_t(len(ek)), bptr(label), C.size_t(len(label)), xp, 1, &cp, &cn)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return takeBytes(cp, cn), nil
}

// TPVEVerify checks, without any secret, that ct encrypts to ek the scalar behind pubX under label.
// The scheme follows the length of pubX: 33 bytes is secp256k1 (ECDSA), 32 bytes is Ed25519.
func TPVEVerify(ek, ct, label, pubX []byte) error {
	const op = "tpve.verify"
	alg, ok := algOfPoint(pubX)
	if len(ek) == 0 || len(ct) == 0 || len(label) == 0 || !ok {
		return badArg(op, "bad sizes")
	}
	err := local(op, func() C.int {
		return C.qv_pve_verify(alg.curve(), bptr(ek), C.size_t(len(ek)), bptr(ct), C.size_t(len(ct)),
			bptr(pubX), C.size_t(len(pubX)), 1, bptr(label), C.size_t(len(label)))
	})
	if e, ok := err.(*Error); ok && e.Kind == KindInternal && e.Code != CodeLayout {
		e.Kind = KindCryptographic // a ciphertext that does not verify is a failed check
	}
	return err
}

// TRestoreScalar decrypts x_i with the offline key dk. Like PVERestore it does not check the proof: run TPVEVerify first
// when the ciphertext is not trusted; TJoin then checks x_i*G against the share point either way.
func TRestoreScalar(dk *Secret, ek, ct, label []byte) (*Secret, error) {
	return TRestoreScalarAlg(ECDSA, dk, ek, ct, label)
}

// TRestoreScalarAlg is TRestoreScalar for either scheme.
func TRestoreScalarAlg(alg Alg, dk *Secret, ek, ct, label []byte) (*Secret, error) {
	op := top(alg, "pve.restore")
	if err := checkTAlg(op, alg); err != nil {
		return nil, err
	}
	if len(ek) == 0 || len(ct) == 0 || len(label) == 0 {
		return nil, badArg(op, "bad sizes")
	}
	var p *C.uint8_t
	var n C.size_t
	err := dk.use(func(dp *C.uint8_t, dn C.size_t) error {
		return local(op, func() C.int {
			return C.qv_pve_decrypt(alg.curve(), dp, dn, bptr(ek), C.size_t(len(ek)), bptr(ct), C.size_t(len(ct)),
				bptr(label), C.size_t(len(label)), &p, &n)
		})
	})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Kind == KindInternal && e.Err == nil && e.Code != CodeLayout {
			e.Kind = KindCryptographic
		}
		return nil, wrapWiped(op, err)
	}
	if n != 1 {
		C.qv_wipe(unsafe.Pointer(p), n*32)
		C.free(unsafe.Pointer(p))
		return nil, &Error{Kind: KindInternal, Op: op, Msg: "unexpected scalar count"}
	}
	return takeSecret(p, 32), nil
}

// algOfPoint tells the scheme from the length of a public point.
func algOfPoint(p []byte) (Alg, bool) {
	switch len(p) {
	case 33:
		return ECDSA, true
	case 32:
		return Ed25519, true
	}
	return 0, false
}

// TJoin rebuilds the share from the public blob and the scalar, after checking x*G == Q_i (the scheme follows the length
// of pubX, as in TPVEVerify). It does not need the other members. The restored share is one generation: after restoring a lost member, refresh the keyset and run SelfTest.
func TJoin(self Member, public []byte, x *Secret, pubX []byte) (*TKey, error) {
	alg, ok := algOfPoint(pubX)
	op := top(alg, "backup.join")
	if err := checkMember(op, self); err != nil {
		return nil, err
	}
	if len(public) == 0 || len(public) > maxBlob || !ok || x == nil || x.Len() != 32 {
		return nil, badArg(op, "bad sizes")
	}
	var kp *C.uint8_t
	var kn C.size_t
	err := x.use(func(xp *C.uint8_t, _ C.size_t) error {
		return local(op, func() C.int {
			return C.qv_t_join(C.int(alg), bptr(public), C.size_t(len(public)), xp, bptr(pubX), &kp, &kn)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return newTKey(op, alg, self, takeSecret(kp, kn))
}
