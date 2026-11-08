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

// Backup of one member's share of a 2-of-3 key, per generation (E23-1).
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
	// Public is the share blob with x wiped. It holds no secret (Qis, Q, names) and is useless for signing until X is
	// attached again; still seal it like the share, it is cheap.
	Public []byte
	X      *Secret // x_i, 32 bytes big-endian
	PubX   []byte  // Q_i, 33 bytes
}

// Wipe wipes the secret scalar.
func (s *TKeySplit) Wipe() {
	if s != nil {
		s.X.Wipe()
	}
}

// Split takes the share apart for backup. The share stays valid.
func (k *TKey) Split() (*TKeySplit, error) {
	const op = "tbackup.split"
	var pp, xp *C.uint8_t
	var pn C.size_t
	err := k.use(func(p *C.uint8_t, n C.size_t) error {
		return local(op, func() C.int { return C.qv_t_split(p, n, &pp, &pn, &xp) })
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return &TKeySplit{Self: k.self, Public: takeBytes(pp, pn), X: takeSecret(xp, 32), PubX: k.SharePoint()}, nil
}

// TBackupLabel binds a PVE ciphertext to a keyset, a member and a generation, so that it cannot be restored into
// another slot or an older generation's place.
func TBackupLabel(keysetID string, self Member, generation uint64) []byte {
	return []byte(fmt.Sprintf("qv-cbmpc-backup|v1|tecdsa|%s|%s|g%d", keysetID, self, generation))
}

// PVEExport encrypts x_i to the offline recovery key ek with a proof anyone can check against PubX (TPVEVerify).
func (s *TKeySplit) PVEExport(ek, label []byte) ([]byte, error) {
	const op = "tpve.export"
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
			return C.qv_pve_encrypt(C.QV_CURVE_SECP256K1, bptr(ek), C.size_t(len(ek)), bptr(label), C.size_t(len(label)), xp, 1, &cp, &cn)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return takeBytes(cp, cn), nil
}

// TPVEVerify checks, without any secret, that ct encrypts to ek the scalar behind pubX under label.
func TPVEVerify(ek, ct, label, pubX []byte) error {
	const op = "tpve.verify"
	if len(ek) == 0 || len(ct) == 0 || len(label) == 0 || len(pubX) != 33 {
		return badArg(op, "bad sizes")
	}
	err := local(op, func() C.int {
		return C.qv_pve_verify(C.QV_CURVE_SECP256K1, bptr(ek), C.size_t(len(ek)), bptr(ct), C.size_t(len(ct)),
			bptr(pubX), 33, 1, bptr(label), C.size_t(len(label)))
	})
	if e, ok := err.(*Error); ok && e.Kind == KindInternal && e.Code != CodeLayout {
		e.Kind = KindCryptographic // a ciphertext that does not verify is a failed check
	}
	return err
}

// TRestoreScalar decrypts x_i with the offline key dk. Like PVERestore it does not check the proof: run TPVEVerify first
// when the ciphertext is not trusted; TJoin then checks x_i*G against the share point either way.
func TRestoreScalar(dk *Secret, ek, ct, label []byte) (*Secret, error) {
	const op = "tpve.restore"
	if len(ek) == 0 || len(ct) == 0 || len(label) == 0 {
		return nil, badArg(op, "bad sizes")
	}
	var p *C.uint8_t
	var n C.size_t
	err := dk.use(func(dp *C.uint8_t, dn C.size_t) error {
		return local(op, func() C.int {
			return C.qv_pve_decrypt(C.QV_CURVE_SECP256K1, dp, dn, bptr(ek), C.size_t(len(ek)), bptr(ct), C.size_t(len(ct)),
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

// TJoin rebuilds the share from the public blob and the scalar, after checking x*G == Q_i. It does not need the other
// members. The restored share is one generation: after restoring a lost member, refresh the keyset and run SelfTest.
func TJoin(self Member, public []byte, x *Secret, pubX []byte) (*TKey, error) {
	const op = "tbackup.join"
	if err := checkMember(op, self); err != nil {
		return nil, err
	}
	if len(public) == 0 || len(public) > maxBlob || len(pubX) != 33 || x == nil || x.Len() != 32 {
		return nil, badArg(op, "bad sizes")
	}
	var kp *C.uint8_t
	var kn C.size_t
	err := x.use(func(xp *C.uint8_t, _ C.size_t) error {
		return local(op, func() C.int {
			return C.qv_t_join(bptr(public), C.size_t(len(public)), xp, bptr(pubX), &kp, &kn)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return newTKey(op, self, takeSecret(kp, kn))
}
