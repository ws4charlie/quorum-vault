package cbmpc

/*
#include <stdlib.h>
#include <string.h>
#include "shim.h"
*/
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"
)

// KeysetSplit is a keyset taken apart for offline backup:
//
//   - X and K: the two secret scalars (x mod q and k, 32 bytes each) that go into PVE;
//   - Stripped: the rest of the blob. For P1 (ECDSA) it STILL CONTAINS THE PAILLIER PRIVATE KEY and c_key, from which
//     the exact x can be recovered without PVE: protect it like the full keyset (encrypt it to the offline key too).
//     For P2 and for Ed25519 it holds no secret, but treat it as confidential anyway;
//   - PubX, PubK: public points of X and K, kept with the backup; PVE verification and Join check against them.
//
// After a Refresh, P1's exact x can exceed q. PVE then carries x mod q and Join recovers the exact value by decrypting
// c_key from Stripped, so the PVE ciphertext and the Stripped blob must be taken from the SAME keyset version.
type KeysetSplit struct {
	Alg      Alg
	Role     Role
	Stripped *Secret
	X, K     *Secret
	PubX     []byte
	PubK     []byte
	// XReduced is true when P1's exact x was >= q (after a refresh): PVE then carries x mod q only and the exact value
	// comes back from the Paillier ciphertext in Stripped. Informational; Join handles both cases.
	XReduced bool
}

// Wipe wipes all secrets of the split.
func (s *KeysetSplit) Wipe() {
	if s == nil {
		return
	}
	s.Stripped.Wipe()
	s.X.Wipe()
	s.K.Wipe()
}

// Split takes the keyset apart for backup. The keyset stays valid.
func (k *Keyset) Split() (*KeysetSplit, error) {
	const op = "backup.split"
	var sp, xp, kp *C.uint8_t
	var sn, ql C.size_t
	var red C.int
	qx, qk := make([]byte, 33), make([]byte, 33)
	err := k.use(func(p *C.uint8_t, n C.size_t) error {
		return local(op, func() C.int {
			return C.qv_ks_split(C.int(k.alg), p, n, &sp, &sn, &xp, &kp, bptr(qx), bptr(qk), &ql, &red)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return &KeysetSplit{
		Alg: k.alg, Role: k.role,
		Stripped: takeSecret(sp, sn), X: takeSecret(xp, 32), K: takeSecret(kp, 32),
		PubX: qx[:ql], PubK: qk[:ql], XReduced: red != 0,
	}, nil
}

// NewKeysetSplit rebuilds a split from stored parts (stripped blob unsealed by the caller). stripped is wiped.
func NewKeysetSplit(alg Alg, role Role, stripped, pubX, pubK []byte) (*KeysetSplit, error) {
	const op = "backup.load"
	if err := hdOK(op, alg); err != nil {
		WipeBytes(stripped)
		return nil, err
	}
	if len(stripped) == 0 || len(stripped) > maxBlob || len(pubX) != alg.pointLen() || len(pubK) != alg.pointLen() {
		WipeBytes(stripped)
		return nil, badArg(op, "bad sizes")
	}
	return &KeysetSplit{Alg: alg, Role: role, Stripped: SecretFromBytes(stripped),
		PubX: append([]byte(nil), pubX...), PubK: append([]byte(nil), pubK...)}, nil
}

// Join rebuilds the keyset from Stripped plus X and K, after checking that X and K match PubX and PubK and (P1) that
// X is consistent with the Paillier plaintext. It does not need the peer.
func Join(s *KeysetSplit) (*Keyset, error) {
	const op = "backup.join"
	if s == nil || s.Stripped == nil || s.X == nil || s.K == nil {
		return nil, badArg(op, "incomplete split")
	}
	if err := hdOK(op, s.Alg); err != nil {
		return nil, err
	}
	if len(s.PubX) != s.Alg.pointLen() || len(s.PubK) != s.Alg.pointLen() {
		return nil, badArg(op, "bad public point size")
	}
	if s.X.Len() != 32 || s.K.Len() != 32 {
		return nil, badArg(op, "scalars must be 32 bytes")
	}
	var kp *C.uint8_t
	var kn C.size_t
	err := s.Stripped.use(func(sp *C.uint8_t, sn C.size_t) error {
		return s.X.use(func(xp *C.uint8_t, _ C.size_t) error {
			return s.K.use(func(kk *C.uint8_t, _ C.size_t) error {
				return local(op, func() C.int {
					return C.qv_ks_join(C.int(s.Alg), sp, sn, xp, kk, bptr(s.PubX), bptr(s.PubK), C.size_t(len(s.PubX)), &kp, &kn)
				})
			})
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	// The role is read back from the blob, not trusted from the caller.
	ks := &Keyset{Secret: takeSecret(kp, kn), alg: s.Alg, role: s.Role}
	var r, c C.int
	if err := ks.use(func(p *C.uint8_t, n C.size_t) error {
		return local(op, func() C.int { return C.qv_hd_info(C.int(s.Alg), p, n, &r, &c) })
	}); err != nil || Role(r) != s.Role {
		ks.Wipe()
		if err == nil {
			err = badArg(op, "restored keyset is for %s, expected %s", Role(r), s.Role)
		}
		return nil, err
	}
	return ks, nil
}

// BackupLabel is the PVE label that binds a ciphertext to a keyset and a party, so that it cannot be restored into
// another slot.
func BackupLabel(keysetID string, alg Alg, role Role) []byte {
	return []byte(fmt.Sprintf("qv-cbmpc-backup|v1|%s|%s|%s", keysetID, alg, role))
}

// GeneratePVEKeys makes an RSA-OAEP backup key pair. ek (public) goes online; dk (private) must go to the offline
// ceremony: it is returned as a Secret so that it does not linger in the Go heap.
func GeneratePVEKeys() (ek []byte, dk *Secret, err error) {
	const op = "pve.keygen"
	var ep, dp *C.uint8_t
	var en, dn C.size_t
	if err = local(op, func() C.int { return C.qv_pve_keygen(&ep, &en, &dp, &dn) }); err != nil {
		return nil, nil, err
	}
	return takeBytes(ep, en), takeSecret(dp, dn), nil
}

// PVEExport encrypts X and K of the split to ek, with a proof anyone can check against PubX/PubK (PVEVerify) without
// the decryption key. The ciphertext is public data (about 49 KB).
func (s *KeysetSplit) PVEExport(ek, label []byte) ([]byte, error) {
	const op = "pve.export"
	if len(ek) == 0 || len(label) == 0 {
		return nil, badArg(op, "ek and label are required")
	}
	if s.X == nil || s.K == nil {
		return nil, badArg(op, "split has no scalars")
	}
	both := C.malloc(64)
	defer func() { C.qv_wipe(both, 64); C.free(both) }()
	if err := s.X.use(func(p *C.uint8_t, n C.size_t) error {
		C.memcpy(both, unsafe.Pointer(p), 32)
		return nil
	}); err != nil {
		return nil, wrapWiped(op, err)
	}
	if err := s.K.use(func(p *C.uint8_t, n C.size_t) error {
		C.memcpy(unsafe.Add(both, 32), unsafe.Pointer(p), 32)
		return nil
	}); err != nil {
		return nil, wrapWiped(op, err)
	}
	var cp *C.uint8_t
	var cn C.size_t
	if err := local(op, func() C.int {
		return C.qv_pve_encrypt(s.Alg.curve(), bptr(ek), C.size_t(len(ek)), bptr(label), C.size_t(len(label)),
			(*C.uint8_t)(both), 2, &cp, &cn)
	}); err != nil {
		return nil, err
	}
	return takeBytes(cp, cn), nil
}

// PVEVerify checks, without any secret, that ct encrypts to ek the scalars whose public points are pubX and pubK
// under label.
func PVEVerify(alg Alg, ek, ct, label, pubX, pubK []byte) error {
	const op = "pve.verify"
	if err := hdOK(op, alg); err != nil {
		return err
	}
	if len(ek) == 0 || len(ct) == 0 || len(label) == 0 || len(pubX) != alg.pointLen() || len(pubK) != alg.pointLen() {
		return badArg(op, "bad sizes")
	}
	pts := bytes.Join([][]byte{pubX, pubK}, nil)
	err := local(op, func() C.int {
		return C.qv_pve_verify(alg.curve(), bptr(ek), C.size_t(len(ek)), bptr(ct), C.size_t(len(ct)),
			bptr(pts), C.size_t(alg.pointLen()), 2, bptr(label), C.size_t(len(label)))
	})
	if err != nil && KindOf(err) == KindInternal && !isLayout(err) {
		// A ciphertext that does not verify is a failed check, not an internal fault.
		e := err.(*Error)
		e.Kind = KindCryptographic
	}
	return err
}

// PVERestore decrypts (X, K) with the offline key. Verify first with PVEVerify when ct is not trusted.
func PVERestore(alg Alg, dk *Secret, ek, ct, label []byte) (x, k *Secret, err error) {
	const op = "pve.restore"
	if err := hdOK(op, alg); err != nil {
		return nil, nil, err
	}
	if len(ek) == 0 || len(ct) == 0 || len(label) == 0 {
		return nil, nil, badArg(op, "bad sizes")
	}
	var p *C.uint8_t
	var n C.size_t
	err = dk.use(func(dp *C.uint8_t, dn C.size_t) error {
		return local(op, func() C.int {
			return C.qv_pve_decrypt(alg.curve(), dp, dn, bptr(ek), C.size_t(len(ek)), bptr(ct), C.size_t(len(ct)),
				bptr(label), C.size_t(len(label)), &p, &n)
		})
	})
	if err != nil {
		if KindOf(err) == KindInternal && !isLayout(err) {
			if e, ok := err.(*Error); ok && e.Err == nil {
				e.Kind = KindCryptographic
			}
		}
		return nil, nil, wrapWiped(op, err)
	}
	if n != 2 {
		C.qv_wipe(unsafe.Pointer(p), n*32)
		C.free(unsafe.Pointer(p))
		return nil, nil, &Error{Kind: KindInternal, Op: op, Msg: "unexpected scalar count"}
	}
	// Split the 64-byte result into two Secrets without passing through the Go heap.
	xp := (*C.uint8_t)(C.malloc(32))
	kp := (*C.uint8_t)(C.malloc(32))
	C.memcpy(unsafe.Pointer(xp), unsafe.Pointer(p), 32)
	C.memcpy(unsafe.Pointer(kp), unsafe.Add(unsafe.Pointer(p), 32), 32)
	C.qv_wipe(unsafe.Pointer(p), 64)
	C.free(unsafe.Pointer(p))
	return takeSecret(xp, 32), takeSecret(kp, 32), nil
}

func isLayout(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == CodeLayout
}
