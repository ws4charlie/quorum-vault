package cbmpc

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"context"
	"crypto/ed25519"
	"unsafe"
)

// Keyset is one party's share of an HD keyset (ECDSA/secp256k1 or Ed25519). The secret stays in C memory.
type Keyset struct {
	*Secret
	alg  Alg
	role Role
}

func (k *Keyset) Alg() Alg   { return k.alg }
func (k *Keyset) Role() Role { return k.role }

func hdOK(op string, alg Alg) error {
	if alg != ECDSA && alg != Ed25519 {
		return badArg(op, "HD keysets exist for ECDSA and Ed25519 only, got %s", alg)
	}
	return nil
}

// DKG generates a new HD keyset together with the peer. ECDSA keysets are on secp256k1.
func DKG(ctx context.Context, tr Transport, role Role, alg Alg, opts ...Option) (*Keyset, error) {
	const op = "hd.dkg"
	if err := hdOK(op, alg); err != nil {
		return nil, err
	}
	if err := checkRole(op, role); err != nil {
		return nil, err
	}
	var p *C.uint8_t
	var n C.size_t
	if err := run(ctx, tr, op, opts, func(h C.uintptr_t) C.int {
		return C.qv_hd_dkg(C.int(alg), C.int(role), h, &p, &n)
	}); err != nil {
		return nil, err
	}
	return &Keyset{takeSecret(p, n), alg, role}, nil
}

// LoadKeyset wraps a keyset blob (for example unsealed from an HSM) after parsing and validating it. blob is wiped.
func LoadKeyset(alg Alg, role Role, blob []byte) (*Keyset, error) {
	const op = "hd.load"
	if err := hdOK(op, alg); err != nil {
		WipeBytes(blob)
		return nil, err
	}
	if err := checkRole(op, role); err != nil {
		WipeBytes(blob)
		return nil, err
	}
	if len(blob) == 0 || len(blob) > maxBlob {
		WipeBytes(blob)
		return nil, badArg(op, "blob size %d out of range", len(blob))
	}
	var r, c C.int
	err := local(op, func() C.int { return C.qv_hd_info(C.int(alg), bptr(blob), C.size_t(len(blob)), &r, &c) })
	if err != nil {
		WipeBytes(blob)
		return nil, err
	}
	if Role(r) != role {
		WipeBytes(blob)
		return nil, badArg(op, "blob is for %s, expected %s", Role(r), role)
	}
	return &Keyset{SecretFromBytes(blob), alg, role}, nil
}

// maxBlob matches the library's own 1 MiB limit on opaque blobs.
const maxBlob = 1 << 20

// Refresh re-randomizes both shares of the same key together with the peer. The public key and all derived public keys
// stay the same.
//
// The result is a NEW keyset; the old one stays valid until you Wipe it. Derived SignKeys are bound to the shares they
// were derived from and must be re-derived after a refresh.
//
// Old and new shares must never be mixed. What happens if they are (tested, both directions, ECDSA and Ed25519):
//   - Sign with one refreshed and one old derived key: P1 fails with KindCryptographic (E_CRYPTO, a proof or the final
//     signature check fails) and gets no signature. P2 can return SUCCESS, because it never sees the result: only P1's
//     outcome tells whether a signature exists. Callers must not treat P2's success as evidence of a signature.
//   - Derive with one refreshed and one old keyset: the side that verifies the peer's proof fails with
//     KindCryptographic; the other side sees the closed link (KindTransport).
//
// No wrong signature is ever produced. Switching atomically is the caller's job (two-phase, P5b-4): keep the old keyset
// until both parties confirmed the new one.
func (k *Keyset) Refresh(ctx context.Context, tr Transport, opts ...Option) (*Keyset, error) {
	const op = "hd.refresh"
	var p *C.uint8_t
	var n C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return run(ctx, tr, op, opts, func(h C.uintptr_t) C.int {
			return C.qv_hd_refresh(C.int(k.alg), C.int(k.role), h, kp, kn, &p, &n)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return &Keyset{takeSecret(p, n), k.alg, k.role}, nil
}

func wrapWiped(op string, err error) error {
	if err == ErrWiped {
		return &Error{Kind: KindInternal, Op: op, Msg: "secret already wiped", Err: ErrWiped}
	}
	return err
}

func checkPaths(op string, hardened, nonHardened []uint32) error {
	if len(hardened) == 0 || len(hardened) > maxPath || len(nonHardened) > maxPath {
		return badArg(op, "path lengths out of range (hardened 1..%d, non-hardened 0..%d)", maxPath, maxPath)
	}
	for _, i := range nonHardened {
		if i >= hardenedLo {
			return badArg(op, "non-hardened index %d must be below 2^31", i)
		}
	}
	return nil
}

// Derive runs the hardened step with the peer and returns the signing key for (hardened path, non-hardened path).
// hardened is cb-mpc's own vector of uint32 (hashed to a curve point; it is NOT BIP32 hardened-index arithmetic).
// nonHardened are plain BIP32 CKDpub indices below 2^31; it may be empty (the account node itself).
// Both parties must call it with the same paths. About 1.5 ms plus one round trip.
func (k *Keyset) Derive(ctx context.Context, tr Transport, hardened, nonHardened []uint32, opts ...Option) (*SignKey, error) {
	const op = "hd.derive"
	if err := checkPaths(op, hardened, nonHardened); err != nil {
		return nil, err
	}
	var p *C.uint8_t
	var n C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return run(ctx, tr, op, opts, func(h C.uintptr_t) C.int {
			return C.qv_hd_derive(C.int(k.alg), C.int(k.role), h, kp, kn, u32(hardened), C.size_t(len(hardened)),
				u32(nonHardened), C.size_t(len(nonHardened)), &p, &n)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return &SignKey{takeSecret(p, n), k.alg, k.role}, nil
}

// Node is the public material of a hardened node: with it anyone derives every non-hardened child public key (BIP32
// CKDpub) without any MPC.
type Node struct {
	PublicKey []byte // compressed point: 33 bytes (secp256k1) or 32 bytes (ed25519)
	ChainCode []byte // 32 bytes
}

// NodeExport runs the hardened step with the peer and returns the node's public key and chain code. It relies on
// cb-mpc internals (see shim.cpp) and is pinned by the golden tests.
func (k *Keyset) NodeExport(ctx context.Context, tr Transport, hardened []uint32, opts ...Option) (Node, error) {
	const op = "hd.node"
	if err := checkPaths(op, hardened, nil); err != nil {
		return Node{}, err
	}
	q := make([]byte, 33)
	cc := make([]byte, 32)
	var ql C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return run(ctx, tr, op, opts, func(h C.uintptr_t) C.int {
			return C.qv_hd_node(C.int(k.alg), C.int(k.role), h, kp, kn, u32(hardened), C.size_t(len(hardened)),
				bptr(q), &ql, bptr(cc))
		})
	})
	if err != nil {
		return Node{}, wrapWiped(op, err)
	}
	return Node{PublicKey: q[:ql], ChainCode: cc}, nil
}

// RootPublicKey returns the keyset's root public key (compressed). Local, no peer needed.
func (k *Keyset) RootPublicKey() ([]byte, error) {
	const op = "hd.root_pub"
	var p *C.uint8_t
	var n C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return local(op, func() C.int { return C.qv_hd_root_pub(C.int(k.alg), kp, kn, &p, &n) })
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	return takeBytes(p, n), nil
}

var _ = unsafe.Pointer(nil)

// SelfTest proves that this keyset and the peer's keyset form a working key: it derives a fixed test child with the peer
// and signs a fixed digest. Both parties must call it. It returns the test child's public key.
//
// WHY YOU NEED IT: a DKG or Refresh in which the peer (or the link) corrupted a message can end with BOTH parties
// reporting success while the resulting shares do not work together (found by the malicious-peer test: the root public
// key is unchanged, Derive succeeds, Sign fails). A caller that deletes its old keyset right after Refresh would lose the
// key. Rule: after every DKG and every Refresh run SelfTest on the NEW shares, and drop the old shares only after P1's
// SelfTest succeeded and P1 told P2.
//
// Only P1 sees the signature: P1's nil error means "works"; P2's nil error means only "the protocol ran".
func (k *Keyset) SelfTest(ctx context.Context, tr Transport, opts ...Option) ([]byte, error) {
	hardened, path := []uint32{0x71765f73, 0x656c6674, 0x65737400}, []uint32{0}
	s, err := k.Derive(ctx, tr, hardened, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Wipe()
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 32)
	copy(msg, "qv-cbmpc-selftest-digest-0000001")
	sig, err := s.Sign(ctx, tr, msg, opts...)
	if err != nil {
		return nil, err
	}
	if k.role == P1 && k.alg == Ed25519 && !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return nil, &Error{Kind: KindCryptographic, Op: "hd.selftest", Msg: "self-test signature does not verify"}
	}
	// ECDSA signatures are verified against the public key inside cb-mpc before sign() returns (ecdsa_2p.cpp).
	if k.role == P1 && len(sig) == 0 {
		return nil, &Error{Kind: KindInternal, Op: "hd.selftest", Msg: "no signature"}
	}
	return pub, nil
}
