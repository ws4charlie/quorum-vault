package cbmpc

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime/cgo"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Threshold ECDSA, 2-of-3, secp256k1: cb-mpc's ecdsa_mp with the access structure Threshold(2, {m0, m1, m2}).
// Not HD. DKG and Refresh need all three members online; Sign needs only two. See docs/spikes/e23-threshold.md.
//
// Differences from the 2-party calls that matter to the caller:
//   - A session talks to up to two peers, through a Mesh (mesh.go), not a Transport.
//   - The signature goes to a receiver you choose (self or the peer), not always to P1.
//   - The share blob does not record the access structure; this package always uses the same constant one.
//   - The blob is name-bound: member numbers are fixed for the life of the keyset.

// TKey is one member's share of a 2-of-3 threshold key.
type TKey struct {
	*Secret
	self Member
	pub  []byte // compressed Q, public
	qi   []byte // this member's share point, public
}

func (k *TKey) Self() Member { return k.self }

// Wipe wipes the share; safe on a nil key.
func (k *TKey) Wipe() {
	if k != nil {
		k.Secret.Wipe()
	}
}

// PublicKey returns the compressed (33 byte) group public key.
func (k *TKey) PublicKey() []byte { return append([]byte(nil), k.pub...) }

// SharePoint returns this member's public share point Qi = x_i * G (33 bytes).
func (k *TKey) SharePoint() []byte { return append([]byte(nil), k.qi...) }

func checkMember(op string, m Member) error {
	if !m.valid() {
		return badArg(op, "member must be 0, 1 or 2")
	}
	return nil
}

// runMesh is run() for a Mesh session.
func runMesh(ctx context.Context, mesh Mesh, op string, opts []Option, f func(h C.uintptr_t) C.int) error {
	if mesh == nil {
		return badArg(op, "nil mesh")
	}
	if err := ctx.Err(); err != nil {
		return &Error{Kind: KindTransport, Op: op, Err: ctxErr(ctx)}
	}
	s := &session{ctx: ctx, mesh: mesh, opts: newOptions(opts)}
	h := cgo.NewHandle(s)
	defer h.Delete()
	if rv := f(C.uintptr_t(h)); rv != 0 {
		return classify(op, uint32(rv), s, true)
	}
	return nil
}

// newTKey checks the blob, binds it to self and takes ownership of the C buffer.
func newTKey(op string, self Member, sec *Secret) (*TKey, error) {
	var m C.int
	q, qi := make([]byte, 33), make([]byte, 33)
	err := sec.use(func(p *C.uint8_t, n C.size_t) error {
		return local(op, func() C.int { return C.qv_t_info(p, n, &m, bptr(q), bptr(qi)) })
	})
	if err == nil && Member(m) != self {
		err = badArg(op, "share belongs to %s, not %s", Member(m), self)
	}
	if err != nil {
		sec.Wipe()
		return nil, wrapWiped(op, err)
	}
	return &TKey{Secret: sec, self: self, pub: q, qi: qi}, nil
}

// LoadTKey wraps a stored share after parsing it and checking that it belongs to self. blob is wiped.
func LoadTKey(self Member, blob []byte) (*TKey, error) {
	const op = "tecdsa.load"
	if err := checkMember(op, self); err != nil {
		WipeBytes(blob)
		return nil, err
	}
	if len(blob) == 0 || len(blob) > maxBlob {
		WipeBytes(blob)
		return nil, badArg(op, "blob size %d out of range", len(blob))
	}
	return newTKey(op, self, SecretFromBytes(blob))
}

// TDKG generates a new 2-of-3 key with the other two members; all three must call it. Run SelfTest on the result before
// the shares are accepted.
func TDKG(ctx context.Context, mesh Mesh, self Member, opts ...Option) (*TKey, error) {
	const op = "tecdsa.dkg"
	if err := checkMember(op, self); err != nil {
		return nil, err
	}
	var p *C.uint8_t
	var n C.size_t
	if err := runMesh(ctx, mesh, op, opts, func(h C.uintptr_t) C.int {
		return C.qv_t_dkg(C.int(self), h, &p, &n)
	}); err != nil {
		return nil, err
	}
	return newTKey(op, self, takeSecret(p, n))
}

// Refresh re-randomizes all three shares without changing the public key; all three must call it. The old key stays
// valid until you Wipe it. The result may be corrupt although every member returned nil (README point 1): run
// SelfTest on the new shares and drop the old ones only after all three passed.
func (k *TKey) Refresh(ctx context.Context, mesh Mesh, opts ...Option) (*TKey, error) {
	const op = "tecdsa.refresh"
	var p *C.uint8_t
	var n C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return runMesh(ctx, mesh, op, opts, func(h C.uintptr_t) C.int {
			return C.qv_t_refresh(C.int(k.self), h, kp, kn, &p, &n)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	nk, err := newTKey(op, k.self, takeSecret(p, n))
	if err != nil {
		return nil, err
	}
	if string(nk.pub) != string(k.pub) { // refresh must not move the public key
		nk.Wipe()
		return nil, &Error{Kind: KindCryptographic, Op: op, Msg: "refresh changed the public key"}
	}
	return nk, nil
}

// Sign runs 2-party-in-3 signing with peer; both call it with the same msg (a 32-byte digest) and the same receiver.
// receiver is self or peer and is the only one that gets the signature (DER, low-S, checked by cb-mpc against the
// public key and again here with btcec); the other gets (nil, nil) and learns nothing about success from it.
func (k *TKey) Sign(ctx context.Context, mesh Mesh, peer, receiver Member, msg []byte, opts ...Option) ([]byte, error) {
	const op = "tecdsa.sign"
	if err := checkMember(op, peer); err != nil {
		return nil, err
	}
	if peer == k.self {
		return nil, badArg(op, "peer must be another member")
	}
	if receiver != k.self && receiver != peer {
		return nil, badArg(op, "receiver must be self or peer")
	}
	if len(msg) != 32 {
		return nil, badArg(op, "message must be a 32-byte digest, got %d bytes", len(msg))
	}
	var p *C.uint8_t
	var n C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return runMesh(ctx, mesh, op, opts, func(h C.uintptr_t) C.int {
			return C.qv_t_sign(C.int(k.self), h, C.int(peer), C.int(receiver), kp, kn, bptr(msg), C.size_t(len(msg)), &p, &n)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	if receiver != k.self {
		return nil, nil
	}
	sig := takeBytes(p, n)
	if err := verifyLowS(k.pub, msg, sig); err != nil {
		return nil, &Error{Kind: KindCryptographic, Op: op, Msg: err.Error()}
	}
	return sig, nil
}

// verifyLowS checks a DER signature with btcec: parses, low-S, verifies against pub (compressed).
func verifyLowS(pub, digest, der []byte) error {
	pk, err := btcec.ParsePubKey(pub)
	if err != nil {
		return fmt.Errorf("bad public key: %v", err)
	}
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return fmt.Errorf("signature is not canonical DER: %v", err)
	}
	sv := sig.S()
	if sv.IsOverHalfOrder() {
		return fmt.Errorf("signature has a high S")
	}
	if !sig.Verify(digest, pk) {
		return fmt.Errorf("signature does not verify against the public key")
	}
	return nil
}

// SelfTestDigest is the fixed message every pair signs in SelfTest: a hash of a domain tag, the group public key, the
// caller's label and the pair. It is derived from public data only, never from anything a peer sent, so a hostile
// peer cannot use the self-test as a signing oracle for a digest of its choosing.
func SelfTestDigest(pub, label []byte, a, b Member) []byte {
	h := sha256.New()
	h.Write([]byte("quorum-vault/tecdsa-selftest/v1"))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(label)))
	h.Write(l[:])
	h.Write(label)
	h.Write(pub)
	h.Write([]byte{byte(a), byte(b)})
	return h.Sum(nil)
}

// SelfTest proves that every pair of members can sign with these shares. All three members call it together over
// their meshes, with the same label (bind it to the keyset id and generation, so a recorded run cannot be replayed
// for another generation). For each pair in the fixed order (0,1), (0,2), (1,2): the lower member receives a
// signature over SelfTestDigest and checks it; it then sends the signature to the higher member, which checks it
// with btcec against ITS OWN public key and answers with one byte, so each member returns nil only if both of its
// pairs signed and the counterpart confirmed it.
//
// What nil means: the pairs this member belongs to work. It says nothing about the pair the member is not in. A caller
// accepts new shares (DKG, Refresh) only when ALL THREE members report nil, and tells each other so (the service's
// two-phase commit, E23-2). A failure is KindCryptographic when a check failed and KindTransport when a link did.
func (k *TKey) SelfTest(ctx context.Context, mesh Mesh, label []byte, opts ...Option) error {
	const op = "tecdsa.selftest"
	for a := Member(0); a < NumMembers; a++ {
		for b := a + 1; b < NumMembers; b++ {
			if k.self != a && k.self != b {
				continue
			}
			peer := a
			if k.self == a {
				peer = b
			}
			if err := k.selfTestPair(ctx, mesh, label, a, b, peer, opts); err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *TKey) selfTestPair(ctx context.Context, mesh Mesh, label []byte, a, b, peer Member, opts []Option) error {
	const op = "tecdsa.selftest"
	digest := SelfTestDigest(k.pub, label, a, b)
	sig, err := k.Sign(ctx, mesh, peer, a, digest, opts...)
	if err != nil {
		return err
	}
	if k.self == a {
		// a holds the signature (already verified in Sign); hand it to b and wait for b's verdict.
		if err := mesh.Send(ctx, b, sig); err != nil {
			return &Error{Kind: KindTransport, Op: op, Err: err}
		}
		ack, err := mesh.Recv(ctx, b)
		if err != nil {
			return &Error{Kind: KindTransport, Op: op, Err: err}
		}
		if len(ack) != 1 || ack[0] != 1 {
			return &Error{Kind: KindCryptographic, Op: op, Msg: fmt.Sprintf("%s did not accept the signature of pair (%s,%s)", b, a, b)}
		}
		return nil
	}
	got, err := mesh.Recv(ctx, a)
	if err != nil {
		return &Error{Kind: KindTransport, Op: op, Err: err}
	}
	ok := len(got) <= 80 && verifyLowS(k.pub, digest, got) == nil
	verdict := byte(0)
	if ok {
		verdict = 1
	}
	if err := mesh.Send(ctx, a, []byte{verdict}); err != nil {
		return &Error{Kind: KindTransport, Op: op, Err: err}
	}
	if !ok {
		return &Error{Kind: KindCryptographic, Op: op, Msg: fmt.Sprintf("pair (%s,%s): the signature from %s does not verify against this member's public key", a, b, a)}
	}
	return nil
}
