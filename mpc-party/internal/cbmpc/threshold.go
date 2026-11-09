package cbmpc

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime/cgo"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Threshold signing, 2-of-3: cb-mpc's ecdsa_mp (secp256k1, E23-1) or eddsa_mp (Ed25519, P8-1) with the access structure
// Threshold(2, {m0, m1, m2}). One type and one code path serve both: a TKey carries its Alg. Not HD. DKG and Refresh need
// all three members online; Sign needs only two. See docs/spikes/e23-threshold.md and docs/spikes/p8-eddsa-threshold.md.
// The ECDSA entry points (TDKG, LoadTKey, ...) keep their names and meaning; the Alg variants add Ed25519.
//
// Differences from the 2-party calls that matter to the caller:
//   - A session talks to up to two peers, through a Mesh (mesh.go), not a Transport.
//   - The signature goes to a receiver you choose (self or the peer), not always to P1.
//   - The share blob does not record the access structure; this package always uses the same constant one.
//   - The blob is name-bound: member numbers are fixed for the life of the keyset.

// TKey is one member's share of a 2-of-3 threshold key.
type TKey struct {
	*Secret
	alg  Alg
	self Member
	pub  []byte // compressed Q (33 bytes ECDSA, 32 bytes Ed25519), public
	qi   []byte // this member's share point, same encoding, public
}

// checkTAlg accepts the two schemes the threshold calls support.
func checkTAlg(op string, alg Alg) error {
	if alg != ECDSA && alg != Ed25519 {
		return badArg(op, "threshold keys support ECDSA and Ed25519 only, not %s", alg)
	}
	return nil
}

// top names an operation: "tecdsa.dkg" or "teddsa.dkg".
func top(alg Alg, what string) string {
	if alg == Ed25519 {
		return "teddsa." + what
	}
	return "tecdsa." + what
}

// Alg returns the signature scheme of the key.
func (k *TKey) Alg() Alg { return k.alg }

func (k *TKey) Self() Member { return k.self }

// Wipe wipes the share; safe on a nil key.
func (k *TKey) Wipe() {
	if k != nil {
		k.Secret.Wipe()
	}
}

// PublicKey returns the group public key: compressed (33 bytes) for ECDSA, the standard 32-byte encoding for Ed25519.
func (k *TKey) PublicKey() []byte { return append([]byte(nil), k.pub...) }

// SharePoint returns this member's public share point Qi = x_i * G (same encoding as PublicKey).
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
func newTKey(op string, alg Alg, self Member, sec *Secret) (*TKey, error) {
	var m C.int
	q, qi := make([]byte, 33), make([]byte, 33) // room for the larger encoding
	err := sec.use(func(p *C.uint8_t, n C.size_t) error {
		return local(op, func() C.int { return C.qv_t_info(C.int(alg), p, n, &m, bptr(q), bptr(qi)) })
	})
	if err == nil && Member(m) != self {
		err = badArg(op, "share belongs to %s, not %s", Member(m), self)
	}
	if err != nil {
		sec.Wipe()
		return nil, wrapWiped(op, err)
	}
	n := alg.pointLen()
	return &TKey{Secret: sec, alg: alg, self: self, pub: q[:n:n], qi: qi[:n:n]}, nil
}

// LoadTKey wraps a stored 2-of-3 ECDSA share after parsing it and checking that it belongs to self. blob is wiped.
func LoadTKey(self Member, blob []byte) (*TKey, error) { return LoadTKeyAlg(ECDSA, self, blob) }

// LoadTKeyAlg is LoadTKey for either scheme. A share of the other scheme does not load.
func LoadTKeyAlg(alg Alg, self Member, blob []byte) (*TKey, error) {
	op := top(alg, "load")
	if err := checkTAlg(op, alg); err != nil {
		WipeBytes(blob)
		return nil, err
	}
	if err := checkMember(op, self); err != nil {
		WipeBytes(blob)
		return nil, err
	}
	if len(blob) == 0 || len(blob) > maxBlob {
		WipeBytes(blob)
		return nil, badArg(op, "blob size %d out of range", len(blob))
	}
	return newTKey(op, alg, self, SecretFromBytes(blob))
}

// TDKG generates a new 2-of-3 key with the other two members; all three must call it. Run SelfTest on the result before
// the shares are accepted.
func TDKG(ctx context.Context, mesh Mesh, self Member, opts ...Option) (*TKey, error) {
	return TDKGAlg(ctx, mesh, self, ECDSA, opts...)
}

// TDKGAlg is TDKG for either scheme (ECDSA or Ed25519); all three members must pass the same alg.
func TDKGAlg(ctx context.Context, mesh Mesh, self Member, alg Alg, opts ...Option) (*TKey, error) {
	op := top(alg, "dkg")
	if err := checkTAlg(op, alg); err != nil {
		return nil, err
	}
	if err := checkMember(op, self); err != nil {
		return nil, err
	}
	var p *C.uint8_t
	var n C.size_t
	if err := runMesh(ctx, mesh, op, opts, func(h C.uintptr_t) C.int {
		return C.qv_t_dkg(C.int(alg), C.int(self), h, &p, &n)
	}); err != nil {
		return nil, err
	}
	return newTKey(op, alg, self, takeSecret(p, n))
}

// Refresh re-randomizes all three shares without changing the public key; all three must call it. The old key stays
// valid until you Wipe it. The result may be corrupt although every member returned nil (README point 1): run
// SelfTest on the new shares and drop the old ones only after all three passed.
func (k *TKey) Refresh(ctx context.Context, mesh Mesh, opts ...Option) (*TKey, error) {
	op := top(k.alg, "refresh")
	var p *C.uint8_t
	var n C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return runMesh(ctx, mesh, op, opts, func(h C.uintptr_t) C.int {
			return C.qv_t_refresh(C.int(k.alg), C.int(k.self), h, kp, kn, &p, &n)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	nk, err := newTKey(op, k.alg, k.self, takeSecret(p, n))
	if err != nil {
		return nil, err
	}
	if string(nk.pub) != string(k.pub) { // refresh must not move the public key
		nk.Wipe()
		return nil, &Error{Kind: KindCryptographic, Op: op, Msg: "refresh changed the public key"}
	}
	return nk, nil
}

// Sign runs 2-party-in-3 signing with peer; both call it with the same msg and the same receiver. receiver is self or
// peer and is the only one that gets the signature; the other gets (nil, nil) and learns nothing about success from it.
//   - ECDSA: msg is a 32-byte digest; the signature is DER, low-S, checked by cb-mpc against the public key and again
//     here with btcec.
//   - Ed25519: msg is the whole message (1 byte to MaxEdMessage); the signature is 64 bytes R||s, checked by cb-mpc and
//     again here with crypto/ed25519 (RFC 8032 verification). R comes from fresh random nonces, so signing the same
//     message twice gives two different valid signatures: store the first one and rebroadcast it, do not re-sign.
func (k *TKey) Sign(ctx context.Context, mesh Mesh, peer, receiver Member, msg []byte, opts ...Option) ([]byte, error) {
	op := top(k.alg, "sign")
	if err := checkMember(op, peer); err != nil {
		return nil, err
	}
	if peer == k.self {
		return nil, badArg(op, "peer must be another member")
	}
	if receiver != k.self && receiver != peer {
		return nil, badArg(op, "receiver must be self or peer")
	}
	if k.alg == ECDSA && len(msg) != 32 {
		return nil, badArg(op, "message must be a 32-byte digest, got %d bytes", len(msg))
	}
	if k.alg == Ed25519 && (len(msg) == 0 || len(msg) > MaxEdMessage) {
		return nil, badArg(op, "message must be 1 to %d bytes, got %d", MaxEdMessage, len(msg))
	}
	var p *C.uint8_t
	var n C.size_t
	err := k.use(func(kp *C.uint8_t, kn C.size_t) error {
		return runMesh(ctx, mesh, op, opts, func(h C.uintptr_t) C.int {
			return C.qv_t_sign(C.int(k.alg), C.int(k.self), h, C.int(peer), C.int(receiver), kp, kn, bptr(msg), C.size_t(len(msg)), &p, &n)
		})
	})
	if err != nil {
		return nil, wrapWiped(op, err)
	}
	if receiver != k.self {
		return nil, nil
	}
	sig := takeBytes(p, n)
	if err := verifyT(k.alg, k.pub, msg, sig); err != nil {
		return nil, &Error{Kind: KindCryptographic, Op: op, Msg: err.Error()}
	}
	return sig, nil
}

// MaxEdMessage bounds an Ed25519 message (a Solana transaction message is at most 1232 bytes).
const MaxEdMessage = 1 << 16

// verifyT checks a threshold signature independently of cb-mpc: btcec for ECDSA, crypto/ed25519 for Ed25519.
func verifyT(alg Alg, pub, msg, sig []byte) error {
	if alg == Ed25519 {
		if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("bad Ed25519 public key or signature size")
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return fmt.Errorf("signature does not verify against the public key")
		}
		return nil
	}
	return verifyLowS(pub, msg, sig)
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
	return selfTestDigest(ECDSA, pub, label, a, b)
}

func selfTestDigest(alg Alg, pub, label []byte, a, b Member) []byte {
	h := sha256.New()
	if alg == Ed25519 {
		h.Write([]byte("quorum-vault/teddsa-selftest/v1"))
	} else {
		h.Write([]byte("quorum-vault/tecdsa-selftest/v1"))
	}
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
	op := top(k.alg, "selftest")
	digest := selfTestDigest(k.alg, k.pub, label, a, b)
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
	ok := len(got) <= 80 && verifyT(k.alg, k.pub, digest, got) == nil
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
