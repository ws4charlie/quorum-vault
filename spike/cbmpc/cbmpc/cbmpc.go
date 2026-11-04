// Package cbmpc is a throwaway cgo wrapper over Coinbase cb-mpc v0.2.2 (2-party protocols).
package cbmpc

/*
#cgo CXXFLAGS: -std=c++17 -O2 -w -fvisibility=hidden -DNO_DEPRECATED_OPENSSL
#cgo CXXFLAGS: -I${SRCDIR}/../.deps/cb-mpc/include -I${SRCDIR}/../.deps/cb-mpc/include-internal -I${SRCDIR}/../.deps/cb-mpc/src/cbmpc/api -I${SRCDIR}/../.deps/openssl/include
#cgo LDFLAGS: -L${SRCDIR}/../.deps/cb-mpc/lib/Release -lcbmpc -L${SRCDIR}/../.deps/openssl/lib -L${SRCDIR}/../.deps/openssl/lib64 -lcrypto -lc++
#cgo linux LDFLAGS: -lstdc++ -lpthread -ldl
#include <stdlib.h>
#include <string.h>
#include "shim.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime/cgo"
	"unsafe"
)

// Transport carries the opaque protocol messages of ONE protocol session between the two parties.
// Both calls block. peer is always the other party's index (0 = p1, 1 = p2).
type Transport interface {
	Send(peer int, msg []byte) error
	Recv(peer int) ([]byte, error)
}

const (
	Secp256k1 = 2
	Ed25519   = 3
	AlgECDSA  = 0
	AlgEdDSA  = 1
	AlgSchnorr = 2
)

type Error int

func (e Error) Error() string { return fmt.Sprintf("cb-mpc error 0x%x", int(e)) }

//export qv_go_send
func qv_go_send(h C.uintptr_t, receiver C.int, msg unsafe.Pointer, n C.size_t) C.int {
	t := cgo.Handle(h).Value().(Transport)
	if err := t.Send(int(receiver), C.GoBytes(msg, C.int(n))); err != nil {
		return C.int(0x0e000001) // E_NET_GENERAL-like
	}
	return 0
}

//export qv_go_recv
func qv_go_recv(h C.uintptr_t, sender C.int, out *unsafe.Pointer, outn *C.size_t) C.int {
	t := cgo.Handle(h).Value().(Transport)
	b, err := t.Recv(int(sender))
	if err != nil {
		return C.int(0x0e000001)
	}
	p := C.malloc(C.size_t(len(b) + 1))
	if len(b) > 0 {
		C.memcpy(p, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	}
	*out = p
	*outn = C.size_t(len(b))
	return 0
}

func take(p *C.uint8_t, n C.size_t) []byte {
	if p == nil {
		return nil
	}
	b := C.GoBytes(unsafe.Pointer(p), C.int(n))
	C.qv_wipe(unsafe.Pointer(p), n)
	C.qv_free(unsafe.Pointer(p))
	return b
}

func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func u32(p []uint32) *C.uint32_t {
	if len(p) == 0 {
		return nil
	}
	return (*C.uint32_t)(unsafe.Pointer(&p[0]))
}

func chk(rv C.int) error {
	if rv != 0 {
		return Error(rv)
	}
	return nil
}

func bi(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

func withTr(t Transport, f func(h C.uintptr_t) C.int) error {
	h := cgo.NewHandle(t)
	defer h.Delete()
	return chk(f(C.uintptr_t(h)))
}

// ---- HD keyset ----

func HDDKG(ecdsa bool, role int, t Transport, curve int) (ks []byte, err error) {
	var p *C.uint8_t
	var n C.size_t
	err = withTr(t, func(h C.uintptr_t) C.int { return C.qv_hd_dkg(bi(ecdsa), C.int(role), h, C.int(curve), &p, &n) })
	if err != nil {
		return nil, err
	}
	return take(p, n), nil
}

func HDRefresh(ecdsa bool, role int, t Transport, ks []byte) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	err := withTr(t, func(h C.uintptr_t) C.int {
		return C.qv_hd_refresh(bi(ecdsa), C.int(role), h, ptr(ks), C.size_t(len(ks)), &p, &n)
	})
	if err != nil {
		return nil, err
	}
	return take(p, n), nil
}

// HDDerive runs the hardened (VRF) step and returns the 2PC key blob for hardened/nonHardened.
func HDDerive(ecdsa bool, role int, t Transport, ks []byte, hardened, nonHardened []uint32, sid []byte) (key, newSid []byte, err error) {
	var sp, kp *C.uint8_t
	var sn, kn C.size_t
	sidc := C.malloc(C.size_t(len(sid) + 1))
	defer C.free(sidc)
	if len(sid) > 0 {
		C.memcpy(sidc, unsafe.Pointer(&sid[0]), C.size_t(len(sid)))
	}
	sp, sn = (*C.uint8_t)(sidc), C.size_t(len(sid))
	err = withTr(t, func(h C.uintptr_t) C.int {
		return C.qv_hd_derive(bi(ecdsa), C.int(role), h, ptr(ks), C.size_t(len(ks)),
			u32(hardened), C.size_t(len(hardened)), u32(nonHardened), C.size_t(len(nonHardened)), &sp, &sn, &kp, &kn)
	})
	if err != nil {
		return nil, nil, err
	}
	// sp was replaced by a malloc'ed buffer on success
	newSid = C.GoBytes(unsafe.Pointer(sp), C.int(sn))
	C.qv_free(unsafe.Pointer(sp))
	return take(kp, kn), newSid, nil
}

// HDNodeECDSA returns the hardened account node: compressed pubkey + chain code (xpub material).
func HDNodeECDSA(role int, t Transport, ks []byte, hardened []uint32) (q33, cc32 []byte, err error) {
	q33, cc32 = make([]byte, 33), make([]byte, 32)
	sidc := C.malloc(1)
	sp, sn := (*C.uint8_t)(sidc), C.size_t(0)
	err = withTr(t, func(h C.uintptr_t) C.int {
		return C.qv_hd_node_ecdsa(C.int(role), h, ptr(ks), C.size_t(len(ks)), u32(hardened), C.size_t(len(hardened)),
			&sp, &sn, ptr(q33), ptr(cc32))
	})
	C.free(sidc)
	if err != nil {
		return nil, nil, err
	}
	C.qv_free(unsafe.Pointer(sp))
	return q33, cc32, nil
}

func HDRootPub(ecdsa bool, ks []byte) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	if err := chk(C.qv_hd_root_pub(bi(ecdsa), ptr(ks), C.size_t(len(ks)), &p, &n)); err != nil {
		return nil, err
	}
	return take(p, n), nil
}

// ---- plain 2PC keys ----

func DKG2P(alg, role int, t Transport, curve int) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	err := withTr(t, func(h C.uintptr_t) C.int { return C.qv_2p_dkg(C.int(alg), C.int(role), h, C.int(curve), &p, &n) })
	if err != nil {
		return nil, err
	}
	return take(p, n), nil
}

// Sign2P: only role 0 (p1) receives the signature.
func Sign2P(alg, role int, t Transport, key, msg []byte) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	err := withTr(t, func(h C.uintptr_t) C.int {
		return C.qv_2p_sign(C.int(alg), C.int(role), h, ptr(key), C.size_t(len(key)), ptr(msg), C.size_t(len(msg)), &p, &n)
	})
	if err != nil {
		return nil, err
	}
	return take(p, n), nil
}

func Pub2P(alg int, key []byte) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	if err := chk(C.qv_2p_pub(C.int(alg), ptr(key), C.size_t(len(key)), &p, &n)); err != nil {
		return nil, err
	}
	return take(p, n), nil
}

func SchnorrXOnly(key []byte) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	if err := chk(C.qv_schnorr_xonly(ptr(key), C.size_t(len(key)), &p, &n)); err != nil {
		return nil, err
	}
	return take(p, n), nil
}

// ---- backup ----

// KeysetSplit removes both secret scalars (x, k) from an ECDSA keyset blob.
// NOTE: for p1 the stripped blob still contains the Paillier private key: protect it like the full blob.
func KeysetSplit(ks []byte) (stripped, x, k, Qx33, Qk33 []byte, err error) {
	var sp, xp, kp, qx, qk *C.uint8_t
	var sn, xn, kn C.size_t
	if err = chk(C.qv_ks_split(1, ptr(ks), C.size_t(len(ks)), &sp, &sn, &xp, &xn, &kp, &kn, &qx, &qk)); err != nil {
		return
	}
	return take(sp, sn), take(xp, xn), take(kp, kn), take(qx, 33), take(qk, 33), nil
}

func KeysetJoin(stripped, x, k []byte) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	if err := chk(C.qv_ks_join(1, ptr(stripped), C.size_t(len(stripped)), ptr(x), C.size_t(len(x)), ptr(k), C.size_t(len(k)), &p, &n)); err != nil {
		return nil, err
	}
	return take(p, n), nil
}

func PVEKeygen() (ek, dk []byte, err error) {
	var ep, dp *C.uint8_t
	var en, dn C.size_t
	if err = chk(C.qv_pve_keygen(Secp256k1, &ep, &en, &dp, &dn)); err != nil {
		return
	}
	return take(ep, en), take(dp, dn), nil
}

func cptrs(bs [][]byte) (**C.uint8_t, *C.size_t, func()) {
	n := len(bs)
	ps := (**C.uint8_t)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	ls := (*C.size_t)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.size_t(0)))))
	pa := unsafe.Slice(ps, n)
	la := unsafe.Slice(ls, n)
	for i, b := range bs {
		m := C.malloc(C.size_t(len(b) + 1))
		if len(b) > 0 {
			C.memcpy(m, unsafe.Pointer(&b[0]), C.size_t(len(b)))
		}
		pa[i], la[i] = (*C.uint8_t)(m), C.size_t(len(b))
	}
	return ps, ls, func() {
		for i := range pa {
			C.free(unsafe.Pointer(pa[i]))
		}
		C.free(unsafe.Pointer(ps))
		C.free(unsafe.Pointer(ls))
	}
}

func PVEEncrypt(ek, label []byte, xs [][]byte) ([]byte, error) {
	ps, ls, free := cptrs(xs)
	defer free()
	var p *C.uint8_t
	var n C.size_t
	if err := chk(C.qv_pve_encrypt(Secp256k1, ptr(ek), C.size_t(len(ek)), ptr(label), C.size_t(len(label)), ps, ls, C.size_t(len(xs)), &p, &n)); err != nil {
		return nil, err
	}
	return take(p, n), nil
}

func PVEVerify(ek, ct, label []byte, Qs [][]byte) error {
	ps, ls, free := cptrs(Qs)
	defer free()
	return chk(C.qv_pve_verify(Secp256k1, ptr(ek), C.size_t(len(ek)), ptr(ct), C.size_t(len(ct)), ps, ls, C.size_t(len(Qs)), ptr(label), C.size_t(len(label))))
}

func PVEDecrypt(dk, ek, ct, label []byte) ([][]byte, error) {
	var p *C.uint8_t
	var n, cnt C.size_t
	if err := chk(C.qv_pve_decrypt(Secp256k1, ptr(dk), C.size_t(len(dk)), ptr(ek), C.size_t(len(ek)), ptr(ct), C.size_t(len(ct)), ptr(label), C.size_t(len(label)), &p, &n, &cnt)); err != nil {
		return nil, err
	}
	flat := take(p, n)
	if cnt == 0 {
		return nil, errors.New("empty")
	}
	each := len(flat) / int(cnt)
	var out [][]byte
	for i := 0; i < int(cnt); i++ {
		out = append(out, flat[i*each:(i+1)*each])
	}
	return out, nil
}
