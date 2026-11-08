// Package cbmpc is a tested Go wrapper over Coinbase cb-mpc (2-party protocols and 2-of-3 threshold ECDSA, see threshold.go), pinned in ../../cbmpc.pin.
//
// Parties: P1 (role 0) is the coordinator and the only party that receives signatures; P2 (role 1) follows.
// Every protocol call is one blocking cgo call on its own OS thread, driven through a Transport (see transport.go).
//
// Thread safety: all functions and methods may be called concurrently from any number of goroutines, on the same or
// different keys, each protocol call with its own Transport. A Keyset or SignKey is immutable after creation (Refresh
// returns a new value and leaves the old one valid until you Wipe it). cb-mpc keeps no global mutable state that
// matters here (tested with -race at concurrency 32). One OS thread is blocked per running protocol call.
//
// Error classes: every error is an *Error with Kind Transport, Cryptographic or Internal, see errors.go.
package cbmpc

/*
#cgo CXXFLAGS: -std=c++17 -O2 -w -fvisibility=hidden -fexceptions -DNO_DEPRECATED_OPENSSL
#cgo CXXFLAGS: -I${SRCDIR}/../../.deps/cb-mpc/include -I${SRCDIR}/../../.deps/cb-mpc/include-internal -I${SRCDIR}/../../.deps/cb-mpc/src/cbmpc/api -I${SRCDIR}/../../.deps/openssl/include
#cgo LDFLAGS: -L${SRCDIR}/../../.deps/cb-mpc/lib/Release -lcbmpc -L${SRCDIR}/../../.deps/openssl/lib -L${SRCDIR}/../../.deps/openssl/lib64 -lcrypto
#cgo darwin LDFLAGS: -lc++
#cgo linux LDFLAGS: -lstdc++ -lpthread -ldl
#include <stdlib.h>
#include <string.h>
#include "shim.h"
*/
import "C"

import (
	"context"
	"fmt"
	"runtime/cgo"
	"unsafe"
)

// Role of a party.
type Role int

const (
	P1 Role = 0 // coordinator, receives signatures
	P2 Role = 1
)

func (r Role) String() string {
	if r == P1 {
		return "p1"
	}
	return "p2"
}

// Alg selects the signature scheme.
type Alg int

const (
	ECDSA   Alg = C.QV_ALG_ECDSA   // secp256k1 (EVM, BTC P2WPKH)
	Ed25519 Alg = C.QV_ALG_EDDSA   // Solana
	BIP340  Alg = C.QV_ALG_SCHNORR // Bitcoin taproot; no HD in cb-mpc
)

func (a Alg) String() string {
	switch a {
	case ECDSA:
		return "ecdsa"
	case Ed25519:
		return "ed25519"
	case BIP340:
		return "bip340"
	}
	return fmt.Sprintf("alg(%d)", int(a))
}

func (a Alg) curve() C.int {
	if a == Ed25519 {
		return C.QV_CURVE_ED25519
	}
	return C.QV_CURVE_SECP256K1
}

func (a Alg) pointLen() int {
	if a == Ed25519 {
		return 32
	}
	return 33
}

const (
	maxPath    = 16
	hardenedLo = 0x80000000
)

// run executes one protocol call: it builds the Go session, hands its handle to C++, and classifies the outcome.
func run(ctx context.Context, tr Transport, op string, opts []Option, f func(h C.uintptr_t) C.int) error {
	if tr == nil {
		return badArg(op, "nil transport")
	}
	if err := ctx.Err(); err != nil {
		return &Error{Kind: KindTransport, Op: op, Err: ctxErr(ctx)}
	}
	s := &session{ctx: ctx, tr: tr, opts: newOptions(opts)}
	h := cgo.NewHandle(s)
	defer h.Delete()
	if rv := f(C.uintptr_t(h)); rv != 0 {
		return classify(op, uint32(rv), s, true)
	}
	return nil
}

// local runs a call that does not touch the network.
func local(op string, f func() C.int) error {
	if rv := f(); rv != 0 {
		return classify(op, uint32(rv), nil, false)
	}
	return nil
}

func u32(p []uint32) *C.uint32_t {
	if len(p) == 0 {
		return nil
	}
	return (*C.uint32_t)(unsafe.Pointer(&p[0]))
}

func bptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func checkRole(op string, r Role) error {
	if r != P1 && r != P2 {
		return badArg(op, "role must be P1 or P2")
	}
	return nil
}

// TestThrow makes the shim throw a C++ exception of the given kind (0 runtime_error, 1 cb_assert, 2 bad_alloc,
// 3 non-exception, 4 none) and returns what the boundary guard returned. Exists only to test the guard.
func TestThrow(kind int) error {
	return local("test.throw", func() C.int { return C.qv_test_throw(C.int(kind)) })
}

// LayoutID identifies the cb-mpc API generation the shim mirrors.
func LayoutID() string { return C.GoString(C.qv_layout_id()) }
