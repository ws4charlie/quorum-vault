package cbmpc

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"runtime"
	"sync"
	"unsafe"
)

// Secret holds key material in C memory (malloc'ed, mlock'ed when the OS allows). The bytes never live in the Go heap
// unless the caller asks for a copy with Bytes. Wipe zeroes the memory (OPENSSL_cleanse) and frees it.
//
// Concurrency: all methods are safe for concurrent use. Operations that read the secret hold a read lock while they
// run, so Wipe waits for in-flight protocol calls that use this secret to finish; use context cancellation to hurry
// them.
//
// What cannot be wiped: copies you take with Bytes (you must Wipe them with WipeBytes), copies the OS makes (swap,
// core dumps: disable them in the process), pages that the Go runtime or cgo copied for you (we pass pointers, we do
// not copy), registers and the C++ stack of a finished call (cb-mpc zeroizes its own buffers, not the stack).
type Secret struct {
	mu     sync.RWMutex
	p      *C.uint8_t
	n      int
	locked bool
}

func newSecret(p *C.uint8_t, n C.size_t) *Secret {
	s := &Secret{p: p, n: int(n)}
	if p != nil && n > 0 {
		s.locked = C.qv_mlock(unsafe.Pointer(p), n) == 0
	}
	runtime.SetFinalizer(s, func(s *Secret) { s.Wipe() }) // safety net only; callers must Wipe explicitly
	return s
}

// SecretFromBytes copies b into C memory and wipes b.
func SecretFromBytes(b []byte) *Secret {
	n := C.size_t(len(b))
	p := (*C.uint8_t)(C.malloc(n + 1))
	if len(b) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), len(b)), b)
	}
	WipeBytes(b)
	return newSecret(p, n)
}

// Len is the size in bytes (0 after Wipe).
func (s *Secret) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.n
}

// Locked reports whether mlock succeeded.
func (s *Secret) Locked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.locked
}

// Bytes returns a copy in the Go heap, for sealing under an HSM key. The caller must call WipeBytes on it as soon as
// it is done.
func (s *Secret) Bytes() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.p == nil {
		return nil, ErrWiped
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(s.p)), s.n)...), nil
}

// Wipe zeroes and frees the memory. Idempotent.
func (s *Secret) Wipe() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.p == nil {
		return
	}
	C.qv_wipe(unsafe.Pointer(s.p), C.size_t(s.n))
	C.free(unsafe.Pointer(s.p))
	s.p, s.n, s.locked = nil, 0, false
}

// use calls f with the C pointer while holding the read lock.
func (s *Secret) use(f func(p *C.uint8_t, n C.size_t) error) error {
	if s == nil {
		return ErrWiped
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.p == nil {
		return ErrWiped
	}
	return f(s.p, C.size_t(s.n))
}

// WipeBytes zeroes b. The compiler cannot drop it (we call into C).
func WipeBytes(b []byte) {
	if len(b) > 0 {
		C.qv_wipe(unsafe.Pointer(&b[0]), C.size_t(len(b)))
	}
}

// takeSecret wraps a shim output buffer without copying.
func takeSecret(p *C.uint8_t, n C.size_t) *Secret { return newSecret(p, n) }

// takeBytes copies a shim output buffer (public data) into Go memory and frees it.
func takeBytes(p *C.uint8_t, n C.size_t) []byte {
	if p == nil {
		return nil
	}
	b := C.GoBytes(unsafe.Pointer(p), C.int(n))
	C.qv_wipe(unsafe.Pointer(p), n)
	C.free(unsafe.Pointer(p))
	return b
}
