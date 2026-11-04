package cbmpc

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"
)

// Transport carries the opaque protocol messages of ONE protocol session between the two parties, in order.
//
// Contract:
//   - Send and Recv block, and MUST return promptly with an error once ctx is done or the link fails. The library
//     also stops waiting on its own when ctx is done (see below), but a Transport that ignores ctx leaks one
//     goroutine per call until the underlying call returns.
//   - Messages are delivered whole and in order, exactly once. Authentication and encryption of the link (mTLS) are the
//     Transport's job: cb-mpc does not authenticate the peer.
//   - A Transport is used by one protocol call at a time (Send and Recv may run concurrently with each other).
//   - Recv should return an error wrapping io.EOF or similar when the peer closes or aborts the session.
type Transport interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
}

// Option tunes one protocol call.
type Option func(*options)

type options struct {
	maxFrame    int
	recvTimeout time.Duration
}

// DefaultMaxFrame is the largest peer message accepted. Real messages are below 100 KB (DKG with Paillier proofs is the
// largest); the library itself caps blobs at 1 MiB.
const DefaultMaxFrame = 4 << 20

// WithMaxFrame sets the largest accepted peer message; a bigger one fails the call with KindCryptographic.
func WithMaxFrame(n int) Option { return func(o *options) { o.maxFrame = n } }

// WithRecvTimeout bounds the wait for each single message from the peer (0 = only ctx bounds it).
// A timeout fails the call with KindTransport.
func WithRecvTimeout(d time.Duration) Option { return func(o *options) { o.recvTimeout = d } }

func newOptions(opts []Option) options {
	o := options{maxFrame: DefaultMaxFrame}
	for _, f := range opts {
		f(&o)
	}
	if o.maxFrame <= 0 || o.maxFrame > 64<<20 {
		o.maxFrame = DefaultMaxFrame
	}
	return o
}

// ErrFrameTooLarge: the peer sent a message above the limit.
var ErrFrameTooLarge = errors.New("peer message exceeds the frame limit")

// ErrRecvTimeout: no message from the peer within the receive timeout.
var ErrRecvTimeout = errors.New("timeout waiting for peer message")

// session is the Go side of one protocol run. The C++ code calls back into it from the cgo thread.
type session struct {
	ctx  context.Context
	tr   Transport
	opts options

	mu    sync.Mutex
	kind  Kind
	cause error
}

func (s *session) setFailure(k Kind, err error) {
	s.mu.Lock()
	if s.cause == nil {
		s.kind, s.cause = k, err
	}
	s.mu.Unlock()
}

func (s *session) failure() (Kind, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kind, s.cause
}

type result struct {
	b   []byte
	err error
}

// guard runs f and returns when it finishes or ctx is done, whichever is first, so a Transport that ignores ctx
// cannot pin the protocol thread.
func guard(ctx context.Context, f func(context.Context) result) result {
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: fmt.Errorf("transport panic: %v", r)}
			}
		}()
		ch <- f(ctx)
	}()
	select {
	case r := <-ch:
		return r
	case <-ctx.Done():
		return result{err: ctxErr(ctx)}
	}
}

func (s *session) send(msg []byte) error {
	if err := s.ctx.Err(); err != nil {
		s.setFailure(KindTransport, ctxErr(s.ctx))
		return err
	}
	r := guard(s.ctx, func(ctx context.Context) result { return result{err: s.tr.Send(ctx, msg)} })
	if r.err != nil {
		s.setFailure(KindTransport, r.err)
	}
	return r.err
}

func (s *session) recv() ([]byte, error) {
	if err := s.ctx.Err(); err != nil {
		s.setFailure(KindTransport, ctxErr(s.ctx))
		return nil, err
	}
	ctx := s.ctx
	var timedOut func() bool
	if s.opts.recvTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(s.ctx, s.opts.recvTimeout, ErrRecvTimeout)
		defer cancel()
		timedOut = func() bool { return errors.Is(context.Cause(ctx), ErrRecvTimeout) }
	}
	r := guard(ctx, func(c context.Context) result {
		b, err := s.tr.Recv(c)
		return result{b, err}
	})
	if r.err != nil {
		if timedOut != nil && timedOut() && s.ctx.Err() == nil {
			r.err = ErrRecvTimeout
		}
		s.setFailure(KindTransport, r.err)
		return nil, r.err
	}
	if len(r.b) > s.opts.maxFrame {
		err := fmt.Errorf("%w: %d > %d bytes", ErrFrameTooLarge, len(r.b), s.opts.maxFrame)
		s.setFailure(KindCryptographic, err)
		return nil, err
	}
	return r.b, nil
}

func sessionOf(h C.uintptr_t) *session { return cgo.Handle(h).Value().(*session) }

//export qv_go_send
func qv_go_send(h C.uintptr_t, msg unsafe.Pointer, n C.size_t) (rv C.int) {
	s := sessionOf(h)
	defer func() {
		if r := recover(); r != nil { // a Go panic must not unwind through C++ frames
			s.setFailure(KindInternal, fmt.Errorf("panic in send: %v", r))
			rv = 1
		}
	}()
	if err := s.send(C.GoBytes(msg, C.int(n))); err != nil {
		return 1
	}
	return 0
}

//export qv_go_recv
func qv_go_recv(h C.uintptr_t, out *unsafe.Pointer, outn *C.size_t) (rv C.int) {
	s := sessionOf(h)
	defer func() {
		if r := recover(); r != nil {
			s.setFailure(KindInternal, fmt.Errorf("panic in recv: %v", r))
			rv = 1
		}
	}()
	b, err := s.recv()
	if err != nil {
		return 1
	}
	p := C.malloc(C.size_t(len(b)) + 1)
	if p == nil {
		s.setFailure(KindInternal, errors.New("malloc failed"))
		return 1
	}
	if len(b) > 0 {
		C.memcpy(p, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	}
	*out = p
	*outn = C.size_t(len(b))
	return 0
}
