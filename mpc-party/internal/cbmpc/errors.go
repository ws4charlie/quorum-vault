package cbmpc

import (
	"context"
	"errors"
	"fmt"
)

// Kind classifies a failure so that the caller (P5b-3) can choose between retry and freeze.
type Kind int

const (
	// KindTransport: the peer or the link failed or was cancelled (connection lost, timeout, context cancelled,
	// peer aborted the session). No key material is suspect. Retry with a fresh session and backoff.
	KindTransport Kind = iota + 1
	// KindCryptographic: the protocol ran and a check failed: a proof did not verify, a message could not be parsed,
	// a frame broke the size limit, a final signature did not verify. Treat the peer (or the stored share) as
	// possibly malicious or corrupted: do not retry automatically more than once, freeze the keyset, page a human.
	KindCryptographic
	// KindInternal: this process misbehaved or was misused: C++ exception or assertion caught at the boundary,
	// allocation failure, invalid argument, unsupported blob layout, use of a wiped secret. Not a peer fault.
	// Do not retry blindly; alert. (A C++ assertion or exception during a PROTOCOL call is classified as
	// cryptographic instead, because hostile peer messages can provoke it; outside a protocol call it is internal.)
	KindInternal
)

func (k Kind) String() string {
	switch k {
	case KindTransport:
		return "transport"
	case KindCryptographic:
		return "cryptographic"
	case KindInternal:
		return "internal"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// Error is returned by every operation of this package on failure.
type Error struct {
	Kind Kind
	Op   string // "hd.dkg", "ecdsa.sign", ...
	Code uint32 // cb-mpc / shim error code, 0 if the failure was detected in Go
	Err  error  // underlying cause, if any (transport error, context error, ...)
	Msg  string
}

func (e *Error) Error() string {
	s := fmt.Sprintf("cbmpc %s: %s error", e.Op, e.Kind)
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	if e.Code != 0 {
		s += fmt.Sprintf(" (code 0x%08x)", e.Code)
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Shim codes, see shim.h.
const (
	CodeTransport   uint32 = 0xff030001
	CodeException   uint32 = 0xff0b0001
	CodeAssert      uint32 = 0xff0b0002
	CodeBadAlloc    uint32 = 0xff0b0003
	CodeLayout      uint32 = 0xff0b0004
	CodeUnsupported uint32 = 0xff0b0005
)

const (
	catGeneric = 0x01
	catNetwork = 0x03
	catCrypto  = 0x04
	catOpenSSL = 0x06
)

// ErrWiped is returned when a Secret was already wiped. It has KindInternal.
var ErrWiped = &Error{Kind: KindInternal, Op: "secret", Msg: "secret already wiped"}

// ErrInvalidArgument is wrapped by KindInternal errors for caller mistakes detected before any C++ call.
var ErrInvalidArgument = errors.New("invalid argument")

func badArg(op, format string, a ...any) error {
	return &Error{Kind: KindInternal, Op: op, Msg: fmt.Sprintf(format, a...), Err: ErrInvalidArgument}
}

// KindOf returns the classification of err, or 0 if err is not (or does not wrap) an *Error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

func IsTransport(err error) bool     { return KindOf(err) == KindTransport }
func IsCryptographic(err error) bool { return KindOf(err) == KindCryptographic }
func IsInternal(err error) bool      { return KindOf(err) == KindInternal }

// classify turns a non-zero code returned by the shim into an *Error. protocol is true for operations that talk to
// the peer. s is the Go-side session (may be nil for local operations).
func classify(op string, rv uint32, s *session, protocol bool) error {
	e := &Error{Op: op, Code: rv}
	if s != nil {
		if k, cause := s.failure(); cause != nil {
			e.Kind, e.Err = k, cause
			return e
		}
	}
	cat := (rv >> 16) & 0xff
	switch {
	case protocol && (rv == CodeAssert || rv == CodeException):
		// cb-mpc asserts on some malformed peer messages (found by the malicious-peer test: a flipped byte in a peer
		// message reaches cb_assert). While a protocol runs we cannot tell that from an internal bug, so fail closed:
		// treat it like any other failed check on the peer's data.
		e.Kind = KindCryptographic
	case rv == CodeAssert || rv == CodeException || rv == CodeBadAlloc || rv == CodeLayout || rv == CodeUnsupported:
		e.Kind = KindInternal
	case cat == catNetwork:
		e.Kind = KindTransport
	case cat == catCrypto:
		e.Kind = KindCryptographic
	case protocol:
		// Parse errors, range errors, proof failures raised while processing the peer's messages.
		e.Kind = KindCryptographic
	default:
		// Local operations on caller-supplied blobs: malformed input is our problem, not a peer's.
		e.Kind = KindInternal
	}
	switch rv {
	case CodeAssert:
		e.Msg = "cb-mpc assertion failed (exception caught at the C boundary)"
	case CodeException:
		e.Msg = "C++ exception caught at the C boundary"
	case CodeBadAlloc:
		e.Msg = "out of memory"
	case CodeLayout:
		e.Msg = "blob does not match the layout this wrapper expects; see README upgrade procedure"
	case CodeUnsupported:
		e.Msg = "unsupported"
	}
	return e
}

func ctxErr(ctx context.Context) error { return context.Cause(ctx) }
