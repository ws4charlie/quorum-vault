package server

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// Fail is the service's own error: a kind (what the caller should do) plus a gRPC code.
type Fail struct {
	Kind pb.ErrorKind
	Code codes.Code
	Op   string
	CB   uint32 // cb-mpc / shim code
	Msg  string
	Peer bool // reported by the other party
	Err  error
}

func (f *Fail) Error() string {
	s := fmt.Sprintf("%s: %s", f.Kind, f.Msg)
	if f.Peer {
		s += " (reported by peer)"
	}
	if f.Err != nil {
		s += ": " + f.Err.Error()
	}
	return s
}
func (f *Fail) Unwrap() error { return f.Err }

func failf(kind pb.ErrorKind, c codes.Code, op, format string, a ...any) *Fail {
	return &Fail{Kind: kind, Code: c, Op: op, Msg: fmt.Sprintf(format, a...)}
}

func invalid(op, format string, a ...any) *Fail {
	return failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.InvalidArgument, op, format, a...)
}

func limitFail(op, format string, a ...any) *Fail {
	f := failf(pb.ErrorKind_ERROR_KIND_LIMIT, codes.ResourceExhausted, op, format, a...)
	f.Err = ErrLimit
	return f
}

// fromWrapper converts an internal/cbmpc error into a Fail with the wrapper's kind.
func fromWrapper(op string, err error) *Fail {
	if err == nil {
		return nil
	}
	var f *Fail
	if errors.As(err, &f) {
		return f
	}
	f = &Fail{Op: op, Msg: err.Error(), Err: err}
	var e *cbmpc.Error
	if errors.As(err, &e) {
		f.CB = e.Code
	}
	var te *transportErr
	switch {
	case errors.As(err, &te):
		f.Kind, f.Code = pb.ErrorKind_ERROR_KIND_TRANSPORT, codes.Unavailable
		if errors.Is(err, context.DeadlineExceeded) {
			f.Code = codes.DeadlineExceeded
		}
	case errors.Is(err, context.DeadlineExceeded) && cbmpc.KindOf(err) == 0:
		f.Kind, f.Code = pb.ErrorKind_ERROR_KIND_TRANSPORT, codes.DeadlineExceeded
	case cbmpc.IsTransport(err):
		f.Kind, f.Code = pb.ErrorKind_ERROR_KIND_TRANSPORT, codes.Unavailable
		if errors.Is(err, context.DeadlineExceeded) {
			f.Code = codes.DeadlineExceeded
		}
	case cbmpc.IsCryptographic(err):
		f.Kind, f.Code = pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted
	default:
		f.Kind, f.Code = pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal
	}
	return f
}

// severity orders kinds when both parties report a failure: the worse one wins.
func severity(k pb.ErrorKind) int {
	switch k {
	case pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC:
		return 5
	case pb.ErrorKind_ERROR_KIND_REFUSED:
		return 4
	case pb.ErrorKind_ERROR_KIND_FROZEN:
		return 6
	case pb.ErrorKind_ERROR_KIND_UNAVAILABLE:
		return 1
	case pb.ErrorKind_ERROR_KIND_LIMIT:
		return 3
	case pb.ErrorKind_ERROR_KIND_INTERNAL:
		return 2
	case pb.ErrorKind_ERROR_KIND_TRANSPORT:
		return 1
	}
	return 0
}

// peerFail turns a failing FIN from the peer into a Fail.
func peerFail(op string, fin *pb.Fin) *Fail {
	f := &Fail{Kind: fin.GetKind(), Op: op, CB: fin.GetCode(), Msg: fin.GetMessage(), Peer: true}
	switch f.Kind {
	case pb.ErrorKind_ERROR_KIND_TRANSPORT:
		f.Code = codes.Unavailable
	case pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC:
		f.Code = codes.Aborted
	case pb.ErrorKind_ERROR_KIND_REFUSED:
		f.Code = codes.PermissionDenied
	case pb.ErrorKind_ERROR_KIND_FROZEN:
		f.Code = codes.FailedPrecondition
	case pb.ErrorKind_ERROR_KIND_UNAVAILABLE:
		f.Code = codes.Unavailable
	case pb.ErrorKind_ERROR_KIND_LIMIT:
		f.Code = codes.ResourceExhausted
		f.Err = ErrLimit
	default:
		f.Kind, f.Code = pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal
	}
	return f
}

// toStatus renders any error as a gRPC status carrying an ErrorDetail.
func toStatus(op string, err error) error {
	if err == nil {
		return nil
	}
	var f0 *Fail
	if !errors.As(err, &f0) {
		if s, ok := status.FromError(err); ok && s.Code() != codes.Unknown {
			return err // already a typed gRPC status
		}
	}
	var f *Fail
	if !errors.As(err, &f) {
		f = fromWrapper(op, err)
	}
	if f.Op == "" {
		f.Op = op
	}
	st := status.New(f.Code, f.Error())
	if d, derr := st.WithDetails(&pb.ErrorDetail{Kind: f.Kind, Op: f.Op, Code: f.CB, Message: f.Msg, Peer: f.Peer}); derr == nil {
		st = d
	}
	return st.Err()
}

// KindOfStatus extracts the typed kind from an error returned by a gRPC call to this service.
func KindOfStatus(err error) (pb.ErrorKind, bool) {
	st, ok := status.FromError(err)
	if !ok {
		return 0, false
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*pb.ErrorDetail); ok {
			return ed.Kind, true
		}
	}
	return 0, false
}

func frozenFail(op, keyset, reason string) *Fail {
	return failf(pb.ErrorKind_ERROR_KIND_FROZEN, codes.FailedPrecondition, op, "keyset %q is frozen (%s); unfreezing needs an operator signature", keyset, reason)
}
