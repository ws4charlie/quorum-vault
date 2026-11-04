package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// Errors a session transport reports to the wrapper (they surface as KindTransport, or KindCryptographic for
// ErrFrameTooLarge/ErrProtocolViolation which are raised by the wrapper / us as peer misbehaviour).
var (
	ErrPeerAborted       = errors.New("peer aborted the session")
	ErrPeerGone          = errors.New("peer closed the session")
	ErrPeerFailed        = errors.New("peer reported a failure")
	ErrProtocolViolation = errors.New("peer violated the session protocol")
)

type frameStream interface {
	Send(*pb.Frame) error
	Recv() (*pb.Frame, error)
}

// sessTransport is a cbmpc.Transport over one gRPC session stream. A pump goroutine reads the stream: DATA frames go to
// Recv, ACK and FIN frames go to their channels, ABORT or a closed stream fail the session and wake blocked calls.
type sessTransport struct {
	sid      string
	st       frameStream
	maxFrame int

	sendMu sync.Mutex
	in     chan []byte
	acks   chan struct{}
	fins   chan *pb.Fin

	done    chan struct{}
	errOnce sync.Once
	err     error

	peerFin atomic.Pointer[pb.Fin] // a failing FIN received from the peer

	stats *frameStats
}

type frameStats struct {
	mu  sync.Mutex
	Max int
}

func (f *frameStats) see(n int) {
	if f == nil {
		return
	}
	f.mu.Lock()
	if n > f.Max {
		f.Max = n
	}
	f.mu.Unlock()
}

func newSessTransport(sid string, st frameStream, maxFrame int, stats *frameStats) *sessTransport {
	t := &sessTransport{sid: sid, st: st, maxFrame: maxFrame, stats: stats,
		in: make(chan []byte, 64), acks: make(chan struct{}, 1), fins: make(chan *pb.Fin, 4), done: make(chan struct{})}
	return t
}

func (t *sessTransport) fail(err error) {
	t.errOnce.Do(func() { t.err = err; close(t.done) })
}

func (t *sessTransport) failure() error {
	select {
	case <-t.done:
		return t.err
	default:
		return nil
	}
}

// pump reads frames until the stream ends. Run it in its own goroutine.
func (t *sessTransport) pump() {
	for {
		f, err := t.st.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = ErrPeerGone
			}
			t.fail(err)
			return
		}
		if f.GetSessionId() != t.sid {
			// Unknown session id: dropped, and the session fails (a peer that mixes ids is broken or hostile).
			t.fail(fmt.Errorf("%w: frame for session %q on session %q", ErrProtocolViolation, f.GetSessionId(), t.sid))
			t.abortPeer("session id mismatch")
			return
		}
		switch f.GetKind() {
		case pb.FrameKind_FRAME_KIND_DATA:
			// Frame size is enforced by the wrapper (WithMaxFrame: cryptographic) and by the gRPC receive limit.
			t.stats.see(len(f.Payload))
			select {
			case t.in <- f.Payload:
			case <-t.done:
				return
			}
		case pb.FrameKind_FRAME_KIND_ACK:
			select {
			case t.acks <- struct{}{}:
			default:
			}
		case pb.FrameKind_FRAME_KIND_FIN:
			var fin pb.Fin
			if err := proto.Unmarshal(f.Payload, &fin); err != nil {
				t.fail(fmt.Errorf("%w: bad FIN: %v", ErrProtocolViolation, err))
				return
			}
			select {
			case t.fins <- &fin:
			default:
				t.fail(fmt.Errorf("%w: too many FIN frames", ErrProtocolViolation))
				return
			}
			if !fin.GetOk() { // the peer gave up: wake anything blocked on this session
				t.peerFin.Store(&fin)
				t.fail(fmt.Errorf("%w: %s", ErrPeerFailed, fin.GetMessage()))
				return
			}
		case pb.FrameKind_FRAME_KIND_ABORT:
			t.fail(fmt.Errorf("%w: %s", ErrPeerAborted, string(f.Payload)))
			return
		default:
			t.fail(fmt.Errorf("%w: unexpected frame kind %v", ErrProtocolViolation, f.GetKind()))
			t.abortPeer("unexpected frame kind")
			return
		}
	}
}

func (t *sessTransport) sendFrame(kind pb.FrameKind, payload []byte) error {
	if err := t.failure(); err != nil {
		return err
	}
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	return t.st.Send(&pb.Frame{SessionId: t.sid, Kind: kind, Payload: payload})
}

func (t *sessTransport) abortPeer(reason string) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	t.st.Send(&pb.Frame{SessionId: t.sid, Kind: pb.FrameKind_FRAME_KIND_ABORT, Payload: []byte(reason)})
}

func (t *sessTransport) sendFin(f *pb.Fin) error {
	b, _ := proto.Marshal(f)
	return t.sendFrame(pb.FrameKind_FRAME_KIND_FIN, b)
}

// Send implements cbmpc.Transport.
func (t *sessTransport) Send(ctx context.Context, msg []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.sendFrame(pb.FrameKind_FRAME_KIND_DATA, msg)
}

// Recv implements cbmpc.Transport. Buffered DATA is delivered before a failure is reported.
func (t *sessTransport) Recv(ctx context.Context) ([]byte, error) {
	select {
	case m := <-t.in:
		return m, nil
	default:
	}
	select {
	case m := <-t.in:
		return m, nil
	case <-t.done:
		select {
		case m := <-t.in:
			return m, nil
		default:
			return nil, t.err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *sessTransport) waitAck(ctx context.Context) error {
	select {
	case <-t.acks:
		return nil
	default:
	}
	select {
	case <-t.acks:
		return nil
	case fin := <-t.fins: // refused or failed before the ACK
		return peerFail("session", fin)
	case <-t.done:
		return t.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *sessTransport) waitFin(ctx context.Context) (*pb.Fin, error) {
	select {
	case f := <-t.fins:
		return f, nil
	default:
	}
	select {
	case f := <-t.fins:
		return f, nil
	case <-t.done:
		select {
		case f := <-t.fins:
			return f, nil
		default:
			return nil, t.err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ cbmpc.Transport = (*sessTransport)(nil)
