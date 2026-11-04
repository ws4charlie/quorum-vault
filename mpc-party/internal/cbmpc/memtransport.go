package cbmpc

import (
	"context"
	"errors"
	"io"
	"sync"
)

// ErrClosed: the in-memory link was closed or aborted by the other end.
var ErrClosed = errors.New("transport closed")

// NewMemPair returns two connected in-memory Transports, one per party. Each direction buffers up to 64 messages.
// Close on either end makes both ends' blocked and future calls fail with ErrClosed.
func NewMemPair() (a, b *MemTransport) {
	l := &memLink{done: make(chan struct{})}
	ab, ba := make(chan []byte, 64), make(chan []byte, 64)
	return &MemTransport{l: l, out: ab, in: ba}, &MemTransport{l: l, out: ba, in: ab}
}

type memLink struct {
	once sync.Once
	done chan struct{}
}

// MemTransport is an in-memory Transport for tests and for in-process parties.
type MemTransport struct {
	l   *memLink
	out chan<- []byte
	in  <-chan []byte
	// Tap, if set, sees every message this end sends and may replace it (used by malicious-peer tests).
	// It is called from the sending goroutine.
	Tap func(n int, msg []byte) []byte
	mu  sync.Mutex
	n   int
}

func (t *MemTransport) Close() { t.l.once.Do(func() { close(t.l.done) }) }

func (t *MemTransport) Send(ctx context.Context, msg []byte) error {
	msg = append([]byte(nil), msg...)
	if t.Tap != nil {
		t.mu.Lock()
		n := t.n
		t.n++
		t.mu.Unlock()
		msg = t.Tap(n, msg)
	}
	select {
	case <-t.l.done:
		return ErrClosed
	default:
	}
	select {
	case t.out <- msg:
		return nil
	case <-t.l.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *MemTransport) Recv(ctx context.Context) ([]byte, error) {
	select {
	case m := <-t.in:
		return m, nil
	case <-t.l.done:
		// drain what the peer sent before closing
		select {
		case m := <-t.in:
			return m, nil
		default:
			return nil, ErrClosed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ Transport = (*MemTransport)(nil)
var _ = io.EOF
