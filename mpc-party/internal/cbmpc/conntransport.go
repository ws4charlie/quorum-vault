package cbmpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ErrBadFrame: a frame header is invalid (length above the limit).
var ErrBadFrame = errors.New("bad frame")

// ReadFrame reads one length-prefixed frame (u32 big-endian length, then payload) and rejects lengths above max
// before allocating. Fuzzed.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if uint64(n) > uint64(max) {
		return nil, fmt.Errorf("%w: length %d exceeds %d", ErrBadFrame, n, max)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, msg []byte) error {
	buf := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(buf, uint32(len(msg)))
	copy(buf[4:], msg)
	_, err := w.Write(buf)
	return err
}

// ConnTransport is a Transport over one stream connection (one protocol session per connection). Production wraps
// this in mTLS or uses gRPC streams (P5b-2); this is the plain building block and the test transport between two OS
// processes. Context cancellation interrupts blocked reads and writes by setting a deadline in the past.
type ConnTransport struct {
	conn     net.Conn
	maxFrame int
	rmu, wmu sync.Mutex
}

func NewConnTransport(c net.Conn, maxFrame int) *ConnTransport {
	if maxFrame <= 0 {
		maxFrame = DefaultMaxFrame
	}
	return &ConnTransport{conn: c, maxFrame: maxFrame}
}

func (t *ConnTransport) Close() error { return t.conn.Close() }

func (t *ConnTransport) Send(ctx context.Context, msg []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	stop := context.AfterFunc(ctx, func() { t.conn.SetWriteDeadline(time.Unix(1, 0)) })
	defer func() { stop(); t.conn.SetWriteDeadline(time.Time{}) }()
	err := WriteFrame(t.conn, msg)
	if err != nil && ctx.Err() != nil {
		return ctxErr(ctx)
	}
	return err
}

func (t *ConnTransport) Recv(ctx context.Context) ([]byte, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	stop := context.AfterFunc(ctx, func() { t.conn.SetReadDeadline(time.Unix(1, 0)) })
	defer func() { stop(); t.conn.SetReadDeadline(time.Time{}) }()
	b, err := ReadFrame(t.conn, t.maxFrame)
	if err != nil && ctx.Err() != nil {
		return nil, ctxErr(ctx)
	}
	return b, err
}

var _ Transport = (*ConnTransport)(nil)
