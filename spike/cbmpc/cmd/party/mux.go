package main

// Mux: many concurrent protocol sessions over ONE TCP connection between the two parties.
// Frame: u32 len | u32 session | u8 kind | payload. This stands in for gRPC streams + mTLS.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"qvspike/cbmpc/cbmpc"
)

const (
	kData  = 0
	kOpen  = 1
	kAbort = 2
	kFin   = 3
)

var ErrPeerGone = errors.New("peer connection lost")
var ErrTimeout = errors.New("protocol receive timeout")

type frame struct {
	sid     uint32
	kind    byte
	payload []byte
	due     time.Time
}

type Mux struct {
	conn      net.Conn
	role      int // 0 = p1, 1 = p2
	delay     time.Duration // one-way delay injected on every frame we send
	recvTO    time.Duration
	mu        sync.Mutex
	sessions  map[uint32]*Session
	nextSid   uint32
	out       chan frame
	onOpen    func(*Session, []byte) // p2 side: new session requested by peer
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	TxBytes, TxFrames, RxBytes, RxFrames atomic.Int64
}

func NewMux(c net.Conn, role int, delay, recvTO time.Duration, onOpen func(*Session, []byte)) *Mux {
	m := &Mux{conn: c, role: role, delay: delay, recvTO: recvTO, sessions: map[uint32]*Session{},
		out: make(chan frame, 4096), onOpen: onOpen, done: make(chan struct{})}
	go m.writer()
	go m.reader()
	return m
}

func (m *Mux) writer() {
	for {
		select {
		case f := <-m.out:
			if d := time.Until(f.due); d > 0 {
				time.Sleep(d)
			}
			hdr := make([]byte, 9)
			binary.BigEndian.PutUint32(hdr[0:], uint32(len(f.payload)+5))
			binary.BigEndian.PutUint32(hdr[4:], f.sid)
			hdr[8] = f.kind
			if f.kind == kData {
				m.TxBytes.Add(int64(len(f.payload)))
				m.TxFrames.Add(1)
			}
			if _, err := m.conn.Write(append(hdr, f.payload...)); err != nil {
				m.fail(err)
				return
			}
		case <-m.done:
			return
		}
	}
}

func (m *Mux) reader() {
	for {
		var lb [4]byte
		if _, err := io.ReadFull(m.conn, lb[:]); err != nil {
			m.fail(err)
			return
		}
		n := binary.BigEndian.Uint32(lb[:])
		if n < 5 || n > 64<<20 {
			m.fail(fmt.Errorf("bad frame length %d", n))
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(m.conn, b); err != nil {
			m.fail(err)
			return
		}
		sid, kind, payload := binary.BigEndian.Uint32(b[0:]), b[4], b[5:]
		switch kind {
		case kOpen:
			s := m.newSession(sid)
			go m.onOpen(s, payload)
		case kData:
			m.RxBytes.Add(int64(len(payload)))
			m.RxFrames.Add(1)
			if s := m.get(sid); s != nil {
				s.in <- payload
			}
		case kFin:
			if s := m.get(sid); s != nil {
				s.fin <- string(payload)
			}
		case kAbort:
			if s := m.get(sid); s != nil {
				s.abort(fmt.Errorf("peer aborted session: %s", payload))
			}
		}
	}
}

func (m *Mux) fail(err error) {
	m.closeOnce.Do(func() {
		m.closeErr = err
		close(m.done)
		m.conn.Close()
		m.mu.Lock()
		for _, s := range m.sessions {
			s.abort(ErrPeerGone)
		}
		m.mu.Unlock()
	})
}

func (m *Mux) Close()                { m.fail(io.EOF) }
func (m *Mux) Done() <-chan struct{} { return m.done }

func (m *Mux) get(sid uint32) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[sid]
}

func (m *Mux) newSession(sid uint32) *Session {
	s := &Session{m: m, id: sid, in: make(chan []byte, 256), fin: make(chan string, 1), dead: make(chan struct{})}
	m.mu.Lock()
	m.sessions[sid] = s
	m.mu.Unlock()
	return s
}

// Open starts a session on both sides; the peer's onOpen runs with payload.
func (m *Mux) Open(payload []byte) (*Session, error) {
	select {
	case <-m.done:
		return nil, ErrPeerGone
	default:
	}
	m.mu.Lock()
	m.nextSid++
	sid := m.nextSid*2 + uint32(m.role) // distinct id space per side
	m.mu.Unlock()
	s := m.newSession(sid)
	m.out <- frame{sid: sid, kind: kOpen, payload: payload, due: time.Now().Add(m.delay)}
	return s, nil
}

type Session struct {
	m        *Mux
	id       uint32
	in       chan []byte
	fin      chan string
	dead     chan struct{}
	deadOnce sync.Once
	deadErr  error
}

func (s *Session) abort(err error) {
	s.deadOnce.Do(func() { s.deadErr = err; close(s.dead) })
}

// Close ends the session; if err != nil the peer is told so its blocked Recv returns.
func (s *Session) Close(err error) {
	if err != nil {
		select {
		case s.m.out <- frame{sid: s.id, kind: kAbort, payload: []byte(err.Error()), due: time.Now()}:
		default:
		}
	}
	s.abort(io.EOF)
	s.m.mu.Lock()
	delete(s.m.sessions, s.id)
	s.m.mu.Unlock()
}

func (s *Session) Send(_ int, msg []byte) error {
	select {
	case <-s.dead:
		return s.deadErr
	default:
	}
	s.m.out <- frame{sid: s.id, kind: kData, payload: append([]byte(nil), msg...), due: time.Now().Add(s.m.delay)}
	return nil
}

func (s *Session) Recv(_ int) ([]byte, error) {
	var to <-chan time.Time
	if s.m.recvTO > 0 {
		t := time.NewTimer(s.m.recvTO)
		defer t.Stop()
		to = t.C
	}
	select {
	case b := <-s.in:
		return b, nil
	case <-s.dead:
		return nil, s.deadErr
	case <-to:
		return nil, ErrTimeout
	}
}

var _ cbmpc.Transport = (*Session)(nil)

// SendFin tells the peer this side finished its part (status "" = ok).
func (s *Session) SendFin(status string) {
	s.m.out <- frame{sid: s.id, kind: kFin, payload: []byte(status), due: time.Now().Add(s.m.delay)}
}

// WaitFin waits for the peer's completion status.
func (s *Session) WaitFin() error {
	var to <-chan time.Time
	if s.m.recvTO > 0 {
		t := time.NewTimer(s.m.recvTO)
		defer t.Stop()
		to = t.C
	}
	select {
	case st := <-s.fin:
		if st != "" {
			return fmt.Errorf("peer failed: %s", st)
		}
		return nil
	case <-s.dead:
		return s.deadErr
	case <-to:
		return ErrTimeout
	}
}
