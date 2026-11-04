package e2e

import (
	"io"
	"net"
	"sync"
	"testing"
)

// tcpProxy forwards raw TCP (TLS stays end to end between A and B) and can cut every connection.
type tcpProxy struct {
	addr   string
	target string
	ln     net.Listener
	mu     sync.Mutex
	conns  []net.Conn
	cut    bool
}

func newTCPProxy(t *testing.T, target string) *tcpProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &tcpProxy{addr: ln.Addr().String(), target: target, ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			cut := p.cut
			p.mu.Unlock()
			if cut {
				c.Close()
				continue
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { io.Copy(up, c); up.Close() }()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close(); p.drop() })
	return p
}

// drop closes every open connection (the listener keeps accepting unless Cut was called).
func (p *tcpProxy) drop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

// Cut drops all connections and refuses new ones until Heal.
func (p *tcpProxy) Cut()  { p.mu.Lock(); p.cut = true; p.mu.Unlock(); p.drop() }
func (p *tcpProxy) Heal() { p.mu.Lock(); p.cut = false; p.mu.Unlock() }
