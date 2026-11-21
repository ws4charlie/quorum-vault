//go:build linux

package kmsrelease

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ParentCID is the vsock address of the parent instance as seen from an enclave. [AWS-DOC] https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
// ("Vsock socket"); vsock-proxy README: the enclave connects to CID 3 on the port the proxy listens on.
const ParentCID = 3

// VsockDialer returns a dialer that ignores the address it is given and connects to (cid, port) over AF_VSOCK. The address in a request (the KMS host
// name) stays what TLS checks the certificate against, so the parent's proxy forwards bytes and cannot present another server.
func VsockDialer(cid, port uint32) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("vsock socket: %w", err)
		}
		tv := unix.NsecToTimeval(int64(10 * time.Second))
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv) // bounds the blocking connect
		if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("vsock connect cid %d port %d: %w", cid, port, err)
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		f := os.NewFile(uintptr(fd), "vsock")
		if f == nil {
			return nil, errors.New("vsock: bad descriptor")
		}
		return &vsockConn{f: f, remote: vsockAddr{cid, port}}, nil
	}
}

type vsockAddr struct{ cid, port uint32 }

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

type vsockConn struct {
	f      *os.File
	remote vsockAddr
}

func (c *vsockConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *vsockConn) Close() error                       { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr                { return vsockAddr{} }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.remote }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }
