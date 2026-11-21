//go:build linux

package kmsrelease

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The vsock dialer against the kernel's local vsock loopback (CID 1, needs the vsock_loopback module). Where the kernel has no vsock (a CI container, a
// laptop VM) the test says so and ends; on the Nitro host the same dialer is checked by step "vsock" of docs/runbooks/nitro-first-run.md.
func TestVsockDialerLoopback(t *testing.T) {
	lfd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no AF_VSOCK in this kernel: %v", err)
	}
	defer unix.Close(lfd)
	if err := unix.Bind(lfd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 47123}); err != nil {
		t.Skipf("cannot bind a vsock port: %v", err)
	}
	if err := unix.Listen(lfd, 1); err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	conn, err := VsockDialer(unix.VMADDR_CID_LOCAL, 47123)(context.Background(), "tcp", "ignored.example:443")
	if err != nil {
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EADDRNOTAVAIL) {
			t.Skipf("no vsock loopback transport: %v", err)
		}
		t.Fatal(err)
	}
	defer conn.Close()
	nfd, _, err := unix.Accept(lfd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(nfd)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if n, err := unix.Read(nfd, buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("server read %q %v", buf, err)
	}
	if _, err := unix.Write(nfd, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("client read %q %v", buf, err)
	}
	// a deadline in the past makes a read fail at once: the dialer's connections honour deadlines (net/http needs them)
	_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("read past its deadline returned data")
	}
}
