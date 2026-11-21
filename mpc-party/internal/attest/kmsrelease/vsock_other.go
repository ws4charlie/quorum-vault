//go:build !linux

package kmsrelease

import (
	"context"
	"errors"
	"net"
)

// ParentCID is the vsock address of the parent instance as seen from an enclave.
const ParentCID = 3

// VsockDialer exists only on Linux.
func VsockDialer(cid, port uint32) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("kmsrelease: vsock exists only on Linux")
	}
}
