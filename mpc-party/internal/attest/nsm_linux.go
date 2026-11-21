//go:build linux

package attest

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctl request _IOWR(0x0A, 0, sizeof(struct nsm_message)): direction read|write (3) in bits 30-31, size 32 (two iovecs of 16 bytes) in bits 16-29, type
// 0x0A in bits 8-15, number 0. The layout is the same on amd64 and arm64, the two architectures of Nitro instances. [NSM-API] driver/mod.rs.
const nsmIoctl = 3<<30 | 32<<16 | 0x0A<<8 | 0

const nsmDevicePath = "/dev/nsm"

type nsmFile struct{ f *os.File }

func openNSMDevice() (NSMDevice, error) {
	f, err := os.OpenFile(nsmDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("attest: cannot open %s (this process does not run inside a Nitro enclave): %w", nsmDevicePath, err)
	}
	return &nsmFile{f: f}, nil
}

func (d *nsmFile) Exchange(request []byte) ([]byte, error) {
	if len(request) == 0 || len(request) > nsmRequestMax {
		return nil, fmt.Errorf("request of %d bytes", len(request))
	}
	resp := make([]byte, nsmResponseMax)
	msg := struct{ req, resp unix.Iovec }{}
	msg.req.Base, msg.resp.Base = &request[0], &resp[0]
	msg.req.SetLen(len(request))
	msg.resp.SetLen(len(resp))
	rc, err := d.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var errno unix.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, nsmIoctl, uintptr(unsafe.Pointer(&msg)))
	}); err != nil {
		return nil, err
	}
	if errno != 0 {
		return nil, fmt.Errorf("ioctl: %w", errno) // EMSGSIZE: request too large
	}
	n := int(msg.resp.Len) // the driver writes the length of what it returned back into the iovec
	if n < 0 || n > len(resp) {
		return nil, fmt.Errorf("the driver returned %d bytes for a buffer of %d", n, len(resp))
	}
	return resp[:n], nil
}

func (d *nsmFile) Close() error { return d.f.Close() }
