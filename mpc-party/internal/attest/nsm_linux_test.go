//go:build linux

package attest

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The ioctl number and the message size are the contract with the kernel driver (aws-nitro-enclaves-nsm-api, driver/mod.rs: request_code_readwrite!(0x0A, 0,
// size_of::<NsmMessage>())). The value is the well-known 0xC0200A00.
func TestNSMIoctlContract(t *testing.T) {
	if nsmIoctl != 0xC0200A00 {
		t.Fatalf("ioctl number %#x", uint32(nsmIoctl))
	}
	var msg struct{ req, resp unix.Iovec }
	if unsafe.Sizeof(msg) != 32 {
		t.Fatalf("nsm_message is %d bytes, the driver expects 32", unsafe.Sizeof(msg))
	}
}

func TestOpenNSMFailsOutsideAnEnclave(t *testing.T) {
	a, err := OpenNSM()
	if err == nil { // only a machine that really has /dev/nsm gets here; nothing else to prove then
		_ = a.Close()
		return
	}
	if a != nil {
		t.Fatal("an attester came back with an error")
	}
}
