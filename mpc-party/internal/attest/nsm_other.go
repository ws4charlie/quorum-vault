//go:build !linux

package attest

import "errors"

func openNSMDevice() (NSMDevice, error) {
	return nil, errors.New("attest: the Nitro Secure Module exists only inside a Linux enclave")
}
