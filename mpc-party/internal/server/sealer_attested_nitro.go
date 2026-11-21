//go:build linux

package server

import "github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"

// The Nitro attester: evidence from the Nitro Secure Module of the enclave this process runs in (/dev/nsm). It is in the production build on purpose: the
// image an EIF is made from is the released image, byte for byte, and nothing here is reachable unless the config says attester.type "nitro". Outside an
// enclave /dev/nsm does not exist and the party refuses to start; it never falls back to another attester. The mock attester is not in this build.
func init() {
	attesterFactories["nitro"] = func(AttesterConfig) (attest.Attester, error) { return attest.OpenNSM() }
}
