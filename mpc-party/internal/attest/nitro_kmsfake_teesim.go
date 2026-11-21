//go:build teesim

package attest

import "time"

// AuthenticateOnly checks a document the way AWS KMS does when it receives one as Recipient: envelope, chain to the configured root, signature, freshness,
// debug mode, and nothing about a nonce or user_data (KMS checks neither). It exists only in simulation builds, for the fake KMS (attest/kmsrelease/kmsfake);
// the party and the broker use Verify, which also binds the document to a request.
func (v *NitroVerifier) AuthenticateOnly(evidence []byte, now time.Time) (*Claims, error) {
	return v.authenticate(evidence, now)
}
