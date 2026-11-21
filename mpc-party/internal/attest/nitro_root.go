package attest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The AWS Nitro Enclaves root of trust, "AWS_NitroEnclaves_Root-G1" (subject CN=aws.nitro-enclaves, valid 2019-10-28 to 2049-10-28).
//
// [AWS-DOC] https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html (read 2026-11-20): the root is downloaded from
// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip and "can be verified using the following fingerprint", SHA-256:
// 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
//
// The certificate is public trust data, like the system CA bundle: it is compiled into the party (so a host cannot swap it: the binary is inside the
// measured image) as DER text, and it is accepted only if its SHA-256 equals the pinned fingerprint. The fingerprint is the pin; the bytes are a convenience.
// The same certificate, compared by content, is cabundle[0] of every real document (TestRealDocumentChain).
const (
	// NitroRootG1Fingerprint is the SHA-256 of the DER of AWS_NitroEnclaves_Root-G1, lower-case hex, from [AWS-DOC].
	NitroRootG1Fingerprint = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

	nitroRootG1DER = "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y="
)

// NitroRootG1 returns the AWS Nitro root certificate after checking its fingerprint against the pin. Production configuration uses it as the
// only trust root of the NitroVerifier.
func NitroRootG1() (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(nitroRootG1DER)
	if err != nil {
		return nil, fmt.Errorf("attest: embedded Nitro root: %w", err)
	}
	if err := CheckFingerprint(der, NitroRootG1Fingerprint); err != nil {
		return nil, fmt.Errorf("attest: embedded Nitro root: %w", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("attest: embedded Nitro root: %w", err)
	}
	if !c.IsCA || c.CheckSignatureFrom(c) != nil {
		return nil, errors.New("attest: embedded Nitro root is not a self-signed CA certificate")
	}
	return c, nil
}

// CheckFingerprint checks that SHA-256(der) equals want (hex, any case, colons allowed as AWS prints them).
func CheckFingerprint(der []byte, want string) error {
	w, err := hex.DecodeString(strings.ReplaceAll(want, ":", ""))
	if err != nil || len(w) != sha256.Size {
		return errors.New("fingerprint is not 32 hex bytes")
	}
	got := sha256.Sum256(der)
	if !ctEqual(got[:], w) {
		return fmt.Errorf("fingerprint %x differs from the pinned %x", got, w)
	}
	return nil
}

// NewProductionNitroVerifier is the verifier a production party and any production relying party uses: the pinned AWS root as the only root, the default
// time windows, debug documents refused.
func NewProductionNitroVerifier() (*NitroVerifier, error) {
	root, err := NitroRootG1()
	if err != nil {
		return nil, err
	}
	return NewNitroVerifier(NitroConfig{Roots: []*x509.Certificate{root}})
}
