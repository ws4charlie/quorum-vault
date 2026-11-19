package server

import (
	"crypto/tls"
	"time"

	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
)

// Pin is the SHA-256 of the certificate's public key (SPKI); one definition for all links, see api/cosigner.
type Pin = wire.Pin

func ParsePin(s string) (Pin, error) { return wire.ParsePin(s) }

// PinOf is the pin of a DER certificate.
func PinOf(der []byte) (Pin, error) { return wire.PinOf(der) }

func parsePins(ss []string) (map[Pin]bool, error) { return wire.ParsePins(ss) }

// ServerTLS: TLS 1.3 only, a client certificate is mandatory and must be pinned.
func ServerTLS(cert tls.Certificate, pins map[Pin]bool) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: wire.VerifyPinned(pins, time.Now),
	}
}

// ClientTLS: TLS 1.3 only, presents our certificate, trusts exactly the pinned server certificate (the host name is not
// used: pinning replaces the CA check, so InsecureSkipVerify is on and VerifyPeerCertificate does the verification).
func ClientTLS(cert tls.Certificate, pins map[Pin]bool) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec // pinned: VerifyPinned
		VerifyPeerCertificate: wire.VerifyPinned(pins, time.Now),
	}
}
