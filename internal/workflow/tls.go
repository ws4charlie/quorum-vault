package workflow

import (
	"errors"
	"net"

	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// TemporalNames is who may answer as the Temporal frontend: the Temporal endpoint of the business zone.
var TemporalNames = pki.Allow{pki.ID(pki.ZoneBusiness, "temporal")}

// ConnectionOptions returns the client connection options for src: our certificate, and the frontend checked against the zone's authority and
// against TemporalNames, for the host of addr (an IP address, as in development, is checked as "temporal", a name the certificate carries).
// src is nil only when pki.PlaintextAllowed (development); otherwise a nil src is an error.
func ConnectionOptions(addr string, src *pki.Source) (client.ConnectionOptions, error) {
	if src == nil {
		if pki.PlaintextAllowed() {
			return client.ConnectionOptions{}, nil
		}
		return client.ConnectionOptions{}, errors.New("temporal: TLS is required (certificate flags missing); plain text is for a development machine only (QV_ALLOW_PLAINTEXT=1, QV_ENV=dev)")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return client.ConnectionOptions{}, err
	}
	if net.ParseIP(host) != nil {
		host = "temporal"
	}
	return client.ConnectionOptions{TLS: src.ClientConfig(host, TemporalNames)}, nil
}
