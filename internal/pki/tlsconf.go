package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// ClientAuth says what a server wants from its callers.
type ClientAuth int

const (
	// RequireClient: no certificate, no connection.
	RequireClient ClientAuth = iota
	// OptionalClient: a caller may come without a certificate (people, with a bearer token); one that is shown must be valid and allow-listed.
	OptionalClient
)

// Allow is an allow-list of names (spiffe://quorumvault/<zone>/<service>) for one endpoint.
type Allow []string

func (a Allow) has(id string) bool {
	for _, x := range a {
		if x == id {
			return true
		}
	}
	return false
}

// ParseAllow turns "business/worker,business/guardian" (or full spiffe:// names) into an Allow for zone-qualified names.
func ParseAllow(list string) (Allow, error) {
	var out Allow
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.HasPrefix(s, "spiffe://") {
			s = "spiffe://" + TrustDomain + "/" + s
		}
		if _, _, err := ParseID(s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// CheckPeer verifies a connection's peer: the chain (Go has done it already for servers; clients call VerifyServer), then the name: exactly one
// spiffe URI SAN, of the zone the CA belongs to, on the allow-list. It returns the peer's name.
func CheckPeer(leaf *x509.Certificate, zone string, allow Allow) (string, error) {
	z, _, err := nameOf(leaf)
	if err != nil {
		return "", err
	}
	if z != zone {
		return "", fmt.Errorf("peer %s is of the %s zone, not %s", leaf.URIs[0], z, zone)
	}
	id := leaf.URIs[0].String()
	if !allow.has(id) {
		return "", fmt.Errorf("peer %s is not allowed on this endpoint", id)
	}
	return id, nil
}

// ServerConfig is the TLS config of a listener: TLS 1.3, our certificate (reloaded), callers checked against the CA pool (reloaded) and the
// allow-list. With OptionalClient a caller without a certificate is let through at this level (the application decides what such a caller may do);
// one that shows a certificate must pass the chain and the allow-list.
func (s *Source) ServerConfig(ca ClientAuth, allow Allow) *tls.Config {
	mode := tls.RequireAndVerifyClientCert
	if ca == OptionalClient {
		mode = tls.VerifyClientCertIfGiven
	}
	build := func() *tls.Config {
		_, pool := s.current()
		return &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: s.GetCertificate,
			ClientAuth:     mode,
			ClientCAs:      pool,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					if ca == OptionalClient {
						return nil
					}
					return errors.New("a client certificate is required")
				}
				_, err := CheckPeer(cs.PeerCertificates[0], s.cfg.Zone, allow)
				return err
			},
		}
	}
	base := build()
	// GetConfigForClient makes every handshake use the CA pool as it is now, so a rotated CA bundle needs no restart either.
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return build(), nil }
	return base
}

// ClientConfig is the TLS config of an outgoing connection: TLS 1.3, our certificate (reloaded), the server's certificate checked against the CA pool
// (reloaded) for serverName, and, when serverAllow is not empty, its spiffe name checked against it. The checks run in VerifyConnection, because
// the stock check would fix the CA pool at start.
func (s *Source) ClientConfig(serverName string, serverAllow Allow) *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: s.GetClientCertificate,
		ServerName:           serverName,
		InsecureSkipVerify:   true, //nolint:gosec // VerifyConnection below does the full verification against the reloaded pool
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the server sent no certificate")
			}
			_, pool := s.current()
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			leaf := cs.PeerCertificates[0]
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: serverName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return fmt.Errorf("server certificate: %w", err)
			}
			if len(serverAllow) > 0 {
				if _, err := CheckPeer(leaf, s.cfg.Zone, serverAllow); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
