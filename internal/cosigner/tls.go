package cosigner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
)

// SocketTLS is the cosigner's side of the authenticated channel: mutual TLS 1.3 with pinned certificates. The cosigner
// presents its own certificate and accepts only the party it is paired with (partyPins: B's cosigner lists B's
// certificate, C's lists C's; any other certificate, or none, fails the handshake and nothing is decided). It refuses to
// build without a pin, or with a certificate that is missing or outside its validity period. A rotation adds the new
// party pin next to the old one, then removes the old one (docs/runbooks/certificates.md).
func SocketTLS(certFile, keyFile string, partyPins []string) (*tls.Config, error) {
	if len(partyPins) == 0 {
		return nil, errors.New("cosigner socket: -party-pins is empty: the cosigner must know which party it serves")
	}
	pins, err := wire.ParsePins(partyPins)
	if err != nil {
		return nil, fmt.Errorf("cosigner socket: -party-pins: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("cosigner socket: certificate: %w", err)
	}
	if err := wire.CheckValid(cert, time.Now()); err != nil {
		return nil, fmt.Errorf("cosigner socket: certificate: %w", err)
	}
	return wire.ServerTLS(cert, pins), nil
}

// ListenUnixTLS is ListenUnix with the authenticated channel on top. A nil cfg is plain text: only for the development switch.
func ListenUnixTLS(path string, cfg *tls.Config) (net.Listener, error) {
	ln, err := ListenUnix(path)
	if err != nil || cfg == nil {
		return ln, err
	}
	return tls.NewListener(ln, cfg), nil
}
