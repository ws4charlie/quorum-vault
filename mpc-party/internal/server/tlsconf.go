package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Pin is the SHA-256 of a DER certificate.
type Pin [32]byte

func ParsePin(s string) (Pin, error) {
	var p Pin
	b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil || len(b) != 32 {
		return p, fmt.Errorf("pin %q: want 64 hex chars (sha256 of the DER certificate)", s)
	}
	copy(p[:], b)
	return p, nil
}

func PinOf(der []byte) Pin { return sha256.Sum256(der) }

func (p Pin) String() string { return hex.EncodeToString(p[:]) }

func parsePins(ss []string) (map[Pin]bool, error) {
	m := map[Pin]bool{}
	for _, s := range ss {
		p, err := ParsePin(s)
		if err != nil {
			return nil, err
		}
		m[p] = true
	}
	return m, nil
}

// verifyPinned accepts exactly the certificates whose fingerprint is pinned (no CA involved), and checks validity dates.
func verifyPinned(pins map[Pin]bool, now func() time.Time) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("no peer certificate")
		}
		if !pins[PinOf(raw[0])] {
			return errors.New("peer certificate is not pinned")
		}
		c, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		if t := now(); t.Before(c.NotBefore) || t.After(c.NotAfter) {
			return errors.New("peer certificate outside its validity period")
		}
		return nil
	}
}

// ServerTLS: TLS 1.3 only, a client certificate is mandatory and must be pinned.
func ServerTLS(cert tls.Certificate, pins map[Pin]bool) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPinned(pins, time.Now),
	}
}

// ClientTLS: TLS 1.3 only, presents our certificate, trusts exactly the pinned server certificate (the host name is not
// used: pinning replaces the CA check, so InsecureSkipVerify is on and VerifyPeerCertificate does the verification).
func ClientTLS(cert tls.Certificate, pins map[Pin]bool) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec // pinned: verifyPinned below
		VerifyPeerCertificate: verifyPinned(pins, time.Now),
	}
}
