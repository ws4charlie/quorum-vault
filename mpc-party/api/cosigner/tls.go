package cosigner

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

// The channel between a party and its cosigner is mutual TLS 1.3 over the unix socket with PINNED certificates: each side
// accepts exactly the certificates whose SHA-256 fingerprint it was given (no CA, no names), and only inside their
// validity period. The party pins its own cosigner's certificate; the cosigner pins the one party it is paired with (B's
// cosigner pins B, C's pins C), so no other party, and no process that merely owns the socket path, can take part.

// Pin is the SHA-256 of a DER certificate.
type Pin [32]byte

// PinOf fingerprints a DER certificate.
func PinOf(der []byte) Pin { return sha256.Sum256(der) }

func (p Pin) String() string { return hex.EncodeToString(p[:]) }

// ParsePins reads lowercase or uppercase hex fingerprints (64 chars each).
func ParsePins(ss []string) (map[Pin]bool, error) {
	m := map[Pin]bool{}
	for _, s := range ss {
		b, err := hex.DecodeString(strings.TrimSpace(s))
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("pin %q: want 64 hex chars (sha256 of the DER certificate)", s)
		}
		var p Pin
		copy(p[:], b)
		m[p] = true
	}
	return m, nil
}

// CheckValid refuses a certificate outside its validity period.
func CheckValid(c tls.Certificate, now time.Time) error {
	if len(c.Certificate) == 0 {
		return errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return err
	}
	if now.Before(leaf.NotBefore) {
		return errors.New("certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

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

// ServerTLS is the cosigner's side: a client certificate is mandatory and must be pinned.
func ServerTLS(cert tls.Certificate, pins map[Pin]bool) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPinned(pins, time.Now),
	}
}

// ClientTLS is the party's side: it presents its certificate and trusts exactly the pinned cosigner certificate (pinning
// replaces the CA and host-name check, so the library's own verification is off and VerifyPeerCertificate does the work).
func ClientTLS(cert tls.Certificate, pins map[Pin]bool) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec // pinned: verifyPinned does the verification
		VerifyPeerCertificate: verifyPinned(pins, time.Now),
	}
}
