package cosigner

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// The channel between a party and its cosigner is mutual TLS 1.3 over the unix socket with PINNED certificates: each side
// accepts exactly the certificates whose public-key pin (SHA-256 of the SPKI) it was given (no CA, no names), and only inside their
// validity period. The party pins its own cosigner's certificate; the cosigner pins the one party it is paired with (B's
// cosigner pins B, C's pins C), so no other party, and no process that merely owns the socket path, can take part.

// Pin is the SHA-256 of the DER SubjectPublicKeyInfo (SPKI) of a certificate: it names the KEY, not the certificate. A
// certificate renewed with the same key keeps its pin; a new key needs a new pin (the operator-run rotation). This is the one
// definition used by every pinned link (party mesh, caller port, cosigner channel, gateway); the root module and the party
// module both take it from here.
type Pin [32]byte

// PinOfCert is the pin of a parsed certificate.
func PinOfCert(c *x509.Certificate) Pin { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// PinOf is the pin of a DER certificate.
func PinOf(der []byte) (Pin, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return Pin{}, fmt.Errorf("certificate: %w", err)
	}
	return PinOfCert(c), nil
}

// CertFingerprint is the OLD pin scheme (SHA-256 of the whole DER certificate). It is never accepted; it exists only so a
// refusal can say "this looks like a certificate fingerprint".
func CertFingerprint(der []byte) Pin { return sha256.Sum256(der) }

func (p Pin) String() string { return hex.EncodeToString(p[:]) }

// ParsePin reads one hex pin (64 chars, either case).
func ParsePin(s string) (Pin, error) {
	var p Pin
	b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil || len(b) != 32 {
		return p, fmt.Errorf("pin %q: want 64 hex chars (sha256 of the certificate's public key, SPKI)", s)
	}
	copy(p[:], b)
	return p, nil
}

// ParsePins reads several hex pins.
func ParsePins(ss []string) (map[Pin]bool, error) {
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

// VerifyPinned accepts exactly the certificates whose public key is pinned (no CA involved) and that are inside their
// validity period. If the key is not pinned but the whole certificate's old-style fingerprint IS in the list, the error says so.
func VerifyPinned(pins map[Pin]bool, now func() time.Time) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("no peer certificate")
		}
		c, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		if !pins[PinOfCert(c)] {
			if pins[CertFingerprint(raw[0])] {
				return fmt.Errorf("peer certificate is not pinned: pins are the SHA-256 of the public key (SPKI), not of the certificate; "+
					"the configured pin %s is a certificate fingerprint (old scheme): replace it with %s", CertFingerprint(raw[0]), PinOfCert(c))
			}
			return fmt.Errorf("peer certificate is not pinned (its SPKI pin is %s)", PinOfCert(c))
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
		VerifyPeerCertificate: VerifyPinned(pins, time.Now),
	}
}

// ClientTLS is the party's side: it presents its certificate and trusts exactly the pinned cosigner key (pinning
// replaces the CA and host-name check, so the library's own verification is off and VerifyPeerCertificate does the work).
func ClientTLS(cert tls.Certificate, pins map[Pin]bool) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec // pinned: VerifyPinned does the verification
		VerifyPeerCertificate: VerifyPinned(pins, time.Now),
	}
}

// WriteCertMetrics writes the seconds left on a pinned-channel certificate in the Prometheus text format, with the same metric name and labels
// every other certificate of the system uses (qv_tls_cert_seconds_to_expiry{name,zone,kind="leaf"}; pki.Source.WriteMetrics), so the one
// alert rule (monitoring/tls-cert.rules.yml) covers both ends of the party-to-cosigner channel. A pinned certificate has no CA, so there
// is no kind="ca" line. The value is negative once the certificate expired; an unreadable certificate writes nothing.
func WriteCertMetrics(w io.Writer, name, zone string, c tls.Certificate, now time.Time) {
	if len(c.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return
	}
	fmt.Fprintf(w, "qv_tls_cert_seconds_to_expiry{name=%q,zone=%q,kind=\"leaf\"} %.0f\n", name, zone, leaf.NotAfter.Sub(now).Seconds())
}
