package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Usage is what a certificate may be used for.
type Usage int

const (
	Server Usage = 1 << iota
	Client
)

// CA is one zone's certificate authority.
type CA struct {
	Zone string
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA makes a fresh authority for a zone, valid for ttl from now. Its key exists only in memory until Save.
func NewCA(zone string, ttl time.Duration, now time.Time) (*CA, error) {
	if err := ValidZone(zone); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	uri, _ := url.Parse("spiffe://" + TrustDomain + "/" + zone)
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "QuorumVault " + zone + " zone CA", Organization: []string{"QuorumVault (development CA)"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Zone: zone, Cert: c, key: key}, nil
}

// LoadCA reads ca.crt and ca.key of a zone from dir/<zone>/.
func LoadCA(dir, zone string) (*CA, error) {
	if err := ValidZone(zone); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, zone, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("pki: %w (run scripts/pki.sh)", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, zone, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Zone: zone, Cert: cert, key: key}, nil
}

// Save writes dir/<zone>/ca.crt (0644) and ca.key (0600). It refuses to overwrite an existing authority: replacing a CA is an operator decision.
func (c *CA) Save(dir string) error {
	d := filepath.Join(dir, c.Zone)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(d, "ca.key")); err == nil {
		return fmt.Errorf("pki: %s already has a CA; delete it first if you mean to replace it", d)
	}
	kb, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(d, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(d, "ca.crt"), pemCert(c.Cert.Raw), 0o644)
}

// Leaf is an issued certificate with its key.
type Leaf struct {
	CertPEM, KeyPEM []byte
	Cert            *x509.Certificate
}

// IssueRequest asks for one certificate. The URI SAN is ID(zone, Service) of the issuing authority's zone.
type IssueRequest struct {
	Service string   // the name in the URI SAN
	CN      string   // subject common name; default Service. Postgres maps it to a role (pg_ident)
	DNS     []string // DNS SANs, for the TLS host name check
	IPs     []string // IP SANs
	Usage   Usage    // default Client
	TTL     time.Duration
	Now     time.Time
}

// MaxLeafTTL is the longest certificate Issue makes. Certificates live hours to days, never a year.
const MaxLeafTTL = 30 * 24 * time.Hour

// Issue makes a certificate and a fresh key for one service.
func (c *CA) Issue(r IssueRequest) (*Leaf, error) {
	if r.Service == "" || r.TTL <= 0 {
		return nil, errors.New("pki: a service name and a positive ttl are required")
	}
	if r.TTL > MaxLeafTTL {
		return nil, fmt.Errorf("pki: certificate lifetime %s is longer than the %s limit: leaf certificates are short-lived", r.TTL, MaxLeafTTL)
	}
	if r.Usage == 0 {
		r.Usage = Client
	}
	if r.CN == "" {
		r.CN = r.Service
	}
	if r.Now.IsZero() {
		r.Now = time.Now()
	}
	uri, err := url.Parse(ID(c.Zone, r.Service))
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, s := range r.IPs {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("pki: %q is not an IP address", s)
		}
		ips = append(ips, ip)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	var eku []x509.ExtKeyUsage
	if r.Usage&Server != 0 {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if r.Usage&Client != 0 {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: r.CN},
		NotBefore:    r.Now.Add(-5 * time.Minute), // a little clock skew is tolerated; more than this is refused with a clear message
		NotAfter:     r.Now.Add(r.TTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		URIs:         []*url.URL{uri},
		DNSNames:     r.DNS,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Leaf{CertPEM: pemCert(der), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), Cert: cert}, nil
}

// WriteLeaf puts tls.crt, tls.key and ca.crt (the issuer's certificate, the trust bundle) into dir, each replaced atomically (written to
// a temporary name, then renamed), the key first, so a service that reloads in between sees a mismatched pair at worst, keeps what it has and
// retries. Safe to call again while services run: that is how rotation works.
func WriteLeaf(dir string, l *Leaf, ca *CA) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "ca.crt"), pemCert(ca.Cert.Raw), 0o644); err != nil {
		return err
	}
	// 0644: a container reads it as another user; these are development files under gitignored data/
	if err := writeFileAtomic(filepath.Join(dir, "tls.key"), l.KeyPEM, 0o644); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "tls.crt"), l.CertPEM, 0o644)
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	return os.WriteFile(path, b, mode)
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func parseCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("pki: no certificate in the PEM file")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("pki: no key in the PEM file")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
}
