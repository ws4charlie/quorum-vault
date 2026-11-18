// Package pkitest gives tests the certificates the services now need. If QV_PKI_DIR names a directory made by scripts/pki.sh (the e2e lanes and CI
// do this), that one is used; otherwise a fresh pair of authorities and certificates is made once per test process in a temporary directory.
// Either way nothing is committed.
package pkitest

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

var (
	once sync.Once
	root string
	rerr error
)

// Root is the PKI directory.
func Root() string {
	once.Do(func() {
		if d := os.Getenv("QV_PKI_DIR"); d != "" {
			if _, err := os.Stat(filepath.Join(d, pki.ZoneBusiness, "core", "tls.crt")); err == nil {
				root = d
				return
			}
		}
		d, err := os.MkdirTemp("", "qv-pki-")
		if err != nil {
			rerr = err
			return
		}
		if rerr = pki.Init(d, 24*time.Hour, time.Now()); rerr == nil {
			rerr = pki.IssueAll(d, 12*time.Hour, time.Now())
		}
		root = d
	})
	if rerr != nil {
		panic(fmt.Sprintf("pkitest: %v", rerr))
	}
	return root
}

// Files are the three TLS flags' values of a service.
func Files(zone, service string) (cert, key, ca string) {
	d := pki.Dir(Root(), zone, service)
	return filepath.Join(d, "tls.crt"), filepath.Join(d, "tls.key"), filepath.Join(d, "ca.crt")
}

// Args is -tls-cert, -tls-key, -tls-ca for a service, to pass to a spawned program.
func Args(zone, service string) []string {
	c, k, a := Files(zone, service)
	return []string{"-tls-cert", c, "-tls-key", k, "-tls-ca", a}
}

// Env is the same as environment variables.
func Env(zone, service string) []string {
	c, k, a := Files(zone, service)
	return []string{"QV_TLS_CERT=" + c, "QV_TLS_KEY=" + k, "QV_TLS_CA=" + a}
}

func pool(zone string) *x509.CertPool {
	b, err := os.ReadFile(filepath.Join(Root(), zone, "ca.crt"))
	if err != nil {
		panic(err)
	}
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(b)
	return p
}

// PeopleClient is an https client that trusts the business CA and shows no certificate: a person with a bearer token.
func PeopleClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool(pki.ZoneBusiness)}}}
}

// ServiceClient is an https client that also shows the certificate of a business-zone service.
func ServiceClient(service string) *http.Client {
	c, k, _ := Files(pki.ZoneBusiness, service)
	pair, err := tls.LoadX509KeyPair(c, k)
	if err != nil {
		panic(err)
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool(pki.ZoneBusiness), Certificates: []tls.Certificate{pair}}}}
}

// CoreArgs is what a spawned qv-core needs: the TLS flags of the business core identity.
func CoreArgs() []string { return Args(pki.ZoneBusiness, "core") }
