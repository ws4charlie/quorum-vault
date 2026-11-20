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
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/db"
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

// EnvFor is the TLS environment of a spawned QuorumVault binary: its own identity, and for the gateway the business-issued link identity.
// Binaries that need none get nothing.
func EnvFor(binary string) []string {
	switch binary {
	case "qv-core":
		return Env(pki.ZoneBusiness, "core")
	case "qv-worker":
		return Env(pki.ZoneBusiness, "worker")
	case "qv-relay":
		return Env(pki.ZoneBusiness, "relay")
	case "qv-anchor-archiver":
		return Env(pki.ZoneBusiness, "archiver")
	case "qv-cosigner":
		return CosignerEnv("b") // cosigner C: the caller passes CosignerEnv("c") after this (a later value wins)
	case "qv-gateway":
		c, k, a := Files(pki.ZoneBusiness, "gateway-link")
		return append(Env(pki.ZoneSigning, "gateway"), "QV_LINK_TLS_CERT="+c, "QV_LINK_TLS_KEY="+k, "QV_LINK_TLS_CA="+a, "QV_ENV=test") // test: the e2e HSM is SoftHSM, which production refuses
	case "mpc-party":
		return []string{"QV_ENV=test"} // the e2e sealer token is SoftHSM, which production refuses
	}
	return nil
}

// CosignerEnv is the TLS environment of cosigner "b" or "c": its own signing certificate (cosigner-b|c) and its own link certificate (cosigner-link-b|c).
func CosignerEnv(role string) []string {
	c, k, a := Files(pki.ZoneBusiness, "cosigner-link-"+role)
	return append(Env(pki.ZoneSigning, "cosigner-"+role), "QV_LINK_TLS_CERT="+c, "QV_LINK_TLS_KEY="+k, "QV_LINK_TLS_CA="+a)
}

// AdminDSN returns base (a DSN of the server of zone, as DATABASE_URL or QV_SIGNING_DB_URL) with the admin certificate of that zone and that zone's CA.
func AdminDSN(base, zone string) string { return WithCert(base, zone, "admin", zone) }

// WithCert returns base using the client certificate of (clientZone, clientService) and the CA of serverZone to verify the server.
func WithCert(base, clientZone, clientService, serverZone string) string {
	c, k, _ := Files(clientZone, clientService)
	_, _, ca := Files(serverZone, "admin")
	return db.WithClientCert(base, c, k, ca)
}

// CopyIdentity copies the files of (zone, service) into a new temporary directory and returns a Source over the copy plus a function that
// replaces the copy with a freshly issued certificate (same name, new key and serial), signed by the zone's real CA from Root(). It is how
// the rotation tests work without touching the files other processes of the run have loaded.
func CopyIdentity(t testing.TB, zone, service string) (src *pki.Source, rotate func()) {
	t.Helper()
	dir := t.TempDir()
	srcDir := pki.Dir(Root(), zone, service)
	for _, f := range []string{"tls.crt", "tls.key", "ca.crt"} {
		b, err := os.ReadFile(filepath.Join(srcDir, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src, err := pki.NewSource(pki.SourceConfig{Name: service, Zone: zone, CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"), CAFile: filepath.Join(dir, "ca.crt")})
	if err != nil {
		t.Fatal(err)
	}
	rotate = func() {
		ca, err := pki.LoadCA(Root(), zone)
		if err != nil {
			t.Fatal(err)
		}
		l, err := ca.Issue(pki.IssueRequest{Service: service, Usage: pki.Client, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.WriteLeaf(dir, l, ca); err != nil {
			t.Fatal(err)
		}
		if err := src.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	return src, rotate
}

var (
	adminOnce sync.Once
	adminSrc  *pki.Source
)

// Source is a Source over the files of (zone, service) in the shared PKI directory.
func Source(t testing.TB, zone, service string) *pki.Source {
	t.Helper()
	c, k, a := Files(zone, service)
	s, err := pki.NewSource(pki.SourceConfig{Name: service, Zone: zone, CertFile: c, KeyFile: k, CAFile: a})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ClientTLS is the client TLS config of any business- or signing-zone identity, trusting that zone's authority, for serverName ("" means the host
// dialled) and, when given, the server names allowed (business-zone service names).
func ClientTLS(zone, service, serverName string, serverAllow ...string) *tls.Config {
	c, k, a := Files(zone, service)
	src, err := pki.NewSource(pki.SourceConfig{Name: service, Zone: zone, CertFile: c, KeyFile: k, CAFile: a})
	if err != nil {
		panic(err)
	}
	var allow pki.Allow
	for _, n := range serverAllow {
		allow = append(allow, pki.ID(pki.ZoneBusiness, n))
	}
	return src.ClientConfig(serverName, allow)
}

// Reissue replaces the certificate files of (zone, service) in the shared PKI directory with a new certificate (new key, new serial) from the same
// CA, with the catalog's names. Running services that follow their files pick it up; this is the rotation under test.
func Reissue(t testing.TB, zone, service string) {
	t.Helper()
	ca, err := pki.LoadCA(Root(), zone)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pki.Catalog {
		if e.Zone != zone || e.Service != service {
			continue
		}
		l, err := ca.Issue(pki.IssueRequest{Service: e.Service, CN: e.CN, DNS: e.DNS, IPs: e.IPs, Usage: e.Usage, TTL: 12 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.WriteLeaf(pki.Dir(Root(), zone, service), l, ca); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("pkitest: %s/%s is not in the catalog", zone, service)
}

// AdminTLS is the client TLS config of the business-zone admin identity (an operator or a test: a Kafka superuser, a Temporal client), for
// serverName ("" means the host dialled, as a Kafka client needs). The brokers' and the frontend's names are checked as in the services.
func AdminTLS(serverName string, serverAllow ...string) *tls.Config {
	adminOnce.Do(func() {
		c, k, a := Files(pki.ZoneBusiness, "admin")
		s, err := pki.NewSource(pki.SourceConfig{Name: "admin", Zone: pki.ZoneBusiness, CertFile: c, KeyFile: k, CAFile: a})
		if err != nil {
			panic(err)
		}
		adminSrc = s
	})
	var allow pki.Allow
	for _, n := range serverAllow {
		allow = append(allow, pki.ID(pki.ZoneBusiness, n))
	}
	return adminSrc.ClientConfig(serverName, allow)
}
