package pki

import (
	"crypto/tls"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pkiDir makes both authorities and the whole catalog in a temp dir.
func pkiDir(t *testing.T, ttl time.Duration, now time.Time) string {
	t.Helper()
	d := t.TempDir()
	if err := Init(d, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := IssueAll(d, ttl, now); err != nil {
		t.Fatal(err)
	}
	return d
}

func source(t *testing.T, root, zone, service string) *Source {
	t.Helper()
	dir := Dir(root, zone, service)
	s, err := NewSource(SourceConfig{Name: service, Zone: zone, CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"), CAFile: filepath.Join(dir, "ca.crt")})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startServer runs an HTTPS server on 127.0.0.1 with the config and returns its URL.
func startServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			who = r.TLS.PeerCertificates[0].URIs[0].String()
		}
		io.WriteString(w, who)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

func get(t *testing.T, url string, cfg *tls.Config) (string, error) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
	defer c.CloseIdleConnections()
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

// A client without a certificate, one from the other zone, one from the right zone with a name that is not on the list, and the right one.
func TestRequireClientMatrix(t *testing.T) {
	root := pkiDir(t, time.Hour, time.Now())
	core := source(t, root, ZoneBusiness, "core")
	allow := Allow{ID(ZoneBusiness, "worker")}
	url := startServer(t, core.ServerConfig(RequireClient, allow))

	worker := source(t, root, ZoneBusiness, "worker")
	relay := source(t, root, ZoneBusiness, "relay")
	gateway := source(t, root, ZoneSigning, "gateway")

	if _, err := get(t, url, worker.ClientConfig("localhost", nil)); err != nil {
		t.Fatalf("the allow-listed client was refused: %v", err)
	}
	// no certificate (the client still trusts our CA: build it from a source, then drop the certificate)
	noCert := worker.ClientConfig("localhost", nil)
	noCert.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	if _, err := get(t, url, noCert); err == nil {
		t.Fatal("a client without a certificate was accepted")
	}
	// right authority, name not on the list
	if _, err := get(t, url, relay.ClientConfig("localhost", nil)); err == nil {
		t.Fatal("a business client whose name is not on the allow-list was accepted")
	}
	// the other zone's certificate (its server check is relaxed so that the refusal tested is the server's)
	other := gateway.ClientConfig("localhost", nil)
	other.VerifyConnection = nil
	if _, err := get(t, url, other); err == nil {
		t.Fatal("a signing-zone certificate was accepted by a business endpoint")
	}
}

func TestOptionalClientAllowsPeopleButChecksCertificates(t *testing.T) {
	root := pkiDir(t, time.Hour, time.Now())
	core := source(t, root, ZoneBusiness, "core")
	url := startServer(t, core.ServerConfig(OptionalClient, Allow{ID(ZoneBusiness, "worker")}))
	worker := source(t, root, ZoneBusiness, "worker")

	person := worker.ClientConfig("localhost", nil)
	person.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	if _, err := get(t, url, person); err != nil {
		t.Fatalf("a caller without a certificate must get through at the TLS level: %v", err)
	}
	if who, err := get(t, url, worker.ClientConfig("localhost", nil)); err != nil || who != ID(ZoneBusiness, "worker") {
		t.Fatalf("allow-listed service: %q, %v", who, err)
	}
	if _, err := get(t, url, source(t, root, ZoneBusiness, "relay").ClientConfig("localhost", nil)); err == nil {
		t.Fatal("a certificate that is not on the allow-list was accepted")
	}
	other := source(t, root, ZoneSigning, "gateway").ClientConfig("localhost", nil)
	other.VerifyConnection = nil
	if _, err := get(t, url, other); err == nil {
		t.Fatal("the other zone's certificate was accepted")
	}
}

// The client refuses a server of the other zone, and a server whose name is not the expected one.
func TestClientChecksTheServer(t *testing.T) {
	root := pkiDir(t, time.Hour, time.Now())
	worker := source(t, root, ZoneBusiness, "worker")
	good := startServer(t, source(t, root, ZoneBusiness, "core").ServerConfig(RequireClient, Allow{ID(ZoneBusiness, "worker")}))
	if _, err := get(t, good, worker.ClientConfig("localhost", Allow{ID(ZoneBusiness, "core")})); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, good, worker.ClientConfig("localhost", Allow{ID(ZoneBusiness, "kafka")})); err == nil {
		t.Fatal("a server with another name was accepted")
	}
	if _, err := get(t, good, worker.ClientConfig("wrong.example", nil)); err == nil {
		t.Fatal("a host name mismatch was accepted")
	}
	// a server of the signing zone (its certificate has the localhost name too): the business client does not trust that authority
	sign := source(t, root, ZoneSigning, "signing-db")
	other := startServer(t, sign.ServerConfig(OptionalClient, nil))
	if _, err := get(t, other, worker.ClientConfig("localhost", nil)); err == nil {
		t.Fatal("a signing-zone server certificate was accepted by a business client")
	}
}

// Replacing the files while the server runs: a new connection sees the new certificate, nothing restarts.
func TestRotationWithoutRestart(t *testing.T) {
	root := pkiDir(t, time.Hour, time.Now())
	core := source(t, root, ZoneBusiness, "core")
	worker := source(t, root, ZoneBusiness, "worker")
	url := startServer(t, core.ServerConfig(RequireClient, Allow{ID(ZoneBusiness, "worker")}))

	serial := func(t *testing.T) string {
		t.Helper()
		var got string
		cfg := worker.ClientConfig("localhost", nil)
		inner := cfg.VerifyConnection
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			got = cs.PeerCertificates[0].SerialNumber.String()
			return inner(cs)
		}
		if _, err := get(t, url, cfg); err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := serial(t)
	if err := IssueAll(root, 2*time.Hour, time.Now()); err != nil { // rotate: new certificates, same CAs
		t.Fatal(err)
	}
	if err := core.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := worker.Reload(); err != nil {
		t.Fatal(err)
	}
	if after := serial(t); after == before {
		t.Fatal("a new connection still used the old certificate after rotation")
	}
	// the background loop does the same by itself
	done := make(chan struct{})
	defer close(done)
	core.cfg.Interval = 20 * time.Millisecond
	go core.Run(done)
	prev := serial(t)
	if err := IssueAll(root, 3*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if serial(t) != prev {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("the reload loop did not pick up the rotated certificate")
}

// A half-written or expired replacement is not used: the old certificate stays, the failure is counted.
func TestBadReplacementKeepsTheOldCertificate(t *testing.T) {
	root := pkiDir(t, time.Hour, time.Now())
	core := source(t, root, ZoneBusiness, "core")
	dir := Dir(root, ZoneBusiness, "core")
	old := core.Leaf().SerialNumber.String()
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := core.Reload(); err == nil {
		t.Fatal("garbage was loaded")
	}
	if core.Leaf().SerialNumber.String() != old {
		t.Fatal("the old certificate was replaced by garbage")
	}
	// an expired replacement
	past := time.Now().Add(-48 * time.Hour)
	ca, _ := LoadCA(root, ZoneBusiness)
	l, _ := ca.Issue(IssueRequest{Service: "core", DNS: []string{"localhost"}, Usage: Server | Client, TTL: time.Hour, Now: past})
	if err := WriteLeaf(dir, l, ca); err != nil {
		t.Fatal(err)
	}
	if err := core.Reload(); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired replacement must be refused: %v", err)
	}
	var b strings.Builder
	core.WriteMetrics(&b)
	if !strings.Contains(b.String(), `qv_tls_cert_reload_failures_total{name="core",zone="business"} 2`) {
		t.Fatalf("failures not counted:\n%s", b.String())
	}
}

func TestExpiredCertificateRefusesToStart(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	root := pkiDir(t, time.Hour, past) // issued two days ago for one hour
	dir := Dir(root, ZoneBusiness, "core")
	_, err := NewSource(SourceConfig{Name: "qv-core", Zone: ZoneBusiness, CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"), CAFile: filepath.Join(dir, "ca.crt"), Now: func() time.Time { return past.Add(48 * time.Hour) }})
	// the CA (24h) expired too, so either message is a clear refusal; the leaf is checked first
	if err == nil || !strings.Contains(err.Error(), "qv-core: TLS certificate") || !strings.Contains(err.Error(), "expired at") || !strings.Contains(err.Error(), "docs/runbooks/certificates.md") {
		t.Fatalf("want a clear expiry refusal, got %v", err)
	}
}

func TestClockSkewIsRefusedClearly(t *testing.T) {
	root := pkiDir(t, time.Hour, time.Now())
	dir := Dir(root, ZoneBusiness, "core")
	_, err := NewSource(SourceConfig{Name: "qv-core", Zone: ZoneBusiness, CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"), CAFile: filepath.Join(dir, "ca.crt"), Now: func() time.Time { return time.Now().Add(-time.Hour) }})
	if err == nil || !strings.Contains(err.Error(), "not valid before") || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("want a clock message, got %v", err)
	}
}

func TestSourceRefusesTheWrongZoneOrAuthority(t *testing.T) {
	root := pkiDir(t, time.Hour, time.Now())
	b := Dir(root, ZoneBusiness, "core")
	s := Dir(root, ZoneSigning, "gateway")
	// the signing certificate configured as a business service
	if _, err := NewSource(SourceConfig{Name: "x", Zone: ZoneBusiness, CertFile: filepath.Join(s, "tls.crt"), KeyFile: filepath.Join(s, "tls.key"), CAFile: filepath.Join(s, "ca.crt")}); err == nil || !strings.Contains(err.Error(), "signing zone") {
		t.Fatalf("a signing certificate was accepted as business: %v", err)
	}
	// a business certificate with the signing CA bundle
	if _, err := NewSource(SourceConfig{Name: "x", Zone: ZoneBusiness, CertFile: filepath.Join(b, "tls.crt"), KeyFile: filepath.Join(b, "tls.key"), CAFile: filepath.Join(s, "ca.crt")}); err == nil || !strings.Contains(err.Error(), "not signed by") {
		t.Fatalf("a certificate with another zone's CA bundle was accepted: %v", err)
	}
}

func TestLeafLifetimeIsCapped(t *testing.T) {
	ca, err := NewCA(ZoneBusiness, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue(IssueRequest{Service: "core", TTL: 365 * 24 * time.Hour}); err == nil {
		t.Fatal("a one-year certificate was issued")
	}
}

func TestNames(t *testing.T) {
	for _, s := range []string{"spiffe://other/business/core", "https://quorumvault/business/core", "spiffe://quorumvault/business", "spiffe://quorumvault/business/a/b", "spiffe://quorumvault/prod/core", "spiffe://quorumvault/business/core?x=1"} {
		if _, _, err := ParseID(s); err == nil {
			t.Errorf("%q was accepted", s)
		}
	}
	z, svc, err := ParseID(ID(ZoneSigning, "gateway"))
	if err != nil || z != ZoneSigning || svc != "gateway" {
		t.Fatal(z, svc, err)
	}
	if _, err := ParseAllow("business/worker, spiffe://quorumvault/signing/gateway"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAllow("bogus"); err == nil {
		t.Fatal("bad allow entry accepted")
	}
}

func TestSecondsToExpiryMetric(t *testing.T) {
	root := pkiDir(t, 2*time.Hour, time.Now())
	s := source(t, root, ZoneBusiness, "core")
	var b strings.Builder
	s.WriteMetrics(&b)
	out := b.String()
	for _, want := range []string{`qv_tls_cert_seconds_to_expiry{name="core",zone="business",kind="leaf"} `, `kind="ca"`, "qv_tls_cert_reloads_total", "qv_tls_cert_last_reload_timestamp_seconds"} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics lack %q:\n%s", want, out)
		}
	}
	if left := s.SecondsToExpiry(); left < 7000 || left > 7200 {
		t.Fatalf("seconds to expiry %v", left)
	}
}

func TestRequireLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9", "[::1]:9", "localhost:9"} {
		if err := RequireLoopback(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:9", ":9", "10.0.0.1:9", "example.com:9"} {
		if err := RequireLoopback(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestPlaintextNeedsTheDevSwitchAndADevEnvironment(t *testing.T) {
	t.Setenv("QV_ENV", "")
	t.Setenv("QV_ALLOW_PLAINTEXT", "1")
	if PlaintextAllowed() {
		t.Fatal("production (QV_ENV unset) allowed plain text")
	}
	t.Setenv("QV_ENV", "staging")
	if PlaintextAllowed() {
		t.Fatal("an unknown environment allowed plain text")
	}
	t.Setenv("QV_ENV", "dev")
	if !PlaintextAllowed() {
		t.Fatal("dev with the switch must allow it")
	}
	t.Setenv("QV_ALLOW_PLAINTEXT", "")
	if PlaintextAllowed() {
		t.Fatal("dev without the switch allowed plain text")
	}
}

// The environment variable of a flag with a prefix: -link-tls-cert reads QV_LINK_TLS_CERT.
func TestFlagsEnvNames(t *testing.T) {
	t.Setenv("QV_LINK_TLS_CERT", "c")
	t.Setenv("QV_TLS_CERT", "main")
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	Flags(fs, "")
	Flags(fs, "link-")
	if got := fs.Lookup("link-tls-cert").DefValue; got != "c" {
		t.Fatalf("-link-tls-cert default %q, want the value of QV_LINK_TLS_CERT", got)
	}
	if got := fs.Lookup("tls-cert").DefValue; got != "main" {
		t.Fatalf("-tls-cert default %q", got)
	}
}
