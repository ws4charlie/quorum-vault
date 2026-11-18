package auth_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// A service token is accepted only with a business-zone client certificate whose name is on the list; people need no certificate.
func TestServiceTokenNeedsAnAllowListedCertificate(t *testing.T) {
	is, a := setup(t)
	a.RequireServiceCert(pki.ZoneBusiness, pki.Allow{pki.ID(pki.ZoneBusiness, "guardian")})

	root := t.TempDir()
	if err := pki.Init(root, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := pki.IssueAll(root, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	peer := func(zone, svc string) *tls.ConnectionState {
		c, err := pki.NewSource(pki.SourceConfig{Name: svc, Zone: zone, CertFile: pki.Dir(root, zone, svc) + "/tls.crt", KeyFile: pki.Dir(root, zone, svc) + "/tls.key", CAFile: pki.Dir(root, zone, svc) + "/ca.crt"})
		if err != nil {
			t.Fatal(err)
		}
		return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.Leaf()}}
	}
	svc := authtest.Spec{Sub: "svc-1", Client: "qv-svc", Service: true, Roles: []string{"operator"}}
	person := authtest.Spec{Sub: "alice", Roles: []string{"approver"}}
	call := func(spec authtest.Spec, cs *tls.ConnectionState) *auth.Failure {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+is.Token(spec))
		r.TLS = cs
		_, f := a.Authenticate(r)
		return f
	}
	if f := call(svc, peer(pki.ZoneBusiness, "guardian")); f != nil {
		t.Fatalf("allow-listed service refused: %v", f)
	}
	if f := call(svc, nil); f == nil || f.Status != 403 {
		t.Fatalf("a service token without a certificate: %v", f)
	}
	if f := call(svc, peer(pki.ZoneBusiness, "worker")); f == nil || f.Status != 403 {
		t.Fatalf("a service certificate that is not on the list: %v", f)
	}
	if f := call(svc, peer(pki.ZoneSigning, "gateway")); f == nil || f.Status != 403 {
		t.Fatalf("a signing-zone certificate: %v", f)
	}
	if f := call(person, nil); f != nil {
		t.Fatalf("a person needs no certificate: %v", f)
	}
}

// The whole path on a real TLS listener: handshake rules of pki.ServerConfig plus the service rule of Authenticate.
func TestCoreListenerEndToEnd(t *testing.T) {
	is, a := setup(t)
	allow := pki.Allow{pki.ID(pki.ZoneBusiness, "guardian")}
	a.RequireServiceCert(pki.ZoneBusiness, allow)
	root := t.TempDir()
	if err := pki.Init(root, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := pki.IssueAll(root, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	src := func(zone, svc string) *pki.Source {
		d := pki.Dir(root, zone, svc)
		s, err := pki.NewSource(pki.SourceConfig{Name: svc, Zone: zone, CertFile: d + "/tls.crt", KeyFile: d + "/tls.key", CAFile: d + "/ca.crt"})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, f := a.Authenticate(r); f != nil {
			f.Write(w)
			return
		}
		w.WriteHeader(200)
	}))
	srv.TLS = src(pki.ZoneBusiness, "core").ServerConfig(pki.OptionalClient, allow)
	srv.StartTLS()
	defer srv.Close()

	do := func(cfg *tls.Config, spec authtest.Spec) (int, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		defer c.CloseIdleConnections()
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.Header.Set("Authorization", "Bearer "+is.Token(spec))
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	svc := authtest.Spec{Sub: "svc-1", Client: "qv-svc", Service: true, Roles: []string{"operator"}}
	person := authtest.Spec{Sub: "alice", Roles: []string{"approver"}}
	guardian := src(pki.ZoneBusiness, "guardian").ClientConfig("127.0.0.1", nil)
	noCert := src(pki.ZoneBusiness, "guardian").ClientConfig("127.0.0.1", nil)
	noCert.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	wrongName := src(pki.ZoneBusiness, "worker").ClientConfig("127.0.0.1", nil)
	otherZone := src(pki.ZoneSigning, "gateway").ClientConfig("127.0.0.1", nil)
	otherZone.VerifyConnection = nil

	if code, err := do(guardian, svc); err != nil || code != 200 {
		t.Fatalf("the allow-listed service: %d %v", code, err)
	}
	if code, err := do(noCert, person); err != nil || code != 200 {
		t.Fatalf("a person without a certificate: %d %v", code, err)
	}
	if code, err := do(noCert, svc); err != nil || code != 403 {
		t.Fatalf("a service token without a certificate: %d %v", code, err)
	}
	if _, err := do(wrongName, svc); err == nil {
		t.Fatal("a business certificate with a name not on the list got through the handshake")
	}
	if _, err := do(otherZone, svc); err == nil {
		t.Fatal("the signing zone's certificate got through the handshake")
	}
}
