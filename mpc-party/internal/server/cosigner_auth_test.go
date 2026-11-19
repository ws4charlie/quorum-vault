package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

type pcert struct {
	cert     tls.Certificate
	crt, key string
	pin      string
}

func newPCert(t *testing.T, dir, name string, from, to time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (pcert, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: isCA, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if parent == nil {
		parent, parentKey = tpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	p := pcert{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pin: wire.PinOf(der).String()}
	p.crt, p.key = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	os.WriteFile(p.crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(p.key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	leaf, _ := x509.ParseCertificate(der)
	return p, leaf, k
}

func valid(t *testing.T, dir, name string) pcert {
	p, _, _ := newPCert(t, dir, name, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil, nil, false)
	return p
}

// fakeCosigner listens on a unix socket and answers "allow" to every request, with the given TLS config (nil: plain text).
func fakeCosigner(t *testing.T, cfg *tls.Config) (sock string, asked *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("", "qv") // short: unix socket paths are limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, "c.sock")
	ln, err := netListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
	}
	asked = new(atomic.Int32)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.Path, func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		json.NewEncoder(w).Encode(wire.Response{Allow: true})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ErrorLog: discardLog()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return
}

func pinsOf(t *testing.T, s string) map[wire.Pin]bool {
	p, err := wire.ParsePins([]string{s})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A cosigner impostor on the socket path says "allow" to everything. The party must not take its word: unavailable, never allow.
func TestCosignerImpostorIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	partyB, partyC := valid(t, dir, "party-b"), valid(t, dir, "party-c")
	realB, realC := valid(t, dir, "cosigner-b"), valid(t, dir, "cosigner-c")
	_, caLeaf, caKey := newPCert(t, dir, "other-zone-ca", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, true)
	otherZone, _, _ := newPCert(t, dir, "cosigner-b-otherzone", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), caLeaf, caKey, false)
	expired, _, _ := newPCert(t, dir, "cosigner-b-expired", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, nil, false)

	// B's party pins the real cosigner of B and presents its own certificate
	newAuthz := func(sock string) server.Authorizer {
		a, err := server.NewCosignerAuthorizer(sock, 2*time.Second, []string{realB.pin}, partyB.crt, partyB.key)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	ask := func(sock string) error {
		return newAuthz(sock).Authorize(t.Context(), server.AuthRequest{JobID: "j"})
	}
	// the real cosigner pins party B
	sock, asked := fakeCosigner(t, wire.ServerTLS(realB.cert, pinsOf(t, partyB.pin)))
	if err := ask(sock); err != nil || asked.Load() != 1 {
		t.Fatalf("the real pair does not work: %v (asked %d)", err, asked.Load())
	}
	for name, cfg := range map[string]*tls.Config{
		"no certificate (plain text)":            nil,
		"another certificate":                    wire.ServerTLS(valid(t, dir, "x").cert, nil),
		"the certificate of the other cosigner":  wire.ServerTLS(realC.cert, pinsOf(t, partyB.pin)),
		"a certificate of another zone's CA":     wire.ServerTLS(otherZone.cert, pinsOf(t, partyB.pin)),
		"the pinned certificate but expired":     wire.ServerTLS(expired.cert, pinsOf(t, partyB.pin)),
		"real certificate, party not recognised": wire.ServerTLS(realB.cert, pinsOf(t, partyC.pin)),
	} {
		s, n := fakeCosigner(t, cfg)
		err := ask(s)
		var u *server.UnavailableError
		if !errors.As(err, &u) {
			t.Errorf("%s: want unavailable, got %v", name, err)
		}
		if name != "real certificate, party not recognised" && n.Load() != 0 {
			t.Errorf("%s: the impostor's handler was reached", name)
		}
	}
	// the expired certificate is pinned too: the pin alone is not enough
	pinExpired, err := server.NewCosignerAuthorizer(sock, 2*time.Second, []string{expired.pin}, partyB.crt, partyB.key)
	if err != nil {
		t.Fatal(err)
	}
	s, n := fakeCosigner(t, wire.ServerTLS(expired.cert, pinsOf(t, partyB.pin)))
	if err := pinExpired.Authorize(t.Context(), server.AuthRequest{JobID: "j"}); err == nil || n.Load() != 0 {
		t.Errorf("a pinned but expired cosigner certificate was accepted: %v", err)
	}
	_ = s
}

// The party does not start with a cosigner channel it cannot authenticate: no pin (production), a bad pin, a missing or expired own certificate.
func TestCosignerAuthorizerRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	p := valid(t, dir, "party-b")
	expired, _, _ := newPCert(t, dir, "party-expired", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, nil, false)
	pin := valid(t, dir, "cosigner-b").pin
	t.Setenv("QV_ALLOW_PLAINTEXT", "")
	t.Setenv("QV_ENV", "")
	for name, c := range map[string]struct {
		pins     []string
		crt, key string
	}{
		"no pin in production":    {nil, p.crt, p.key},
		"bad pin":                 {[]string{"nothex"}, p.crt, p.key},
		"missing own certificate": {[]string{pin}, "/nonexistent.crt", p.key},
		"expired own certificate": {[]string{pin}, expired.crt, expired.key},
	} {
		if _, err := server.NewCosignerAuthorizer("/x.sock", time.Second, c.pins, c.crt, c.key); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	// plaintext only under the development switch, both variables
	t.Setenv("QV_ALLOW_PLAINTEXT", "1")
	if _, err := server.NewCosignerAuthorizer("/x.sock", time.Second, nil, p.crt, p.key); err == nil {
		t.Error("plain text accepted with QV_ALLOW_PLAINTEXT=1 alone (QV_ENV unset = production)")
	}
	t.Setenv("QV_ENV", "prod")
	if _, err := server.NewCosignerAuthorizer("/x.sock", time.Second, nil, p.crt, p.key); err == nil {
		t.Error("plain text accepted in QV_ENV=prod")
	}
	t.Setenv("QV_ENV", "test")
	if _, err := server.NewCosignerAuthorizer("/x.sock", time.Second, nil, p.crt, p.key); err != nil {
		t.Errorf("the development switch is refused: %v", err)
	}
}
