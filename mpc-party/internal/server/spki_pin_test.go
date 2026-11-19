package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

func spkiCert(t *testing.T, k *ecdsa.PrivateKey, serial int64, from, to time.Time) tls.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "p"}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func pinStr(t *testing.T, c tls.Certificate) string {
	t.Helper()
	p, err := server.PinOf(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return p.String()
}

// shake runs one mutual TLS handshake between the mesh/caller-port configs and returns both sides' errors.
func shake(t *testing.T, srvCert tls.Certificate, srvPins []string, cliCert tls.Certificate, cliPins []string) (srvErr, cliErr error) {
	t.Helper()
	sp, err := wire.ParsePins(srvPins)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := wire.ParsePins(cliPins)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		c := tls.Server(a, server.ServerTLS(srvCert, sp))
		err := c.Handshake()
		if err == nil { // TLS 1.3: the client's certificate is checked after its Finished; read to see a late alert
			_, err = c.Read(make([]byte, 1))
		}
		done <- err
	}()
	c := tls.Client(b, server.ClientTLS(cliCert, cp))
	cliErr = c.Handshake()
	if cliErr == nil {
		_, _ = c.Write([]byte{1})
	}
	b.Close()
	srvErr = <-done
	if cliErr == nil && srvErr != nil && strings.Contains(srvErr.Error(), "EOF") {
		srvErr = nil
	}
	return
}

// Mesh and caller port share these configs (party <-> party, gateway <-> party caller port).
func TestMeshPinsAreSPKI(t *testing.T) {
	now := time.Now()
	ks, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kc, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kn, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv, cli := spkiCert(t, ks, 1, now.Add(-time.Hour), now.Add(time.Hour)), spkiCert(t, kc, 2, now.Add(-time.Hour), now.Add(time.Hour))
	sp, cp := pinStr(t, srv), pinStr(t, cli)

	if s, c := shake(t, srv, []string{cp}, cli, []string{sp}); s != nil || c != nil {
		t.Fatalf("baseline: %v / %v", s, c)
	}
	// both sides renewed with the same keys: no config change
	srv2, cli2 := spkiCert(t, ks, 11, now.Add(-time.Minute), now.Add(90*24*time.Hour)), spkiCert(t, kc, 12, now.Add(-time.Minute), now.Add(90*24*time.Hour))
	if s, c := shake(t, srv2, []string{cp}, cli2, []string{sp}); s != nil || c != nil {
		t.Fatalf("renewed with the same key, pins unchanged: %v / %v", s, c)
	}
	// new server key: refused until its pin is added; both pins work during the rotation
	srvN := spkiCert(t, kn, 21, now.Add(-time.Minute), now.Add(time.Hour))
	if _, c := shake(t, srvN, []string{cp}, cli, []string{sp}); c == nil {
		t.Fatal("new server key accepted before its pin was added")
	}
	for _, c := range []tls.Certificate{srv, srvN} {
		if s, e := shake(t, c, []string{cp}, cli, []string{sp, pinStr(t, srvN)}); s != nil || e != nil {
			t.Fatalf("rotation, two pins: %v / %v", s, e)
		}
	}
	// a new client key is refused by the server until pinned
	cliN := spkiCert(t, kn, 31, now.Add(-time.Minute), now.Add(time.Hour))
	if s, c := shake(t, srv, []string{cp}, cliN, []string{sp}); s == nil && c == nil {
		t.Fatal("new client key accepted before its pin was added")
	}
	// expired certificate whose key is pinned
	exp := spkiCert(t, ks, 41, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	if _, c := shake(t, exp, []string{cp}, cli, []string{sp}); c == nil || !strings.Contains(c.Error(), "validity") {
		t.Fatalf("expired certificate with a pinned key: %v", c)
	}
	// an old-style fingerprint of the server certificate in the client's config
	old := wire.CertFingerprint(srv.Certificate[0]).String()
	_, c := shake(t, srv, []string{cp}, cli, []string{old})
	if c == nil || !strings.Contains(c.Error(), "SPKI") || !strings.Contains(c.Error(), "certificate fingerprint") || !strings.Contains(c.Error(), sp) {
		t.Fatalf("old-style pin: want the scheme message, got %v", c)
	}
}
