package mpcsigner

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
)

func spki(t *testing.T, k *ecdsa.PrivateKey, serial int64, from, to time.Time) tls.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "p"}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func pinOf(t *testing.T, c tls.Certificate) string {
	t.Helper()
	p, err := wire.PinOf(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return p.String()
}

// handshake dials a party presenting srv from a gateway whose server_pin is pin; it returns the gateway side's error.
func handshake(t *testing.T, srv tls.Certificate, pin string) error {
	t.Helper()
	cli := spki(t, mustKey(t), 99, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	creds, err := pinnedCreds(cli, pin)
	if err != nil {
		return err
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		c := tls.Server(a, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{srv}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{"h2"}})
		_ = c.Handshake()
	}()
	_, _, err = creds.ClientHandshake(t.Context(), "party", b)
	return err
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The gateway's server_pin is the SHA-256 of the party's public key: renewal with the same key needs no config change.
func TestServerPinIsSPKI(t *testing.T) {
	now := time.Now()
	k, kn := mustKey(t), mustKey(t)
	srv := spki(t, k, 1, now.Add(-time.Hour), now.Add(time.Hour))
	pin := pinOf(t, srv)
	if err := handshake(t, srv, pin); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := handshake(t, spki(t, k, 2, now.Add(-time.Minute), now.Add(90*24*time.Hour)), pin); err != nil {
		t.Fatalf("renewed with the same key, same server_pin: %v", err)
	}
	if err := handshake(t, spki(t, kn, 3, now.Add(-time.Minute), now.Add(time.Hour)), pin); err == nil {
		t.Fatal("a new key was accepted under the old pin")
	}
	if err := handshake(t, spki(t, k, 4, now.Add(-3*time.Hour), now.Add(-2*time.Hour)), pin); err == nil || !strings.Contains(err.Error(), "validity") {
		t.Fatalf("expired certificate with a pinned key: %v", err)
	}
	err := handshake(t, srv, wire.CertFingerprint(srv.Certificate[0]).String())
	if err == nil || !strings.Contains(err.Error(), "SPKI") || !strings.Contains(err.Error(), "certificate fingerprint") {
		t.Fatalf("old-style pin: want the scheme message, got %v", err)
	}
}
