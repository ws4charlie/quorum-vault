package cosigner_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/cosigner"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
)

type tcert struct {
	cert tls.Certificate
	pin  string
}

func mkCert(t *testing.T, name string, notBefore, notAfter time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (tcert, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: isCA, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if parent == nil {
		parent, parentKey = tpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tcert{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pin: mustPin(t, der)}, leaf, k
}

func selfSigned(t *testing.T, name string) tcert {
	c, _, _ := mkCert(t, name, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil, nil, false)
	return c
}

func writePair(t *testing.T, c tcert) (crt, key string) {
	t.Helper()
	dir := t.TempDir()
	crt, key = filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	kb, _ := x509.MarshalECPrivateKey(c.cert.PrivateKey.(*ecdsa.PrivateKey))
	write := func(p, typ string, der []byte) {
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(crt, "CERTIFICATE", c.cert.Certificate[0])
	write(key, "EC PRIVATE KEY", kb)
	return
}

// A stub that answers "allow" to everything and counts how often it was reached: the authentication must stop a caller before this.
func serve(t *testing.T, cfg *tls.Config) (sock string, reached *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("", "qv") // short: unix socket paths are limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, "c.sock")
	ln, err := cosigner.ListenUnixTLS(sock, cfg)
	if err != nil {
		t.Fatal(err)
	}
	reached = new(atomic.Int32)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.Path, func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		json.NewEncoder(w).Encode(wire.Response{Allow: true})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return
}

func call(sock string, cfg *tls.Config) (*wire.Response, error) {
	scheme := "http"
	if cfg != nil {
		scheme = "https"
	}
	cl := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	resp, err := cl.Post(scheme+"://cosigner"+wire.Path, "application/json", strings.NewReader(`{}`))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out wire.Response
	json.NewDecoder(resp.Body).Decode(&out)
	return &out, nil
}

// Only the paired party gets an answer. Nobody else, with or without a certificate, reaches the handler.
func TestSocketAcceptsOnlyThePairedParty(t *testing.T) {
	cosCert := selfSigned(t, "cosigner-b")
	partyB, partyC := selfSigned(t, "party-b"), selfSigned(t, "party-c")
	crt, key := writePair(t, cosCert)
	cfg, err := cosigner.SocketTLS(crt, key, []string{partyB.pin})
	if err != nil {
		t.Fatal(err)
	}
	sock, reached := serve(t, cfg)
	trust := func(c tcert, own tcert) *tls.Config {
		pins, _ := wire.ParsePins([]string{c.pin})
		return wire.ClientTLS(own.cert, pins)
	}
	// the other zone's CA issues a certificate with the same name as party B: a CA is not what we trust
	ca, caLeaf, caKey := mkCert(t, "other-zone-ca", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, true)
	_ = ca
	otherZoneB, _, _ := mkCert(t, "party-b", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), caLeaf, caKey, false)
	expiredB := func() tcert { // same key material is not reusable: a pinned but expired certificate of its own
		c, _, _ := mkCert(t, "party-b", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, nil, false)
		return c
	}()
	// a pinned-but-expired caller must also fail: re-pin the server on it
	crt2, key2 := writePair(t, cosCert)
	cfgExp, err := cosigner.SocketTLS(crt2, key2, []string{expiredB.pin})
	if err != nil {
		t.Fatal(err)
	}
	sockExp, reachedExp := serve(t, cfgExp)

	if r, err := call(sock, trust(cosCert, partyB)); err != nil || !r.Allow {
		t.Fatalf("the paired party was refused: %v %+v", err, r)
	}
	if reached.Load() != 1 {
		t.Fatalf("handler reached %d times, want 1", reached.Load())
	}
	for name, c := range map[string]*tls.Config{
		"no certificate":            wire.ClientTLS(tls.Certificate{}, mustPins(t, cosCert.pin)),
		"the other party's cert":    trust(cosCert, partyC),
		"the same name, other CA":   trust(cosCert, otherZoneB),
		"plain text":                nil,
		"does not pin the cosigner": trust(selfSigned(t, "someone"), partyB),
	} {
		before := reached.Load()
		if r, err := call(sock, c); err == nil && r.Allow {
			t.Errorf("%s: the cosigner answered allow", name)
		}
		if reached.Load() != before {
			t.Errorf("%s: the handler was reached", name)
		}
	}
	if r, err := call(sockExp, trust(cosCert, expiredB)); err == nil && r.Allow || reachedExp.Load() != 0 {
		t.Errorf("an expired party certificate was accepted")
	}
}

func mustPins(t *testing.T, s string) map[wire.Pin]bool {
	p, err := wire.ParsePins([]string{s})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The cosigner will not start its socket without its material: no pin, an unreadable, mismatched or expired certificate.
func TestSocketTLSRefusals(t *testing.T) {
	good := selfSigned(t, "cosigner-b")
	crt, key := writePair(t, good)
	pin := selfSigned(t, "party-b").pin
	if _, err := cosigner.SocketTLS(crt, key, nil); err == nil {
		t.Error("no party pin accepted")
	}
	if _, err := cosigner.SocketTLS(crt, key, []string{"zz"}); err == nil {
		t.Error("a bad pin accepted")
	}
	if _, err := cosigner.SocketTLS("/nonexistent.crt", key, []string{pin}); err == nil {
		t.Error("a missing certificate accepted")
	}
	exp, _, _ := mkCert(t, "cosigner-b", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, nil, false)
	ecrt, ekey := writePair(t, exp)
	if _, err := cosigner.SocketTLS(ecrt, ekey, []string{pin}); err == nil {
		t.Error("an expired certificate accepted")
	}
	if _, err := cosigner.SocketTLS(crt, key, []string{pin}); err != nil {
		t.Errorf("good material refused: %v", err)
	}
}

func mustPin(t *testing.T, der []byte) string {
	t.Helper()
	p, err := wire.PinOf(der)
	if err != nil {
		t.Fatal(err)
	}
	return p.String()
}

func sameKeyCert(t *testing.T, k *ecdsa.PrivateKey, serial int64, from, to time.Time) tcert {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "p"}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tcert{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pin: mustPin(t, der)}
}

// Pins on the cosigner channel are SPKI pins: renewal with the same key needs no config change, a new key needs its pin (two
// pins during a rotation), and an old-style whole-certificate pin fails with a message that names the scheme.
func TestSocketPinsAreSPKI(t *testing.T) {
	now := time.Now()
	kp, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kc, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kn, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	party := sameKeyCert(t, kp, 1, now.Add(-time.Hour), now.Add(time.Hour))
	cos := sameKeyCert(t, kc, 2, now.Add(-time.Hour), now.Add(time.Hour))
	crt, key := writePair(t, cos)
	cfg, err := cosigner.SocketTLS(crt, key, []string{party.pin})
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := serve(t, cfg)
	client := func(own tcert, pins ...string) *tls.Config {
		m, err := wire.ParsePins(pins)
		if err != nil {
			t.Fatal(err)
		}
		return wire.ClientTLS(own.cert, m)
	}
	if r, err := call(sock, client(party, cos.pin)); err != nil || !r.Allow {
		t.Fatalf("baseline: %v", err)
	}
	// the party renewed its certificate with the same key; the cosigner config is unchanged
	renewed := sameKeyCert(t, kp, 9, now.Add(-time.Minute), now.Add(90*24*time.Hour))
	if r, err := call(sock, client(renewed, cos.pin)); err != nil || !r.Allow {
		t.Fatalf("renewed party certificate (same key) refused: %v", err)
	}
	// the cosigner renewed its own certificate with the same key: the party's pin still holds
	cos2 := sameKeyCert(t, kc, 10, now.Add(-time.Minute), now.Add(90*24*time.Hour))
	crt2, key2 := writePair(t, cos2)
	cfg2, err := cosigner.SocketTLS(crt2, key2, []string{party.pin})
	if err != nil {
		t.Fatal(err)
	}
	sock2, _ := serve(t, cfg2)
	if r, err := call(sock2, client(party, cos.pin)); err != nil || !r.Allow {
		t.Fatalf("renewed cosigner certificate (same key) refused: %v", err)
	}
	// a new party key: refused until pinned; with two pins both keys work
	newParty := sameKeyCert(t, kn, 11, now.Add(-time.Minute), now.Add(time.Hour))
	if r, err := call(sock, client(newParty, cos.pin)); err == nil && r.Allow {
		t.Fatal("a new party key was accepted before its pin was added")
	}
	crt3, key3 := writePair(t, cos)
	cfg3, err := cosigner.SocketTLS(crt3, key3, []string{party.pin, newParty.pin})
	if err != nil {
		t.Fatal(err)
	}
	sock3, _ := serve(t, cfg3)
	for _, p := range []tcert{party, newParty} {
		if r, err := call(sock3, client(p, cos.pin)); err != nil || !r.Allow {
			t.Fatalf("rotation with two pins: %v", err)
		}
	}
	// an old-style fingerprint of the cosigner's certificate on the party side
	_, err = call(sock, client(party, wire.CertFingerprint(cos.cert.Certificate[0]).String()))
	if err == nil || !strings.Contains(err.Error(), "SPKI") || !strings.Contains(err.Error(), "certificate fingerprint") {
		t.Fatalf("old-style pin: want the scheme message, got %v", err)
	}
	// an expired certificate with a pinned key (existing test covers the CA-issued kind; this one reuses the pinned key)
	expired := sameKeyCert(t, kp, 12, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	if r, err := call(sock, client(expired, cos.pin)); err == nil && r.Allow {
		t.Fatal("an expired certificate with a pinned key was accepted")
	}
}

// The socket certificate's time left is published under the name every other certificate uses, so the one alert rule covers it.
func TestSocketMetricsExpiry(t *testing.T) {
	c := selfSigned(t, "cosigner-b")
	crt, key := writePair(t, c)
	partyB := selfSigned(t, "party-b")
	cfg, err := cosigner.SocketTLS(crt, key, []string{partyB.pin})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var b strings.Builder
	cosigner.WriteSocketMetrics(&b, cfg, now)
	line := strings.TrimSpace(b.String())
	if !strings.HasPrefix(line, `qv_tls_cert_seconds_to_expiry{name="qv-cosigner-socket",zone="signing",kind="leaf"} `) {
		t.Fatalf("metric line: %q", line)
	}
	leaf, _ := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	want := fmt.Sprintf("%.0f", leaf.NotAfter.Sub(now).Seconds())
	if !strings.HasSuffix(line, " "+want) {
		t.Fatalf("value: %q, want suffix %s", line, want)
	}
	// a later look shows less time; past the end it is negative
	b.Reset()
	cosigner.WriteSocketMetrics(&b, cfg, leaf.NotAfter.Add(time.Hour))
	if !strings.Contains(b.String(), "} -3600") {
		t.Fatalf("after expiry: %q", b.String())
	}
	b.Reset()
	cosigner.WriteSocketMetrics(&b, nil, now) // the development plain-text channel has no certificate
	if b.Len() != 0 {
		t.Fatalf("nil config wrote %q", b.String())
	}
}
