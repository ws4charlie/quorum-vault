// Package testenv builds throwaway certificates, configs and clients for tests of the mpc-party service. Certificates
// are generated at run time in a temp dir and never committed.
package testenv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

type Cert struct {
	Name    string
	CertPEM []byte
	KeyPEM  []byte
	Pin     string
	TLS     tls.Certificate
}

// NewCert makes a self-signed P-256 certificate valid for one hour.
func NewCert(t testing.TB, name string) Cert {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	c := Cert{Name: name,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
		Pin:     server.PinOf(der).String()}
	c.TLS, err = tls.X509KeyPair(c.CertPEM, c.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Write stores the PEM files in dir and returns their paths.
func (c Cert) Write(t testing.TB, dir string) (certFile, keyFile string) {
	t.Helper()
	certFile, keyFile = filepath.Join(dir, c.Name+".crt"), filepath.Join(dir, c.Name+".key")
	if err := os.WriteFile(certFile, c.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, c.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// FreeAddr returns 127.0.0.1:port for a port that was free a moment ago.
func FreeAddr(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// Env is a full set of identities for one A/B pair plus a legitimate caller.
type Env struct {
	Dir                      string
	CertA, CertB, CertCaller Cert
	Stranger                 Cert // pinned nowhere
	SealKeyFile              string
}

func NewEnv(t testing.TB) *Env {
	t.Helper()
	dir := t.TempDir()
	e := &Env{Dir: dir, CertA: NewCert(t, "party-a"), CertB: NewCert(t, "party-b"), CertCaller: NewCert(t, "caller"), Stranger: NewCert(t, "stranger")}
	e.SealKeyFile = filepath.Join(dir, "seal.key")
	key := make([]byte, 32)
	rand.Read(key)
	if err := os.WriteFile(e.SealKeyFile, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

// Config returns the config of one party. For role A pass B's peer address.
func (e *Env) Config(t testing.TB, role string, peerAddr string, callerAddr, peerListen string) *server.Config {
	t.Helper()
	own, other := e.CertA, e.CertB
	if role == "B" {
		own, other = e.CertB, e.CertA
	}
	crt, key := own.Write(t, e.Dir)
	c := &server.Config{Role: role, CallerListen: callerAddr, CertFile: crt, KeyFile: key,
		PeerPins: []string{other.Pin}, CallerPins: []string{e.CertCaller.Pin},
		DataDir:    filepath.Join(e.Dir, "data-"+role),
		Sealer:     server.SealerConfig{Type: server.InsecureSealerType, KeyFile: e.SealKeyFile},
		Authorizer: server.AuthorizerConfig{Type: "dev-allow-all", AcceptRisk: server.DevAllowAllRiskPhrase}}
	if role == "A" {
		c.PeerAddress = peerAddr
	} else {
		c.PeerListen = peerListen
	}
	return c
}

// WriteConfig writes cfg as JSON and returns the path.
func (e *Env) WriteConfig(t testing.TB, cfg *server.Config, name string) string {
	t.Helper()
	b, _ := json.MarshalIndent(cfg, "", " ")
	p := filepath.Join(e.Dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Dial connects a caller (mTLS, pinned to serverPin) to a caller port.
func Dial(t testing.TB, addr string, client Cert, serverPin string) (pb.MpcPartyClient, *grpc.ClientConn) {
	t.Helper()
	pins, err := parse(serverPin)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(server.ClientTLS(client.TLS, pins))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewMpcPartyClient(conn), conn
}

func parse(pin string) (map[server.Pin]bool, error) {
	p, err := server.ParsePin(pin)
	if err != nil {
		return nil, err
	}
	return map[server.Pin]bool{p: true}, nil
}
