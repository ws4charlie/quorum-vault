// Package testenv builds throwaway certificates, configs and clients for tests of the mpc-party service. Certificates
// are generated at run time in a temp dir and never committed.
package testenv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
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

var (
	freeMu    sync.Mutex
	freeGiven = map[string]bool{}
)

// FreeAddr returns 127.0.0.1:port for a port that was free a moment ago. The kernel may hand out a port again as soon as it is
// closed, so one test could give the same port to two processes: an address is never returned twice in a test binary.
func FreeAddr(t testing.TB) string {
	t.Helper()
	freeMu.Lock()
	defer freeMu.Unlock()
	for {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		if !freeGiven[addr] {
			freeGiven[addr] = true
			return addr
		}
	}
}

// Env is a full set of identities for one A/B pair plus a legitimate caller.
type Env struct {
	Dir                             string
	CertA, CertB, CertC, CertCaller Cert
	Stranger                        Cert // pinned nowhere
	SealKeyFile                     string
	mu                              sync.Mutex
	n                               int
	AdminPriv                       ed25519.PrivateKey
	AdminPub                        ed25519.PublicKey
}

func NewEnv(t testing.TB) *Env {
	t.Helper()
	dir := t.TempDir()
	apub, apriv, _ := ed25519.GenerateKey(rand.Reader)
	e := &Env{AdminPriv: apriv, AdminPub: apub, Dir: dir, CertA: NewCert(t, "party-a"), CertB: NewCert(t, "party-b"), CertC: NewCert(t, "party-c"), CertCaller: NewCert(t, "caller"), Stranger: NewCert(t, "stranger")}
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
		PeerPins: []string{other.Pin}, CallerPins: []string{e.CertCaller.Pin}, AdminKeys: []string{hex.EncodeToString(e.AdminPub)},
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

// Addrs are the listen addresses of a three-party deployment.
type Addrs struct {
	CallerA, CallerB, CallerC string
	PeerB, PeerC              string
}

// NewAddrs picks free addresses.
func NewAddrs(t testing.TB) Addrs {
	return Addrs{CallerA: FreeAddr(t), CallerB: FreeAddr(t), CallerC: FreeAddr(t), PeerB: FreeAddr(t), PeerC: FreeAddr(t)}
}

// Config3 returns the config of one party of a three-party (A, B, C) deployment: A dials B and C, B dials C. peerB and peerC
// are the addresses A and B actually dial (they may point at a proxy).
func (e *Env) Config3(t testing.TB, role string, a Addrs, dialB, dialC string) *server.Config {
	t.Helper()
	own := map[string]Cert{"A": e.CertA, "B": e.CertB, "C": e.CertC}[role]
	crt, key := own.Write(t, e.Dir)
	c := &server.Config{Role: role, CertFile: crt, KeyFile: key, CallerPins: []string{e.CertCaller.Pin},
		AdminKeys:  []string{hex.EncodeToString(e.AdminPub)},
		DataDir:    filepath.Join(e.Dir, "data-"+role),
		Sealer:     server.SealerConfig{Type: server.InsecureSealerType, KeyFile: e.SealKeyFile},
		Authorizer: server.AuthorizerConfig{Type: "dev-allow-all", AcceptRisk: server.DevAllowAllRiskPhrase}}
	switch role {
	case "A":
		c.CallerListen, c.PeerAddress, c.PeerPins = a.CallerA, dialB, []string{e.CertB.Pin}
		c.PeerCAddress, c.PeerCPins = dialC, []string{e.CertC.Pin}
	case "B":
		c.CallerListen, c.PeerListen, c.PeerPins = a.CallerB, a.PeerB, []string{e.CertA.Pin}
		c.PeerCAddress, c.PeerCPins = dialC, []string{e.CertC.Pin}
	case "C":
		c.CallerListen, c.PeerListen = a.CallerC, a.PeerC
		c.PeerAPins, c.PeerBPins = []string{e.CertA.Pin}, []string{e.CertB.Pin}
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

// Admin signs an operator authorization for (op, keyset) with the environment's admin key.
// Each call uses a timestamp one second later than the previous: Ed25519 signatures are deterministic and an admin
// signature is accepted only once.
func (e *Env) Admin(op, keysetID string) *pb.AdminAuth {
	e.mu.Lock()
	e.n++
	n := e.n
	e.mu.Unlock()
	return server.SignAdmin(e.AdminPriv, op, keysetID, time.Now().Add(time.Duration(n)*time.Second))
}

// CertCallerKey returns an Ed25519 key that is NOT a configured admin key (for refusal tests).
func (e *Env) CertCallerKey() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}

// StaticSealer is a test-only AES-256-GCM sealer with an in-memory key. It lives here, not in the server package, so that a
// production build of the service contains no insecure sealer at all.
type StaticSealer struct{ gcm cipher.AEAD }

func NewStaticSealer(t testing.TB) *StaticSealer {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return &StaticSealer{g}
}

func (s *StaticSealer) Seal(aad, pt []byte) ([]byte, error) {
	n := make([]byte, s.gcm.NonceSize())
	rand.Read(n)
	return s.gcm.Seal(n, n, pt, aad), nil
}

func (s *StaticSealer) Open(aad, ct []byte) ([]byte, error) {
	n := s.gcm.NonceSize()
	if len(ct) < n+s.gcm.Overhead() {
		return nil, errors.New("short")
	}
	return s.gcm.Open(nil, ct[:n], ct[n:], aad)
}

// Store builds a file store for one party with a fresh StaticSealer.
func Store(t testing.TB, cfg *server.Config) *server.FileStore {
	t.Helper()
	fs, err := server.NewFileStore(cfg.DataDir, cfg.Role, NewStaticSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// HSMEnv points SOFTHSM2_CONF at the repo-local SoftHSM config written by scripts/setup-softhsm.sh (<repo root>/data/softhsm)
// and returns the PIN (QV_HSM_PIN or the documented dev-only default). The test is skipped when SoftHSM is not set up,
// unless QV_REQUIRE_HSM=1, then it fails.
func HSMEnv(t testing.TB) (pin string) {
	t.Helper()
	dir, _ := os.Getwd()
	conf := ""
	for d := dir; ; d = filepath.Dir(d) {
		c := filepath.Join(d, "data", "softhsm", "softhsm2.conf")
		if _, err := os.Stat(c); err == nil {
			conf = c
			break
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if os.Getenv("SOFTHSM2_CONF") != "" {
		conf = os.Getenv("SOFTHSM2_CONF")
	}
	if conf == "" {
		if os.Getenv("QV_REQUIRE_HSM") == "1" {
			t.Fatal("QV_REQUIRE_HSM=1 but no SoftHSM config: run scripts/setup-softhsm.sh")
		}
		t.Skip("no SoftHSM config: run scripts/setup-softhsm.sh")
	}
	os.Setenv("SOFTHSM2_CONF", conf)
	pin = os.Getenv("QV_HSM_PIN")
	if pin == "" {
		pin = "user-dev-1234" // dev-only value, documented in .env.example
	}
	return pin
}
