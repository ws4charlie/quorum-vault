// Package testenv builds throwaway certificates, configs and clients for tests of the mpc-party service. Certificates
// are generated at run time in a temp dir and never committed.
package testenv

import (
	"context"
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
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
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
		Pin:     mustPinOf(t, der)}
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

// FreeAddr returns 127.0.0.1:port for a port that was free a moment ago. A port is looked for below the kernel's dynamic range
// (20000 to 31999) first: any client socket of any process can take a port from that range between our probe and the party's bind
// (the cause of "bind: address already in use" in CI, as in e2e/mpcstack.FreeAddr). An address is never returned twice in a test
// binary; only EADDRINUSE is retried, any other error ends the test; the kernel's choice is the bounded fallback.
func FreeAddr(t testing.TB) string {
	t.Helper()
	freeMu.Lock()
	defer freeMu.Unlock()
	try := func(addr string) string {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) {
				return ""
			}
			t.Fatal(err)
		}
		got := l.Addr().String()
		l.Close()
		if freeGiven[got] {
			return ""
		}
		freeGiven[got] = true
		return got
	}
	for i := 0; i < 300; i++ {
		if a := try(fmt.Sprintf("127.0.0.1:%d", 20000+mrand.IntN(12000))); a != "" {
			return a
		}
	}
	for i := 0; i < 1000; i++ {
		if a := try("127.0.0.1:0"); a != "" {
			return a
		}
	}
	t.Fatal("FreeAddr: no free port after 1300 tries")
	return ""
}

// Env is a full set of identities for one A/B pair plus a legitimate caller.
type Env struct {
	Dir                             string
	CertA, CertB, CertC, CertCaller Cert
	Stranger                        Cert // pinned nowhere
	SealKeyFile                     string
	mu                              sync.Mutex
	n                               int
	// AdminKeys is the admin set the parties are configured with: three keys, two of them needed (admin_threshold 2). AdminPriv/AdminPub are the first.
	AdminKeys []ed25519.PrivateKey
	AdminPriv ed25519.PrivateKey
	AdminPub  ed25519.PublicKey
	pending   map[string][]ed25519.PrivateKey // nonce of a placeholder authorization -> who signs it
}

// AdminThreshold is the admin_threshold every test party is configured with.
const AdminThreshold = 2

func (e *Env) adminKeyHex() []string {
	var l []string
	for _, k := range e.AdminKeys {
		l = append(l, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	}
	return l
}

func NewEnv(t testing.TB) *Env {
	t.Helper()
	dir := t.TempDir()
	var keys []ed25519.PrivateKey
	for range 3 {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		keys = append(keys, k)
	}
	apriv := keys[0]
	apub := apriv.Public().(ed25519.PublicKey)
	e := &Env{AdminKeys: keys, pending: map[string][]ed25519.PrivateKey{}, AdminPriv: apriv, AdminPub: apub, Dir: dir, CertA: NewCert(t, "party-a"), CertB: NewCert(t, "party-b"), CertC: NewCert(t, "party-c"), CertCaller: NewCert(t, "caller"), Stranger: NewCert(t, "stranger")}
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
		PeerPins: []string{other.Pin}, CallerPins: []string{e.CertCaller.Pin}, AdminKeys: e.adminKeyHex(), AdminThreshold: AdminThreshold,
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
		AdminKeys: e.adminKeyHex(), AdminThreshold: AdminThreshold,
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

// DialAs connects a caller (mTLS, pinned to serverPin) to a caller port, for a test that signs admin calls: a request whose Admin comes from Env.Admin or Env.AdminBy is signed here, over the request
// as it goes out, so the test does not repeat the request body to sign it.
func (e *Env) DialAs(t testing.TB, addr string, client Cert, serverPin string) (pb.MpcPartyClient, *grpc.ClientConn) {
	t.Helper()
	pins, err := parse(serverPin)
	if err != nil {
		t.Fatal(err)
	}
	return dialWith(t, addr, client, pins, e.signInterceptor())
}

func dialWith(t testing.TB, addr string, client Cert, pins map[server.Pin]bool, ic grpc.UnaryClientInterceptor) (pb.MpcPartyClient, *grpc.ClientConn) {
	t.Helper()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(server.ClientTLS(client.TLS, pins)))}
	if ic != nil {
		opts = append(opts, grpc.WithUnaryInterceptor(ic))
	}
	conn, err := grpc.NewClient(addr, opts...)
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

// Admin is a placeholder authorization for the admin call it is put into (op and keysetID only name it for the reader): the client made by
// DialAs signs it with the first AdminThreshold admin keys over that request's body, with a fresh nonce, valid for ten minutes. Sending the same
// request object twice replays the signed authorization, as a captured request would be.
func (e *Env) Admin(op, keysetID string) *pb.AdminAuth {
	return e.AdminBy(e.AdminKeys[:AdminThreshold]...)
}

// AdminBy is Admin signed by exactly these keys (a stranger, one key too few, the same key twice ...).
func (e *Env) AdminBy(keys ...ed25519.PrivateKey) *pb.AdminAuth {
	var nonce [admin.NonceSize]byte
	rand.Read(nonce[:])
	e.mu.Lock()
	e.pending[string(nonce[:])] = keys
	e.mu.Unlock()
	now := time.Now()
	return &pb.AdminAuth{V2: &pb.AdminAuthV2{IssuedUnix: now.Unix(), ExpiresUnix: now.Add(10 * time.Minute).Unix(), Nonce: nonce[:]}}
}

// SignAuth completes an authorization for (op, req) with keys, as the CLI flow would: the body hash comes from req itself.
func SignAuth(op string, req proto.Message, domain string, issued, expires time.Time, nonce []byte, keys ...ed25519.PrivateKey) (*pb.AdminAuth, error) {
	if d, ok := req.(*pb.DKGRequest); ok {
		req = admin.DKGBody(d.KeysetId, d.Scheme, d.Curve)
	}
	hash, err := admin.BodyHash(op, req)
	if err != nil {
		return nil, err
	}
	return admin.AuthorizeWithNonce(op, req, domain, issued, expires, nonce, hash, keys...), nil
}

func (e *Env) signInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, inv grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		var op string
		var a **pb.AdminAuth
		switch r := req.(type) {
		case *pb.DKGRequest:
			op, a = admin.OpDKG, &r.Admin
		case *pb.RefreshRequest:
			op, a = admin.OpRefresh, &r.Admin
		case *pb.UnfreezeRequest:
			op, a = admin.OpUnfreeze, &r.Admin
		}
		if a != nil && (*a).GetV2() != nil && len((*a).V2.Signatures) == 0 {
			v := (*a).V2
			e.mu.Lock()
			keys, ok := e.pending[string(v.Nonce)]
			e.mu.Unlock()
			if ok {
				signed, err := SignAuth(op, req.(proto.Message), v.Domain, time.Unix(v.IssuedUnix, 0), time.Unix(v.ExpiresUnix, 0), v.Nonce, keys...)
				if err != nil {
					return err
				}
				*a = signed
			}
		}
		return inv(ctx, method, req, reply, cc, opts...)
	}
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
// and returns the PIN (QV_HSM_PIN, or the .env that `make dev-env` writes at the repo root; there is no default). The test is skipped when SoftHSM is not set up,
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
	t.Setenv("QV_ENV", "test") // SoftHSM is refused when QV_ENV is unset (production); child processes inherit this
	pin = os.Getenv("QV_HSM_PIN")
	if pin == "" {
		pin = pinFromDotEnv(dir)
	}
	if pin == "" {
		msg := "QV_HSM_PIN is not set: run `make dev-env` in the repository root (it writes random PINs to .env)"
		if os.Getenv("QV_REQUIRE_HSM") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return pin
}

// pinFromDotEnv reads QV_HSM_PIN from the first .env found from dir upwards (the repo root), or returns "".
func pinFromDotEnv(dir string) string {
	for d := dir; ; d = filepath.Dir(d) {
		if b, err := os.ReadFile(filepath.Join(d, ".env")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "QV_HSM_PIN="); ok {
					return v
				}
			}
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

func mustPinOf(t testing.TB, der []byte) string {
	t.Helper()
	p, err := server.PinOf(der)
	if err != nil {
		t.Fatal(err)
	}
	return p.String()
}
