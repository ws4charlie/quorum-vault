// Package mpcsign_test runs the real processes of the cb-mpc signing path: qv-gateway, mpc-party A and B, qv-cosigner,
// Postgres and (for the mining test) anvil. It needs the cb-mpc build (mpc-party/scripts/fetch-build-cbmpc.sh) and is
// skipped unless QV_MPC_E2E=1:  make test-mpc
package mpcsign_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

var binMPC, binCosigner, binGateway string

func TestMain(m *testing.M) {
	mpcstack.ReaperMain() // in the reaper process: waits for this binary to die, kills the children, never returns
	stopReaper := func() {}
	if os.Getenv("QV_MPC_E2E") != "1" {
		fmt.Println("skipped: set QV_MPC_E2E=1 (needs the cb-mpc build, Postgres; see make test-mpc)")
		os.Exit(0)
	}
	if stop, err := mpcstack.StartReaper(); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	} else {
		stopReaper = stop
	}
	dir, err := os.MkdirTemp("", "mpcsign-bin-")
	if err != nil {
		panic(err)
	}
	build := func(workdir, out, pkg string) string {
		p := filepath.Join(dir, out)
		cmd := exec.Command("go", "build", "-o", p, pkg)
		cmd.Dir = workdir
		if o, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s failed: %v\n%s\n", out, err, o)
			os.Exit(1)
		}
		return p
	}
	binMPC = build("../../mpc-party", "mpc-party", "./cmd/mpc-party") // production build: no dev authorizer
	binCosigner = build("../..", "qv-cosigner", "./cmd/qv-cosigner")
	binGateway = build("../..", "qv-gateway", "./cmd/qv-gateway")
	code := m.Run()
	stopReaper()
	os.RemoveAll(dir)
	os.Exit(code)
}

// ---- certificates ----

type cert struct {
	name    string
	certPEM []byte
	keyPEM  []byte
	pin     string
	tls     tls.Certificate
}

func newCert(t testing.TB, name string) cert {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	c := cert{name: name, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})}
	sum := sha256.Sum256(der)
	c.pin = hex.EncodeToString(sum[:])
	c.tls, err = tls.X509KeyPair(c.certPEM, c.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (c cert) write(t testing.TB, dir string) (crt, key string) {
	crt, key = filepath.Join(dir, c.name+".crt"), filepath.Join(dir, c.name+".key")
	if err := os.WriteFile(crt, c.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, c.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// pinnedTLS: TLS 1.3, our certificate, trusts exactly the pinned peer certificate.
func pinnedTLS(own cert, peerPin string) *tls.Config {
	want, _ := hex.DecodeString(peerPin)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{own.tls}, InsecureSkipVerify: true, //nolint:gosec
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fmt.Errorf("no certificate")
			}
			if sum := sha256.Sum256(raw[0]); !bytes.Equal(sum[:], want) {
				return fmt.Errorf("certificate is not the pinned one")
			}
			return nil
		}}
}

// ---- processes ----

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type proc struct {
	name string
	cmd  *exec.Cmd
	out  *syncBuf
	done chan struct{}
}

func startProc(t testing.TB, name, bin string, env []string, args ...string) *proc {
	t.Helper()
	p := &proc{name: name, cmd: exec.Command(bin, args...), out: &syncBuf{}, done: make(chan struct{})}
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stdout, p.cmd.Stderr = p.out, p.out
	mpcstack.Guard(p.cmd)
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.stop() })
	return p
}

func (p *proc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
}

func (p *proc) kill() { p.cmd.Process.Kill(); <-p.done }

var (
	freeMu    sync.Mutex
	freeGiven = map[string]bool{}
)

// freeAddr returns 127.0.0.1:port for a port that was free a moment ago. The kernel may hand out a port again as soon as it is closed,
// so an address is never returned twice in a test binary: two processes must not be given the same port.
func freeAddr(t testing.TB) string {
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

// ---- the stack ----

type stack struct {
	t        *testing.T
	dir      string
	certA    cert
	certB    cert
	certGW   cert // the gateway's client certificate (pinned by party A's caller port)
	certProx cert
	adminPub ed25519.PublicKey
	admin    ed25519.PrivateKey

	callerA, callerB, peerB string
	peerForA                string // where A dials: B's peer port, or the tamper proxy
	sock                    string

	proxy          *tamperProxy
	cosignerTweak  func(gateway.File) gateway.File
	a, b, cosigner *proc
	cfgA, cfgB     string
	cosignerArgs   []string
	cosignerCfg    string

	client pb.MpcPartyClient // gateway identity -> party A
	conn   *grpc.ClientConn

	keysetID string
	keyID    string
	pub33    []byte
	pub65    []byte
	hot      common.Address

	h                      *gatewaytest.Harness
	biz                    *pgxpool.Pool
	bizDSN                 string
	gwGuardDSN, csGuardDSN string
	chainID                uint64
}

type stackOpts struct {
	chainID  uint64
	proxy    bool // A talks to B through a session-level proxy (set up by the test via startProxy)
	noCosign bool
}

func (s *stack) adminAuth(op, keyset string, at time.Time) *pb.AdminAuth {
	return admin.Sign(s.admin, op, keyset, at)
}

var adminSkew int

// adminNow returns an admin signature timestamp that has not been used: signatures are deterministic per second.
func adminNow() time.Time { adminSkew++; return time.Now().Add(time.Duration(adminSkew) * time.Second) }

func newStack(t *testing.T, o stackOpts) *stack {
	t.Helper()
	if o.chainID == 0 {
		o.chainID = 31337
	}
	s := &stack{t: t, dir: t.TempDir(), chainID: o.chainID, keysetID: "hot"}
	s.certA, s.certB, s.certGW, s.certProx = newCert(t, "party-a"), newCert(t, "party-b"), newCert(t, "gateway"), newCert(t, "proxy")
	s.adminPub, s.admin, _ = ed25519.GenerateKey(rand.Reader)
	s.callerA, s.callerB, s.peerB = freeAddr(t), freeAddr(t), freeAddr(t)
	s.peerForA = s.peerB
	s.sock = filepath.Join(os.TempDir(), fmt.Sprintf("qvcs-%d.sock", time.Now().UnixNano()%1e9))
	t.Cleanup(func() { os.Remove(s.sock) })
	pin := ""
	if o.proxy {
		// A believes the proxy is party B; B believes the proxy is party A.
		s.proxy, s.peerForA = startProxy(t, s)
		pin = s.certProx.pin
	}
	s.cfgA, s.cfgB = s.writeParty(t, "A", "", pin), s.writeParty(t, "B", "", pin)
	s.startParties(t)
	return s
}

// writeParty writes a mpc-party config. peerPin overrides the pin of the other party (tamper proxy).
func (s *stack) writeParty(t *testing.T, role, seal, peerPin string) string {
	own, other := s.certA, s.certB
	if role == "B" {
		own, other = s.certB, s.certA
	}
	if peerPin == "" {
		peerPin = other.pin
	}
	crt, key := own.write(t, s.dir)
	cfg := map[string]any{
		"role": role, "cert_file": crt, "key_file": key, "peer_pins": []string{peerPin}, "caller_pins": []string{s.certGW.pin},
		"data_dir": filepath.Join(s.dir, "data-"+role), "admin_keys": []string{hex.EncodeToString(s.adminPub)},
		"sealer": mpcstack.SealerConfig(role),
		"limits": map[string]any{"recv_timeout_ms": 3000, "session_timeout_ms": 20000, "sessions_per_sec_key": 100000, "max_peer_sessions": 32},
	}
	if role == "A" {
		cfg["caller_listen"], cfg["peer_address"] = s.callerA, s.peerForA
		cfg["authorizer"] = map[string]any{"type": "pinned-caller"}
	} else {
		cfg["caller_listen"], cfg["peer_listen"] = s.callerB, s.peerB
		cfg["authorizer"] = map[string]any{"type": "cosigner", "socket": s.sock, "timeout_ms": 5000}
	}
	raw, _ := json.MarshalIndent(cfg, "", " ")
	p := filepath.Join(s.dir, "party-"+role+".json")
	os.WriteFile(p, raw, 0o600)
	return p
}

func (s *stack) startParties(t *testing.T) {
	s.b = startProc(t, "B", binMPC, mpcstack.SoftHSMEnv(), "-config", s.cfgB)
	s.a = startProc(t, "A", binMPC, mpcstack.SoftHSMEnv(), "-config", s.cfgA)
	conn, err := grpc.NewClient(s.callerA, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(s.certGW, s.certA.pin))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	s.conn, s.client = conn, pb.NewMpcPartyClient(conn)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h, err := s.client.Health(c, &pb.HealthRequest{})
		cancel()
		if err == nil && h.PeerReachable {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("parties not ready\nA: %s\nB: %s", s.a.out, s.b.out)
}

func ctx(t testing.TB, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

// provision runs DKG and Derive through party A (as the operator/gateway would) and builds the signing-zone config for
// the derived hot address, the cosigner and the business database.
func (s *stack) provision(t *testing.T, noCosigner bool) {
	t.Helper()
	x := ctx(t, 60*time.Second)
	if _, err := s.client.DKG(x, &pb.DKGRequest{KeysetId: s.keysetID, Curve: pb.Curve_CURVE_SECP256K1, Admin: s.adminAuth("dkg", s.keysetID, adminNow())}); err != nil {
		t.Fatal(err)
	}
	d, err := s.client.Derive(x, &pb.DeriveRequest{KeysetId: s.keysetID, HardenedPath: []uint32{44, 60, 0}, Path: []uint32{0}})
	if err != nil {
		t.Fatal(err)
	}
	s.keyID, s.pub33 = d.KeyId, d.PublicKey
	pk, err := crypto.DecompressPubkey(s.pub33)
	if err != nil {
		t.Fatal(err)
	}
	s.pub65 = crypto.FromECDSAPub(pk)
	s.hot = crypto.PubkeyToAddress(*pk)
	s.h = gatewaytest.New(t, s.chainID, s.hot)

	s.biz = dbtest.New(t)
	for _, q := range []string{
		fmt.Sprintf(`INSERT INTO assets (chain, symbol, decimals) VALUES ('%s','ETH',18),('%s','USDT',6)`, gatewaytest.Chain, gatewaytest.Chain),
		fmt.Sprintf(`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('%s','qv-us','%s','ETH','hot','omnibus',0)`, gatewaytest.Partition, gatewaytest.Chain),
		fmt.Sprintf(`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('%s','qv-us','%s','ETH','hot','omnibus',1)`, gatewaytest.ColdPartition, gatewaytest.Chain),
	} {
		if _, err := s.biz.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	var dbname string
	s.biz.QueryRow(context.Background(), `SELECT current_database()`).Scan(&dbname)
	u, _ := url.Parse(os.Getenv("DATABASE_URL"))
	u.Path = "/" + dbname
	s.bizDSN = u.String()
	_, s.gwGuardDSN = gatewaytest.NewGuardDB(t)
	_, s.csGuardDSN = gatewaytest.NewGuardDB(t)

	s.cosignerCfg = filepath.Join(s.dir, "cosigner.json")
	cf := s.h.File
	if s.cosignerTweak != nil { // the cosigner has its own config: tests make it stricter than the gateway's
		cf = s.cosignerTweak(cf)
	}
	raw, _ := json.MarshalIndent(cf, "", " ")
	os.WriteFile(s.cosignerCfg, raw, 0o600)
	if !noCosigner {
		s.startCosigner(t)
	}
}

func (s *stack) startCosigner(t *testing.T) {
	s.cosigner = startProc(t, "cosigner", binCosigner, nil, "-config", s.cosignerCfg, "-guard-dsn", s.csGuardDSN, "-gateway-guard-dsn", s.gwGuardDSN, "-socket", s.sock)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", s.sock); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("cosigner did not start: %s", s.cosigner.out)
}

// gatewayConfig writes the gateway's signing-zone config: the same chain and approvers, plus the mpc signer entry.
func (s *stack) gatewayConfig() string {
	f := s.h.File
	// Every hot partition needs a signer; the rebalance test partitions have no key (they are destinations only, known to the
	// cosigner), so the gateway's copy of the config leaves them out.
	f.Chains = map[string]gateway.ChainFile{}
	for name, cf := range s.h.File.Chains {
		e := *cf.EVM
		e.HotAddresses = map[string]string{}
		for p, a := range cf.EVM.HotAddresses {
			if p != gatewaytest.Shard2Partition && p != gatewaytest.OtherPoolPartition {
				e.HotAddresses[p] = a
			}
		}
		cf.EVM = &e
		f.Chains[name] = cf
	}
	sf := gateway.SignerFile{Backend: "mpc", KeyID: s.keyID, PublicKey: hex.EncodeToString(s.pub65),
		MPC: &gateway.MPCSignerFile{Address: s.callerA, CertFile: filepath.Join(s.dir, "gateway.crt"), KeyFile: filepath.Join(s.dir, "gateway.key"), ServerPin: s.certA.pin}}
	// Every hot partition needs a signer; the cold-move test partition shares the one hot key.
	f.Signers = map[string]gateway.SignerFile{gatewaytest.Partition: sf, gatewaytest.ColdPartition: sf}
	f.SignTimeout = "4s" // short on purpose: outage tests wait past it
	s.certGW.write(s.t, s.dir)
	raw, _ := json.MarshalIndent(f, "", " ")
	p := filepath.Join(s.dir, "gateway.json")
	os.WriteFile(p, raw, 0o600)
	return p
}

func (s *stack) startGateway(id string) *proc {
	return startProc(s.t, "gateway-"+id, binGateway, nil, "-config", s.gatewayConfig(), "-jobs-dsn", s.bizDSN, "-guard-dsn", s.gwGuardDSN,
		"-worker-id", id, "-interval", "100ms", "-lease", "3s")
}

func (s *stack) enqueue(j signjob.Job) {
	s.t.Helper()
	tx, err := s.biz.Begin(context.Background())
	if err != nil {
		s.t.Fatal(err)
	}
	if err := signjob.Enqueue(context.Background(), tx, j); err != nil {
		tx.Rollback(context.Background())
		s.t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		s.t.Fatal(err)
	}
}

// waitJob waits until the job leaves pending/signing and returns it.
func (s *stack) waitJob(id string, d time.Duration) signjob.Job {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		j, err := signjob.Get(context.Background(), s.biz, id)
		if err == nil && j.Status != signjob.StatusPending && j.Status != signjob.StatusSigning {
			return j
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("job %s did not finish", id)
	return signjob.Job{}
}

func hasPrefix(s, p string) bool { return strings.HasPrefix(s, p) }

func bigInt(v int64) *big.Int { return big.NewInt(v) }

func newAdminKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func signWith(priv ed25519.PrivateKey, op, keyset string, at time.Time) *pb.AdminAuth {
	return admin.Sign(priv, op, keyset, at)
}

func signerPub(s *stack) (*ecdsa.PublicKey, error) { return crypto.UnmarshalPubkey(s.pub65) }

func kindOfErr(err error) (pb.ErrorKind, bool) {
	st, ok := grpcstatus.FromError(err)
	if !ok {
		return 0, false
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*pb.ErrorDetail); ok {
			return ed.Kind, true
		}
	}
	return 0, false
}

// tamperProxy is a man in the middle at the session layer (TLS terminated on both sides with the proxy's own certificate,
// pinned by A and by B). It forwards frames and flips one byte in the payload of the n-th DATA frame going in direction
// dir (0: A to B, 1: B to A) after set(dir, n); n < 0 forwards faithfully.
type tamperProxy struct {
	pb.UnimplementedPeerServer
	client pb.PeerClient
	dir, n atomic.Int32
	count  [2]atomic.Int32
}

func (p *tamperProxy) set(dir, n int) {
	p.count[0].Store(0)
	p.count[1].Store(0)
	p.dir.Store(int32(dir))
	p.n.Store(int32(n))
}

func (p *tamperProxy) mutate(dir int, f *pb.Frame) {
	if f.Kind != pb.FrameKind_FRAME_KIND_DATA || len(f.Payload) == 0 {
		return
	}
	idx := p.count[dir].Add(1) - 1
	if int(p.dir.Load()) == dir && idx == p.n.Load() {
		f.Payload = append([]byte(nil), f.Payload...)
		f.Payload[len(f.Payload)/2] ^= 0x01
	}
}

func (p *tamperProxy) Session(in pb.Peer_SessionServer) error {
	out, err := p.client.Session(in.Context())
	if err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() {
		for {
			f, err := in.Recv()
			if err != nil {
				out.CloseSend()
				break
			}
			p.mutate(0, f)
			if out.Send(f) != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		for {
			f, err := out.Recv()
			if err != nil {
				break
			}
			p.mutate(1, f)
			if in.Send(f) != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
	return nil
}

func startProxy(t *testing.T, s *stack) (*tamperProxy, string) {
	conn, err := grpc.NewClient(s.peerB, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(s.certProx, s.certB.pin))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	p := &tamperProxy{client: pb.NewPeerClient(conn)}
	p.n.Store(-1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := pinnedTLS(s.certProx, s.certA.pin)
	cfg.ClientAuth = tls.RequireAnyClientCert
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	pb.RegisterPeerServer(srv, p)
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return p, ln.Addr().String()
}

func (s *stack) restartB(t *testing.T) {
	s.b = startProc(t, "B", binMPC, mpcstack.SoftHSMEnv(), "-config", s.cfgB)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h, err := s.client.Health(c, &pb.HealthRequest{})
		cancel()
		if err == nil && h.PeerReachable {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("B did not come back")
}

func (s *stack) countLog(b *syncBuf, parts ...string) int {
	n := 0
	for _, l := range strings.Split(b.String(), "\n") {
		ok := true
		for _, p := range parts {
			if !strings.Contains(l, p) {
				ok = false
			}
		}
		if ok {
			n++
		}
	}
	return n
}
