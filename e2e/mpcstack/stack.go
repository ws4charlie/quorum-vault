// Package mpcstack starts the real processes of the two-party signing service for end-to-end tests: mpc-party A and B (real
// SoftHSM sealing, mTLS with pinned certificates), the qv-cosigner next to B, and an optional session-level proxy between
// A and B for partition, latency and tamper tests. It is test support: the root module links it only into test binaries.
package mpcstack

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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// ---- binaries ----

// Binaries are the two executables this package starts. Build them once per test binary (in TestMain).
type Binaries struct{ MPCParty, Cosigner string }

// Build compiles the production mpc-party (no dev authorizer, no failpoints, no insecure sealer) and qv-cosigner into dir.
func Build(dir string) (Binaries, error) {
	root := RepoRoot()
	build := func(workdir, out, pkg string) (string, error) {
		p := filepath.Join(dir, out)
		cmd := exec.Command("go", "build", "-o", p, pkg)
		cmd.Dir = workdir
		if o, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("build %s: %v\n%s", out, err, o)
		}
		return p, nil
	}
	var b Binaries
	var err error
	if b.MPCParty, err = build(filepath.Join(root, "mpc-party"), "mpc-party", "./cmd/mpc-party"); err != nil {
		return b, err
	}
	b.Cosigner, err = build(root, "qv-cosigner", "./cmd/qv-cosigner")
	return b, err
}

// RepoRoot is the root of the repository this package is in.
func RepoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(f), "..", ".."))
}

// SoftHSMEnv is the environment the parties need to open their tokens: the repo-local SoftHSM config and the dev PIN.
func SoftHSMEnv() []string {
	env := []string{"QV_HSM_PIN=" + pin()}
	if os.Getenv("SOFTHSM2_CONF") == "" {
		env = append(env, "SOFTHSM2_CONF="+filepath.Join(RepoRoot(), "data", "softhsm", "softhsm2.conf"))
	}
	return env
}

func pin() string {
	if p := os.Getenv("QV_HSM_PIN"); p != "" {
		return p
	}
	return "user-dev-1234"
}

// SealerConfig is the sealer section of a party config: the party's own SoftHSM token (A: qv-party-1, B: qv-party-2).
func SealerConfig(role string) map[string]any {
	tok := "qv-party-1"
	if role == "B" {
		tok = "qv-party-2"
	}
	return map[string]any{"type": "pkcs11", "token": tok, "pin_env": "QV_HSM_PIN"}
}

// ---- certificates ----

type Cert struct {
	Name    string
	CertPEM []byte
	KeyPEM  []byte
	Pin     string
	tls     tls.Certificate
}

func NewCert(t testing.TB, name string) Cert {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	c := Cert{Name: name, CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})}
	sum := sha256.Sum256(der)
	c.Pin = hex.EncodeToString(sum[:])
	if c.tls, err = tls.X509KeyPair(c.CertPEM, c.KeyPEM); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c Cert) Write(t testing.TB, dir string) (crt, key string) {
	crt, key = filepath.Join(dir, c.Name+".crt"), filepath.Join(dir, c.Name+".key")
	if err := os.WriteFile(crt, c.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, c.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// PinnedTLS: TLS 1.3, our certificate, trusts exactly the pinned peer certificate.
func PinnedTLS(own Cert, peerPin string) *tls.Config {
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

// Proc is one child process whose output goes to a log file and which can be killed and started again.
type Proc struct {
	Name string
	Log  string
	bin  string
	args []string
	env  []string

	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
}

func NewProc(t testing.TB, name, logPath, bin string, env []string, args ...string) *Proc {
	p := &Proc{Name: name, Log: logPath, bin: bin, args: args, env: env}
	t.Cleanup(func() { p.Stop() })
	return p
}

// Start launches the process (again). The log file is appended to, so a restart keeps the earlier output.
func (p *Proc) Start(t testing.TB) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := os.OpenFile(p.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(p.bin, p.args...)
	cmd.Env = append(os.Environ(), p.env...)
	cmd.Stdout, cmd.Stderr = f, f
	Guard(cmd)
	if err := cmd.Start(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	p.cmd, p.done = cmd, done
	go func() { cmd.Wait(); f.Close(); close(done) }()
}

func (p *Proc) current() (*exec.Cmd, chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd, p.done
}

// Running reports whether the process is up.
func (p *Proc) Running() bool {
	_, done := p.current()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// Pid is the process id, 0 if it never ran.
func (p *Proc) Pid() int {
	cmd, _ := p.current()
	if cmd == nil || cmd.Process == nil {
		return 0
	}
	return cmd.Process.Pid
}

// Kill is SIGKILL: a crash.
func (p *Proc) Kill() {
	cmd, done := p.current()
	if cmd == nil {
		return
	}
	select {
	case <-done:
		return
	default:
	}
	cmd.Process.Kill()
	<-done
}

// Stop asks for a clean shutdown and kills after 10 seconds.
func (p *Proc) Stop() {
	cmd, done := p.current()
	if cmd == nil {
		return
	}
	select {
	case <-done:
		return
	default:
	}
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		<-done
	}
}

func (p *Proc) Output() string {
	b, _ := os.ReadFile(p.Log)
	return string(b)
}

// CountLog counts log lines that contain every one of parts.
func (p *Proc) CountLog(parts ...string) int {
	n := 0
	for _, l := range strings.Split(p.Output(), "\n") {
		ok := true
		for _, s := range parts {
			if !strings.Contains(l, s) {
				ok = false
			}
		}
		if ok {
			n++
		}
	}
	return n
}

// RSSAndThreads reads the resident set size (KiB) and the thread count of the running process.
func (p *Proc) RSSAndThreads() (rssKB, threads int, err error) {
	pid := p.Pid()
	if pid == 0 || !p.Running() {
		return 0, 0, fmt.Errorf("%s is not running", p.Name)
	}
	return RSSAndThreads(pid)
}

// RSSAndThreads reads the resident set size (KiB) and the thread count of a process.
func RSSAndThreads(pid int) (rssKB, threads int, err error) {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			return 0, 0, err
		}
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 && f[0] == "VmRSS:" {
				rssKB, _ = strconv.Atoi(f[1])
			}
			if len(f) >= 2 && f[0] == "Threads:" {
				threads, _ = strconv.Atoi(f[1])
			}
		}
		return rssKB, threads, nil
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, err
	}
	rssKB, _ = strconv.Atoi(strings.TrimSpace(string(out)))
	// macOS: one line per thread with -M, plus the header.
	out, err = exec.Command("ps", "-M", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, err
	}
	threads = len(strings.Split(strings.TrimSpace(string(out)), "\n")) - 1
	return rssKB, threads, nil
}

var (
	freeMu    sync.Mutex
	freeGiven = map[string]bool{}
)

// FreeAddr returns 127.0.0.1:port for a port that was free a moment ago. The kernel may hand out a port again as soon as it is closed,
// so an address is never returned twice in a test binary: two processes must not be given the same port.
func FreeAddr(t testing.TB) string {
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

type Opts struct {
	// Proxy puts a session-level proxy between A and B (partition, latency, tamper).
	Proxy bool
	// Limits override the parties' defaults; zero keeps the value below.
	RecvTimeoutMS, SessionTimeoutMS, KeygenRecvTimeoutMS int
}

type Stack struct {
	t   testing.TB
	Dir string
	Bin Binaries

	CertA, CertB, CertGW, CertProx Cert
	adminPub                       ed25519.PublicKey
	admin                          ed25519.PrivateKey
	adminSkew                      atomic.Int64

	CallerA, CallerB, PeerB string
	peerForA                string
	Sock                    string // the cosigner's unix socket

	Proxy *Proxy
	A, B  *Proc
	Cos   *Proc

	cfgA, cfgB string
	Client     pb.MpcPartyClient // gateway identity -> party A
	conn       *grpc.ClientConn

	KeysetID string
	RootPub  []byte
}

// New writes the party configs and starts B and then A. The keyset does not exist yet: call DKG.
func New(t testing.TB, dir string, bin Binaries, o Opts) *Stack {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Stack{t: t, Dir: dir, Bin: bin, KeysetID: "hot"}
	s.CertA, s.CertB, s.CertGW, s.CertProx = NewCert(t, "party-a"), NewCert(t, "party-b"), NewCert(t, "gateway"), NewCert(t, "proxy")
	s.adminPub, s.admin, _ = ed25519.GenerateKey(rand.Reader)
	s.CallerA, s.CallerB, s.PeerB = FreeAddr(t), FreeAddr(t), FreeAddr(t)
	s.peerForA = s.PeerB
	s.Sock = filepath.Join(os.TempDir(), fmt.Sprintf("qvcs-%d.sock", time.Now().UnixNano()%1e9))
	t.Cleanup(func() { os.Remove(s.Sock) })
	pinForA, pinForB := s.CertB.Pin, s.CertA.Pin
	if o.Proxy {
		// A believes the proxy is party B; B believes the proxy is party A.
		s.Proxy, s.peerForA = startProxy(t, s)
		pinForA, pinForB = s.CertProx.Pin, s.CertProx.Pin
	}
	s.cfgA = s.writeParty("A", pinForA, o)
	s.cfgB = s.writeParty("B", pinForB, o)
	env := SoftHSMEnv()
	s.B = NewProc(t, "party-B", filepath.Join(dir, "party-B.log"), bin.MPCParty, env, "-config", s.cfgB)
	s.A = NewProc(t, "party-A", filepath.Join(dir, "party-A.log"), bin.MPCParty, env, "-config", s.cfgA)
	s.B.Start(t)
	s.A.Start(t)
	conn, err := grpc.NewClient(s.CallerA, grpc.WithTransportCredentials(credentials.NewTLS(PinnedTLS(s.CertGW, s.CertA.Pin))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	s.conn, s.Client = conn, pb.NewMpcPartyClient(conn)
	s.WaitReady(60 * time.Second)
	return s
}

func (s *Stack) writeParty(role, peerPin string, o Opts) string {
	t := s.t
	own := s.CertA
	if role == "B" {
		own = s.CertB
	}
	crt, key := own.Write(t, s.Dir)
	lim := map[string]any{"recv_timeout_ms": 5000, "session_timeout_ms": 30000, "keygen_recv_timeout_ms": 60000, "sessions_per_sec_key": 100000, "max_peer_sessions": 64}
	if o.RecvTimeoutMS > 0 {
		lim["recv_timeout_ms"] = o.RecvTimeoutMS
	}
	if o.SessionTimeoutMS > 0 {
		lim["session_timeout_ms"] = o.SessionTimeoutMS
	}
	if o.KeygenRecvTimeoutMS > 0 {
		lim["keygen_recv_timeout_ms"] = o.KeygenRecvTimeoutMS
	}
	cfg := map[string]any{
		"role": role, "cert_file": crt, "key_file": key, "peer_pins": []string{peerPin}, "caller_pins": []string{s.CertGW.Pin},
		"data_dir": filepath.Join(s.Dir, "data-"+role), "admin_keys": []string{hex.EncodeToString(s.adminPub)},
		"sealer": SealerConfig(role), "limits": lim,
	}
	if role == "A" {
		cfg["caller_listen"], cfg["peer_address"] = s.CallerA, s.peerForA
		cfg["authorizer"] = map[string]any{"type": "pinned-caller"}
	} else {
		cfg["caller_listen"], cfg["peer_listen"] = s.CallerB, s.PeerB
		cfg["authorizer"] = map[string]any{"type": "cosigner", "socket": s.Sock, "timeout_ms": 5000}
	}
	raw, _ := json.MarshalIndent(cfg, "", " ")
	p := filepath.Join(s.Dir, "party-"+role+".json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Health asks party A.
func (s *Stack) Health() (*pb.HealthResponse, error) {
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.Client.Health(c, &pb.HealthRequest{})
}

// WaitReady waits until A is up and sees B, and (if the keyset exists) the keyset is reconciled and not frozen.
func (s *Stack) WaitReady(d time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		h, err := s.Health()
		if err == nil && h.PeerReachable {
			ok := true
			for _, k := range h.Keysets {
				if !k.Resolved {
					ok = false
				}
			}
			if ok {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("parties not ready\nA: %s\nB: %s", tail(s.A.Output()), tail(s.B.Output()))
}

func tail(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > 15 {
		l = l[len(l)-15:]
	}
	return strings.Join(l, "\n")
}

// AdminAuth is an operator signature that has not been used before (signatures are deterministic per second).
func (s *Stack) AdminAuth(op string) *pb.AdminAuth {
	return admin.Sign(s.admin, op, s.KeysetID, time.Now().Add(time.Duration(s.adminSkew.Add(1))*time.Second))
}

// DKG runs the distributed key generation through A.
func (s *Stack) DKG() {
	s.t.Helper()
	x, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	r, err := s.Client.DKG(x, &pb.DKGRequest{KeysetId: s.KeysetID, Curve: pb.Curve_CURVE_SECP256K1, Admin: s.AdminAuth("dkg")})
	if err != nil {
		s.t.Fatalf("DKG: %v\nA: %s\nB: %s", err, tail(s.A.Output()), tail(s.B.Output()))
	}
	s.RootPub = r.RootPublicKey
}

// Shard is one derived signing key.
type Shard struct {
	KeyID string
	Pub65 []byte
	Addr  common.Address
}

// Derive derives the i-th hot key (m/44'/60'/0'/i).
func (s *Stack) Derive(i int) Shard {
	s.t.Helper()
	x, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d, err := s.Client.Derive(x, &pb.DeriveRequest{KeysetId: s.KeysetID, HardenedPath: []uint32{44, 60, 0}, Path: []uint32{uint32(i)}})
	if err != nil {
		s.t.Fatalf("Derive %d: %v", i, err)
	}
	pk, err := crypto.DecompressPubkey(d.PublicKey)
	if err != nil {
		s.t.Fatal(err)
	}
	return Shard{KeyID: d.KeyId, Pub65: crypto.FromECDSAPub(pk), Addr: crypto.PubkeyToAddress(*pk)}
}

// Refresh re-randomizes the shares through A. It returns the error unchanged.
func (s *Stack) Refresh() error {
	x, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := s.Client.Refresh(x, &pb.RefreshRequest{KeysetId: s.KeysetID, Admin: s.AdminAuth("refresh")})
	return err
}

// Unfreeze lifts the freeze on both parties with an operator signature.
func (s *Stack) Unfreeze() error {
	x, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := s.Client.Unfreeze(x, &pb.UnfreezeRequest{KeysetId: s.KeysetID, Admin: s.AdminAuth("unfreeze")})
	return err
}

// Frozen reports whether party A says the keyset is frozen.
func (s *Stack) Frozen() bool {
	h, err := s.Health()
	if err != nil {
		return false
	}
	for _, k := range h.Keysets {
		if k.KeysetId == s.KeysetID {
			return k.Frozen
		}
	}
	return false
}

// GatewaySigner is the gateway.json signer entry for one derived key. It writes the gateway's client certificate.
func (s *Stack) GatewaySigner(sh Shard) gateway.SignerFile {
	crt, key := s.CertGW.Write(s.t, s.Dir)
	return gateway.SignerFile{Backend: "mpc", KeyID: sh.KeyID, PublicKey: hex.EncodeToString(sh.Pub65),
		MPC: &gateway.MPCSignerFile{Address: s.CallerA, CertFile: crt, KeyFile: key, ServerPin: s.CertA.Pin}}
}

// StartCosigner starts qv-cosigner (B's authorizer) with its own config and guard database.
func (s *Stack) StartCosigner(cfgPath, guardDSN, gatewayGuardDSN string) {
	s.t.Helper()
	s.Cos = NewProc(s.t, "cosigner", filepath.Join(s.Dir, "cosigner.log"), s.Bin.Cosigner, nil,
		"-config", cfgPath, "-guard-dsn", guardDSN, "-gateway-guard-dsn", gatewayGuardDSN, "-socket", s.Sock)
	s.StartCosignerAgain()
}

// StartCosignerAgain starts the cosigner process again after a kill and waits for its socket.
func (s *Stack) StartCosignerAgain() {
	s.t.Helper()
	s.Cos.Start(s.t)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", s.Sock); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatalf("cosigner did not start: %s", tail(s.Cos.Output()))
}

// RestartA / RestartB start a killed party again and wait until A sees B and the keyset is reconciled.
func (s *Stack) RestartA() { s.A.Start(s.t); s.WaitReady(60 * time.Second) }
func (s *Stack) RestartB() { s.B.Start(s.t); s.WaitReady(60 * time.Second) }

// ---- the session proxy ----

// Proxy is a man in the middle at the session layer (TLS is terminated on both sides with the proxy's own certificate,
// pinned by A and by B). It forwards frames and can: add latency to every frame, cut the link (a partition), and flip one
// byte in the payload of the n-th DATA frame in one direction.
type Proxy struct {
	pb.UnimplementedPeerServer
	client pb.PeerClient

	delayNS atomic.Int64
	cut     atomic.Bool

	tdir, tn atomic.Int32 // tamper: direction (0: A to B, 1: B to A) and index; tn < 0 off
	count    [2]atomic.Int32

	mu     sync.Mutex
	active map[int]context.CancelFunc
	nextID int

	Sessions atomic.Int64
}

// SetLatency adds d to every frame in both directions.
func (p *Proxy) SetLatency(d time.Duration) { p.delayNS.Store(int64(d)) }

// Partition cuts the link: open sessions are broken and new ones are refused until Heal.
func (p *Proxy) Partition() {
	p.cut.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.active {
		c()
	}
}

// Heal lets sessions through again.
func (p *Proxy) Heal() { p.cut.Store(false) }

// Tamper flips a byte in the n-th DATA frame going in direction dir (0: A to B, 1: B to A). n < 0 turns it off.
func (p *Proxy) Tamper(dir, n int) {
	p.count[0].Store(0)
	p.count[1].Store(0)
	p.tdir.Store(int32(dir))
	p.tn.Store(int32(n))
}

func (p *Proxy) mutate(dir int, f *pb.Frame) {
	if f.Kind != pb.FrameKind_FRAME_KIND_DATA || len(f.Payload) == 0 {
		return
	}
	idx := p.count[dir].Add(1) - 1
	if int(p.tdir.Load()) == dir && idx == p.tn.Load() {
		f.Payload = append([]byte(nil), f.Payload...)
		f.Payload[len(f.Payload)/2] ^= 0x01
	}
}

func (p *Proxy) delay(ctx context.Context) bool {
	d := time.Duration(p.delayNS.Load())
	if d <= 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *Proxy) Session(in pb.Peer_SessionServer) error {
	if p.cut.Load() {
		return grpcUnavailable()
	}
	p.Sessions.Add(1)
	ctx, cancel := context.WithCancel(in.Context())
	defer cancel()
	p.mu.Lock()
	if p.active == nil {
		p.active = map[int]context.CancelFunc{}
	}
	id := p.nextID
	p.nextID++
	p.active[id] = cancel
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.active, id); p.mu.Unlock() }()

	out, err := p.client.Session(ctx)
	if err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	// Frames are delayed without stalling the pipe: each is forwarded after its own delay, in order (one goroutine per
	// direction sleeping before each send gives a fixed one-way latency per frame, which is what a slow link does).
	go func() {
		for {
			f, err := in.Recv()
			if err != nil {
				out.CloseSend()
				break
			}
			if p.cut.Load() || !p.delay(ctx) {
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
			if p.cut.Load() || !p.delay(ctx) {
				break
			}
			p.mutate(1, f)
			if in.Send(f) != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}

func startProxy(t testing.TB, s *Stack) (*Proxy, string) {
	conn, err := grpc.NewClient(s.PeerB, grpc.WithTransportCredentials(credentials.NewTLS(PinnedTLS(s.CertProx, s.CertB.Pin))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	p := &Proxy{client: pb.NewPeerClient(conn)}
	p.tn.Store(-1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := PinnedTLS(s.CertProx, s.CertA.Pin)
	cfg.ClientAuth = tls.RequireAnyClientCert
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	pb.RegisterPeerServer(srv, p)
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return p, ln.Addr().String()
}

func grpcUnavailable() error { return status.Error(codes.Unavailable, "proxy: link is cut") }
