// Package e2e runs the real mpc-party binaries as separate OS processes with generated certificates.
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

var binDev, binProd string // built with and without -tags devauth

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mpcparty-bin-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	build := func(out string, tags ...string) string {
		p := filepath.Join(dir, out)
		args := []string{"build", "-o", p}
		if len(tags) > 0 {
			args = append(args, "-tags", tags[0])
		}
		cmd := exec.Command("go", append(args, "./cmd/mpc-party")...)
		cmd.Dir = ".."
		if o, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", err, o)
			os.Exit(1)
		}
		return p
	}
	binDev = build("mpc-party-dev", "devauth")
	binProd = build("mpc-party-prod")
	os.Exit(m.Run())
}

type proc struct {
	cmd    *exec.Cmd
	stderr *syncBuf
	done   chan struct{}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func start(t *testing.T, bin, cfg string) *proc {
	t.Helper()
	p := &proc{cmd: exec.Command(bin, "-config", cfg), stderr: &syncBuf{}, done: make(chan struct{})}
	p.cmd.Stderr = p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		p.cmd.Process.Signal(syscall.SIGCONT)
		p.cmd.Process.Kill()
		<-p.done
	})
	return p
}

func (p *proc) signal(s syscall.Signal) { p.cmd.Process.Signal(s) }
func (p *proc) kill()                   { p.cmd.Process.Kill(); <-p.done }
func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// cluster is party A and party B as real processes, with an optional TCP forwarder in front of B's peer port.
type cluster struct {
	env          *testenv.Env
	cfgA, cfgB   string
	a, b         *proc
	callerA      string
	callerB      string
	peerB        string // where B really listens
	peerViaProxy string // where A dials
	client       pb.MpcPartyClient
	proxy        *tcpProxy
}

func newCluster(t *testing.T, tweak func(role string, c *server.Config), withProxy bool) *cluster {
	t.Helper()
	env := testenv.NewEnv(t)
	cl := &cluster{env: env, callerA: testenv.FreeAddr(t), callerB: testenv.FreeAddr(t), peerB: testenv.FreeAddr(t)}
	cl.peerViaProxy = cl.peerB
	if withProxy {
		cl.proxy = newTCPProxy(t, cl.peerB)
		cl.peerViaProxy = cl.proxy.addr
	}
	cb := env.Config(t, "B", "", cl.callerB, cl.peerB)
	ca := env.Config(t, "A", cl.peerViaProxy, cl.callerA, "")
	if tweak != nil {
		tweak("A", ca)
		tweak("B", cb)
	}
	cl.cfgA, cl.cfgB = env.WriteConfig(t, ca, "a.json"), env.WriteConfig(t, cb, "b.json")
	cl.b = start(t, binDev, cl.cfgB)
	cl.a = start(t, binDev, cl.cfgA)
	c, _ := testenv.Dial(t, cl.callerA, env.CertCaller, env.CertA.Pin)
	cl.client = c
	cl.waitReady(t)
	return cl
}

func (cl *cluster) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h, err := cl.client.Health(ctx, &pb.HealthRequest{})
		cancel()
		if err == nil && h.PeerReachable {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("parties not ready.\nA: %s\nB: %s", cl.a.stderr, cl.b.stderr)
}

func (cl *cluster) restartB(t *testing.T) {
	cl.b = start(t, binDev, cl.cfgB)
}

func (cl *cluster) restartA(t *testing.T) {
	cl.a = start(t, binDev, cl.cfgA)
}

func ctx(t testing.TB, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func verifyECDSA(t testing.TB, pub, digest, der []byte) {
	t.Helper()
	pk, err := btcec.ParsePubKey(pub)
	must(t, err)
	sig, err := btcecdsa.ParseDERSignature(der)
	must(t, err)
	if !sig.Verify(digest, pk) {
		t.Fatal("ECDSA signature does not verify (btcec)")
	}
}

func dgst(seed int) []byte { d := sha256.Sum256([]byte(fmt.Sprint("digest", seed))); return d[:] }

func kindOf(err error) (pb.ErrorKind, bool) { return server.KindOfStatus(err) }

// retry calls f until it succeeds or the deadline passes (recovery needs no operator step, only time for reconnects).
func retry(t *testing.T, d time.Duration, f func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	var err error
	for time.Now().Before(deadline) {
		if err = f(); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("did not recover within %v: %v", d, err)
}
