// Package sole2e is the end-to-end suite of the Solana cell: a real solana-test-validator (docker compose profile solana), the real two-party
// mpc-party (A and B, SoftHSM sealing) holding an Ed25519 HD keyset, Temporal, Postgres, and the real qv-core and qv-worker processes. Jobs are
// named e2e-sol-<group>. See the Makefile target test-e2e-sol-deposits.
package sole2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/e2e/phasetime"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

var (
	binDir   string
	buildErr error
	mpcBin   mpcstack.Binaries
)

func TestMain(m *testing.M) {
	mpcstack.ReaperMain() // in the reaper process: waits for this binary to die, kills the children, never returns
	stopReaper := func() {}
	if os.Getenv("QV_REQUIRE_SOL") == "1" {
		dir, err := os.MkdirTemp("", "qv-e2e-sol-bin-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		binDir = dir
		built := time.Now()
		if stop, err := mpcstack.StartReaper(); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		} else {
			stopReaper = stop
		}
		if mpcBin, err = mpcstack.Build(dir); err != nil {
			buildErr = err
		}
		for _, b := range []string{"qv-worker", "qv-core", "qv-gateway", "qv-sol-nonces", "qv-cold"} {
			if buildErr != nil {
				break
			}
			// The worker has the crash-test failpoints (QV_FAILPOINT), which exist only in binaries built with -tags devauth.
			args := []string{"build", "-o", filepath.Join(dir, b)}
			if b == "qv-worker" {
				args = append(args, "-tags", "devauth")
			}
			out, err := exec.Command("go", append(args, "github.com/ws4charlie/quorum-vault/cmd/"+b)...).CombinedOutput()
			if err != nil {
				buildErr = fmt.Errorf("build %s: %v\n%s", b, err, out)
			}
		}
		fmt.Printf("qv-timing-main package=e2e/sol build=%.1f\n", time.Since(built).Seconds())
	}
	code := m.Run()
	stopReaper()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// requireSOL is the one place a Solana e2e test may skip: when the suite was not asked to run (QV_REQUIRE_SOL unset). Every CI job and make
// target sets it, and then a missing service fails the test instead.
func requireSOL(t *testing.T) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_SOL") != "1" {
		t.Skip("QV_REQUIRE_SOL != 1 (`make sol-up infra-up softhsm mpc-build test-e2e-sol-deposits`)")
	}
	if buildErr != nil {
		t.Fatal(buildErr)
	}
}

func nodeURL() string {
	if v := os.Getenv("QV_SOL_RPC"); v != "" {
		return v
	}
	return "http://127.0.0.1:18899"
}

type proc struct {
	name string
	cmd  *exec.Cmd
	log  string
	done chan struct{}
	err  error
}

func (p *proc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

type system struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	pool    *pgxpool.Pool
	bizDSN  string
	mpc     *mpcstack.Stack
	chain   string
	queue   string
	cf      custody.File
	cfgPath string
	apiURL  string
	worker  *proc
	core    *proc
	tm      *phasetime.Timer
	tc      client.Client

	c          *chainT
	funder     key
	mint       key // the configured token ("TKN", 6 decimals); zero when opts.noToken
	node       sol.Node
	adapterCfg sol.Config
}

type opts struct {
	minDeposit string // SOL, lamports; default 1000
	tokenMin   string // default 1
	noToken    bool
	network    string // default localnet
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (s *system) spawn(name string, args ...string) *proc { return s.spawnEnv(name, nil, args...) }

// spawnEnv starts a binary with extra environment (the crash failpoint of the worker).
func (s *system) spawnEnv(name string, env []string, args ...string) *proc {
	s.t.Helper()
	logPath := filepath.Join(s.dir, fmt.Sprintf("%s-%d.log", name, time.Now().UnixNano()))
	lf, err := os.Create(logPath)
	if err != nil {
		s.t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(binDir, name), args...)
	cmd.Env = append(append(os.Environ(), env...), "SOFTHSM2_CONF="+hsm.RepoSoftHSMConf())
	cmd.Stdout, cmd.Stderr = lf, lf
	mpcstack.Guard(cmd)
	if err := cmd.Start(); err != nil {
		s.t.Fatalf("start %s: %v", name, err)
	}
	p := &proc{name: name, cmd: cmd, log: logPath, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		lf.Close()
		close(p.done)
	}()
	s.t.Cleanup(func() {
		p.stop()
		if s.t.Failed() {
			b, _ := os.ReadFile(p.log)
			if len(b) > 6000 {
				b = b[len(b)-6000:]
			}
			s.t.Logf("---- %s log tail ----\n%s", name, b)
		}
	})
	return p
}

func fileContains(path, sub string) bool {
	b, _ := os.ReadFile(path)
	return strings.Contains(string(b), sub)
}

// scale stretches every condition wait on a slow runner (QV_E2E_TIMEOUT_SCALE, as in the other suites).
func scale(d time.Duration) time.Duration {
	if v, err := strconv.Atoi(os.Getenv("QV_E2E_TIMEOUT_SCALE")); err == nil && v > 1 {
		return d * time.Duration(v)
	}
	return d
}

func (s *system) waitFor(timeout time.Duration, what string, f func() bool) {
	s.t.Helper()
	start := time.Now()
	dl := start.Add(scale(timeout))
	for {
		if f() {
			s.tm.Wait(what, time.Since(start))
			return
		}
		if time.Now().After(dl) {
			s.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// holds checks that cond stays true for d.
func (s *system) holds(d time.Duration, what string, cond func() bool) {
	s.t.Helper()
	dl := time.Now().Add(d)
	for time.Now().Before(dl) {
		if !cond() {
			s.t.Fatalf("did not hold: %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ed25519DKG makes the Ed25519 HD keyset the deposit addresses come from, on the stack's two parties.
func ed25519DKG(t *testing.T, m *mpcstack.Stack, id string) {
	t.Helper()
	m.KeysetID = id
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := m.Client.DKG(ctx, &pb.DKGRequest{KeysetId: id, Curve: pb.Curve_CURVE_ED25519, Admin: m.AdminAuth("dkg")}); err != nil {
		t.Fatalf("Ed25519 DKG: %v", err)
	}
}

func newSystem(t *testing.T, o opts) *system {
	t.Helper()
	requireSOL(t)
	if o.minDeposit == "" {
		o.minDeposit = "1000"
	}
	if o.tokenMin == "" {
		o.tokenMin = "1"
	}
	if o.network == "" {
		o.network = "localnet"
	}
	tm := phasetime.Start(t, "sol")
	s := &system{t: t, ctx: context.Background(), dir: t.TempDir(), chain: "sol-" + uuid.NewString()[:8], queue: "qv-e2e-sol-" + uuid.NewString()[:8], tm: tm}
	s.mpc = mpcstack.Start(t, filepath.Join(s.dir, "mpc"), mpcBin, mpcstack.Opts{})
	tm.Phase("mpc-start")
	s.c = &chainT{t: t, rpc: sol.NewRPC(nodeURL())}
	if _, err := s.c.rpc.Slot(s.ctx, sol.Finalized); err != nil {
		t.Fatalf("solana-test-validator: %v (make sol-up)", err)
	}
	s.funder = newKey(t)
	s.c.airdrop(s.funder.addr(), 1000*1_000_000_000)
	if !o.noToken {
		s.mint = s.c.newMint(s.funder, 6)
	}
	tm.Phase("chain")
	s.pool = dbtest.New(t)
	cc := s.pool.Config().ConnConfig
	s.bizDSN = fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cc.User, cc.Host, cc.Port, cc.Database)
	tm.Phase("db")
	s.mpc.WaitReady(60 * time.Second)
	tm.Phase("mpc-wait")
	ed25519DKG(t, s.mpc, "sol-hd")
	tm.Phase("dkg")
	nctx, cancel := context.WithTimeout(s.ctx, time.Minute)
	node, err := sol.AccountNode(nctx, s.mpc.Client, "sol-hd")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	s.node = node
	tm.Phase("node")
	start, err := s.c.rpc.Slot(s.ctx, sol.Finalized)
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string]custody.AssetFile{"SOL": {Decimals: 9, MinDeposit: o.minDeposit}}
	if !o.noToken {
		assets["TKN"] = custody.AssetFile{Address: s.mint.addr(), Decimals: 6, MinDeposit: o.tokenMin}
	}
	s.cf = custody.File{
		Entity: "qv-us",
		Chain: custody.ChainFile{Family: "sol", Name: s.chain,
			SOL:    &custody.SOLFile{Network: o.network, RPCURL: nodeURL(), AccountPublicKey: hex.EncodeToString(node.PublicKey[:]), AccountChainCode: hex.EncodeToString(node.ChainCode[:])},
			Assets: assets},
		Withdrawal: custody.WithdrawalFile{ApprovalWindow: "10m", ApprovalTimeout: "20s", ActivityTimeout: "5s"},
		Scan:       custody.ScanFile{Interval: "300ms", StartHeight: start + 1},
	}
	s.cfgPath = filepath.Join(s.dir, "custody.json")
	s.writeConfig(s.cf)
	tm.Phase("configs")

	addr := os.Getenv("QV_TEMPORAL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:7233"
	}
	rctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer cancel()
	if err := workflow.RegisterNamespace(rctx, addr, "default"); err != nil {
		t.Fatal(err)
	}
	tc, err := client.DialContext(s.ctx, client.Options{HostPort: addr, Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	s.tc = tc
	t.Cleanup(tc.Close)
	t.Cleanup(func() { _ = tc.TerminateWorkflow(context.Background(), workflow.ScanID(s.chain), "", "test over") })
	tm.Phase("temporal")
	s.startWorker()
	s.startCore()
	tm.Phase("spawn")
	tm.Ready(t)
	return s
}

func (s *system) writeConfig(cf custody.File) {
	s.t.Helper()
	b, _ := json.MarshalIndent(cf, "", "  ")
	if err := os.WriteFile(s.cfgPath, b, 0o600); err != nil {
		s.t.Fatal(err)
	}
}

func (s *system) startWorker() {
	s.worker = s.spawn("qv-worker", "-config", s.cfgPath, "-dsn", s.bizDSN, "-task-queue", s.queue)
	p := s.worker
	s.waitFor(30*time.Second, "worker started", func() bool { return fileContains(p.log, "qv-worker started") })
}

func (s *system) restartWorker() {
	s.worker.stop()
	s.startWorker()
}

func (s *system) startCore() {
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(s.t))
	s.core = s.spawn("qv-core", "-config", s.cfgPath, "-dsn", s.bizDSN, "-addr", addr, "-task-queue", s.queue)
	s.apiURL = "http://" + addr
	s.waitFor(30*time.Second, "qv-core listening", func() bool {
		resp, err := http.Get(s.apiURL + "/v2/reconcile")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	})
}

func (s *system) call(method, path string, body any) (int, map[string]any) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.apiURL+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("X-Actor", "ops")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// newCustomer creates a customer and returns the Solana address of its deposits.
func (s *system) newCustomer(id string) string {
	s.t.Helper()
	if code, out := s.call("POST", "/v2/customers", map[string]any{"id": id}); code != 201 && code != 200 {
		s.t.Fatalf("create customer: %d %v", code, out)
	}
	code, out := s.call("POST", "/v2/customers/"+id+"/deposit-addresses", map[string]any{"chain": s.chain})
	if code != 200 {
		s.t.Fatalf("deposit address: %d %v", code, out)
	}
	return out["address"].(string)
}

func (s *system) available(customer, asset string) *big.Int {
	s.t.Helper()
	code, out := s.call("GET", "/v2/customers/"+customer+"/balances", nil)
	if code != 200 {
		s.t.Fatalf("balances: %d %v", code, out)
	}
	v := new(big.Int)
	for _, b := range out["balances"].([]any) {
		m := b.(map[string]any)
		if m["asset"] == asset {
			v.SetString(m["available"].(string), 10)
		}
	}
	return v
}

func (s *system) waitAvailable(customer, asset string, want uint64, timeout time.Duration) {
	s.t.Helper()
	s.waitFor(timeout, fmt.Sprintf("%s available %s = %d", customer, asset, want), func() bool { return s.available(customer, asset).Cmp(new(big.Int).SetUint64(want)) == 0 })
}

func (s *system) count(q string, args ...any) int {
	s.t.Helper()
	var n int
	if err := s.pool.QueryRow(s.ctx, q, args...).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func (s *system) cursor() int64 {
	var n int64
	if err := s.pool.QueryRow(s.ctx, `SELECT next_height FROM chain_cursors WHERE chain=$1`, s.chain).Scan(&n); err != nil {
		return -1
	}
	return n
}

// waitScanned waits until the scan cursor is past the finalized slot as it is now: everything final so far has been read.
func (s *system) waitScanned() {
	s.t.Helper()
	slot, err := s.c.rpc.Slot(s.ctx, sol.Finalized)
	if err != nil {
		s.t.Fatal(err)
	}
	s.waitFor(60*time.Second, fmt.Sprintf("scan past finalized slot %d", slot), func() bool { return s.cursor() > int64(slot) })
}

// reconcileClean runs Reconcile through the API and requires a clean report; the Solana comparison waits for the scan itself.
func (s *system) reconcileClean(stage string) {
	s.t.Helper()
	var out map[string]any
	for i := 0; i < 20; i++ {
		var code int
		code, out = s.call("GET", "/v2/reconcile", nil)
		if code == 200 && out["clean"] == true {
			return
		}
		time.Sleep(time.Second)
	}
	s.t.Fatalf("%s: Reconcile is not clean: %v", stage, out)
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

var _ sync.Mutex

func bigU(n uint64) *big.Int { return new(big.Int).SetUint64(n) }

func bytesRead(path string) (string, error) { b, err := os.ReadFile(path); return string(b), err }
