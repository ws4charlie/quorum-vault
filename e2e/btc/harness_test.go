// Package btce2e is the end-to-end suite of the Bitcoin cell: a real bitcoind in regtest (docker compose profile btc), the real
// two-party mpc-party (A and B, SoftHSM sealing), Temporal, Postgres, and the real qv-core and qv-worker processes. Jobs are named
// e2e-btc-<group>. See the Makefile target test-e2e-btc-deposits.
package btce2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

const (
	rpcUser = "qv"
	rpcPass = "qv-regtest-only"
)

var (
	binDir   string
	buildErr error
	mpcBin   mpcstack.Binaries
)

func TestMain(m *testing.M) {
	code := 0
	if os.Getenv("QV_REQUIRE_BTC") == "1" {
		dir, err := os.MkdirTemp("", "qv-e2e-btc-bin-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		binDir = dir
		if mpcBin, err = mpcstack.Build(dir); err != nil {
			buildErr = err
		}
		for _, b := range []string{"qv-worker", "qv-core", "qv-gateway"} {
			if buildErr != nil {
				break
			}
			out, err := exec.Command("go", "build", "-o", filepath.Join(dir, b), "github.com/ws4charlie/quorum-vault/cmd/"+b).CombinedOutput()
			if err != nil {
				buildErr = fmt.Errorf("build %s: %v\n%s", b, err, out)
			}
		}
	}
	code = m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func requireBTC(t *testing.T) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_BTC") != "1" {
		t.Skip("QV_REQUIRE_BTC != 1 (`make btc-up infra-up softhsm mpc-build test-e2e-btc-deposits`)")
	}
	if buildErr != nil {
		t.Fatal(buildErr)
	}
}

func nodeURL() string {
	if v := os.Getenv("QV_BTC_RPC"); v != "" {
		return v
	}
	return "http://127.0.0.1:18443"
}

// node is bitcoind with a wallet of its own for the test: it mines and pays.
type node struct {
	t     *testing.T
	root  *btc.RPC
	w     *btc.RPC
	miner string // the wallet's address, which receives the block rewards
}

func newNode(t *testing.T) *node {
	t.Helper()
	ctx := context.Background()
	n := &node{t: t, root: btc.NewRPC(nodeURL(), rpcUser, rpcPass)}
	var info struct{ Chain string }
	if err := n.root.Call(ctx, &info, "getblockchaininfo"); err != nil {
		t.Fatalf("bitcoind: %v (make btc-up)", err)
	}
	if info.Chain != "regtest" {
		t.Fatalf("refusing to run on bitcoind chain %q", info.Chain)
	}
	name := "e2e-" + uuid.NewString()[:8]
	if err := n.root.Call(ctx, nil, "createwallet", name); err != nil {
		t.Fatal(err)
	}
	n.w = btc.NewRPC(nodeURL()+"/wallet/"+name, rpcUser, rpcPass)
	if err := n.w.Call(ctx, &n.miner, "getnewaddress"); err != nil {
		t.Fatal(err)
	}
	n.mine(101, "") // the first reward is spendable
	// Regtest halves the block reward every 150 blocks, so a node that has run many tests pays little: mine until the wallet (0.05 BTC) can
	// pay the tests, and say so when the node is spent (the reward reaches zero near height 9600).
	for mined := 0; ; mined += 50 {
		var bal float64
		if err := n.w.Call(ctx, &bal, "getbalance"); err != nil {
			t.Fatal(err)
		}
		if bal >= 0.05 {
			break
		}
		if mined >= 1000 {
			t.Fatalf("the wallet has %v BTC after %d more blocks: the regtest block reward is spent; recreate the node (make btc-down btc-up)", bal, mined)
		}
		n.mine(50, "")
	}
	return n
}

func (n *node) height() int64 {
	var h int64
	if err := n.root.Call(context.Background(), &h, "getblockcount"); err != nil {
		n.t.Fatal(err)
	}
	return h
}

// mine mines count blocks to addr (the wallet's own when empty) and returns their hashes.
func (n *node) mine(count int, addr string) []string {
	n.t.Helper()
	if addr == "" {
		addr = n.miner
	}
	var hashes []string
	if err := n.root.Call(context.Background(), &hashes, "generatetoaddress", count, addr); err != nil {
		n.t.Fatal(err)
	}
	return hashes
}

// pay sends amount BTC (a decimal string) to each address in one transaction and returns its txid.
func (n *node) pay(outs map[string]string) string {
	n.t.Helper()
	var txid string
	if err := n.w.Call(context.Background(), &txid, "sendmany", "", outs); err != nil {
		n.t.Fatal(err)
	}
	return txid
}

// fresh is a new address of the wallet. After a block was invalidated, mine to a fresh address: blocks to the same address at the same
// second would be the very block that was just invalidated, and the node refuses it.
func (n *node) fresh() string {
	n.t.Helper()
	var a string
	if err := n.w.Call(context.Background(), &a, "getnewaddress"); err != nil {
		n.t.Fatal(err)
	}
	return a
}

// coinbaseTo is the amount, in satoshis, that the coinbase of the block at height pays to addr.
func (n *node) coinbaseTo(height int64, addr string) int64 {
	n.t.Helper()
	blk, err := btc.NewRPC(nodeURL(), rpcUser, rpcPass).GetBlock(context.Background(), n.blockHash(height))
	if err != nil {
		n.t.Fatal(err)
	}
	for _, o := range blk.Tx[0].Vout {
		if o.ScriptPubKey.Address == addr {
			v, err := btc.Sats(o.Value.String())
			if err != nil {
				n.t.Fatal(err)
			}
			return v.Int64()
		}
	}
	n.t.Fatalf("the coinbase of block %d does not pay %s", height, addr)
	return 0
}

func (n *node) blockHash(height int64) string {
	var h string
	if err := n.root.Call(context.Background(), &h, "getblockhash", height); err != nil {
		n.t.Fatal(err)
	}
	return h
}

func (n *node) invalidate(hash string) {
	n.t.Helper()
	if err := n.root.Call(context.Background(), nil, "invalidateblock", hash); err != nil {
		n.t.Fatal(err)
	}
}

type proc struct {
	name string
	cmd  *exec.Cmd
	log  string
	done chan struct{}
	mu   sync.Mutex
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
	node    *node
	xpub    string
	chain   string
	queue   string
	cfgPath string
	cf      custody.File
	apiURL  string
	worker  *proc
	core    *proc
	start   int64 // the height the scan starts from

	// withdrawals (opts.withdraw)
	acct    *btc.Account
	part    string // the hot partition
	hotAddr string // its address, [1,0]
	approv  map[string]ed25519.PrivateKey
	keyPath string
	gateway *proc
	gwPath  string
	gwGuard string
	tc      client.Client
	tag     string
}

type opts struct {
	minDeposit string // default 1000 sats
	conf       uint64 // default 6
	// withdraw starts the whole withdrawal path: the signing gateway and party B's cosigner, one hot shard, approvers and the automated key.
	withdraw bool
	// gwDest, when set, is the only list of destinations the gateway lets withdrawals pay (otherwise any).
	gwDest []string
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (s *system) spawn(name string, args ...string) *proc {
	s.t.Helper()
	logPath := filepath.Join(s.dir, fmt.Sprintf("%s-%d.log", name, time.Now().UnixNano()))
	lf, err := os.Create(logPath)
	if err != nil {
		s.t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(binDir, name), args...)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+hsm.RepoSoftHSMConf())
	cmd.Stdout, cmd.Stderr = lf, lf
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

// scale stretches every condition wait on a slow runner (QV_E2E_TIMEOUT_SCALE, as in the EVM suite).
func scale(d time.Duration) time.Duration {
	if v, err := strconv.Atoi(os.Getenv("QV_E2E_TIMEOUT_SCALE")); err == nil && v > 1 {
		return d * time.Duration(v)
	}
	return d
}

func (s *system) waitFor(timeout time.Duration, what string, f func() bool) {
	s.t.Helper()
	dl := time.Now().Add(scale(timeout))
	for {
		if f() {
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

// accountXpub asks party A for the account node m/84'/1'/0' and builds the xpub the core is configured with.
func accountXpub(t *testing.T, mpc *mpcstack.Stack, network string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	path := btc.AccountPath(network)
	acct, err := mpc.Client.Node(ctx, &pb.NodeRequest{KeysetId: mpc.KeysetID, HardenedPath: path})
	if err != nil {
		t.Fatalf("Node: %v", err)
	}
	parent, err := mpc.Client.Node(ctx, &pb.NodeRequest{KeysetId: mpc.KeysetID, HardenedPath: path[:2]})
	if err != nil {
		t.Fatalf("Node (parent): %v", err)
	}
	x, err := btc.XpubFromNode(network, acct.PublicKey, acct.ChainCode, parent.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func newMPC(t *testing.T, dir string) *mpcstack.Stack {
	t.Helper()
	m := mpcstack.New(t, filepath.Join(dir, "mpc"), mpcBin, mpcstack.Opts{})
	m.DKG()
	return m
}

func newSystem(t *testing.T, o opts) *system {
	t.Helper()
	requireBTC(t)
	if o.minDeposit == "" {
		o.minDeposit = "1000"
	}
	s := &system{t: t, ctx: context.Background(), dir: t.TempDir(), chain: "btc-" + uuid.NewString()[:8], queue: "qv-e2e-btc-" + uuid.NewString()[:8]}
	s.node = newNode(t)
	s.pool = dbtest.New(t)
	cc := s.pool.Config().ConnConfig
	s.bizDSN = fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cc.User, cc.Host, cc.Port, cc.Database)
	s.mpc = newMPC(t, s.dir)
	s.xpub = accountXpub(t, s.mpc, "regtest")
	s.start = s.node.height() + 1
	s.cf = custody.File{
		Entity: "qv-us",
		Chain: custody.ChainFile{Family: "btc", Name: s.chain,
			BTC:    &custody.BTCFile{Network: "regtest", RPCURL: nodeURL(), RPCUser: rpcUser, RPCPassword: rpcPass, Confirmations: o.conf, AccountXpub: s.xpub},
			Assets: map[string]custody.AssetFile{"BTC": {Decimals: 8, MinDeposit: o.minDeposit}}},
		Withdrawal: custody.WithdrawalFile{ApprovalWindow: "10m", ApprovalTimeout: "20s", ActivityTimeout: "5s"},
		Scan:       custody.ScanFile{Interval: "300ms", StartHeight: uint64(s.start)},
	}
	s.cfgPath = filepath.Join(s.dir, "custody.json")
	s.tag = uuid.NewString()[:8]
	if o.withdraw {
		s.setupWithdrawals(o)
	}
	s.writeConfig(s.cf)

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
	t.Cleanup(func() { // the workflows outlive their worker: end them with the test
		ids := []string{workflow.ScanID(s.chain), workflow.ReconcilerID(s.chain)}
		if rows, err := s.pool.Query(context.Background(), `SELECT id FROM withdrawals`); err == nil {
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
		}
		for _, id := range ids {
			_ = tc.TerminateWorkflow(context.Background(), id, "", "test over")
		}
	})
	if o.withdraw {
		s.startGateway()
	}
	s.startWorker()
	s.startCore()
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
	args := []string{"-config", s.cfgPath, "-dsn", s.bizDSN, "-task-queue", s.queue}
	if s.keyPath != "" {
		args = append(args, "-auto-approver-key-file", s.keyPath)
	}
	s.worker = s.spawn("qv-worker", args...)
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
	return s.callWith(method, path, map[string]string{"X-Actor": "ops"}, body)
}

func (s *system) callWith(method, path string, hdr map[string]string, body any) (int, map[string]any) {
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
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
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

// newCustomer creates a customer and returns the Bitcoin address of its deposits.
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

func (s *system) available(customer string) *big.Int {
	s.t.Helper()
	code, out := s.call("GET", "/v2/customers/"+customer+"/balances", nil)
	if code != 200 {
		s.t.Fatalf("balances: %d %v", code, out)
	}
	v := new(big.Int)
	for _, b := range out["balances"].([]any) {
		m := b.(map[string]any)
		if m["asset"] == "BTC" {
			v.SetString(m["available"].(string), 10)
		}
	}
	return v
}

func (s *system) waitAvailable(customer string, want int64, timeout time.Duration) {
	s.t.Helper()
	s.waitFor(timeout, fmt.Sprintf("%s available = %d sats", customer, want), func() bool { return s.available(customer).Cmp(big.NewInt(want)) == 0 })
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

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
