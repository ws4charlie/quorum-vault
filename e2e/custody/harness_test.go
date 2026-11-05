// Package custody_test runs the whole closed loop with real components: a
// fresh Postgres database, Temporal, Redpanda, anvil, SoftHSM, and the
// qv-gateway, qv-relay, qv-worker and qv-core binaries as separate processes
// that the tests kill and restart. Skipped unless QV_REQUIRE_CUSTODY=1.
//
// Prerequisites (see the task doc): Postgres on DATABASE_URL, Temporal on
// 127.0.0.1:7233, Redpanda on 127.0.0.1:19092, anvil (chain id 11155111) on
// QV_ANVIL_RPC (default http://127.0.0.1:18545), SoftHSM set up.
package custody_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
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
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/e2e"
	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

const ether = 1_000_000_000_000_000_000

var (
	binDir   string
	buildErr error
	mpcBin   mpcstack.Binaries
)

// mpcMode reports whether the hot keys are two-party MPC keys (QV_CUSTODY_SIGNER=mpc) instead of HSM keys (hsm, the default).
func mpcMode() bool { return os.Getenv("QV_CUSTODY_SIGNER") == "mpc" }

func TestMain(m *testing.M) {
	code := 0
	if os.Getenv("QV_REQUIRE_CUSTODY") == "1" {
		dir, err := os.MkdirTemp("", "qv-e2e-bin-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		binDir = dir
		switch os.Getenv("QV_CUSTODY_SIGNER") {
		case "", "hsm", "mpc":
		default:
			fmt.Fprintf(os.Stderr, "QV_CUSTODY_SIGNER=%q: want hsm or mpc\n", os.Getenv("QV_CUSTODY_SIGNER"))
			os.Exit(1)
		}
		if mpcMode() { // the production mpc-party (needs the cb-mpc build) and qv-cosigner
			if mpcBin, err = mpcstack.Build(dir); err != nil {
				buildErr = err
			}
		}
		for _, b := range []string{"qv-gateway", "qv-relay", "qv-worker", "qv-core", "qv-cold"} {
			// The worker is built with -tags devauth: only then does it have the crash-test failpoints (QV_FAILPOINT).
			args := []string{"build", "-o", filepath.Join(dir, b)}
			if b == "qv-worker" {
				args = append(args, "-tags", "devauth")
			}
			out, err := exec.Command("go", append(args, "github.com/ws4charlie/quorum-vault/cmd/"+b)...).CombinedOutput()
			if err != nil {
				buildErr = fmt.Errorf("build %s: %v\n%s", b, err, out)
				break
			}
		}
	}
	code = m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func requireCustody(t *testing.T) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_CUSTODY") != "1" {
		t.Skip("QV_REQUIRE_CUSTODY != 1")
	}
	if buildErr != nil {
		t.Fatal(buildErr)
	}
}

// opts tunes a system. Zero values give the standard setup.
type opts struct {
	shards          int    // hot shards, default 1
	frozen          bool   // factory deployed frozen and left frozen
	gwETHPerTx      string // gateway per-tx cap for ETH (wei), default huge
	businessOneTier bool   // business config knows only the lowest tier (the gateway still has two)
	approvalTimeout string // default 20s
	stuckAfter      string // default 4s (scaled)
	noRelay         bool
	minSweepWei     string
	// signTimeout overrides the gateway sign timeout (and with it the retry window and the lease) for a test whose signatures are
	// made slow on purpose.
	signTimeout string
	mpcProxy    bool // mpc mode: A reaches B through the session proxy (partition, latency, tamper)
	cold        *coldOpts
}

// coldOpts turns hot-to-cold on: the business config gets the cold address and these limits (base units; target defaults to
// halfway). The gateway and the cosigner always know the cold address.
type coldOpts struct {
	ethLow, ethHigh, ethTarget    string
	usdtLow, usdtHigh, usdtTarget string
	// coldHSM puts the cold key in the qv-cold token (as in production) and prepares the offline signer's config and three
	// operators (2 of 3 must approve). refillStuck is the ALERT time for a broadcast refill that does not confirm (default 30m).
	coldHSM     bool
	refillStuck string
}

type proc struct {
	name string
	cmd  *exec.Cmd
	log  string
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// exitCode waits for the process to end; ok is false on timeout.
func (p *proc) exitCode(timeout time.Duration) (int, bool) {
	select {
	case <-p.done:
		return p.cmd.ProcessState.ExitCode(), true
	case <-time.After(timeout):
		return 0, false
	}
}

func (p *proc) kill() {
	if p == nil || p.exited() {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	<-p.done
}

func (p *proc) stop() {
	if p == nil || p.exited() {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		p.kill()
	}
}

type system struct {
	t   *testing.T
	ctx context.Context
	o   opts

	pool     *pgxpool.Pool
	bizDSN   string
	guardDSN string
	rpcURL   string
	rc       *rpc.Client
	ec       *ethclient.Client

	deployer, admin, guardian *ecdsa.PrivateKey
	factory, usdt             common.Address
	tokABI                    abi.ABI
	factoryABI                abi.ABI
	shardAddr                 []common.Address
	coldAddr                  common.Address  // the cold address both zones are configured with
	cold                      *coldKit        // the offline signer's side, when opts.cold.coldHSM
	mpc                       *mpcstack.Stack // mpc mode only
	tm                        *timing
	cosGuardDSN               string
	chainName                 string
	queue                     string

	cfg     *custody.Config
	cfgPath string
	gwPath  string
	keyPath string
	dir     string
	approv  map[string]ed25519.PrivateKey

	svc *custody.Service
	tc  client.Client

	gateway, relay, worker, core *proc
	apiURL                       string
	extraEnv                     []string
	tag                          string // makes withdrawal IDs unique to this system (see withdraw)
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (s *system) mustSend(key *ecdsa.PrivateKey, to *common.Address, value *big.Int, data []byte) *types.Receipt {
	s.t.Helper()
	from := crypto.PubkeyToAddress(key.PublicKey)
	nonce, err := s.ec.PendingNonceAt(s.ctx, from)
	if err != nil {
		s.t.Fatal(err)
	}
	gas, err := s.ec.EstimateGas(s.ctx, ethereum.CallMsg{From: from, To: to, Value: value, Data: data})
	if err != nil {
		s.t.Fatalf("estimate gas: %v", err)
	}
	h, err := s.ec.HeaderByNumber(s.ctx, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	tip := big.NewInt(2e9)
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: nonce, GasTipCap: tip,
		GasFeeCap: new(big.Int).Add(new(big.Int).Mul(h.BaseFee, big.NewInt(2)), tip), Gas: gas * 12 / 10, To: to, Value: value, Data: data})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(tx.ChainId()), key)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := s.ec.SendTransaction(s.ctx, signed); err != nil {
		s.t.Fatalf("send: %v", err)
	}
	for i := 0; i < 200; i++ {
		if r, err := s.ec.TransactionReceipt(s.ctx, signed.Hash()); err == nil {
			if r.Status != 1 {
				s.t.Fatalf("tx %s reverted", signed.Hash())
			}
			return r
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatalf("no receipt for %s", signed.Hash())
	return nil
}

func readBin(t *testing.T, name string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "chain", "evm", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return common.FromHex(strings.TrimSpace(string(b)))
}

func (s *system) fundETH(a common.Address, wei *big.Int) {
	s.t.Helper()
	if err := s.rc.CallContext(s.ctx, nil, "anvil_setBalance", a, (*hexutil.Big)(wei)); err != nil {
		s.t.Fatal(err)
	}
}

func eth(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(ether)) }

func newSystem(t *testing.T, o opts) *system {
	t.Helper()
	requireCustody(t)
	tm := newTiming(t)
	t.Cleanup(func() { tm.finish(t) }) // registered first, so it runs last: after everything is torn down
	if o.shards == 0 {
		o.shards = 1
	}
	if o.approvalTimeout == "" {
		o.approvalTimeout = "20s"
	}
	if o.stuckAfter == "" {
		o.stuckAfter = sd(4 * time.Second)
	}
	if o.gwETHPerTx == "" {
		o.gwETHPerTx = "1000000000000000000000000"
	}
	if o.minSweepWei == "" {
		o.minSweepWei = "1000000000000000" // 0.001 ETH
	}
	dir := t.TempDir()
	if keep := os.Getenv("QV_E2E_LOGDIR"); keep != "" { // keep every process log of a run
		dir = filepath.Join(keep, strings.ReplaceAll(t.Name(), "/", "_")+"-"+uuid.NewString()[:6])
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := &system{t: t, o: o, ctx: context.Background(), approv: map[string]ed25519.PrivateKey{}, dir: dir, tag: uuid.NewString()[:8], tm: tm}
	s.rpcURL = os.Getenv("QV_ANVIL_RPC")
	if s.rpcURL == "" {
		s.rpcURL = "http://127.0.0.1:18545"
	}
	cctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if err := e2e.CheckLocalChain(cctx, s.rpcURL); err != nil {
		t.Fatalf("refusing to run: %v", err)
	}
	var err error
	if s.rc, err = rpc.DialContext(s.ctx, s.rpcURL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.rc.Close)
	_ = s.rc.CallContext(s.ctx, nil, "evm_setAutomine", true)
	s.ec = ethclient.NewClient(s.rc)

	// Databases: the business database, and the gateway's own replay guard.
	s.pool = dbtest.New(t)
	cc := s.pool.Config().ConnConfig
	s.bizDSN = fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cc.User, cc.Host, cc.Port, cc.Database)
	s.guardDSN = s.newGuardDB()
	s.gatewayLogin()

	s.chainName = "evm-" + uuid.NewString()[:8]
	s.queue = "qv-e2e-" + uuid.NewString()[:8]

	s.tm.phase("databases (Postgres, guard DBs)")
	// Chain: factory (deployed frozen), token, keys. All keys are generated now.
	s.deployer, _ = crypto.GenerateKey()
	s.admin, _ = crypto.GenerateKey()
	s.guardian, _ = crypto.GenerateKey()
	for _, k := range []*ecdsa.PrivateKey{s.deployer, s.admin, s.guardian} {
		s.fundETH(crypto.PubkeyToAddress(k.PublicKey), eth(1_000_000))
	}
	if raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "chain", "evm", "testdata", "Token.abi.json")); err != nil {
		t.Fatal(err)
	} else if s.tokABI, err = abi.JSON(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	s.factoryABI, _ = abi.JSON(strings.NewReader(`[{"type":"function","name":"setDestination","inputs":[{"name":"d","type":"address"}]},{"type":"function","name":"freeze","inputs":[]}]`))
	s.factory = s.mustSend(s.deployer, nil, new(big.Int), evm.FactoryDeployData(common.Address{}, crypto.PubkeyToAddress(s.admin.PublicKey), crypto.PubkeyToAddress(s.guardian.PublicKey))).ContractAddress
	s.usdt = s.mustSend(s.deployer, nil, new(big.Int), readBin(t, "UsdtLike.bin")).ContractAddress

	s.tm.phase("chain (factory, token, funding keys)")
	// Hot shards: HSM keys that never leave the token, or (mpc mode) keys derived from a two-party DKG whose shares live
	// in two parties' own HSM tokens.
	signers := map[string]gateway.SignerFile{}
	var keys []struct{ id, pub string }
	var mpcShards []mpcstack.Shard
	if mpcMode() {
		s.mpc = mpcstack.New(t, filepath.Join(dir, "mpc"), mpcBin, mpcstack.Opts{Proxy: o.mpcProxy})
		s.mpc.DKG()
		for i := 0; i < o.shards; i++ {
			sh := s.mpc.Derive(i)
			mpcShards = append(mpcShards, sh)
			s.shardAddr = append(s.shardAddr, sh.Addr)
			s.fundETH(s.shardAddr[i], eth(0))
		}
	} else {
		tok := hsmtest.Token(t, "quorumvault")
		gen := hsmsigner.NewGenerator(tok)
		for i := 0; i < o.shards; i++ {
			k, err := gen.Generate(s.ctx, "p3b-"+uuid.NewString()[:8], 1)
			if err != nil {
				t.Fatal(err)
			}
			id := k.HSMKeyID
			t.Cleanup(func() { tok.DestroyPrivateKey(context.Background(), id) })
			s.shardAddr = append(s.shardAddr, common.HexToAddress(k.Address))
			keys = append(keys, struct{ id, pub string }{hex.EncodeToString(k.HSMKeyID), hex.EncodeToString(k.PublicKey)})
			s.fundETH(s.shardAddr[i], eth(0)) // exists, empty; funded below with the ledger entry
		}
	}

	s.tm.phase("hot keys (HSM generate, or mpc parties + DKG + derive)")
	// Approvers.
	apprFiles := map[string]gateway.ApproverFile{}
	for _, name := range []string{"alice", "bob", "carol", "auto"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		s.approv[name] = priv
		apprFiles[name] = gateway.ApproverFile{PublicKey: hex.EncodeToString(pub), Enabled: true}
	}
	seed := s.approv["auto"].Seed()
	s.keyPath = filepath.Join(s.dir, "auto.key")
	if err := os.WriteFile(s.keyPath, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		t.Fatal(err)
	}

	// Business config.
	hexAddrs := make([]string, len(s.shardAddr))
	for i, a := range s.shardAddr {
		hexAddrs[i] = a.Hex()
	}
	tiers := map[string][]custody.TierFile{
		"ETH":  {{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: fmt.Sprint(int64(ether)), Approvals: 2}},
		"USDT": {{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: "2000000000", Approvals: 2}},
	}
	if o.businessOneTier {
		tiers = map[string][]custody.TierFile{"ETH": {{MinAmount: "0", Approvals: 1, Auto: true}}, "USDT": {{MinAmount: "0", Approvals: 1, Auto: true}}}
	}
	startHeight, err := s.ec.BlockNumber(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	cf := custody.File{
		Entity: "qv-us",
		Chain: custody.ChainFile{Name: s.chainName, ChainID: 11155111, RPCURL: s.rpcURL, Confirmations: 0,
			Factory: s.factory.Hex(), SweepDestination: s.shardAddr[0].Hex(), HotShards: hexAddrs, MaxTxFeeWei: "100000000000000000",
			Assets: map[string]custody.AssetFile{
				"ETH":  {Decimals: 18, MinDeposit: "0", PriceWei: "1"},
				"USDT": {Address: s.usdt.Hex(), Decimals: 6, MinDeposit: "1000", PriceWei: "300000000"},
			}},
		Sweep: custody.SweepFile{K: 20, MinSweepWei: o.minSweepWei, PlanInterval: "300ms"},
		Withdrawal: custody.WithdrawalFile{ApprovalWindow: "10m", ApprovalTimeout: o.approvalTimeout, SignTimeout: signTimeout(o), StuckAfter: o.stuckAfter, ActivityTimeout: sd(5 * time.Second),
			HotWait: "1m", MaxReplacements: 3, Tiers: tiers},
		Scan: custody.ScanFile{Interval: "500ms", StartHeight: startHeight},
	}
	s.coldAddr = randAddr()
	if o.cold != nil && o.cold.coldHSM {
		s.cold = newColdKit(t, s)
		s.coldAddr = s.cold.addr
	}
	if o.cold != nil {
		cf.Cold = custody.ColdFile{
			Addresses: map[string]string{"omnibus/native": s.coldAddr.Hex(), "omnibus/token": s.coldAddr.Hex()},
			Limits: map[string]custody.LimitFile{
				"ETH":  {Low: o.cold.ethLow, High: o.cold.ethHigh, Target: o.cold.ethTarget},
				"USDT": {Low: o.cold.usdtLow, High: o.cold.usdtHigh, Target: o.cold.usdtTarget},
			},
			PlanInterval: "1s",
			Refill:       custody.RefillFile{Poll: "1s", StuckAfter: o.cold.refillStuck},
		}
	}
	s.cfgPath = filepath.Join(s.dir, "custody.json")
	writeJSON(t, s.cfgPath, cf)
	if s.cfg, err = custody.LoadConfig(s.cfgPath); err != nil {
		t.Fatal(err)
	}

	// Signing-zone config: separate file, separate trust.
	hot := map[string]string{}
	for _, sym := range s.cfg.AssetList {
		for i := range s.shardAddr {
			p := s.cfg.PartitionKey(sym, i).String()
			hot[p] = s.shardAddr[i].Hex()
			if mpcMode() {
				signers[p] = s.mpc.GatewaySigner(mpcShards[i])
			} else {
				signers[p] = gateway.SignerFile{Token: "quorumvault", KeyID: keys[i].id, PublicKey: keys[i].pub}
			}
		}
	}
	gf := gateway.File{
		Approvers: apprFiles, Signers: signers, SignTimeout: signTimeout(o), MaxIntentAge: "24h",
		Chains: map[string]gateway.ChainFile{s.chainName: {
			EVM: &gateway.EVMFile{ChainID: 11155111, Factory: s.factory.Hex(), SweepDestination: s.shardAddr[0].Hex(), HotAddresses: hot,
				ColdAddresses: map[string]string{"omnibus/native": s.coldAddr.Hex(), "omnibus/token": s.coldAddr.Hex()},
				Tokens:        map[string]gateway.TokenFile{"USDT": {Address: s.usdt.Hex(), Decimals: 6}}, MaxTxFeeWei: "100000000000000000"},
			Assets: map[string]gateway.AssetFile{
				"ETH": {PerTxCap: o.gwETHPerTx, DailyCap: "1000000000000000000000000000",
					Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: fmt.Sprint(int64(ether)), Approvals: 2}}, ToColdDailyCap: "1000000000000000000000000000"},
				"USDT": {PerTxCap: "1000000000000000", DailyCap: "1000000000000000000", ToColdDailyCap: "1000000000000000000",
					Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: "2000000000", Approvals: 2}}},
			},
			SweepsPerHour: 100000, CancelsPerHour: 1000, ToColdPerHour: 1000}},
	}
	s.gwPath = filepath.Join(s.dir, "gateway.json")
	writeJSON(t, s.gwPath, gf)
	if mpcMode() {
		// The cosigner (party B's authorizer) has its own copy of the signing-zone rules, without any signer entries, and
		// its own replay-guard database. It also reads the gateway's guard to see what the gateway reserved.
		cf2 := gf
		cf2.Signers = nil
		cosPath := filepath.Join(s.dir, "cosigner.json")
		writeJSON(t, cosPath, cf2)
		s.cosGuardDSN = s.newGuardDB()
		s.mpc.StartCosigner(cosPath, s.cosGuardDSN, s.guardDSN)
	}

	s.tm.phase("configs")
	// In-process service for funding and Reconcile (reads only, plus FundHot).
	adapter, err := evm.New(s.ctx, s.cfg.EVM, s.pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adapter.Close)
	reader, err := custody.NewEVMReader(s.ctx, s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	s.svc = custody.New(s.pool, s.cfg, adapter, reader)
	if err := s.svc.Bootstrap(s.ctx); err != nil {
		t.Fatal(err)
	}

	s.tm.phase("in-process service + adapter")
	// Temporal.
	addr := os.Getenv("QV_TEMPORAL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:7233"
	}
	rctx, rcancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer rcancel()
	if err := workflow.RegisterNamespace(rctx, addr, "default"); err != nil {
		t.Fatal(err)
	}
	dl := time.Now().Add(60 * time.Second)
	for {
		s.tc, err = client.DialContext(s.ctx, client.Options{HostPort: addr, Namespace: "default"})
		if err == nil {
			if _, err = s.tc.CheckHealth(s.ctx, &client.CheckHealthRequest{}); err == nil {
				break
			}
		}
		if time.Now().After(dl) {
			t.Fatalf("temporal: %v", err)
		}
		time.Sleep(time.Second)
	}
	t.Cleanup(s.tc.Close)
	t.Cleanup(s.terminateWorkflows)

	s.tm.phase("Temporal connect")
	// Fund the hot wallets: gas money on chain and in the books.
	for i, a := range s.shardAddr {
		s.fundETH(a, eth(100))
		if err := s.svc.FundHot(s.ctx, fmt.Sprintf("seed-%d", i), i, eth(100)); err != nil {
			t.Fatal(err)
		}
	}
	if !o.frozen {
		s.setDestination(s.shardAddr[0])
	}

	s.tm.phase("fund hot wallets")
	s.startGateway()
	if !o.noRelay {
		s.startRelay()
	}
	s.startWorker("")
	s.startCore()
	s.tm.phase("start gateway, relay, worker, core")
	s.tm.markReady()
	t.Cleanup(tm.markBodyEnd) // registered last, so it runs first: the moment the test body is over
	return s
}

// signTimeout bounds one signer call at the gateway, and is also how long a reserved digest counts as "being signed" (a retry
// after an outage waits that long) and, with the lease, how long a failed attempt keeps its job. An HSM answers in milliseconds
// and two parties in about 50 ms, so the test values are short (they are stretched by QV_E2E_TIMEOUT_SCALE on a slow runner):
// 3 s for the HSM, 5 s for two parties. A test that makes signatures slow on purpose sets opts.signTimeout. The business config's
// sign_timeout (how long the workflow waits before it re-enqueues a failed job) is the same value.
// QV_CUSTODY_SIGN_TIMEOUT overrides everything.
func signTimeout(o opts) string {
	if v := os.Getenv("QV_CUSTODY_SIGN_TIMEOUT"); v != "" {
		return v
	}
	if o.signTimeout != "" {
		return o.signTimeout
	}
	if mpcMode() {
		return sd(5 * time.Second)
	}
	return "3s"
}

// gatewayLease is how long a claimed job stays with its worker before another may take it: longer than one signer call.
func gatewayLease(o opts) string {
	d, err := time.ParseDuration(signTimeout(o))
	if err != nil {
		return "30s"
	}
	return (d + sdur(3*time.Second)).String()
}

// sd is a test duration written as a config string, stretched by QV_E2E_TIMEOUT_SCALE.
func sd(d time.Duration) string { return sdur(d).String() }

func sdur(d time.Duration) time.Duration { return scaled(d) }

// scaled stretches a wait by QV_E2E_TIMEOUT_SCALE (default 1; CI sets a larger value). Every wait in these tests is on a
// condition, so the scale only changes how long a slow machine is given before the test calls it stuck.
func scaled(d time.Duration) time.Duration {
	if v, err := strconv.ParseFloat(os.Getenv("QV_E2E_TIMEOUT_SCALE"), 64); err == nil && v > 0 {
		return time.Duration(float64(d) * v)
	}
	return d
}

func writeJSON(t *testing.T, path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *system) newGuardDB() string {
	t := s.t
	url := os.Getenv("DATABASE_URL")
	admin, err := pgx.Connect(s.ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(s.ctx)
	name := "qv_guard_" + strings.ReplaceAll(uuid.NewString()[:12], "-", "")
	if _, err := admin.Exec(s.ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), url)
		if err == nil {
			c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	cfg, _ := pgx.ParseConfig(url)
	return fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cfg.User, cfg.Host, cfg.Port, name)
}

// gatewayLogin lets the gateway connect as role qv_gateway (SELECT and UPDATE on
// sign_jobs only). The migration creates it NOLOGIN; operators grant LOGIN.
func (s *system) gatewayLogin() {
	url := os.Getenv("DATABASE_URL")
	c, err := pgx.Connect(s.ctx, url)
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close(s.ctx)
	if _, err := c.Exec(s.ctx, `ALTER ROLE qv_gateway LOGIN`); err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), url)
		if err == nil {
			c.Exec(context.Background(), `ALTER ROLE qv_gateway NOLOGIN`)
			c.Close(context.Background())
		}
	})
}

func (s *system) gatewayJobsDSN() string {
	return strings.Replace(s.bizDSN, "//qv@", "//qv_gateway@", 1)
}

func (s *system) setDestination(dest common.Address) {
	s.t.Helper()
	data, err := s.factoryABI.Pack("setDestination", dest)
	if err != nil {
		s.t.Fatal(err)
	}
	s.mustSend(s.admin, &s.factory, new(big.Int), data)
}

func (s *system) freeze() {
	s.t.Helper()
	data, _ := s.factoryABI.Pack("freeze")
	s.mustSend(s.guardian, &s.factory, new(big.Int), data)
}

// ---- processes ----

func (s *system) spawn(name string, env []string, args ...string) *proc {
	s.t.Helper()
	logPath := filepath.Join(s.dir, fmt.Sprintf("%s-%d.log", name, time.Now().UnixNano()))
	lf, err := os.Create(logPath)
	if err != nil {
		s.t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(binDir, name), args...)
	cmd.Env = append(os.Environ(), env...)
	if os.Getenv("SOFTHSM2_CONF") == "" {
		cmd.Env = append(cmd.Env, "SOFTHSM2_CONF="+hsm.RepoSoftHSMConf())
	}
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
			s.t.Logf("---- %s log (%s) tail ----\n%s", name, filepath.Base(p.log), b)
		}
	})
	return p
}

func (s *system) startGateway() {
	s.gateway = s.spawn("qv-gateway", []string{"QV_HSM_PIN=" + hsmtest.PIN()},
		"-config", s.gwPath, "-jobs-dsn", s.gatewayJobsDSN(), "-guard-dsn", s.guardDSN, "-interval", "200ms", "-lease", gatewayLease(s.o),
		"-worker-id", "gw-"+uuid.NewString()[:6])
}

func (s *system) startRelay() {
	s.relay = s.spawn("qv-relay", nil, "-dsn", s.bizDSN, "-brokers", "127.0.0.1:19092", "-idle", "200ms")
}

// startWorker starts qv-worker; failpoint "" arms nothing.
func (s *system) startWorker(failpoint string) {
	env := []string{"QV_FAILPOINT=" + failpoint}
	s.worker = s.spawn("qv-worker", env, "-config", s.cfgPath, "-dsn", s.bizDSN, "-task-queue", s.queue, "-auto-approver-key-file", s.keyPath)
	// Never stop a worker before it is polling: a task dispatched to a poller
	// that dies at once is stranded until the server gives up on it.
	p := s.worker
	s.waitFor(30*time.Second, "worker started", func() bool { return fileContains(p.log, "qv-worker started") })
}

func (s *system) startCore() {
	port := freePort(s.t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	s.core = s.spawn("qv-core", nil, "-config", s.cfgPath, "-dsn", s.bizDSN, "-addr", addr, "-task-queue", s.queue)
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

func (s *system) terminateWorkflows() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ids := []string{workflow.ScanID(s.chainName), workflow.PlannerID(s.chainName), workflow.ReconcilerID(s.chainName), workflow.ColdPlannerID(s.chainName)}
	for _, q := range []string{`SELECT id FROM withdrawals`, `SELECT id FROM sweeps`, `SELECT id FROM cold_moves`, `SELECT id FROM refills`} {
		rows, err := s.pool.Query(ctx, q)
		if err != nil {
			continue
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
	}
	for _, id := range ids {
		_ = s.tc.TerminateWorkflow(ctx, id, "", "test finished")
	}
}

// ---- helpers ----

func (s *system) waitFor(timeout time.Duration, what string, f func() bool) {
	s.t.Helper()
	timeout = scaled(timeout)
	start := time.Now()
	dl := start.Add(timeout)
	for {
		if f() {
			s.tm.wait(what, time.Since(start))
			return
		}
		if time.Now().After(dl) {
			s.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// historyLen is the number of history events of a workflow's latest run.
func (s *system) historyLen(id string) int {
	d, err := s.tc.DescribeWorkflowExecution(s.ctx, id, "")
	if err != nil {
		return 0
	}
	return int(d.WorkflowExecutionInfo.HistoryLength)
}

// waitHistory waits until the workflow has written n more history events: it has run again. (A run that continued as new counts as
// progress.)
func (s *system) waitHistory(id string, n int) {
	s.t.Helper()
	base := s.historyLen(id)
	s.waitFor(30*time.Second, fmt.Sprintf("%s to write %d more history events", id, n), func() bool {
		cur := s.historyLen(id)
		return cur >= base+n || cur < base
	})
}

// waitPasses waits for a long-running loop workflow to go round a few more times (each pass writes at least six events).
func (s *system) waitPasses(id string, passes int) { s.t.Helper(); s.waitHistory(id, passes*6) }

// holds asserts that cond stays true for d (a negative check cannot be a condition wait: something that must NOT happen is only
// shown by waiting). d is stretched by QV_E2E_TIMEOUT_SCALE.
func (s *system) holds(d time.Duration, what string, cond func() bool) {
	s.t.Helper()
	end := time.Now().Add(scaled(d))
	for time.Now().Before(end) {
		if !cond() {
			s.t.Fatalf("%s: stopped being true", what)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func (s *system) call(method, path string, hdr map[string]string, body any) (int, map[string]any) {
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

func (s *system) newCustomer(id string) common.Address {
	s.t.Helper()
	if code, out := s.call("POST", "/v2/customers", map[string]string{"X-Actor": "ops"}, map[string]any{"id": id}); code != 201 && code != 200 {
		s.t.Fatalf("create customer: %d %v", code, out)
	}
	code, out := s.call("POST", "/v2/customers/"+id+"/deposit-addresses", map[string]string{"X-Actor": "ops"}, map[string]any{"chain": s.chainName})
	if code != 200 {
		s.t.Fatalf("deposit address: %d %v", code, out)
	}
	return common.HexToAddress(out["address"].(string))
}

func (s *system) sendETH(to common.Address, wei *big.Int) { s.mustSend(s.deployer, &to, wei, nil) }

func (s *system) mintUSDT(to common.Address, amt int64) {
	data, err := s.tokABI.Pack("mint", to, big.NewInt(amt))
	if err != nil {
		s.t.Fatal(err)
	}
	s.mustSend(s.deployer, &s.usdt, new(big.Int), data)
}

func (s *system) ethBalance(a common.Address) *big.Int {
	b, err := s.ec.BalanceAt(s.ctx, a, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

func (s *system) usdtBalance(a common.Address) *big.Int {
	data, _ := s.tokABI.Pack("balanceOf", a)
	out, err := s.ec.CallContract(s.ctx, ethereum.CallMsg{To: &s.usdt, Data: data}, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return new(big.Int).SetBytes(out)
}

func (s *system) chainBalance(asset string, a common.Address) *big.Int {
	if asset == "ETH" {
		return s.ethBalance(a)
	}
	return s.usdtBalance(a)
}

// customer balance fields for an asset, as big ints.
func (s *system) balance(customer, asset string) (avail, held, posted *big.Int) {
	s.t.Helper()
	code, out := s.call("GET", "/v2/customers/"+customer+"/balances", nil, nil)
	if code != 200 {
		s.t.Fatalf("balances: %d %v", code, out)
	}
	zero := func() *big.Int { return new(big.Int) }
	avail, held, posted = zero(), zero(), zero()
	for _, b := range out["balances"].([]any) {
		m := b.(map[string]any)
		if m["asset"] == asset {
			avail.SetString(m["available"].(string), 10)
			held.SetString(m["held"].(string), 10)
			posted.SetString(m["posted"].(string), 10)
		}
	}
	return
}

func (s *system) waitAvailable(customer, asset string, want *big.Int, timeout time.Duration) {
	s.t.Helper()
	s.waitFor(timeout, fmt.Sprintf("%s %s available = %s", customer, asset, want), func() bool {
		a, _, _ := s.balance(customer, asset)
		return a.Cmp(want) == 0
	})
}

type wd struct {
	ID, Status, Reason, Tx string
	Code                   int
	Raw                    map[string]any
}

func (s *system) withdraw(actor, key, customer, asset string, to common.Address, amount *big.Int) wd {
	s.t.Helper()
	// A withdrawal's workflow ID is derived from (actor, key). Tests share one
	// Temporal server, so identical keys in two runs would give identical workflow
	// IDs, and a workflow left running by an earlier (killed) run would be joined
	// instead of a new one started. A per-system tag keeps IDs unique.
	key += "~" + s.tag
	code, out := s.call("POST", "/v2/withdrawals", map[string]string{"X-Actor": actor, "Idempotency-Key": key},
		map[string]any{"customer": customer, "asset": asset, "to": to.Hex(), "amount": amount.String()})
	w := wd{Code: code, Raw: out}
	if code == 200 || code == 201 {
		w.ID, _ = out["id"].(string)
		w.Status, _ = out["status"].(string)
	}
	return w
}

func (s *system) getWd(id string) wd {
	s.t.Helper()
	code, out := s.call("GET", "/v2/withdrawals/"+id, nil, nil)
	if code != 200 {
		s.t.Fatalf("get withdrawal: %d %v", code, out)
	}
	w := wd{ID: id, Code: code, Raw: out}
	w.Status, _ = out["status"].(string)
	w.Reason, _ = out["failure_reason"].(string)
	w.Tx, _ = out["tx_hash"].(string)
	return w
}

func (s *system) waitWd(id, status string, timeout time.Duration) wd {
	s.t.Helper()
	var w wd
	s.waitFor(timeout, fmt.Sprintf("withdrawal %s = %s", id, status), func() bool {
		w = s.getWd(id)
		if w.Status == "failed" && status != "failed" {
			s.t.Fatalf("withdrawal %s failed: %s", id, w.Reason)
		}
		return w.Status == status
	})
	return w
}

// approve fetches the intent the way an approver would, signs its hash, and posts the approval.
func (s *system) approve(actor, id string) (int, map[string]any) {
	s.t.Helper()
	code, in := s.call("GET", "/v2/withdrawals/"+id+"/intent", nil, nil)
	if code != 200 {
		s.t.Fatalf("intent: %d %v", code, in)
	}
	h, err := hex.DecodeString(in["hash"].(string))
	if err != nil {
		s.t.Fatal(err)
	}
	sig := ed25519.Sign(s.approv[actor], h)
	return s.call("POST", "/v2/withdrawals/"+id+"/approvals", map[string]string{"X-Actor": actor},
		map[string]any{"actor": actor, "signature": hex.EncodeToString(sig)})
}

func (s *system) count(query string, args ...any) int {
	var n int
	if err := s.pool.QueryRow(s.ctx, query, args...).Scan(&n); err != nil {
		s.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (s *system) posted(acct string) *big.Int {
	var p string
	if err := s.pool.QueryRow(s.ctx, `SELECT posted::text FROM ledger_accounts WHERE id=$1`, acct).Scan(&p); err != nil {
		s.t.Fatalf("account %s: %v", acct, err)
	}
	n, _ := new(big.Int).SetString(p, 10)
	return n
}

// reconcileClean waits for Reconcile to come back clean (the scan may still be catching up) and fails with the report otherwise.
func (s *system) reconcileClean() custody.Report {
	s.t.Helper()
	var rep custody.Report
	dl := time.Now().Add(scaled(45 * time.Second))
	for {
		var err error
		rep, err = s.svc.Reconcile(s.ctx)
		if err != nil {
			s.t.Fatal(err)
		}
		if rep.Clean {
			return rep
		}
		if time.Now().After(dl) {
			b, _ := json.MarshalIndent(rep.Failures(), "", "  ")
			s.t.Fatalf("Reconcile is not clean: in flight %d, height %d, cursor %d\n%s", rep.InFlight, rep.Height, rep.ScanCursor, b)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (s *system) sweepsConfirmed() int {
	return s.count(`SELECT count(*) FROM sweeps WHERE status='confirmed'`)
}

func (s *system) openWork() int {
	return s.count(`SELECT (SELECT count(*) FROM sweeps WHERE status NOT IN ('confirmed','failed')) + (SELECT count(*) FROM withdrawals WHERE status NOT IN ('confirmed','failed')) + (SELECT count(*) FROM cold_moves WHERE status NOT IN ('confirmed','failed'))`)
}

// waitIdle waits until no sweep or withdrawal is open.
func (s *system) waitIdle(timeout time.Duration) {
	s.t.Helper()
	s.waitFor(timeout, "no open sweeps or withdrawals", func() bool { return s.openWork() == 0 })
}

func randAddr() common.Address {
	k, _ := crypto.GenerateKey()
	return crypto.PubkeyToAddress(k.PublicKey)
}

func common20(hex string) common.Address { return common.HexToAddress(hex) }

func fileContains(path, sub string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(b), sub)
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// dump prints the state of everything a stuck money flow could be waiting on.
func (s *system) dump(label string) {
	s.t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "==== state dump: %s ====\n", label)
	q := func(title, sql string) {
		rows, err := s.pool.Query(context.Background(), sql)
		if err != nil {
			fmt.Fprintf(&b, "%s: %v\n", title, err)
			return
		}
		defer rows.Close()
		fmt.Fprintf(&b, "-- %s\n", title)
		for rows.Next() {
			vals, _ := rows.Values()
			fmt.Fprintf(&b, "   %v\n", vals)
		}
	}
	q("withdrawals (id, status, reason, job, tx)", `SELECT id, status, COALESCE(failure_reason,''), COALESCE(job_id,''), COALESCE(tx_hash,'') FROM withdrawals ORDER BY created_at`)
	q("open or parked sweeps (id, status, from, reason)", `SELECT id, status, from_address, COALESCE(failure_reason,'') FROM sweeps WHERE status NOT IN ('confirmed','failed') OR failure_reason IS NOT NULL ORDER BY created_at`)
	q("sign jobs not done (id, status, reject)", `SELECT id, status, COALESCE(reject_reason,'') FROM sign_jobs WHERE status<>'done' ORDER BY created_at`)
	q("open nonce allocations (address, nonce, owner, status)", `SELECT address, nonce, owner_kind||' '||owner_id, status FROM evm_nonce_allocations WHERE status NOT IN ('confirmed','cancelled') ORDER BY address, nonce`)
	q("cold moves (id, status, amount, reason)", `SELECT id, status, amount::text, COALESCE(failure_reason,'') FROM cold_moves ORDER BY created_at`)
	q("scan cursor", `SELECT chain, next_height FROM chain_cursors`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, id := range s.openIDs() {
		if d, err := s.tc.DescribeWorkflowExecution(ctx, id, ""); err == nil {
			fmt.Fprintf(&b, "workflow %s: %s on task queue %q (this system's is %q), %d events, %d pending activities\n", id, d.WorkflowExecutionInfo.Status,
				d.ExecutionConfig.GetTaskQueue().GetName(), s.queue, d.WorkflowExecutionInfo.HistoryLength, len(d.PendingActivities))
			for _, pa := range d.PendingActivities {
				fmt.Fprintf(&b, "   pending activity %s attempt %d last failure %v\n", pa.ActivityType.Name, pa.Attempt, pa.LastFailure.GetMessage())
			}
		}
	}
	if head, err := s.ec.BlockNumber(ctx); err == nil {
		fmt.Fprintf(&b, "chain head %d\n", head)
	}
	tail := func(name string, p *proc) {
		if p == nil {
			return
		}
		lines := strings.Split(strings.TrimSpace(readFile(p.log)), "\n")
		if len(lines) > 12 {
			lines = lines[len(lines)-12:]
		}
		fmt.Fprintf(&b, "-- last log lines of %s (%s)\n%s\n", name, p.log, strings.Join(lines, "\n"))
	}
	tail("worker", s.worker)
	tail("gateway", s.gateway)
	s.t.Log(b.String())
}

func (s *system) openIDs() []string {
	var ids []string
	for _, q := range []string{`SELECT id FROM withdrawals WHERE status NOT IN ('confirmed','failed')`, `SELECT id FROM sweeps WHERE status NOT IN ('confirmed','failed')`, `SELECT id FROM cold_moves WHERE status NOT IN ('confirmed','failed')`} {
		rows, err := s.pool.Query(context.Background(), q)
		if err != nil {
			continue
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
	}
	return ids
}
