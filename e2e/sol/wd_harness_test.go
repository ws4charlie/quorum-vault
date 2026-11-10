package sole2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/base58"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/e2e/phasetime"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

// The withdrawal suite of the Solana cell (P8-5): the hot shard is a real 2-of-3 Ed25519 keyset on mpc-party A, B and C, the signing zone is the
// real qv-gateway with the cosigners of B and C, the business zone is qv-core and qv-worker (built with the crash failpoints), and every
// transaction lands on a real solana-test-validator. Deposits come in through the 2-party HD keyset as in the deposit suite.

const (
	oneSOL    = lamportsPerSOL
	tknUnit   = 1_000_000
	hotSOL    = 100 * lamportsPerSOL
	hotTKN    = 1_000_000 * tknUnit
	maxMicro  = 100_000
	startUnit = 100_000
)

type wdOpts struct {
	pool          int    // nonce accounts per shard (default 3)
	stuckAfter    string // default 4s
	maxReplace    int    // default 3
	noPool        bool   // do not create the nonce pool
	approvalWait  string
	gwTweak       func(*gateway.File)
	signTimeout   string
	hotSOL        uint64 // lamports of the hot shard (default 100 SOL)
	noGatewayWait bool
}

type wdSys struct {
	*system
	m3      *mpcstack.Stack3
	o       wdOpts
	hot     [32]byte
	hotATA  [32]byte
	svc     *custody.Service
	adapter *sol.Adapter
	approv  map[string]ed25519.PrivateKey
	gwPath  string
	guard   string
	keyPath string
	gateway *mpcstack.Proc
	tag     string
	cfg     *custody.Config
	gf      gateway.File
	apprPub map[string]string
	proxy   *rpcProxy
}

func (s *wdSys) hotAddr() string { return sol.Address(s.hot) }

func (s *wdSys) newGuardDB() string {
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

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *wdSys) ensureValidator() {
	s.t.Helper()
	dl := time.Now().Add(120 * time.Second)
	for time.Now().Before(dl) {
		if slot, err := s.c.rpc.Slot(s.ctx, sol.Finalized); err == nil && slot > 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	s.t.Fatalf("the validator (%s) does not finalize slots", nodeURL())
}

func newWdSystem(t *testing.T, o wdOpts) *wdSys {
	t.Helper()
	requireSOL(t)
	if o.pool == 0 {
		o.pool = 3
	}
	if o.stuckAfter == "" {
		o.stuckAfter = "4s"
	}
	if o.maxReplace == 0 {
		o.maxReplace = 3
	}
	if o.approvalWait == "" {
		o.approvalWait = "20s"
	}
	if o.signTimeout == "" {
		o.signTimeout = "6s"
	}
	if o.hotSOL == 0 {
		o.hotSOL = hotSOL
	}
	tm := phasetime.Start(t, "sol-withdrawals")
	sys := &system{t: t, ctx: context.Background(), dir: t.TempDir(), chain: "sol-" + uuid.NewString()[:8], queue: "qv-e2e-sol-" + uuid.NewString()[:8], tm: tm}
	s := &wdSys{system: sys, o: o, approv: map[string]ed25519.PrivateKey{}, tag: uuid.NewString()[:8], apprPub: map[string]string{}}
	s.m3 = mpcstack.Start3(t, filepath.Join(s.dir, "mpc"), mpcBin, mpcstack.Opts{})
	tm.Phase("mpc-start")
	s.proxy = newRPCProxy(t, nodeURL())
	s.c = &chainT{t: t, rpc: sol.NewRPC(nodeURL())}
	s.ensureValidator()
	s.funder = newKey(t)
	s.c.airdrop(s.funder.addr(), 2_000*lamportsPerSOL)
	s.mint = s.c.newMint(s.funder, 6)
	tm.Phase("chain")
	s.pool = dbtest.New(t)
	cc := s.pool.Config().ConnConfig
	s.bizDSN = fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cc.User, cc.Host, cc.Port, cc.Database)
	s.guard = s.newGuardDB()
	tm.Phase("db")

	s.m3.WaitReady(90 * time.Second)
	tm.Phase("mpc-wait")
	pub := s.m3.DKGEd25519("sol-hot")
	copy(s.hot[:], pub)
	s.m3.DKGHDEd25519("sol-hd")
	nctx, cancel := context.WithTimeout(s.ctx, time.Minute)
	node, err := sol.AccountNode(nctx, s.m3.Client("A"), "sol-hd")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	s.node = node
	tm.Phase("dkg")

	// The hot shard: SOL for fees and withdrawals, tokens in its associated token account.
	s.c.airdrop(s.hotAddr(), o.hotSOL)
	s.hotATA = s.c.ata(s.hot, s.mint.pub)
	s.c.run(s.funder, nil, s.c.createATA(s.funder.pub, s.hotATA, s.hot, s.mint.pub), s.c.mintTo(s.mint.pub, s.hotATA, s.funder.pub, hotTKN))
	// Wait until the funding is final: the core reads the shard at finalized commitment.
	s.c.waitStatus(s.c.run(s.funder, nil, s.c.sysTransfer(s.funder.pub, s.funder.pub, 1)), "finalized", false)
	tm.Phase("hot")

	rent := s.c.rent(sol.NonceAccountSize)
	if rent != sol.DefaultNonceRent {
		t.Fatalf("the node asks %d for a nonce account, the code assumes %d", rent, sol.DefaultNonceRent)
	}
	for _, n := range []string{"alice", "bob", "carol", "auto"} {
		p, priv, _ := ed25519.GenerateKey(rand.Reader)
		s.approv[n] = priv
		s.apprPub[n] = hex.EncodeToString(p)
	}
	s.keyPath = filepath.Join(s.dir, "auto.key")
	if err := os.WriteFile(s.keyPath, []byte(hex.EncodeToString(s.approv["auto"].Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	start, err := s.c.rpc.Slot(s.ctx, sol.Finalized)
	if err != nil {
		t.Fatal(err)
	}
	tiersSOL := []custody.TierFile{{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: fmt.Sprint(5 * oneSOL), Approvals: 2}}
	tiersTKN := []custody.TierFile{{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: fmt.Sprint(500 * tknUnit), Approvals: 2}}
	s.cf = custody.File{
		Entity: "qv-us",
		Chain: custody.ChainFile{Family: "sol", Name: s.chain,
			SOL: &custody.SOLFile{Network: "localnet", RPCURL: s.proxy.url, AccountPublicKey: hex.EncodeToString(node.PublicKey[:]), AccountChainCode: hex.EncodeToString(node.ChainCode[:]),
				HotShards: []string{s.hotAddr()}, NoncePool: o.pool, NonceRentLamports: rent, ComputeUnitLimit: startUnit, ComputeUnitPrice: 1000, FeeBumpPercent: 25, MaxMicroLamports: maxMicro},
			Assets: map[string]custody.AssetFile{"SOL": {Decimals: 9, MinDeposit: "1000"}, "TKN": {Address: s.mint.addr(), Decimals: 6, MinDeposit: "1"}}},
		Withdrawal: custody.WithdrawalFile{ApprovalWindow: "10m", ApprovalTimeout: o.approvalWait, SignTimeout: o.signTimeout, StuckAfter: o.stuckAfter, ActivityTimeout: "5s",
			HotWait: "1m", MaxReplacements: o.maxReplace, Tiers: map[string][]custody.TierFile{"SOL": tiersSOL, "TKN": tiersTKN}},
		Scan: custody.ScanFile{Interval: "300ms", StartHeight: start + 1},
	}
	s.cfgPath = filepath.Join(s.dir, "custody.json")
	writeJSONFile(t, s.cfgPath, s.cf)
	if s.cfg, err = custody.LoadConfig(s.cfgPath); err != nil {
		t.Fatal(err)
	}

	// The signing zone's config: separate file, separate trust.
	partSOL, partTKN := s.cfg.PartitionKey("SOL", 0).String(), s.cfg.PartitionKey("TKN", 0).String()
	sf := s.m3.GatewaySignerEd("sol-hot", pub, "sol-hd", sol.AccountPath())
	apprs := map[string]gateway.ApproverFile{}
	for n, p := range s.apprPub {
		apprs[n] = gateway.ApproverFile{PublicKey: p, Enabled: true}
	}
	s.gf = gateway.File{
		Approvers: apprs, SignTimeout: o.signTimeout, MaxIntentAge: "24h",
		Signers: map[string]gateway.SignerFile{partSOL: sf, partTKN: sf},
		Chains: map[string]gateway.ChainFile{s.chain: {Family: "sol", WithdrawalsPerHour: 100000, SweepsPerHour: 100000, CancelsPerHour: 1000,
			SOL: &gateway.SOLFile{AccountPublicKey: hex.EncodeToString(node.PublicKey[:]), AccountChainCode: hex.EncodeToString(node.ChainCode[:]),
				HotShards: map[string]string{partSOL: s.hotAddr(), partTKN: s.hotAddr()}, Tokens: map[string]gateway.SOLTokenFile{"TKN": {Mint: s.mint.addr(), Decimals: 6}},
				MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: maxMicro, MaxPriorityFeeLamports: 15_000, NoncePool: o.pool, NonceRentLamports: rent},
			Assets: map[string]gateway.AssetFile{
				"SOL": {AnyDestination: true, PerTxCap: fmt.Sprint(50 * oneSOL), DailyCap: fmt.Sprint(1000 * oneSOL),
					Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: fmt.Sprint(5 * oneSOL), Approvals: 2}}},
				"TKN": {AnyDestination: true, PerTxCap: fmt.Sprint(100_000 * tknUnit), DailyCap: fmt.Sprint(10_000_000 * tknUnit),
					Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: fmt.Sprint(500 * tknUnit), Approvals: 2}}}}}},
	}
	if o.gwTweak != nil {
		o.gwTweak(&s.gf)
	}
	s.gwPath = filepath.Join(s.dir, "gateway.json")
	writeJSONFile(t, s.gwPath, s.gf)
	cos := s.gf
	cos.Signers = nil
	cosB, cosC := filepath.Join(s.dir, "cosigner-b.json"), filepath.Join(s.dir, "cosigner-c.json")
	writeJSONFile(t, cosB, cos)
	writeJSONFile(t, cosC, cos)
	s.m3.StartCosigner(cosB, s.newGuardDB(), s.guard)
	s.m3.StartCosignerC(cosC, s.newGuardDB(), s.guard)
	tm.Phase("configs")

	// In-process service: funding, the nonce pool, Reconcile.
	direct := s.cfg.SOL
	direct.RPCURL = nodeURL() // the tests' own adapter reads and sends straight to the validator, not through the proxy that can hold sends back
	if s.adapter, err = sol.New(s.ctx, direct, s.pool); err != nil {
		t.Fatal(err)
	}
	s.svc = custody.New(s.pool, s.cfg, s.adapter, s.adapter)
	if err := s.svc.Bootstrap(s.ctx); err != nil {
		t.Fatal(err)
	}
	addr := os.Getenv("QV_TEMPORAL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:7233"
	}
	rctx, rcancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer rcancel()
	if err := workflow.RegisterNamespace(rctx, addr, "default"); err != nil {
		t.Fatal(err)
	}
	if s.tc, err = client.DialContext(s.ctx, client.Options{HostPort: addr, Namespace: "default"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.tc.Close)
	t.Cleanup(s.terminateWorkflows)
	tm.Phase("service")

	s.startGateway()
	if !o.noGatewayWait {
		s.m3.WaitSigning(90 * time.Second)
	}
	tm.Phase("gateway")

	// The books learn what the operator put on the shard, then the pool is created through the signing zone.
	if err := s.svc.FundHot(s.ctx, "seed-sol", 0, bigU(o.hotSOL)); err != nil {
		t.Fatal(err)
	}
	if err := s.svc.FundHotAsset(s.ctx, "seed-tkn", 0, "TKN", bigU(hotTKN)); err != nil {
		t.Fatal(err)
	}
	if !o.noPool {
		s.setupPool()
	}
	tm.Phase("pool")

	s.startWorker("")
	s.startCore()
	tm.Phase("spawn")
	tm.Ready(t)
	return s
}

// setupPool creates the shard's nonce accounts through the signing zone, as the operator command does.
func (s *wdSys) setupPool() int {
	s.t.Helper()
	n, err := s.svc.SetupNonces(s.ctx, 0, "carol", s.approv["carol"], 3*time.Minute)
	if err != nil {
		s.t.Fatalf("nonce pool: %v\ngateway: %s", err, tail(s.gateway.Output()))
	}
	return n
}

func tail(s string) string {
	if len(s) > 4000 {
		return s[len(s)-4000:]
	}
	return s
}

func (s *wdSys) startGateway() {
	s.gateway = mpcstack.NewProc(s.t, "gateway", filepath.Join(s.dir, "gateway.log"), filepath.Join(binDir, "qv-gateway"), nil,
		"-config", s.gwPath, "-jobs-dsn", s.bizDSN, "-guard-dsn", s.guard, "-worker-id", "gw-"+s.tag, "-interval", "100ms", "-lease", "12s")
	s.gateway.Start(s.t)
}

// startWorker starts qv-worker (built with the failpoints); failpoint "" arms nothing.
func (s *wdSys) startWorker(failpoint string) {
	s.t.Helper()
	s.worker = s.spawnEnv("qv-worker", []string{"QV_FAILPOINT=" + failpoint}, "-config", s.cfgPath, "-dsn", s.bizDSN, "-task-queue", s.queue, "-auto-approver-key-file", s.keyPath)
	p := s.worker
	s.waitFor(30*time.Second, "worker started", func() bool { return fileContains(p.log, "qv-worker started") })
}

func (s *wdSys) terminateWorkflows() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ids := []string{workflow.ScanID(s.chain), workflow.ReconcilerID(s.chain)}
	rows, err := s.pool.Query(ctx, `SELECT id FROM withdrawals`)
	if err == nil {
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

var _ = http.StatusOK
var _ = big.NewInt

// rpcProxy sits between qv-core and qv-worker and the validator. Reads pass through; while hold is set, sendTransaction is answered with the
// transaction's signature and the transaction is kept instead of being sent, which is how a test makes a withdrawal that was broadcast but
// has not landed.
type rpcProxy struct {
	url  string
	hold atomic.Bool
	mu   sync.Mutex
	held [][]byte
}

func newRPCProxy(t *testing.T, target string) *rpcProxy {
	p := &rpcProxy{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.Unmarshal(body, &req) == nil && req.Method == "sendTransaction" && p.hold.Load() && len(req.Params) > 0 {
			var b64 string
			if json.Unmarshal(req.Params[0], &b64) == nil {
				if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) > 65 {
					p.mu.Lock()
					p.held = append(p.held, raw)
					p.mu.Unlock()
					out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": base58.Encode(raw[1:65])})
					w.Header().Set("Content-Type", "application/json")
					w.Write(out)
					return
				}
			}
		}
		fr, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(body))
		fr.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(fr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

func (p *rpcProxy) heldCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.held)
}
