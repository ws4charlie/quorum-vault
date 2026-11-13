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

	// sweeps: the planner only sweeps what is worth at least minSweep lamports (default: so much that nothing is ever swept)
	minSweep   string
	batch      int    // addresses per sweep (default 3)
	closeQuiet string // see custody.SOLFile.CloseQuietAfter
	activity   string // the engine's activity timeout (default 5s; sweep suites, whose scan reads more, use more)

	// the cold tier (P8-7)
	shards      int                 // hot shards (default 1), each its own 2-of-3 keyset
	seedSOL     []uint64            // lamports on each shard (default hotSOL)
	seedTKN     []uint64            // tokens on each shard (default hotTKN)
	cold        map[string]coldBand // asset -> the pool's cold bands; with it the cold tier is configured
	rebalance   map[string]string   // asset (or asset/shard) -> the shard's rebalance target
	coldAddr    string              // the pool's cold address (default: a fresh key's)
	coldPlan    string              // the cold planner's interval (default 1s)
	refillStuck string              // ALERT time of a broadcast refill that does not confirm (default 30m)
	toColdCap   string              // the zone's daily cap on moves to cold, per asset (default: far above anything a test moves)
}

// coldBand is the low-water mark, high-water mark and target of an asset's hot shards.
type coldBand struct{ low, high, target string }

type wdSys struct {
	root *testing.T // the test that owns the processes
	*system
	m3      *mpcstack.Stack3
	o       wdOpts
	hot     [32]byte
	hotATA  [32]byte
	hots    [][32]byte // every hot shard; hot is the first
	coldKey key        // the pool's cold key when the test holds it (a plain address; the ceremony tests use the token's key)
	coldAdr string
	seeded  [][2]uint64 // per shard: the lamports and tokens put on it
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

func (s *wdSys) hotAddrs() []string {
	var out []string
	for _, h := range s.hots {
		out = append(out, sol.Address(h))
	}
	return out
}

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
	if o.minSweep == "" {
		o.minSweep = "1000000000000000000"
	}
	if o.batch == 0 {
		o.batch = 3
	}
	if o.shards == 0 {
		o.shards = 1
	}
	if o.activity == "" {
		o.activity = "5s"
	}
	tm := phasetime.Start(t, "sol-withdrawals")
	sys := &system{t: t, ctx: context.Background(), dir: t.TempDir(), chain: "sol-" + uuid.NewString()[:8], queue: "qv-e2e-sol-" + uuid.NewString()[:8], tm: tm}
	s := &wdSys{root: t, system: sys, o: o, approv: map[string]ed25519.PrivateKey{}, tag: uuid.NewString()[:8], apprPub: map[string]string{}}
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
	pubs := make([][]byte, o.shards)
	for i := 0; i < o.shards; i++ {
		id := "sol-hot"
		if i > 0 {
			id = fmt.Sprintf("sol-hot-%d", i)
		}
		pubs[i] = s.m3.DKGEd25519(id)
		var h [32]byte
		copy(h[:], pubs[i])
		s.hots = append(s.hots, h)
	}
	s.hot = s.hots[0]
	s.m3.DKGHDEd25519("sol-hd")
	nctx, cancel := context.WithTimeout(s.ctx, time.Minute)
	node, err := sol.AccountNode(nctx, s.m3.Client("A"), "sol-hd")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	s.node = node
	tm.Phase("dkg")

	// The hot shards: SOL for fees and withdrawals, tokens in the associated token account.
	for i, h := range s.hots {
		sl, tk := uint64(o.hotSOL), uint64(hotTKN)
		if i < len(o.seedSOL) {
			sl = o.seedSOL[i]
		}
		if i < len(o.seedTKN) {
			tk = o.seedTKN[i]
		}
		if sl > 0 {
			s.c.airdrop(sol.Address(h), sl)
		}
		ata := s.c.ata(h, s.mint.pub)
		ixs := []ix{s.c.createATA(s.funder.pub, ata, h, s.mint.pub)}
		if tk > 0 {
			ixs = append(ixs, s.c.mintTo(s.mint.pub, ata, s.funder.pub, tk))
		}
		s.c.run(s.funder, nil, ixs...)
		if i == 0 {
			s.hotATA = ata
		}
		s.seeded = append(s.seeded, [2]uint64{sl, tk})
	}
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
	if o.cold != nil || o.coldAddr != "" {
		s.coldAdr = o.coldAddr
		if s.coldAdr == "" {
			s.coldKey = newKey(t)
			s.coldAdr = s.coldKey.addr()
		}
	}
	tiersSOL := []custody.TierFile{{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: fmt.Sprint(5 * oneSOL), Approvals: 2}}
	tiersTKN := []custody.TierFile{{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: fmt.Sprint(500 * tknUnit), Approvals: 2}}
	s.cf = custody.File{
		Entity: "qv-us",
		Chain: custody.ChainFile{Family: "sol", Name: s.chain,
			SOL: &custody.SOLFile{Network: "localnet", RPCURL: s.proxy.url, AccountPublicKey: hex.EncodeToString(node.PublicKey[:]), AccountChainCode: hex.EncodeToString(node.ChainCode[:]),
				HotShards: s.hotAddrs(), NoncePool: o.pool, NonceRentLamports: rent, ComputeUnitLimit: startUnit, ComputeUnitPrice: 1000, FeeBumpPercent: 25, MaxMicroLamports: maxMicro,
				SweepBatch: o.batch, CloseQuietAfter: o.closeQuiet},
			Assets: map[string]custody.AssetFile{"SOL": {Decimals: 9, MinDeposit: "1000"}, "TKN": {Address: s.mint.addr(), Decimals: 6, MinDeposit: "1"}}},
		Withdrawal: custody.WithdrawalFile{ApprovalWindow: "10m", ApprovalTimeout: o.approvalWait, SignTimeout: o.signTimeout, StuckAfter: o.stuckAfter, ActivityTimeout: o.activity,
			HotWait: "1m", MaxReplacements: o.maxReplace, Tiers: map[string][]custody.TierFile{"SOL": tiersSOL, "TKN": tiersTKN}},
		Sweep: custody.SweepFile{K: 20, MinSweepWei: o.minSweep, PlanInterval: "500ms", RetryAfter: "3s"},
		Cold:  s.coldFile(),
		Scan:  custody.ScanFile{Interval: "300ms", StartHeight: start + 1},
	}
	s.cfgPath = filepath.Join(s.dir, "custody.json")
	writeJSONFile(t, s.cfgPath, s.cf)
	if s.cfg, err = custody.LoadConfig(s.cfgPath); err != nil {
		t.Fatal(err)
	}

	// The signing zone's config: separate file, separate trust.
	signers, hotMap := map[string]gateway.SignerFile{}, map[string]string{}
	for i := range s.hots {
		id := "sol-hot"
		if i > 0 {
			id = fmt.Sprintf("sol-hot-%d", i)
		}
		sf := s.m3.GatewaySignerEd(id, pubs[i], "sol-hd", sol.AccountPath())
		for _, sym := range []string{"SOL", "TKN"} {
			p := s.cfg.PartitionKey(sym, i).String()
			signers[p], hotMap[p] = sf, sol.Address(s.hots[i])
		}
	}
	apprs := map[string]gateway.ApproverFile{}
	for n, p := range s.apprPub {
		apprs[n] = gateway.ApproverFile{PublicKey: p, Enabled: true}
	}
	s.gf = gateway.File{
		Approvers: apprs, SignTimeout: o.signTimeout, MaxIntentAge: "24h",
		Signers: signers,
		Chains: map[string]gateway.ChainFile{s.chain: {Family: "sol", WithdrawalsPerHour: 100000, SweepsPerHour: 100000, CancelsPerHour: 1000, ToColdPerHour: 1000, RebalancePerHour: 1000,
			SOL: &gateway.SOLFile{AccountPublicKey: hex.EncodeToString(node.PublicKey[:]), AccountChainCode: hex.EncodeToString(node.ChainCode[:]),
				HotShards: hotMap, ColdAddresses: s.coldMap(), Tokens: map[string]gateway.SOLTokenFile{"TKN": {Mint: s.mint.addr(), Decimals: 6}},
				MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: maxMicro, MaxPriorityFeeLamports: 15_000, NoncePool: o.pool, NonceRentLamports: rent},
			Assets: map[string]gateway.AssetFile{
				"SOL": {AnyDestination: true, PerTxCap: fmt.Sprint(50 * oneSOL), DailyCap: fmt.Sprint(1000 * oneSOL), ToColdDailyCap: fmt.Sprint(100_000 * oneSOL), RebalanceDailyCap: fmt.Sprint(100_000 * oneSOL),
					Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: fmt.Sprint(5 * oneSOL), Approvals: 2}}},
				"TKN": {AnyDestination: true, PerTxCap: fmt.Sprint(100_000 * tknUnit), DailyCap: fmt.Sprint(10_000_000 * tknUnit), ToColdDailyCap: fmt.Sprint(100_000_000 * tknUnit), RebalanceDailyCap: fmt.Sprint(100_000_000 * tknUnit),
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
	for i, sd := range s.seeded {
		if sd[0] > 0 {
			if err := s.svc.FundHot(s.ctx, fmt.Sprintf("seed-sol-%d", i), i, bigU(sd[0])); err != nil {
				t.Fatal(err)
			}
		}
		if sd[1] > 0 {
			if err := s.svc.FundHotAsset(s.ctx, fmt.Sprintf("seed-tkn-%d", i), i, "TKN", bigU(sd[1])); err != nil {
				t.Fatal(err)
			}
		}
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
	total := 0
	for i := range s.hots {
		n, err := s.svc.SetupNonces(s.ctx, i, "carol", s.approv["carol"], 3*time.Minute)
		if err != nil {
			s.t.Fatalf("nonce pool of shard %d: %v\ngateway: %s", i, err, tail(s.gateway.Output()))
		}
		total += n
	}
	return total
}

// coldMap is the zone's and the core's pinned cold address per pool ("" when the test has no cold tier).
func (s *wdSys) coldFile() custody.ColdFile {
	if s.coldAdr == "" {
		return custody.ColdFile{}
	}
	o := s.o
	plan := o.coldPlan
	if plan == "" {
		plan = "1s"
	}
	cf := custody.ColdFile{Addresses: map[string]string{"omnibus": s.coldAdr}, Limits: map[string]custody.LimitFile{}, PlanInterval: plan,
		Refill: custody.RefillFile{Poll: "1s", StuckAfter: o.refillStuck}}
	for asset, b := range o.cold {
		cf.Limits[asset] = custody.LimitFile{Low: b.low, High: b.high, Target: b.target}
	}
	if len(o.rebalance) > 0 {
		cf.Rebalance = custody.RebalanceFile{Targets: o.rebalance}
	}
	return cf
}

func (s *wdSys) coldMap() map[string]string {
	if s.coldAdr == "" {
		return nil
	}
	return map[string]string{"omnibus": s.coldAdr}
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
	// The process is cleaned up when the test that STARTED it ends: a worker started inside a subtest belongs to the whole test, not to that subtest.
	sub := s.t
	s.t = s.root
	defer func() { s.t = sub }()
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
