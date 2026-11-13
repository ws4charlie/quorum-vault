// Package solsign_test runs the real processes of the Solana signing path: qv-gateway, mpc-party A, B and C (the hot shard is a 2-of-3 Ed25519
// keyset, the deposit keys come from a 2-party HD Ed25519 keyset on A and B), a qv-cosigner next to B and one next to C, Postgres, and a local
// solana-test-validator on which every signed transaction must land. Run with `make test-e2e-sol-signing`.
package solsign_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	st "github.com/ws4charlie/quorum-vault/internal/chain/sol/soltest"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

var (
	binDir   string
	mpcBin   mpcstack.Binaries
	binGW    string
	buildErr error
)

func TestMain(m *testing.M) {
	mpcstack.ReaperMain()
	stopReaper := func() {}
	if os.Getenv("QV_REQUIRE_SOL") == "1" {
		dir, err := os.MkdirTemp("", "solsign-bin-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		binDir = dir
		if stop, err := mpcstack.StartReaper(); err == nil {
			stopReaper = stop
		}
		if mpcBin, err = mpcstack.Build(dir); err != nil {
			buildErr = err
		} else {
			binGW = filepath.Join(dir, "qv-gateway")
			if out, err := exec.Command("go", "build", "-o", binGW, "github.com/ws4charlie/quorum-vault/cmd/qv-gateway").CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("build qv-gateway: %v\n%s", err, out)
			}
		}
	}
	code := m.Run()
	stopReaper()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func requireSOL(t *testing.T) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_SOL") != "1" {
		t.Skip("QV_REQUIRE_SOL != 1 (`make sol-up softhsm mpc-build test-e2e-sol-signing`)")
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

const (
	chainName = "sol-sign"
	partSOL   = "qv-us/sol-sign/SOL/hot/omnibus/0"
	partTKN   = "qv-us/sol-sign/TKN/hot/omnibus/0"
)

// ---- the validator ----

type node struct {
	t   testing.TB
	rpc *sol.RPC
}

func (n *node) blockhash() [32]byte {
	var out struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := n.rpc.Call(context.Background(), &out, "getLatestBlockhash", map[string]string{"commitment": "confirmed"}); err != nil {
		n.t.Fatal(err)
	}
	var b [32]byte
	copy(b[:], sol.MustDecodeBase58(out.Value.Blockhash))
	return b
}

// sendRaw submits a transaction and returns its first signature; skipPreflight lets one that fails on the chain land and fail.
func (n *node) sendRaw(tx []byte, skipPreflight bool) (string, error) {
	var sig string
	err := n.rpc.Call(context.Background(), &sig, "sendTransaction", base64.StdEncoding.EncodeToString(tx),
		map[string]any{"encoding": "base64", "skipPreflight": skipPreflight, "preflightCommitment": "confirmed"})
	return sig, err
}

// wait waits until sig has the commitment; it reports the error the transaction ended with, if any.
func (n *node) wait(sig, commitment string) (failed any) {
	n.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	rank := map[string]int{"processed": 1, "confirmed": 2, "finalized": 3}
	for time.Now().Before(deadline) {
		var out struct {
			Value []*struct {
				Err                any    `json:"err"`
				ConfirmationStatus string `json:"confirmationStatus"`
			} `json:"value"`
		}
		if err := n.rpc.Call(context.Background(), &out, "getSignatureStatuses", []string{sig}, map[string]bool{"searchTransactionHistory": true}); err != nil {
			n.t.Fatal(err)
		}
		if len(out.Value) == 1 && out.Value[0] != nil && rank[out.Value[0].ConfirmationStatus] >= rank[commitment] {
			return out.Value[0].Err
		}
		time.Sleep(100 * time.Millisecond)
	}
	n.t.Fatalf("transaction %s did not reach %s\n%s", sig, commitment, n.dump(sig))
	return nil
}

// dump explains a validator that does not confirm: what the node says (health, version, slots at each commitment, epoch, the blockhash, the
// signature's status) and what the container says (state, OOMKilled, exit code, the last log lines, docker stats). The jobs of CI run the tests in
// a container with the Docker socket, so the docker CLI answers; where it does not, that is said and the RPC part still stands.
func (n *node) dump(sig string) string {
	var b strings.Builder
	call := func(label, method string, params ...any) {
		var raw json.RawMessage
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := n.rpc.Call(ctx, &raw, method, params...); err != nil {
			fmt.Fprintf(&b, "  %-26s error: %v\n", label, err)
			return
		}
		out := string(raw)
		if len(out) > 300 {
			out = out[:300] + "..."
		}
		fmt.Fprintf(&b, "  %-26s %s\n", label, out)
	}
	fmt.Fprintf(&b, "validator at %s, %s:\n", nodeURL(), time.Now().UTC().Format(time.RFC3339))
	call("getHealth", "getHealth")
	call("getVersion", "getVersion")
	for _, c := range []string{"processed", "confirmed", "finalized"} {
		call("getSlot "+c, "getSlot", map[string]string{"commitment": c})
	}
	call("getEpochInfo", "getEpochInfo")
	call("getLatestBlockhash", "getLatestBlockhash", map[string]string{"commitment": "confirmed"})
	if sig != "" {
		call("getSignatureStatuses", "getSignatureStatuses", []string{sig}, map[string]bool{"searchTransactionHistory": true})
	}
	run := func(args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			return fmt.Sprintf("(docker %s: %v)\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	names := strings.Fields(run("ps", "-a", "--filter", "name=solana", "--format", "{{.Names}}"))
	fmt.Fprintf(&b, "containers: %v\n", names)
	for _, c := range names {
		fmt.Fprintf(&b, "inspect %s: %s", c, run("inspect", "-f", "status={{.State.Status}} oomkilled={{.State.OOMKilled}} exit={{.State.ExitCode}} started={{.State.StartedAt}} finished={{.State.FinishedAt}} restarts={{.RestartCount}}", c))
		fmt.Fprintf(&b, "logs %s (last 40):\n%s", c, run("logs", "--tail", "40", c))
	}
	fmt.Fprintf(&b, "docker stats:\n%s", run("stats", "--no-stream", "--format", "{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}"))
	fmt.Fprintf(&b, "host: %s", run("info", "--format", "cpus={{.NCPU}} mem={{.MemTotal}}"))
	return b.String()
}

var validatorOnce sync.Once

// ensureValidator runs once per test binary: it fails the whole group at once, with the dump, when the validator does not produce blocks and confirm a
// transaction, instead of letting every test wait out its own timeout. It also waits for the first rooted slot, so no test starts on a validator that
// is healthy but has not finished its first epoch.
func (n *node) ensureValidator() {
	n.t.Helper()
	validatorOnce.Do(func() {
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if slot, err := n.rpc.Slot(context.Background(), sol.Finalized); err == nil && slot > 0 {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		probe := st.NewKey()
		var sig string
		if err := n.rpc.Call(context.Background(), &sig, "requestAirdrop", sol.Address(probe.Pub), 1_000_000_000); err != nil {
			n.t.Fatalf("the validator refuses an airdrop: %v\n%s", err, n.dump(""))
		}
		n.wait(sig, "confirmed") // dumps and fails if it never confirms
	})
}

func (n *node) land(tx []byte) string {
	n.t.Helper()
	sig, err := n.sendRaw(tx, false)
	if err != nil {
		n.t.Fatalf("sendTransaction: %v", err)
	}
	if e := n.wait(sig, "confirmed"); e != nil {
		n.t.Fatalf("transaction %s failed on the chain: %v", sig, e)
	}
	return sig
}

func (n *node) airdrop(to [32]byte, lamports uint64) {
	n.t.Helper()
	var sig string
	if err := n.rpc.Call(context.Background(), &sig, "requestAirdrop", sol.Address(to), lamports); err != nil {
		n.t.Fatal(err)
	}
	n.wait(sig, "confirmed")
}

func (n *node) lamports(a [32]byte) uint64 {
	v, _, err := n.rpc.Lamports(context.Background(), sol.Address(a), sol.Confirmed)
	if err != nil {
		n.t.Fatal(err)
	}
	return v
}

func (n *node) tokens(owner, mint [32]byte) uint64 {
	accts, err := n.rpc.TokenAccountsByOwner(context.Background(), sol.Address(owner), sol.Address(mint), sol.Confirmed)
	if err != nil {
		n.t.Fatal(err)
	}
	var sum uint64
	for _, a := range accts {
		sum += a.Amount
	}
	return sum
}

func (n *node) rent(space uint64) uint64 {
	var v uint64
	if err := n.rpc.Call(context.Background(), &v, "getMinimumBalanceForRentExemption", space); err != nil {
		n.t.Fatal(err)
	}
	return v
}

// run signs instructions with keys the test holds and lands them.
func (n *node) run(payer st.Key, signers []st.Key, ixs ...st.Ix) string {
	n.t.Helper()
	msg := st.Compile(payer.Pub, n.blockhash(), ixs...)
	dm, err := sol.DecodeMessage(msg)
	if err != nil {
		n.t.Fatal(err)
	}
	by := map[[32]byte]st.Key{payer.Pub: payer}
	for _, k := range signers {
		by[k.Pub] = k
	}
	var sigs [][]byte
	for i := 0; i < dm.NumSigners; i++ {
		sigs = append(sigs, by[dm.Keys[i]].Sign(msg))
	}
	return n.land(st.Assemble(msg, sigs...))
}

func (n *node) newMint(payer st.Key, decimals uint8) st.Key {
	mint := st.NewKey()
	tokp, _ := sol.ParseAddress(sol.TokenProgram)
	n.run(payer, []st.Key{mint}, st.CreateAccount(payer.Pub, mint.Pub, tokp, n.rent(82), 82), st.InitMint2(mint.Pub, payer.Pub, decimals))
	return mint
}

// ---- the stack ----

type stack struct {
	t       *testing.T
	dir     string
	mpc     *mpcstack.Stack3
	n       *node
	hotPub  [32]byte
	hot     st.Key // only the public half is the hot shard's: the secret is shared among A, B and C
	node    sol.Node
	acct    sol.Node
	mint    st.Key
	funder  st.Key
	biz     *pgxpool.Pool
	bizDSN  string
	gwGuard string
	gw      *mpcstack.Proc
	appr    ed25519.PrivateKey
	seq     int

	noncesMade bool
}

func ctxT(t testing.TB, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

type optsT struct {
	cosignerTweak func(gateway.File) gateway.File // B's and C's cosigners get a different copy of the config
	noDeposit     bool
}

func newStack(t *testing.T, o optsT) *stack {
	t.Helper()
	requireSOL(t)
	s := &stack{t: t, dir: t.TempDir(), n: &node{t: t, rpc: sol.NewRPC(nodeURL())}, funder: st.NewKey()}
	if _, err := s.n.rpc.Slot(context.Background(), sol.Finalized); err != nil {
		t.Fatalf("solana-test-validator: %v (make sol-up)\n%s", err, s.n.dump(""))
	}
	s.n.ensureValidator()
	s.mpc = mpcstack.Start3(t, filepath.Join(s.dir, "mpc"), mpcBin, mpcstack.Opts{})
	s.n.airdrop(s.funder.Pub, 1000*1_000_000_000)
	s.mint = s.n.newMint(s.funder, 6)
	s.mpc.WaitReady(90 * time.Second)

	pub := s.mpc.DKGEd25519("sol-hot")
	copy(s.hotPub[:], pub)
	s.mpc.DKGHDEd25519("sol-hd")
	node, err := sol.AccountNode(ctxT(t, time.Minute), s.mpc.Client("A"), "sol-hd")
	if err != nil {
		t.Fatal(err)
	}
	s.node = node
	s.n.airdrop(s.hotPub, 100*1_000_000_000)

	apub, apriv, _ := ed25519.GenerateKey(rand.Reader)
	s.appr = apriv
	hotAddr := sol.Address(s.hotPub)
	f := gateway.File{
		Approvers: map[string]gateway.ApproverFile{"alice": {PublicKey: hex.EncodeToString(apub), Enabled: true}},
		Chains: map[string]gateway.ChainFile{chainName: {Family: "sol", WithdrawalsPerHour: 1000, SweepsPerHour: 1000,
			SOL: &gateway.SOLFile{AccountPublicKey: hex.EncodeToString(node.PublicKey[:]), AccountChainCode: hex.EncodeToString(node.ChainCode[:]),
				HotShards:       map[string]string{partSOL: hotAddr, partTKN: hotAddr},
				Tokens:          map[string]gateway.SOLTokenFile{"TKN": {Mint: s.mint.Address(), Decimals: 6}},
				MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: 100_000, MaxPriorityFeeLamports: 15_000, NoncePool: 3, NonceRentLamports: sol.DefaultNonceRent},
			Assets: map[string]gateway.AssetFile{
				"SOL": {AnyDestination: true, PerTxCap: "50000000000", DailyCap: "100000000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}},
				"TKN": {AnyDestination: true, PerTxCap: "1000000000", DailyCap: "2000000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}}}},
	}
	dep, depPath := "", []uint32(nil)
	if !o.noDeposit {
		dep, depPath = "sol-hd", sol.AccountPath()
	}
	sf := s.mpc.GatewaySignerEd("sol-hot", pub, dep, depPath)
	gf := f
	gf.Signers = map[string]gateway.SignerFile{partSOL: sf, partTKN: sf}
	gf.SignTimeout = "8s"

	s.biz = dbtest.New(t)
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('` + chainName + `','SOL',9),('` + chainName + `','TKN',6)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + partSOL + `','qv-us','` + chainName + `','SOL','hot','omnibus',0)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + partTKN + `','qv-us','` + chainName + `','TKN','hot','omnibus',0)`,
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
	_, s.gwGuard = gatewaytest.NewGuardDB(t)
	_, guardB := gatewaytest.NewGuardDB(t)
	_, guardC := gatewaytest.NewGuardDB(t)

	cos := f
	if o.cosignerTweak != nil {
		cos = o.cosignerTweak(f)
	}
	writeJSON := func(name string, v any) string {
		p := filepath.Join(s.dir, name)
		b, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	s.mpc.StartCosigner(writeJSON("cosigner-b.json", cos), guardB, s.gwGuard)
	s.mpc.StartCosignerC(writeJSON("cosigner-c.json", cos), guardC, s.gwGuard)
	gwCfg := writeJSON("gateway.json", gf)
	s.gw = mpcstack.NewProc(t, "gateway", filepath.Join(s.dir, "gateway.log"), binGW, nil, "-config", gwCfg, "-jobs-dsn", s.bizDSN, "-guard-dsn", s.gwGuard,
		"-worker-id", "w1", "-interval", "100ms", "-lease", "10s")
	s.gw.Start(t)
	s.mpc.WaitSigning(90 * time.Second)
	return s
}

// ---- jobs ----

func (s *stack) intent(kind, id, asset, part, from, to string, amount uint64) signjob.Intent {
	in := signjob.Intent{Kind: kind, ID: id, PartitionID: part, Chain: chainName, Asset: asset, From: from, To: to, Amount: fmt.Sprint(amount)}
	if kind == "withdrawal" {
		in.NotAfter = time.Now().Add(time.Hour).Unix()
	}
	return in
}

func (s *stack) job(id string, in signjob.Intent, msg []byte, keyPath string, dep *uint32) signjob.Job {
	var ix []uint32
	if dep != nil {
		ix = []uint32{*dep}
	}
	p, _ := json.Marshal(sol.Payload{Message: msg, DepositIndices: ix})
	ib, _ := json.Marshal(in)
	apps := []signjob.Approval{}
	if in.Kind == "withdrawal" || in.Kind == sol.KindNonceSetup {
		h := in.Hash()
		apps = append(apps, signjob.Approval{Actor: "alice", Signature: ed25519.Sign(s.appr, h[:])})
	}
	return signjob.Job{ID: id, PartitionID: in.PartitionID, KeyRef: keyPath, Chain: chainName, Intent: ib, Digest: msg, Payload: p, Approvals: apps}
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

func (s *stack) wait(id string, d time.Duration) signjob.Job {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		j, err := signjob.Get(context.Background(), s.biz, id)
		if err == nil && j.Status != signjob.StatusPending && j.Status != signjob.StatusSigning {
			return j
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("job %s did not finish\ngateway: %s", id, tailOf(s.gw.Output()))
	return signjob.Job{}
}

func tailOf(s string) string {
	if len(s) > 3000 {
		return s[len(s)-3000:]
	}
	return s
}

// sign enqueues a job and returns it done, or fails the test.
func (s *stack) sign(id string, in signjob.Intent, msg []byte, keyPath string, dep *uint32) []byte {
	s.t.Helper()
	s.enqueue(s.job(id, in, msg, keyPath, dep))
	j := s.wait(id, 90*time.Second)
	if j.Status != signjob.StatusDone {
		s.t.Fatalf("job %s: %s %s\ngateway: %s", id, j.Status, j.RejectReason, tailOf(s.gw.Output()))
	}
	if len(j.Signature) != 64 {
		s.t.Fatalf("job %s: signature of %d bytes", id, len(j.Signature))
	}
	return j.Signature
}

// refused enqueues a job and requires the gateway to reject or fail it; it returns the reason.
func (s *stack) refused(id string, in signjob.Intent, msg []byte, keyPath string, dep *uint32) string {
	s.t.Helper()
	s.enqueue(s.job(id, in, msg, keyPath, dep))
	j := s.wait(id, 90*time.Second)
	if j.Status == signjob.StatusDone {
		s.t.Fatalf("job %s was signed", id)
	}
	return j.RejectReason
}

// wdMsg is a withdrawal message on durable-nonce account 0 of the hot shard: it creates the account through the signing zone the first time, then
// signs the value it holds and advances it first. Each test lands at most one withdrawal, so one account is enough.
func (s *stack) wdMsg(ixs ...st.Ix) []byte {
	s.t.Helper()
	acct := sol.NonceAddress(s.hotPub, 0)
	if !s.noncesMade {
		s.noncesMade = true
		create := sol.CreateNonceIxs(s.hotPub, 0, sol.DefaultNonceRent)
		var sx []st.Ix
		for _, c := range append([]sol.Ix{sol.SetLimitIx(30_000)}, create...) {
			x := st.Ix{Program: c.Program, Data: c.Data}
			for _, m := range c.Accts {
				x.Accts = append(x.Accts, st.Meta{Key: m.Key, Signer: m.Signer, Writable: m.Writable})
			}
			sx = append(sx, x)
		}
		msg := s.msgFromHot(sx...)
		in := signjob.Intent{Kind: sol.KindNonceSetup, ID: "nonce-setup", PartitionID: partSOL, Chain: chainName, Asset: "SOL", To: sol.Address(s.hotPub), Amount: fmt.Sprint(sol.DefaultNonceRent)}
		sig := s.sign("nonce-setup", in, msg, sol.PathHot, nil)
		s.n.land(st.Assemble(msg, sig))
	}
	nc, err := s.n.rpc.GetNonce(context.Background(), sol.Address(acct), sol.Confirmed)
	if err != nil {
		s.t.Fatal(err)
	}
	adv := st.AdvanceNonce(acct, s.hotPub)
	return st.Compile(s.hotPub, nc.Value, append([]st.Ix{adv}, ixs...)...)
}

func (s *stack) msgFromHot(ixs ...st.Ix) []byte { return st.Compile(s.hotPub, s.n.blockhash(), ixs...) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func encodePackage(j signjob.Job) ([]byte, error) { return gateway.EncodePackage(j) }
