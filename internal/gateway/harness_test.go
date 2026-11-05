package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

const (
	testChain     = "evm-test"
	testPartition = "p-hot"
	// testColdPartition is a hot partition with a well-formed ID (the to-cold verifier reads the pool from it), on the same hot
	// address as testPartition.
	testColdPartition = "qv-us/evm-test/ETH/hot/omnibus/1"
)

var (
	addrFactory = common.HexToAddress("0x00000000000000000000000000000000000fAc70")
	addrDest    = common.HexToAddress("0x000000000000000000000000000000000000De57") // configured sweep destination
	addrToken   = common.HexToAddress("0x00000000000000000000000000000000000070C3")
	addrUser    = common.HexToAddress("0x00000000000000000000000000000000000c0DE5")
	addrEvil    = common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	addrCold    = common.HexToAddress("0x00000000000000000000000000000000000c01d0") // configured cold address
)

// countingSigner counts SignDigest calls so tests can assert "nothing signed".
type countingSigner struct {
	signer.Signer
	calls atomic.Int32
	// before runs ahead of every signing call (tests block or delay here). It
	// may return an error to make the signer fail.
	before atomic.Pointer[func(d [32]byte) error]
}

func (c *countingSigner) setBefore(f func(d [32]byte) error) { c.before.Store(&f) }

func (c *countingSigner) SignDigest(ctx context.Context, d [32]byte, o signer.SignOptions) (signer.Result, error) {
	c.calls.Add(1)
	if f := c.before.Load(); f != nil {
		if err := (*f)(d); err != nil {
			return signer.Result{}, err
		}
	}
	return c.Signer.SignDigest(ctx, d, o)
}

type harness struct {
	t       *testing.T
	biz     *pgxpool.Pool
	guardDB *pgxpool.Pool
	guard   *Guard
	cfg     *Config
	signer  *countingSigner
	hot     common.Address
	keys    map[string]ed25519.PrivateKey // alice, bob, carol, auto, dave (disabled)
	gw      *Gateway
	chainID uint64

	mu  sync.Mutex
	now time.Time
	seq int

	// notAfter overrides the default expiry of withdrawal intents built by job():
	// 0 = now+1h; use noExpiry for a literal zero.
	notAfter int64
	noExpiry bool
}

func newGuardDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)
	name := "qv_guard_" + hex.EncodeToString(uuid.NewSHA1(uuid.NameSpaceOID, []byte(t.Name()+time.Now().String())).NodeID())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), url)
		if err == nil {
			c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	cfg, _ := pgxpool.ParseConfig(url)
	cfg.ConnConfig.Database = name
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func newHarness(t *testing.T) *harness { return newHarnessChainID(t, 31337) }

func newHarnessChainID(t *testing.T, chainID uint64) *harness {
	t.Helper()
	ctx := context.Background()
	h := &harness{t: t, biz: dbtest.New(t), guardDB: newGuardDB(t), chainID: chainID, keys: map[string]ed25519.PrivateKey{},
		now: time.Now()}

	tok := hsmtest.Token(t, "quorumvault")
	gen := hsmsigner.NewGenerator(tok)
	key, err := gen.Generate(ctx, "gw-"+uuid.NewString()[:8], 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tok.DestroyPrivateKey(ctx, key.HSMKeyID) })
	s, err := hsmsigner.New(tok, key)
	if err != nil {
		t.Fatal(err)
	}
	h.signer = &countingSigner{Signer: s}
	h.hot = common.HexToAddress(key.Address)

	approvers := map[string]ApproverFile{}
	for _, name := range []string{"alice", "bob", "carol", "auto", "dave"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		h.keys[name] = priv
		approvers[name] = ApproverFile{PublicKey: hex.EncodeToString(pub), Enabled: name != "dave"}
	}
	f := File{
		Approvers: approvers,
		Chains: map[string]ChainFile{testChain: {
			EVM: &EVMFile{ChainID: chainID, Factory: addrFactory.Hex(), SweepDestination: addrDest.Hex(),
				HotAddresses:  map[string]string{testPartition: h.hot.Hex(), testColdPartition: h.hot.Hex()},
				ColdAddresses: map[string]string{"omnibus/native": addrCold.Hex(), "omnibus/token": addrCold.Hex()},
				Tokens:        map[string]TokenFile{"USDT": {Address: addrToken.Hex(), Decimals: 6}},
				MaxTxFeeWei:   "300000000000000"},
			Assets: map[string]AssetFile{
				"ETH": {PerTxCap: "5000", DailyCap: "8000", Tiers: []TierFile{{"0", 1}, {"1000", 2}}, ToColdDailyCap: "6000"},
				"USDT": {PerTxCap: "5000000", DailyCap: "8000000",
					Tiers: []TierFile{{"0", 1}, {"1000000", 2}}, ToColdDailyCap: "6000000"},
			},
			SweepsPerHour: 2, CancelsPerHour: 3, ToColdPerHour: 2,
		}},
	}
	raw, _ := json.Marshal(f)
	if h.cfg, err = ParseConfig(raw); err != nil {
		t.Fatal(err)
	}
	if h.guard, err = OpenGuard(ctx, h.guardDB); err != nil {
		t.Fatal(err)
	}
	h.gw = h.newGateway("w1")

	for _, q := range []string{
		fmt.Sprintf(`INSERT INTO assets (chain, symbol, decimals) VALUES ('%s','ETH',18),('%s','USDT',6)`, testChain, testChain),
		fmt.Sprintf(`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('%s','qv-us','%s','ETH','hot','omnibus',0)`, testPartition, testChain),
		fmt.Sprintf(`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('%s','qv-us','%s','ETH','hot','omnibus',1)`, testColdPartition, testChain),
	} {
		if _, err := h.biz.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *harness) newGateway(worker string) *Gateway {
	gw, err := New(h.cfg, nil, map[string]signer.Signer{testPartition: h.signer, testColdPartition: h.signer}, h.guard, h.biz,
		Options{WorkerID: worker, Lease: time.Minute, Now: h.clock})
	if err != nil {
		h.t.Fatal(err)
	}
	// Runs before the token's cleanup: finalizing the HSM library under a signer
	// call crashes the test binary.
	h.t.Cleanup(func() {
		if !gw.Wait(10 * time.Second) {
			h.t.Error("a signer call is still running at the end of the test")
		}
	})
	return gw
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

// --- building jobs the way the business zone would (and the attacker can) ---

type txSpec struct {
	nonce  uint64
	to     common.Address
	value  *big.Int
	data   []byte
	gas    uint64
	tip    *big.Int
	feeCap *big.Int
}

func (s txSpec) fill() txSpec {
	if s.value == nil {
		s.value = new(big.Int)
	}
	if s.gas == 0 {
		s.gas = 100000
	}
	if s.tip == nil {
		s.tip = big.NewInt(1e9)
	}
	if s.feeCap == nil {
		s.feeCap = big.NewInt(3e9)
	}
	return s
}

// payloadFor returns the JSON payload and digest of spec as sent from the hot address.
func (h *harness) payloadFor(s txSpec) (payload, digest []byte) {
	s = s.fill()
	p := eth.TxParams{ChainID: new(big.Int).SetUint64(h.chainID), Nonce: s.nonce, To: s.to, Value: s.value, Data: s.data,
		Gas: s.gas, GasTipCap: s.tip, GasFeeCap: s.feeCap}
	_, d, err := eth.BuildTx(p)
	if err != nil {
		h.t.Fatal(err)
	}
	pl, _ := json.Marshal(evm.Payload{ChainID: h.chainID, From: h.hot.Hex(), Nonce: s.nonce, To: s.to.Hex(), Value: s.value.String(),
		Data: hexutil.Encode(s.data), Gas: s.gas, Tip: s.tip.String(), FeeCap: s.feeCap.String()})
	return pl, d[:]
}

var erc20 = mustABI(`[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"type":"bool"}]}]`)
var factoryABI = mustABI(`[{"type":"function","name":"deployAndFlush","inputs":[{"name":"salt","type":"bytes32"},{"name":"tokens","type":"address[]"}],"outputs":[]}]`)

func mustABI(s string) abi.ABI {
	a, err := abi.JSON(strings.NewReader(s))
	if err != nil {
		panic(err)
	}
	return a
}

func (h *harness) ethTx(to common.Address, amount int64, nonce uint64) txSpec {
	return txSpec{nonce: nonce, to: to, value: big.NewInt(amount), gas: 21000}
}

func (h *harness) tokenTx(to common.Address, amount int64, nonce uint64) txSpec {
	data, err := erc20.Pack("transfer", to, big.NewInt(amount))
	if err != nil {
		h.t.Fatal(err)
	}
	return txSpec{nonce: nonce, to: addrToken, data: data}
}

func (h *harness) sweepTx(customer string, nonce uint64) (txSpec, common.Address) {
	salt := evm.DeriveSalt(customer, 1)
	data, err := factoryABI.Pack("deployAndFlush", salt, []common.Address{})
	if err != nil {
		h.t.Fatal(err)
	}
	return txSpec{nonce: nonce, to: addrFactory, data: data}, evm.PredictAddress(addrFactory, salt)
}

func (h *harness) cancelTx(nonce uint64) txSpec {
	return txSpec{nonce: nonce, to: h.hot, gas: 21000}
}

// job assembles a sign job for intent and tx, approved by the named actors.
func (h *harness) job(id string, in signjob.Intent, s txSpec, approvers ...string) signjob.Job {
	if in.Chain == "" {
		in.Chain = testChain
	}
	if in.PartitionID == "" {
		in.PartitionID = testPartition
	}
	if in.Kind == "withdrawal" && in.NotAfter == 0 && !h.noExpiry {
		in.NotAfter = h.clock().Add(time.Hour).Unix()
	}
	payload, digest := h.payloadFor(s)
	return signjob.Job{ID: id, PartitionID: in.PartitionID, KeyRef: "m/0", Chain: in.Chain, Intent: mustJSON(in),
		Digest: digest, Payload: payload, Approvals: h.approvals(in, approvers...)}
}

func (h *harness) approvals(in signjob.Intent, actors ...string) []signjob.Approval {
	hash := in.Hash()
	var out []signjob.Approval
	for _, a := range actors {
		out = append(out, signjob.Approval{Actor: a, Signature: ed25519.Sign(h.keys[a], hash[:])})
	}
	return out
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (h *harness) withdrawal(id string, to common.Address, amount int64, nonce uint64, approvers ...string) signjob.Job {
	in := signjob.Intent{Kind: "withdrawal", ID: "w-" + id, Asset: "ETH", To: to.Hex(), Amount: fmt.Sprint(amount)}
	return h.job(id, in, h.ethTx(to, amount, nonce), approvers...)
}

// put writes job into the business database exactly as the business zone (or an attacker with SQL access) would.
func (h *harness) put(j signjob.Job) {
	h.t.Helper()
	tx, err := h.biz.Begin(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	if err := signjob.Enqueue(context.Background(), tx, j); err != nil {
		tx.Rollback(context.Background())
		h.t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

// run enqueues j, lets the gateway handle exactly it, and returns the decision.
func (h *harness) run(j signjob.Job) Decision {
	h.t.Helper()
	h.put(j)
	d, ok, err := h.gw.RunOnce(context.Background())
	if err != nil || !ok {
		h.t.Fatalf("RunOnce: ok=%v err=%v", ok, err)
	}
	if d.JobID != j.ID {
		h.t.Fatalf("processed job %s, want %s", d.JobID, j.ID)
	}
	return d
}

// mustSign expects a signed or replayed outcome and checks the signature recovers to the hot address.
func (h *harness) mustSign(j signjob.Job) Decision {
	h.t.Helper()
	d := h.run(j)
	if d.Outcome != OutcomeSigned && d.Outcome != OutcomeReplayed {
		h.t.Fatalf("job %s: outcome %s (%s), want signed", j.ID, d.Outcome, d.Reason)
	}
	h.checkSig(j.Digest, d.Sig)
	got, err := signjob.Get(context.Background(), h.biz, j.ID)
	if err != nil || got.Status != signjob.StatusDone || string(got.Signature) != string(d.Sig) {
		h.t.Fatalf("job row = %+v, %v", got, err)
	}
	return d
}

// mustReject expects a rejection with code and asserts nothing was signed for it.
func (h *harness) mustReject(j signjob.Job, code string) Decision {
	h.t.Helper()
	before := h.signer.calls.Load()
	var recorded int
	h.guardDB.QueryRow(context.Background(), `SELECT count(*) FROM signed_digests WHERE digest=$1`, j.Digest).Scan(&recorded)
	d := h.run(j)
	if d.Outcome != OutcomeRejected || !hasPrefix(d.Reason, code+":") {
		h.t.Fatalf("job %s: outcome %s reason %q, want rejected %s", j.ID, d.Outcome, d.Reason, code)
	}
	if h.signer.calls.Load() != before {
		h.t.Fatalf("job %s: signer was called for a rejected job", j.ID)
	}
	got, _ := signjob.Get(context.Background(), h.biz, j.ID)
	if got.Status != signjob.StatusRejected || len(got.Signature) != 0 || !hasPrefix(got.RejectReason, code+":") {
		h.t.Fatalf("job row = %+v", got)
	}
	var n int
	h.guardDB.QueryRow(context.Background(), `SELECT count(*) FROM signed_digests WHERE digest=$1`, j.Digest).Scan(&n)
	if n != recorded {
		h.t.Fatalf("job %s: the guard recorded a digest for a rejected job", j.ID)
	}
	return d
}

func (h *harness) checkSig(digest, sig []byte) {
	h.t.Helper()
	if len(sig) != 64 {
		h.t.Fatalf("signature is %d bytes", len(sig))
	}
	for v := byte(0); v < 2; v++ {
		pub, err := crypto.Ecrecover(digest, append(append([]byte{}, sig...), v))
		if err == nil && common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]) == h.hot {
			return
		}
	}
	h.t.Fatalf("signature does not recover to the hot address %s", h.hot)
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
