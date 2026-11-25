package custody

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// x402Model is the chain model of reconcile_evm_test.go that also knows the AuthorizationUsed events of the token and a block time.
type x402Model struct {
	*evmModel
	events    []UsedAuthorization // all payers, one token: the tests use one
	blockTime uint64
}

func (m *x402Model) AuthorizationsUsed(_ context.Context, _, _ string, from, to uint64) ([]UsedAuthorization, error) {
	var out []UsedAuthorization
	for _, e := range m.events {
		if e.Block >= from && e.Block <= to {
			out = append(out, e)
		}
	}
	return out, nil
}
func (m *x402Model) BlockTime(context.Context, uint64) (uint64, error) { return m.blockTime, nil }

var _ AuthorizationReader = (*x402Model)(nil)
var _ ReceiptReader = (*x402Model)(nil)

const x402Asset = "USDT"

type x402Env struct {
	s     *Service
	m     *x402Model
	key   *ecdsa.PrivateKey
	payer common.Address
	hot   string // the ledger account of the paying hot shard
}

// x402World is the core with one hot USDT shard that holds 1,000,000 units in the books and on the chain model, and USDT enabled for x402.
func x402World(t *testing.T) *x402Env {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	cfg := testConfig(t)
	cfg.HotShards[0] = payer
	for _, sym := range cfg.AssetList {
		cfg.EVM.HotAddresses[cfg.PartitionKey(sym, 0).String()] = payer
	}
	cfg.EVM.X402 = map[string]evm.X402Token{x402Asset: {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: big.NewInt(500_000)}}
	cfg.X402Shard = map[string]int{x402Asset: 0}
	pool := dbtest.New(t)
	m := &x402Model{evmModel: newModel(), blockTime: 1000}
	m.head = 60 // the final head when the authorizations are requested; payOnChain moves it on
	s := New(pool, cfg, &fakeChain{fee: big.NewInt(7), statuses: map[string]chain.TxStatus{}}, m)
	s.Now = func() time.Time { return time.Unix(1000, 0) }
	ctx := context.Background()
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.FundHotAsset(ctx, "seed", 0, x402Asset, big.NewInt(1_000_000)); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.bal[key2(payer.Hex(), x402Asset)] = big.NewInt(1_000_000)
	m.mu.Unlock()
	if _, err := pool.Exec(ctx, `INSERT INTO chain_cursors (chain, next_height) VALUES ($1, 200)`, testChain); err != nil {
		t.Fatal(err)
	}
	return &x402Env{s: s, m: m, key: key, payer: payer, hot: hotAcct(cfg.PartitionKey(x402Asset, 0).String())}
}

func key2(addr, asset string) string { return strings.ToLower(addr) + "|" + asset }

func (e *x402Env) request(t *testing.T, id string, amount int64, nonce byte) X402Authorization {
	t.Helper()
	var n [32]byte
	n[31] = nonce
	a, _, err := e.s.RequestX402(context.Background(), X402Request{ID: id, Asset: x402Asset, Payee: "0x00000000000000000000000000000000000fac01",
		Amount: big.NewInt(amount), ValidAfter: 990, ValidBefore: 1300, Nonce: n})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// zoneSigns marks the job done the way the gateway does: the signature of the job's digest by the hot key (r || s, low s).
func (e *x402Env) zoneSigns(t *testing.T, id string) {
	t.Helper()
	job, err := signjob.Get(context.Background(), e.s.Pool, "x402:"+id)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(job.Digest, e.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Pool.Exec(context.Background(), `UPDATE sign_jobs SET status='done', signature=$2 WHERE id=$1`, "x402:"+id, sig[:64]); err != nil {
		t.Fatal(err)
	}
}

// payOnChain is the facilitator submitting the authorization: the token moves value out of the hot wallet at block, and emits AuthorizationUsed.
func (e *x402Env) payOnChain(a X402Authorization, block uint64) {
	e.m.mu.Lock()
	e.m.head = 100
	e.m.mu.Unlock()
	e.m.events = append(e.m.events, UsedAuthorization{Nonce: a.Nonce, Block: block, TxHash: "0xpay" + a.ID})
	e.m.add(e.payer.Hex(), x402Asset, -a.Amount.Int64())
}

func (e *x402Env) held(t *testing.T) int64 {
	t.Helper()
	var h string
	if err := e.s.Pool.QueryRow(context.Background(), `SELECT held::text FROM ledger_accounts WHERE id=$1`, x402Acct(testChain, x402Asset)).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return parseBig(h).Int64()
}

func (e *x402Env) status(t *testing.T, id string) string {
	t.Helper()
	var st string
	if err := e.s.Pool.QueryRow(context.Background(), `SELECT status FROM x402_authorizations WHERE id=$1`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func (e *x402Env) liabilityCheck(t *testing.T, rep Report) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == "x402_liability" {
			return c
		}
	}
	t.Fatal("no x402_liability check in the report")
	return Check{}
}

func TestX402RequestBooksTheLiabilityAndQueuesTheJob(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	requireClean(t, "before", mustReconcile(t, e.s))
	a := e.request(t, "o1", 250_000, 1)
	if a.Status != X402Requested || a.Payer != e.payer.Hex() || a.Amount.Int64() != 250_000 {
		t.Fatalf("row %+v", a)
	}
	if e.held(t) != 250_000 {
		t.Fatalf("held %d", e.held(t))
	}
	job, err := signjob.Get(ctx, e.s.Pool, "x402:o1")
	if err != nil || job.Status != signjob.StatusPending || job.PartitionID != a.PartitionID {
		t.Fatalf("job %+v err %v", job, err)
	}
	rep := mustReconcile(t, e.s)
	requireClean(t, "with an open authorization", rep)
	if c := e.liabilityCheck(t, rep); c.Ledger != "250000" || c.Chain != "250000" {
		t.Fatalf("liability check %+v", c)
	}
	if rep.InFlight != 1 {
		t.Fatalf("in flight %d", rep.InFlight)
	}
	// The same request again is the same row; another request under the same id, or the same nonce under another id, is refused.
	b, created, err := e.s.RequestX402(ctx, X402Request{ID: "o1", Asset: x402Asset, Payee: a.Payee, Amount: big.NewInt(250_000), ValidAfter: 990, ValidBefore: 1300, Nonce: [32]byte{31: 1}})
	if err != nil || created || b.ID != "o1" || e.held(t) != 250_000 {
		t.Fatalf("repeat: %+v created=%v err=%v held=%d", b, created, err, e.held(t))
	}
	if _, _, err := e.s.RequestX402(ctx, X402Request{ID: "o1", Asset: x402Asset, Payee: a.Payee, Amount: big.NewInt(1), ValidAfter: 990, ValidBefore: 1300, Nonce: [32]byte{31: 1}}); err == nil || !strings.Contains(err.Error(), "reused") {
		t.Fatalf("same id, other request: %v", err)
	}
	if _, _, err := e.s.RequestX402(ctx, X402Request{ID: "o2", Asset: x402Asset, Payee: a.Payee, Amount: big.NewInt(1), ValidAfter: 990, ValidBefore: 1300, Nonce: [32]byte{31: 1}}); err == nil {
		t.Fatal("the same token nonce under another id was accepted")
	}
	if e.held(t) != 250_000 {
		t.Fatalf("a refused request changed the hold: %d", e.held(t))
	}
	for name, r := range map[string]X402Request{
		"over the limit":       {ID: "p1", Asset: x402Asset, Payee: a.Payee, Amount: big.NewInt(500_001), ValidAfter: 990, ValidBefore: 1300},
		"window too long":      {ID: "p2", Asset: x402Asset, Payee: a.Payee, Amount: big.NewInt(1), ValidAfter: 100, ValidBefore: 1300},
		"already over":         {ID: "p3", Asset: x402Asset, Payee: a.Payee, Amount: big.NewInt(1), ValidAfter: 100, ValidBefore: 900},
		"not an x402 asset":    {ID: "p4", Asset: "ETH", Payee: a.Payee, Amount: big.NewInt(1), ValidAfter: 990, ValidBefore: 1300},
		"payee is not an addr": {ID: "p5", Asset: x402Asset, Payee: "nobody", Amount: big.NewInt(1), ValidAfter: 990, ValidBefore: 1300},
	} {
		if _, _, err := e.s.RequestX402(ctx, r); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// Used: the facilitator submits it. Reconcile stays clean in every step: before the books know, after, and when the same event is seen again.
func TestX402UsedIsBookedAndReconcileStaysClean(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	a := e.request(t, "u1", 250_000, 1)
	e.zoneSigns(t, "u1")
	r, err := e.s.X402(ctx, "u1")
	if err != nil || r.Status != X402Signed || (r.V != 27 && r.V != 28) {
		t.Fatalf("signed result %+v %v", r, err)
	}
	// The signature is the payer's over the EIP-712 digest of the typed data the job carries.
	job, _ := signjob.Get(ctx, e.s.Pool, "x402:u1")
	var d [32]byte
	copy(d[:], job.Digest)
	rec := append(append(append([]byte{}, r.R[:]...), r.S[:]...), r.V-27)
	if pub, err := crypto.SigToPub(d[:], rec); err != nil || crypto.PubkeyToAddress(*pub) != e.payer {
		t.Fatalf("the returned r, s, v do not recover to the payer: %v", err)
	}
	requireClean(t, "signed, unused", mustReconcile(t, e.s))

	// The token paid at block 90 (final: head is 100); the worker has not booked it yet.
	e.payOnChain(a, 90)
	rep := mustReconcile(t, e.s)
	requireClean(t, "paid on chain, not booked", rep)
	if !hasAdjusted(rep, "hot") {
		t.Fatal("the hot check does not say it was adjusted for the unbooked payment")
	}
	// An event above the pinned height is not on the books' side yet (and the model's balance is not height-aware, so only the explanation is checked here).
	res, err := e.s.SettleX402(ctx)
	if err != nil || res.Used != 1 {
		t.Fatalf("settle %+v %v", res, err)
	}
	requireClean(t, "booked", mustReconcile(t, e.s))
	if e.held(t) != 0 || e.status(t, "u1") != X402Used {
		t.Fatalf("held %d status %s", e.held(t), e.status(t, "u1"))
	}
	expectPosted(t, e.s, x402Acct(testChain, x402Asset), -250_000)
	expectPosted(t, e.s, e.hot, -750_000)
	// Seen again: by the worker's pass, and by a direct booking of the same event: nothing changes.
	res, err = e.s.SettleX402(ctx)
	if err != nil || res != (X402Settled{}) {
		t.Fatalf("second pass %+v %v", res, err)
	}
	if booked, err := e.s.x402Pay(ctx, "u1", e.m.events[0]); err != nil || booked {
		t.Fatalf("the same event booked twice: %v %v", booked, err)
	}
	expectPosted(t, e.s, x402Acct(testChain, x402Asset), -250_000)
	expectPosted(t, e.s, e.hot, -750_000)
	requireClean(t, "after the repeat", mustReconcile(t, e.s))
}

// Expired: nobody uses it. The books release the hold only when a final block is at or past validBefore and the event was not seen up to it.
func TestX402ExpiredIsReleasedOnlyOnceNoBlockCanUseIt(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	e.request(t, "e1", 250_000, 1)
	e.zoneSigns(t, "e1")
	if _, err := e.s.X402(ctx, "e1"); err != nil {
		t.Fatal(err)
	}
	// The final head's time is still before validBefore (1300): a block may yet include it.
	e.m.blockTime = 1299
	if res, err := e.s.SettleX402(ctx); err != nil || res.Expired != 0 || e.held(t) != 250_000 {
		t.Fatalf("settled too early: %+v %v held %d", res, err, e.held(t))
	}
	requireClean(t, "before validBefore", mustReconcile(t, e.s))
	e.m.blockTime = 1300
	res, err := e.s.SettleX402(ctx)
	if err != nil || res.Expired != 1 {
		t.Fatalf("settle %+v %v", res, err)
	}
	if e.held(t) != 0 || e.status(t, "e1") != X402Expired {
		t.Fatalf("held %d status %s", e.held(t), e.status(t, "e1"))
	}
	expectPosted(t, e.s, x402Acct(testChain, x402Asset), 0)
	expectPosted(t, e.s, e.hot, -1_000_000)
	rep := mustReconcile(t, e.s)
	requireClean(t, "expired", rep)
	if c := e.liabilityCheck(t, rep); c.Ledger != "0" || c.Chain != "0" {
		t.Fatalf("liability %+v", c)
	}
	if res, err := e.s.SettleX402(ctx); err != nil || res != (X402Settled{}) {
		t.Fatalf("second pass %+v %v", res, err)
	}
}

// Used in the last block before validBefore, seen in the same pass that sees the head pass validBefore: the payment wins, never the expiry.
func TestX402PaymentSeenInTheSamePassAsTheExpiryIsBookedAsPaid(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	a := e.request(t, "m1", 100_000, 1)
	e.zoneSigns(t, "m1")
	e.payOnChain(a, 95)
	e.m.blockTime = 5000
	res, err := e.s.SettleX402(ctx)
	if err != nil || res.Used != 1 || res.Expired != 0 {
		t.Fatalf("settle %+v %v", res, err)
	}
	requireClean(t, "paid", mustReconcile(t, e.s))
}

func TestX402RefusedJobReleasesTheHold(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	e.request(t, "f1", 250_000, 1)
	if _, err := e.s.Pool.Exec(ctx, `UPDATE sign_jobs SET status='rejected', reject_reason='policy_payment_rule: no rule' WHERE id='x402:f1'`); err != nil {
		t.Fatal(err)
	}
	r, err := e.s.X402(ctx, "f1")
	if err != nil || r.Status != X402Refused || !strings.Contains(r.Reason, "policy_payment_rule") {
		t.Fatalf("%+v %v", r, err)
	}
	if e.held(t) != 0 {
		t.Fatalf("held %d", e.held(t))
	}
	requireClean(t, "refused", mustReconcile(t, e.s))
	if _, err := e.s.X402(ctx, "f1"); err != nil || e.held(t) != 0 {
		t.Fatalf("again: %v held %d", err, e.held(t))
	}
}

// What the books cannot explain still alerts: a payment on the chain that no authorization of ours accounts for.
func TestX402ReconcileStillSeesAWalletThatPaidSomethingElse(t *testing.T) {
	e := x402World(t)
	e.request(t, "z1", 250_000, 1)
	e.m.add(e.payer.Hex(), x402Asset, -250_000) // the balance fell, and no AuthorizationUsed names an authorization of ours
	rep := mustReconcile(t, e.s)
	if rep.Clean {
		t.Fatalf("a payment nobody booked was explained away: %+v", rep.Checks)
	}
	found := false
	for _, f := range rep.Failures() {
		found = found || f.Name == "hot"
	}
	if !found {
		t.Fatalf("failures %+v", rep.Failures())
	}
}

func TestX402ReaderWithoutEventsFailsTheLiabilityCheck(t *testing.T) {
	e := x402World(t)
	e.request(t, "n1", 1000, 1)
	e.s.Reader = e.m.evmModel // a reader that can read receipts but not the token's events
	rep := mustReconcile(t, e.s)
	if rep.Clean || e.liabilityCheck(t, rep).OK {
		t.Fatalf("an open authorization was explained by a reader that cannot read events: %+v", rep.Checks)
	}
}

func TestX402ConfigBuildsAndRefusesBadEntries(t *testing.T) {
	build := func(x X402File) (*Config, error) {
		cf := File{
			Chain: ChainFile{Name: testChain, ChainID: 84532, Factory: "0x00000000000000000000000000000000000000f1",
				SweepDestination: "0x00000000000000000000000000000000000000a1",
				HotShards:        []string{"0x00000000000000000000000000000000000000a1", "0x00000000000000000000000000000000000000a2"},
				MaxTxFeeWei:      "1000000000000000000",
				Assets: map[string]AssetFile{
					"ETH":  {Decimals: 18, PriceWei: "1"},
					"USDT": {Address: "0x00000000000000000000000000000000000000c1", Decimals: 6, MinDeposit: "1000", PriceWei: "1000"},
				},
				X402: map[string]X402File{"USDT": x}},
			Withdrawal: WithdrawalFile{Tiers: map[string][]TierFile{"ETH": {{MinAmount: "0", Approvals: 1, Auto: true}}}},
		}
		return cf.Build()
	}
	c, err := build(X402File{Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "500000", Shard: 1})
	if err != nil {
		t.Fatal(err)
	}
	if c.X402Shard["USDT"] != 1 || c.EVM.X402["USDT"].PerPaymentLimit.Int64() != 500000 || c.EVM.X402["USDT"].Name != "USDC" {
		t.Fatalf("config %+v %+v", c.X402Shard, c.EVM.X402)
	}
	for name, x := range map[string]X402File{
		"shard out of range": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "5", Shard: 2},
		"no limit":           {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "0"},
		"no version":         {Name: "USDC", MaxWindowSeconds: 600, PerPaymentLimit: "5"},
		"a signed limit":     {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "-1"},
	} {
		if _, err := build(x); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An open authorization reserves the funds: freeHot (what every planner and withdrawal reads) shows them as gone, and a request that the free balance
// cannot cover is refused with nothing recorded. Expiry gives them back.
func TestX402OpenAuthorizationsReserveTheShardBalance(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	part := e.s.Cfg.PartitionKey(x402Asset, 0).String()
	free := func() int64 {
		f, err := e.s.freeHot(ctx, e.s.Pool, part)
		if err != nil {
			t.Fatal(err)
		}
		return f.Int64()
	}
	if free() != 1_000_000 {
		t.Fatalf("free %d", free())
	}
	e.request(t, "r1", 400_000, 1)
	e.request(t, "r2", 400_000, 2)
	if free() != 200_000 {
		t.Fatalf("free after two authorizations %d", free())
	}
	// A third that does not fit is refused; so is one for the remaining balance plus one (what a withdrawal would also see).
	for i, amt := range []int64{400_000, 200_001} {
		_, _, err := e.s.RequestX402(ctx, X402Request{ID: "r3" + string(rune('a'+i)), Asset: x402Asset, Payee: "0x00000000000000000000000000000000000fac01",
			Amount: big.NewInt(amt), ValidAfter: 990, ValidBefore: 1300, Nonce: [32]byte{31: byte(10 + i)}})
		if !errors.Is(err, ErrX402InsufficientFunds) {
			t.Fatalf("amount %d: %v", amt, err)
		}
	}
	var n int
	e.s.Pool.QueryRow(ctx, `SELECT count(*) FROM x402_authorizations`).Scan(&n)
	if n != 2 || e.held(t) != 800_000 {
		t.Fatalf("%d rows, held %d", n, e.held(t))
	}
	e.request(t, "r4", 200_000, 5) // exactly the rest fits
	if free() != 0 {
		t.Fatalf("free %d", free())
	}
	// Expiry gives it back.
	e.zoneSigns(t, "r1")
	e.m.blockTime = 1300
	if res, err := e.s.SettleX402(ctx); err != nil || res.Expired != 3 {
		t.Fatalf("settle %+v %v", res, err)
	}
	if free() != 1_000_000 {
		t.Fatalf("free after expiry %d", free())
	}
}

// The payer is the address of the shard's active key generation, not the configured one: after a replacement the old key is never asked.
func TestX402PayerFollowsTheActiveGeneration(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	newKey, _ := crypto.GenerateKey()
	newAddr := crypto.PubkeyToAddress(newKey.PublicKey)
	shard := string(e.s.Cfg.shardIDOf(0))
	for _, q := range []string{
		`UPDATE keysets SET state='retired' WHERE shard_id='` + shard + `' AND generation=1`,
		`INSERT INTO keysets (shard_id, generation, key_ref, address, public_key, state) VALUES ('` + shard + `', 2, 'ref2', '` + newAddr.Hex() + `', '\x02', 'active')`,
	} {
		if _, err := e.s.Pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	e.s.Pool.Exec(ctx, `UPDATE x402_authorizations SET status=status`) // no-op: the table is reachable
	// The new generation holds the funds now.
	if err := e.s.FundHotAsset(ctx, "seed2", 0, x402Asset, big.NewInt(1)); err != nil {
		t.Fatal(err)
	}
	a := e.request(t, "g1", 1000, 1)
	if a.Payer != newAddr.Hex() || a.Payer == e.payer.Hex() {
		t.Fatalf("payer %s, active generation %s, old %s", a.Payer, newAddr.Hex(), e.payer.Hex())
	}
	job, err := signjob.Get(ctx, e.s.Pool, "x402:g1")
	if err != nil || !strings.Contains(strings.ToLower(string(job.Payload)), strings.ToLower(newAddr.Hex())) || strings.Contains(strings.ToLower(string(job.Payload)), strings.ToLower(e.payer.Hex())) {
		t.Fatalf("the typed data names the wrong payer: %v %s", err, job.Payload)
	}
}

// A retry of a request that was answered is answered again, whatever the clock says now; another request under the id is still a conflict.
func TestX402LateRetryReturnsTheStoredRow(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	a := e.request(t, "l1", 1000, 1)
	e.s.Now = func() time.Time { return time.Unix(5000, 0) } // long after validBefore (1300)
	req := X402Request{ID: "l1", Asset: x402Asset, Payee: a.Payee, Amount: big.NewInt(1000), ValidAfter: 990, ValidBefore: 1300, Nonce: [32]byte{31: 1}}
	b, created, err := e.s.RequestX402(ctx, req)
	if err != nil || created || b.ID != "l1" || b.Status != X402Requested {
		t.Fatalf("late retry: %+v created=%v err=%v", b, created, err)
	}
	req.Amount = big.NewInt(1001)
	if _, _, err := e.s.RequestX402(ctx, req); !errors.Is(err, ErrX402Conflict) {
		t.Fatalf("another body: %v", err)
	}
	// A new id with that window is refused: it is over.
	req.ID, req.Amount, req.Nonce = "l2", big.NewInt(1000), [32]byte{31: 2}
	if _, _, err := e.s.RequestX402(ctx, req); err == nil {
		t.Fatal("a new request with a past window was accepted")
	}
}

// A failed read of the final head refuses the request and records nothing (a stored 0 would make the event search start at the first block).
type headFails struct{ *x402Model }

func (headFails) SafeHead(context.Context) (uint64, error) { return 0, errors.New("node unreachable") }

func TestX402FailedHeadReadRecordsNothing(t *testing.T) {
	e := x402World(t)
	ctx := context.Background()
	e.s.Reader = headFails{e.m}
	_, _, err := e.s.RequestX402(ctx, X402Request{ID: "h1", Asset: x402Asset, Payee: "0x00000000000000000000000000000000000fac01", Amount: big.NewInt(1000),
		ValidAfter: 990, ValidBefore: 1300, Nonce: [32]byte{31: 1}})
	if err == nil || !strings.Contains(err.Error(), "retry") {
		t.Fatalf("err %v", err)
	}
	var n, jobs int
	e.s.Pool.QueryRow(ctx, `SELECT count(*) FROM x402_authorizations`).Scan(&n)
	e.s.Pool.QueryRow(ctx, `SELECT count(*) FROM sign_jobs`).Scan(&jobs)
	if n != 0 || jobs != 0 || e.held(t) != 0 {
		t.Fatalf("rows %d jobs %d held %d", n, jobs, e.held(t))
	}
	e.s.Reader = e.m // the node is back: the same request goes through
	if a := e.request(t, "h1", 1000, 1); a.SinceBlock != 60 {
		t.Fatalf("since_block %d", a.SinceBlock)
	}
}
