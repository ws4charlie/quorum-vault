package custody

import (
	"context"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

const testChain = "evm-t"

func testConfig(t *testing.T) *Config {
	t.Helper()
	cf := File{
		Chain: ChainFile{Name: testChain, ChainID: 1, Factory: "0x00000000000000000000000000000000000000f1",
			SweepDestination: "0x00000000000000000000000000000000000000a1",
			HotShards:        []string{"0x00000000000000000000000000000000000000a1", "0x00000000000000000000000000000000000000a2"},
			MaxTxFeeWei:      "1000000000000000000",
			Assets: map[string]AssetFile{
				"ETH":  {Decimals: 18, PriceWei: "1"},
				"USDT": {Address: "0x00000000000000000000000000000000000000c1", Decimals: 6, MinDeposit: "1000", PriceWei: "1000"},
			}},
		Withdrawal: WithdrawalFile{Tiers: map[string][]TierFile{"ETH": {{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: "1000", Approvals: 2}}}},
	}
	c, err := cf.Build()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExampleConfigParses(t *testing.T) {
	b, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfig(b); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfig([]byte(`{"chain":{"nope":1}}`)); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestConfigRules(t *testing.T) {
	c := testConfig(t)
	if c.SinkShard != 0 || c.EVM.SweepDestination != c.HotShards[0] {
		t.Fatalf("sink shard %d", c.SinkShard)
	}
	if n, auto := c.Required("ETH", big.NewInt(10)); n != 1 || !auto {
		t.Fatalf("lowest tier: %d %v", n, auto)
	}
	if n, auto := c.Required("ETH", big.NewInt(1000)); n != 2 || auto {
		t.Fatalf("second tier: %d %v", n, auto)
	}
	// Every (asset, shard) is a partition with a hot address; one address serves both assets.
	for _, sym := range c.AssetList {
		for i, a := range c.HotShards {
			if got := c.EVM.HotAddresses[c.PartitionKey(sym, i).String()]; got != a {
				t.Fatalf("%s shard %d -> %s", sym, i, got)
			}
		}
	}
	bad := File{Chain: ChainFile{Name: "x", Factory: "0x00000000000000000000000000000000000000f1", SweepDestination: "0x00000000000000000000000000000000000000b9",
		HotShards: []string{"0x00000000000000000000000000000000000000a1"}, MaxTxFeeWei: "1", Assets: map[string]AssetFile{"ETH": {PriceWei: "1"}}}}
	if _, err := bad.Build(); err == nil {
		t.Fatal("a sweep destination that is not a hot shard must be refused")
	}
}

func TestNormalizeAddressAndIDs(t *testing.T) {
	good := "0x52908400098527886E0F7030069857D2E4169EE7"
	if a, err := NormalizeAddress(good); err != nil || a != good {
		t.Fatalf("%s %v", a, err)
	}
	if a, err := NormalizeAddress("0x52908400098527886e0f7030069857d2e4169ee7"); err != nil || a != good {
		t.Fatalf("lowercase: %s %v", a, err)
	}
	for _, bad := range []string{"", "52908400098527886E0F7030069857D2E4169EE7", "0x1234", "0x52908400098527886E0F7030069857D2E4169Ee7", "0x0000000000000000000000000000000000000000"} {
		if _, err := NormalizeAddress(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if WithdrawalID("a", "k") != WithdrawalID("a", "k") || WithdrawalID("a", "k") == WithdrawalID("b", "k") {
		t.Fatal("withdrawal ids must depend on actor and key")
	}
	if !ValidID("c-1.x") || ValidID("a:b") || ValidID("") || ValidID("a b") {
		t.Fatal("ValidID")
	}
}

// ---- ledger flows against a fake chain ----

type fakeChain struct {
	chain.Adapter // unused methods panic
	moved         []chain.MovedAsset
	fee           *big.Int
	statuses      map[string]chain.TxStatus
}

func (f *fakeChain) Chain() string { return testChain }
func (f *fakeChain) TxFee(context.Context, string) (*big.Int, error) {
	return f.fee, nil
}
func (f *fakeChain) MovedAssets(context.Context, string) ([]chain.MovedAsset, error) {
	return f.moved, nil
}
func (f *fakeChain) Status(_ context.Context, h string) (chain.TxStatus, error) {
	return f.statuses[h], nil
}

type fakeReader struct{ block uint64 }

func (r fakeReader) SafeHead(context.Context) (uint64, error)        { return r.block, nil }
func (r fakeReader) TxBlock(context.Context, string) (uint64, error) { return r.block, nil }
func (r fakeReader) Balance(context.Context, string, string, uint64) (*big.Int, error) {
	return new(big.Int), nil
}

func newSvc(t *testing.T) (*Service, *fakeChain) {
	t.Helper()
	pool := dbtest.New(t)
	fc := &fakeChain{fee: big.NewInt(7), statuses: map[string]chain.TxStatus{}}
	s := New(pool, testConfig(t), fc, fakeReader{block: 50})
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, fc
}

func (s *Service) mustPosted(t *testing.T, acct string) *big.Int {
	t.Helper()
	p, err := s.posted(context.Background(), acct)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func expectPosted(t *testing.T, s *Service, acct string, want int64) {
	t.Helper()
	if got := s.mustPosted(t, acct); got.Cmp(big.NewInt(want)) != 0 {
		t.Fatalf("%s = %s, want %d", acct, got, want)
	}
}

func TestBootstrapIsIdempotent(t *testing.T) {
	s, _ := newSvc(t)
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	var n int
	s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM partitions`).Scan(&n)
	if n != 4 { // 2 assets x 2 shards
		t.Fatalf("%d partitions", n)
	}
}

func TestScanCreditsOnceAndSendsDustAndStrangersToSuspense(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", "CA"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('c1',$1,'0xADDR',0,'forwarder')`, testChain); err != nil {
		t.Fatal(err)
	}
	res := chain.ScanResult{SafeHeadHeight: 9, Deposits: []chain.ObservedDeposit{
		{Chain: testChain, Asset: "ETH", Address: "0xADDR", Amount: big.NewInt(500), BlockHeight: 5, TxHash: "0xaa", DedupKey: testChain + ":0xaa:native"},
		{Chain: testChain, Asset: "USDT", Address: "0xADDR", Amount: big.NewInt(999), BlockHeight: 6, TxHash: "0xbb", DedupKey: testChain + ":0xbb:0"},        // below min_deposit
		{Chain: testChain, Asset: "ETH", Address: "0xSTRANGER", Amount: big.NewInt(40), BlockHeight: 7, TxHash: "0xcc", DedupKey: testChain + ":0xcc:native"}, // unknown address
	}}
	n, err := s.ApplyScan(ctx, 0, res)
	if err != nil || n != 3 {
		t.Fatalf("credited %d: %v", n, err)
	}
	// The same scan again (a crash after the commit): nothing is credited twice.
	if _, err := s.ApplyScan(ctx, 0, res); !errors.Is(err, ErrCursorMoved) {
		t.Fatalf("a scan from a stale cursor must be refused, got %v", err)
	}
	if n, err = s.ApplyScan(ctx, 10, res); err != nil || n != 0 {
		t.Fatalf("repeat credited %d: %v", n, err)
	}
	if cur, _ := s.Cursor(ctx); cur != 10 {
		t.Fatalf("cursor %d", cur)
	}
	expectPosted(t, s, custAcct("c1", testChain, "ETH"), 500)
	expectPosted(t, s, suspenseAcct(testChain, "USDT"), 999)
	expectPosted(t, s, suspenseAcct(testChain, "ETH"), 40)
	expectPosted(t, s, depAcct(testChain, "ETH"), -540)
	if err := ledger.CheckInvariants(ctx, s.Pool); err != nil {
		t.Fatal(err)
	}
}

// settle books a sweep of the given expected amount that moved `moved`, and returns the service.
func setupSweep(t *testing.T, s *Service, id, asset string, expected int64) {
	ctx := context.Background()
	if _, err := s.Pool.Exec(ctx, `INSERT INTO sweeps (id, chain, asset, from_address, to_partition_id, amount, status) VALUES ($1,$2,$3,'0xADDR',$4,$5,'signing')`,
		id, testChain, asset, s.Cfg.SinkPartition(asset), expected); err != nil {
		t.Fatal(err)
	}
}

func TestSweepAccounting(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		expected int64
		moved    []chain.MovedAsset
		reverted bool
		// wanted balances afterwards
		hotETH, hotUSDT, dep, sweep int64
	}{
		{"exact", 100, []chain.MovedAsset{{Address: "0xADDR", Asset: "ETH", Amount: big.NewInt(100)}}, false, 100, 0, 0, 0},
		{"more than expected", 100, []chain.MovedAsset{{Address: "0xADDR", Asset: "ETH", Amount: big.NewInt(130)}}, false, 130, 0, 30, 0},
		{"less than expected", 100, []chain.MovedAsset{{Address: "0xADDR", Asset: "ETH", Amount: big.NewInt(60)}}, false, 60, 0, -40, 0},
		{"nothing moved", 100, nil, false, 0, 0, -100, 0},
		{"reverted", 100, nil, true, 0, 0, -100, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fc := newSvc(t)
			// The 100 expected were credited to a customer earlier: dep = -100.
			if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
				t.Fatal(err)
			}
			if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
				return s.transfer(ctx, tx, "pre", depAcct(testChain, "ETH"), custAcct("c1", testChain, "ETH"), big.NewInt(tc.expected), nil)
			}); err != nil {
				t.Fatal(err)
			}
			setupSweep(t, s, "sw1", "ETH", tc.expected)
			fc.moved = tc.moved
			st := chain.TxConfirmed
			if tc.reverted {
				st = chain.TxFailed
			}
			if err := s.SettleSweep(ctx, "sw1", "0xtx", st); err != nil {
				t.Fatal(err)
			}
			if err := s.SettleSweep(ctx, "sw1", "0xtx", st); err != nil { // a repeat changes nothing
				t.Fatal(err)
			}
			expectPosted(t, s, sweepAcct(testChain, "ETH"), tc.sweep)
			// dep started at -expected (the credit); the broadcast gives it +expected back, then the excess or shortfall.
			expectPosted(t, s, depAcct(testChain, "ETH"), tc.dep)
			expectPosted(t, s, hotAcct(s.Cfg.SinkPartition("ETH")), -tc.hotETH+7) // minus what arrived, plus the fee of 7
			expectPosted(t, s, feeAcct(testChain, "ETH"), -7)
			if err := ledger.CheckInvariants(ctx, s.Pool); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTokenSweepCarriesEthAndTrueUpSendsTheUnexplainedToSuspense(t *testing.T) {
	ctx := context.Background()
	s, fc := newSvc(t)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	// A customer was credited 5000 USDT (dep -5000) and nothing in ETH was ever seen.
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "pre", depAcct(testChain, "USDT"), custAcct("c1", testChain, "USDT"), big.NewInt(5000), nil)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO deposits (id, chain, asset, address, amount, dedup_key, status, block_height) VALUES ('d1',$1,'USDT','0xADDR',5000,'k1','credited',3)`, testChain); err != nil {
		t.Fatal(err)
	}
	setupSweep(t, s, "sw1", "USDT", 5000)
	fc.moved = []chain.MovedAsset{
		{Address: "0xADDR", Asset: "USDT", Amount: big.NewInt(5000)},
		{Address: "0xADDR", Asset: "ETH", Amount: big.NewInt(77)}, // ETH nobody ever saw (an internal-call deposit)
	}
	if err := s.SettleSweep(ctx, "sw1", "0xtx", chain.TxConfirmed); err != nil {
		t.Fatal(err)
	}
	expectPosted(t, s, sweepAcct(testChain, "USDT"), 0)
	expectPosted(t, s, sweepAcct(testChain, "ETH"), 0)
	expectPosted(t, s, depAcct(testChain, "ETH"), 77) // positive until true-up: ETH left an address no deposit explains
	expectPosted(t, s, hotAcct(s.Cfg.SinkPartition("ETH")), -77+7)
	expectPosted(t, s, hotAcct(s.Cfg.SinkPartition("USDT")), -5000)

	// True-up waits until the scan has passed the sweep's block (50).
	if done, err := s.TrueUp(ctx, "sw1"); err != nil || done {
		t.Fatalf("true-up before the scan caught up: %v %v", done, err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO chain_cursors (chain, next_height) VALUES ($1, 60) ON CONFLICT (chain) DO UPDATE SET next_height=60`, testChain); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // and a repeat changes nothing
		if done, err := s.TrueUp(ctx, "sw1"); err != nil || !done {
			t.Fatalf("true-up: %v %v", done, err)
		}
	}
	expectPosted(t, s, depAcct(testChain, "ETH"), 0)
	expectPosted(t, s, suspenseAcct(testChain, "ETH"), 77)
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM deposits WHERE origin='unexplained'`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d unexplained deposits", n)
	}
	if err := ledger.CheckInvariants(ctx, s.Pool); err != nil {
		t.Fatal(err)
	}
}

func TestWithdrawalRequestIsIdempotentAndRefusesWhenPoor(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "pre", depAcct(testChain, "ETH"), custAcct("c1", testChain, "ETH"), big.NewInt(1000), nil)
	}); err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7").Hex()
	req := WithdrawalRequest{Actor: "ini", IdempotencyKey: "k1", Customer: "c1", Asset: "ETH", To: to, Amount: big.NewInt(300)}
	w1, created, err := s.RequestWithdrawal(ctx, req)
	if err != nil || !created {
		t.Fatalf("%v %v", created, err)
	}
	w2, created, err := s.RequestWithdrawal(ctx, req)
	if err != nil || created || w2.ID != w1.ID {
		t.Fatalf("duplicate: %v %v %v", w2.ID, created, err)
	}
	other := req
	other.Amount = big.NewInt(301)
	if _, _, err := s.RequestWithdrawal(ctx, other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key, other body: %v", err)
	}
	bal, _ := s.Led.Balance(ctx, s.Pool, custAcct("c1", testChain, "ETH"))
	if bal.Held.Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("held %s: the hold was doubled", bal.Held)
	}
	req.IdempotencyKey, req.Amount = "k2", big.NewInt(701)
	if _, _, err := s.RequestWithdrawal(ctx, req); !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("over the balance: %v", err)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM withdrawals`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d rows: a refused request left a row", n)
	}

	// Approvals: not the initiator, once per actor.
	sig := make([]byte, 64)
	if _, err := s.AddApproval(ctx, w1.ID, "ini", sig); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("initiator approval: %v", err)
	}
	for i := 0; i < 3; i++ {
		if got, err := s.AddApproval(ctx, w1.ID, "alice", sig); err != nil || got != 1 {
			t.Fatalf("approval #%d: %d %v", i, got, err)
		}
	}
}

// Void refuses while the nonce is live: a signature at that nonce may still be broadcast.
func TestVoidRefusesWhileTheNonceIsLive(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "pre", depAcct(testChain, "ETH"), custAcct("c1", testChain, "ETH"), big.NewInt(1000), nil)
	}); err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7").Hex()
	w, _, err := s.RequestWithdrawal(ctx, WithdrawalRequest{Actor: "ini", IdempotencyKey: "k", Customer: "c1", Asset: "ETH", To: to, Amount: big.NewInt(300)})
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []string{"allocated", "broadcast"} {
		if _, err := s.Pool.Exec(ctx, `INSERT INTO evm_nonce_allocations (chain, address, nonce, owner_kind, owner_id, status) VALUES ($1,'0xhot',1,'withdrawal',$2,$3)
			ON CONFLICT (chain, address, nonce) DO UPDATE SET status=EXCLUDED.status`, testChain, w.ID, st); err != nil {
			t.Fatal(err)
		}
		if err := s.VoidWithdrawal(ctx, w.ID, "x", ""); !errors.Is(err, ErrNonceOpen) {
			t.Fatalf("void with a %s nonce: %v", st, err)
		}
	}
	bal, _ := s.Led.Balance(ctx, s.Pool, custAcct("c1", testChain, "ETH"))
	if bal.Held.Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("the hold was released while the nonce was live: held %s", bal.Held)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE evm_nonce_allocations SET status='cancelled' WHERE owner_id=$1`, w.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.VoidWithdrawal(ctx, w.ID, "cancelled", ""); err != nil {
		t.Fatal(err)
	}
	bal, _ = s.Led.Balance(ctx, s.Pool, custAcct("c1", testChain, "ETH"))
	if bal.Held.Sign() != 0 || bal.Available().Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("after the void: %+v", bal)
	}
}
