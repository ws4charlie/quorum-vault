package custody

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// A scan that is a few blocks behind the safe head must not make Reconcile alert; a real difference, a stuck scan and a scan far behind must.

// scanChain is an EVM chain cell whose Scan returns what the blocks the scan has not read hold (read only: nothing is applied).
type scanChain struct {
	*fakeChain
	mu    sync.Mutex
	res   chain.ScanResult
	err   error
	calls int
	from  uint64
}

func (f *scanChain) Scan(_ context.Context, from uint64) (chain.ScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.from = from
	return f.res, f.err
}

// captureAlerts collects what Reconcile logs while the test runs.
func captureAlerts(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func setCursor(t *testing.T, s *Service, next uint64) {
	t.Helper()
	if _, err := s.Pool.Exec(context.Background(), `UPDATE chain_cursors SET next_height=$2, updated_at=now() WHERE chain=$1`, s.Cfg.Chain, int64(next)); err != nil {
		t.Fatal(err)
	}
}

func failedNames(rep Report) []string {
	var out []string
	for _, f := range rep.Failures() {
		out = append(out, f.Name)
	}
	return out
}

func checkOf(rep Report, name string) Check {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

// lagWorld is an EVM cell, safe head 100, one customer deposit address holding 5 wei that the books know nothing of yet because the scan has not
// read block 99: the scan cursor is 98 (behind by 3 blocks).
func lagWorld(t *testing.T) (*Service, *scanChain, *evmModel) {
	t.Helper()
	ctx := context.Background()
	s, fc, m := evmWorld(t)
	sc := &scanChain{fakeChain: fc}
	s.Chain = sc
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('c1',$1,'0xADDR',0,'forwarder')`, testChain); err != nil {
		t.Fatal(err)
	}
	m.add("0xADDR", "ETH", 5)
	sc.res = chain.ScanResult{SafeHeadHeight: 100, Deposits: []chain.ObservedDeposit{{Chain: testChain, Asset: "ETH", Address: "0xADDR", Amount: big.NewInt(5), BlockHeight: 99,
		TxHash: "0xd1", DedupKey: testChain + ":0xd1:native"}}}
	setCursor(t, s, 98)
	return s, sc, m
}

// The cause of the false ALERT: the chain holds a deposit in a block the scan has not read. With the lag accounted for, the report is clean, says
// how far behind the scan is, and raises no ALERT; once the scan has booked it, still clean.
func TestReconcileEVMScanLagIsAStatusNotAnAlert(t *testing.T) {
	ctx := context.Background()
	buf := captureAlerts(t)
	s, sc, _ := lagWorld(t)
	rep := mustReconcile(t, s)
	requireClean(t, "scan 3 blocks behind", rep)
	if rep.ScanLag != 3 {
		t.Fatalf("lag %d, want 3", rep.ScanLag)
	}
	if c := checkOf(rep, "scan_caught_up"); !c.OK || !strings.Contains(c.Detail, "behind by 3 blocks") {
		t.Fatalf("%+v", c)
	}
	if sc.from != 98 {
		t.Fatalf("the pending read started at %d, want the cursor 98", sc.from)
	}
	if strings.Contains(buf.String(), "ALERT") {
		t.Fatalf("an ALERT for a scan that is 3 blocks behind: %s", buf.String())
	}
	// The scan catches up: it books the deposit and moves its cursor. Nothing pending any more.
	if _, err := s.ApplyScan(ctx, 98, chain.ScanResult{SafeHeadHeight: 100, Deposits: sc.res.Deposits}); err != nil {
		t.Fatal(err)
	}
	sc.res = chain.ScanResult{SafeHeadHeight: 100}
	rep = mustReconcile(t, s)
	requireClean(t, "caught up", rep)
	if rep.ScanLag != 0 {
		t.Fatalf("lag %d after the scan caught up", rep.ScanLag)
	}
}

// A moving chain with a healthy scan: the head and the cursor advance, the lag changes from 0 to 5 blocks, and no report is ever unclean.
func TestReconcileEVMMovingChainWithHealthyScanNeverAlerts(t *testing.T) {
	buf := captureAlerts(t)
	s, sc, m := lagWorld(t)
	sc.res = chain.ScanResult{SafeHeadHeight: 100} // the 5 wei are already booked below
	m.add("0xADDR", "ETH", -5)
	now := time.Now()
	s.Now = func() time.Time { return now }
	for head := uint64(100); head < 130; head++ {
		m.mu.Lock()
		m.head = head
		m.mu.Unlock()
		setCursor(t, s, head+1-uint64(head%6)) // lag 0..5
		sc.res = chain.ScanResult{SafeHeadHeight: head}
		now = now.Add(12 * time.Second)
		requireClean(t, "moving chain", mustReconcile(t, s))
	}
	if strings.Contains(buf.String(), "ALERT") {
		t.Fatalf("ALERT on a moving chain: %s", buf.String())
	}
}

// Real differences still alert at once while the scan is behind: a missing credit (the books hold a deposit the chain does not), a wrong amount, an
// unexpected balance at a deposit address, and a hot wallet that does not add up.
func TestReconcileEVMRealDifferencesStillAlertWhileTheScanIsBehind(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, s *Service, sc *scanChain, m *evmModel)
		want   string
	}{
		{"unexpected balance", func(t *testing.T, s *Service, sc *scanChain, m *evmModel) { m.add("0xADDR", "ETH", 1) }, "deposit_addresses"},
		{"the pending read has a wrong amount", func(t *testing.T, s *Service, sc *scanChain, m *evmModel) {
			sc.res.Deposits[0].Amount = big.NewInt(4)
		}, "deposit_addresses"},
		{"a deposit the chain does not have", func(t *testing.T, s *Service, sc *scanChain, m *evmModel) { m.add("0xADDR", "ETH", -5) }, "deposit_addresses"},
		{"a pending deposit above the pinned height is not counted", func(t *testing.T, s *Service, sc *scanChain, m *evmModel) {
			sc.res.Deposits[0].BlockHeight = 101
		}, "deposit_addresses"},
		{"the hot wallet is short", func(t *testing.T, s *Service, sc *scanChain, m *evmModel) { m.add(s.Cfg.HotShards[0].Hex(), "ETH", -1) }, "hot"},
		{"a missing credit at a height the scan has finished", func(t *testing.T, s *Service, sc *scanChain, m *evmModel) {
			// The scan has read block 99 (cursor 100, lag 1) and booked 5 wei the chain does not hold: the credit is missing from the chain side.
			setCursor(t, s, 100)
			sc.res = chain.ScanResult{SafeHeadHeight: 100}
			if _, err := s.ApplyScan(ctx, 100, chain.ScanResult{SafeHeadHeight: 100, Deposits: []chain.ObservedDeposit{{Chain: testChain, Asset: "ETH", Address: "0xADDR",
				Amount: big.NewInt(9), BlockHeight: 100, TxHash: "0xd2", DedupKey: testChain + ":0xd2:native"}}}); err != nil {
				t.Fatal(err)
			}
			setCursor(t, s, 100)
		}, "deposit_addresses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureAlerts(t)
			s, sc, m := lagWorld(t)
			tc.mutate(t, s, sc, m)
			rep := mustReconcile(t, s)
			if rep.Clean || len(failedNames(rep)) != 1 || failedNames(rep)[0] != tc.want {
				t.Fatalf("clean=%v failures=%v, want only %s", rep.Clean, failedNames(rep), tc.want)
			}
			if !strings.Contains(buf.String(), "ALERT: the books and the chain disagree") || !strings.Contains(buf.String(), "check="+tc.want) {
				t.Fatalf("no ALERT: %s", buf.String())
			}
		})
	}
}

// A pending read that fails does not hide a difference: the deposit the chain holds is then unexplained, and it alerts.
func TestReconcileEVMUnreadablePendingBlocksAreNotHidden(t *testing.T) {
	s, sc, _ := lagWorld(t)
	sc.err = errors.New("node unreachable")
	rep := mustReconcile(t, s)
	if rep.Clean || len(failedNames(rep)) != 1 || failedNames(rep)[0] != "deposit_addresses" {
		t.Fatalf("clean=%v %v", rep.Clean, failedNames(rep))
	}
	if !strings.Contains(checkOf(rep, "deposit_addresses").Detail, "could not be read") {
		t.Fatalf("%+v", checkOf(rep, "deposit_addresses"))
	}
}

// A stuck scan: the cursor does not move while the chain is ahead. Inside reconcile.scan_stuck_after it is a status; after it, an ALERT on scan_caught_up.
// And a scan that is behind by more than reconcile.max_scan_lag_blocks alerts at once, however fast it moves.
func TestReconcileEVMStuckScanAndFarBehindScanAlert(t *testing.T) {
	buf := captureAlerts(t)
	s, _, _ := lagWorld(t)
	now := time.Now()
	s.Now = func() time.Time { return now }
	rep := mustReconcile(t, s)
	requireClean(t, "first look", rep)
	now = now.Add(s.Cfg.ReconcileScanStuckAfter - time.Second)
	requireClean(t, "just inside the stuck time", mustReconcile(t, s))
	if strings.Contains(buf.String(), "ALERT") {
		t.Fatalf("early ALERT: %s", buf.String())
	}
	now = now.Add(2 * time.Second)
	rep = mustReconcile(t, s)
	if got := failedNames(rep); len(got) == 0 || got[0] != "scan_caught_up" || !strings.Contains(checkOf(rep, "scan_caught_up").Detail, "stuck") {
		t.Fatalf("a cursor that has not moved for the stuck time: %v %+v", got, checkOf(rep, "scan_caught_up"))
	}
	if !strings.Contains(buf.String(), "check=scan_caught_up") {
		t.Fatalf("no ALERT for the stuck scan: %s", buf.String())
	}
	// The cursor moves one block: the clock starts again.
	setCursor(t, s, 99)
	if rep := mustReconcile(t, s); checkOf(rep, "scan_caught_up").OK == false {
		t.Fatalf("a cursor that moved still stuck: %+v", checkOf(rep, "scan_caught_up"))
	}
	// Far behind.
	setCursor(t, s, 100-s.Cfg.ReconcileMaxScanLag-2)
	rep = mustReconcile(t, s)
	if c := checkOf(rep, "scan_caught_up"); c.OK || !strings.Contains(c.Detail, "more than the") {
		t.Fatalf("far behind: %+v", c)
	}
}

func TestScanLagMetric(t *testing.T) {
	s, _, _ := lagWorld(t)
	mustReconcile(t, s)
	var b bytes.Buffer
	WriteScanLagMetrics(&b)
	if !strings.Contains(b.String(), `qv_scan_lag_blocks{chain="`+testChain+`"} 3`) {
		t.Fatalf("%s", b.String())
	}
}

func TestReconcileScanLagDefaultsPerFamily(t *testing.T) {
	evmCfg, _ := testConfig(t), error(nil)
	btcCfg, err := btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if evmCfg.ReconcileMaxScanLag != 32 || btcCfg.ReconcileMaxScanLag != 6 || evmCfg.ReconcileScanStuckAfter != 5*time.Minute {
		t.Fatalf("evm %d btc %d stuck %s", evmCfg.ReconcileMaxScanLag, btcCfg.ReconcileMaxScanLag, evmCfg.ReconcileScanStuckAfter)
	}
	f := btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams))
	f.Reconcile = ReconcileFile{MaxScanLagBlocks: 2, ScanStuckAfter: "90s"}
	c, err := f.Build()
	if err != nil || c.ReconcileMaxScanLag != 2 || c.ReconcileScanStuckAfter != 90*time.Second {
		t.Fatalf("%v %+v", err, c)
	}
}

// ---- Bitcoin ----

// btcLagChain produces a view (a deposit output and an operator funding output the chain holds and the table does not) and the pending read of the scan.
type btcLagChain struct {
	chain.Adapter
	views int
	view  chain.ChainView
	res   chain.ScanResult
	err   error
}

func (f *btcLagChain) Chain() string { return "btc-reg" }
func (f *btcLagChain) ChainView(context.Context, []string) (chain.ChainView, error) {
	f.views++
	return f.view, nil
}
func (f *btcLagChain) Scan(context.Context, uint64) (chain.ScanResult, error) { return f.res, f.err }

type fixedHead uint64

func (h fixedHead) SafeHead(context.Context) (uint64, error)        { return uint64(h), nil }
func (h fixedHead) TxBlock(context.Context, string) (uint64, error) { return uint64(h), nil }
func (h fixedHead) Balance(context.Context, string, string, uint64) (*big.Int, error) {
	return new(big.Int), nil
}

const btcDepAddr = "bcrt1qdeposit0000000000000000000000000000000"

// btcLagWorld: safe head 1000, scan cursor 998. The chain holds 7000 sats on a customer's deposit address (output tx1:0) and 5000 sats an operator sent to the
// hot address (tx2:1), both in blocks the scan has not read; the table and the books know neither.
func btcLagWorld(t *testing.T) (*Service, *btcLagChain) {
	t.Helper()
	ctx := context.Background()
	xpub := xpubFor(t, &chaincfg.RegressionNetParams)
	hotAddr, err := btc.DeriveHotAddress("regtest", xpub, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := btcFile("regtest", xpub)
	f.Chain.BTC.HotShards = []BTCShardFile{{Address: hotAddr, Path: []uint32{1, 0}}}
	cfg, err := f.Build()
	if err != nil {
		t.Fatal(err)
	}
	fc := &btcLagChain{}
	s := New(dbtest.New(t), cfg, fc, fixedHead(1000))
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO chain_cursors (chain, next_height) VALUES ($1, 998)`, cfg.Chain); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('c1',$1,$2,0,'xpub')`, s.Cfg.Chain, btcDepAddr); err != nil {
		t.Fatal(err)
	}
	hot := hotAddr
	fc.view = chain.ChainView{Height: 1001, SpentInFlight: map[string]*big.Int{},
		Balance: map[string]*big.Int{btcDepAddr: big.NewInt(7000), hot: big.NewInt(5000)},
		Diffs: []chain.OutputDiff{
			{Address: btcDepAddr, Output: "tx1:0", Detail: "an unspent output on a deposit address that no deposit of ours explains"},
			{Address: hot, Output: "tx2:1", Detail: "an unspent output on a hot address that the table does not hold"},
		}}
	fc.res = chain.ScanResult{SafeHeadHeight: 1000,
		Deposits: []chain.ObservedDeposit{{Chain: s.Cfg.Chain, Asset: "BTC", Address: btcDepAddr, Amount: big.NewInt(7000), BlockHeight: 999, TxHash: "tx1", DedupKey: s.Cfg.Chain + ":tx1:0"}},
		Funding:  []chain.FundingOutput{{Chain: s.Cfg.Chain, Asset: "BTC", PartitionID: s.Cfg.PartitionKey("BTC", 0).String(), Address: hot, TxHash: "tx2", Vout: 1, Amount: big.NewInt(5000), BlockHeight: 1000}}}
	return s, fc
}

func TestReconcileBTCScanLagIsAStatusNotAnAlert(t *testing.T) {
	buf := captureAlerts(t)
	s, _ := btcLagWorld(t)
	rep := mustReconcile(t, s)
	if !rep.Clean || rep.ScanLag != 3 {
		t.Fatalf("clean=%v lag=%d failures=%+v", rep.Clean, rep.ScanLag, rep.Failures())
	}
	if strings.Contains(buf.String(), "ALERT") {
		t.Fatalf("ALERT for a Bitcoin scan 3 blocks behind: %s", buf.String())
	}
}

func TestReconcileBTCRealDifferencesStillAlertWhileTheScanIsBehind(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(s *Service, fc *btcLagChain)
		want   []string
	}{
		{"an output nothing explains", func(s *Service, fc *btcLagChain) {
			fc.view.Diffs = append(fc.view.Diffs, chain.OutputDiff{Address: btcDepAddr, Output: "tx9:0", Detail: "unexplained"})
		}, []string{"outputs_on_chain"}},
		{"the pending read is smaller than what the chain holds", func(s *Service, fc *btcLagChain) {
			fc.res.Deposits[0].Amount = big.NewInt(6000)
		}, []string{"deposit_addresses"}},
		{"the pending read is unreadable", func(s *Service, fc *btcLagChain) { fc.err = errors.New("rpc down") },
			[]string{"deposit_addresses", "hot", "outputs_on_chain"}},
		{"the hot wallet holds more than the funding explains", func(s *Service, fc *btcLagChain) {
			fc.view.Balance[s.Cfg.BTC.HotShards[0].Address] = big.NewInt(5001)
		}, []string{"hot"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureAlerts(t)
			s, fc := btcLagWorld(t)
			tc.mutate(s, fc)
			rep := mustReconcile(t, s)
			got := map[string]bool{}
			for _, n := range failedNames(rep) {
				got[n] = true
			}
			if rep.Clean || len(got) != len(tc.want) {
				t.Fatalf("clean=%v failures=%v want %v", rep.Clean, failedNames(rep), tc.want)
			}
			for _, w := range tc.want {
				if !got[w] || !strings.Contains(buf.String(), "check="+w) {
					t.Fatalf("no ALERT for %s: %v\n%s", w, failedNames(rep), buf.String())
				}
			}
		})
	}
}

func TestReconcileBTCStuckScanAlerts(t *testing.T) {
	buf := captureAlerts(t)
	s, _ := btcLagWorld(t)
	now := time.Now()
	s.Now = func() time.Time { return now }
	if rep := mustReconcile(t, s); !rep.Clean {
		t.Fatalf("%+v", rep.Failures())
	}
	now = now.Add(s.Cfg.ReconcileScanStuckAfter + time.Second)
	rep := mustReconcile(t, s)
	// A stuck scan explains nothing: the outputs it has not booked are differences again.
	if got := failedNames(rep); len(got) < 2 || got[0] != "scan_caught_up" {
		t.Fatalf("%v", got)
	}
	if !strings.Contains(buf.String(), "check=scan_caught_up") {
		t.Fatalf("no ALERT: %s", buf.String())
	}
}

// A held deposit (sweep_holds: credited, left below the sweep threshold) is a reading for operators and moves no money: Reconcile does not report it as a
// difference, and a real difference beside it still alerts.
func TestReconcileEVMSweepHoldsAreNotDifferencesAndHideNone(t *testing.T) {
	ctx := context.Background()
	buf := captureAlerts(t)
	s, sc, m := lagWorld(t)
	sc.res = chain.ScanResult{SafeHeadHeight: 100}
	setCursor(t, s, 101)
	// The 5 wei were credited (the scan booked them) and are held below the threshold.
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "held", depAcct(testChain, "ETH"), custAcct("c1", testChain, "ETH"), big.NewInt(5), nil)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO sweep_holds (chain, address, asset, amount, value, cause) VALUES ($1,'0xADDR','ETH',5,5,'min_sweep')`, testChain); err != nil {
		t.Fatal(err)
	}
	requireClean(t, "a held deposit", mustReconcile(t, s))
	if strings.Contains(buf.String(), "ALERT") {
		t.Fatalf("ALERT: %s", buf.String())
	}
	m.add("0xADDR", "ETH", 1) // a real difference at the held address
	rep := mustReconcile(t, s)
	if rep.Clean || len(failedNames(rep)) != 1 || failedNames(rep)[0] != "deposit_addresses" {
		t.Fatalf("clean=%v %v", rep.Clean, failedNames(rep))
	}
}
