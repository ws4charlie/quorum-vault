package custody

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// evmModel is an EVM node for Reconcile: balances, receipts and a safe head that a test sets by hand.
type evmModel struct {
	mu        sync.Mutex
	head      uint64
	bal       map[string]*big.Int
	rc        map[string]Receipt
	onBalance func() // called before every balance read
	reads     int
	noBalance bool
}

func newModel() *evmModel {
	return &evmModel{head: 100, bal: map[string]*big.Int{}, rc: map[string]Receipt{}}
}

var tenETH = new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))

func key(addr, asset string) string { return strings.ToLower(addr) + "|" + asset }

func (m *evmModel) add(addr, asset string, d int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(addr, asset)
	if m.bal[k] == nil {
		m.bal[k] = new(big.Int)
	}
	m.bal[k].Add(m.bal[k], big.NewInt(d))
}

func (m *evmModel) SafeHead(context.Context) (uint64, error)        { return m.head, nil }
func (m *evmModel) TxBlock(context.Context, string) (uint64, error) { return m.head, nil }
func (m *evmModel) Balance(_ context.Context, addr, asset string, _ uint64) (*big.Int, error) {
	if m.noBalance {
		return nil, chain.ErrNotSupported
	}
	if m.onBalance != nil {
		m.onBalance()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if b := m.bal[key(addr, asset)]; b != nil {
		return new(big.Int).Set(b), nil
	}
	return new(big.Int), nil
}
func (m *evmModel) Receipt(_ context.Context, hash string) (Receipt, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rc[hash]
	return r, ok, nil
}

// The model only has a Reader's methods; a plain Reader (no Receipt) is fakeReader.
var _ ReceiptReader = (*evmModel)(nil)

// evmWorld is an EVM cell with 10 ETH on hot shard 0, in the books and on the model chain.
func evmWorld(t *testing.T) (*Service, *fakeChain, *evmModel) {
	t.Helper()
	s, fc := newSvc(t)
	m := newModel()
	s.Reader = m
	if err := s.FundHot(context.Background(), "seed", 0, tenETH); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.bal[key(s.Cfg.HotShards[0].Hex(), "ETH")] = new(big.Int).Set(tenETH)
	m.mu.Unlock()
	if _, err := s.Pool.Exec(context.Background(), `INSERT INTO chain_cursors (chain, next_height) VALUES ($1, 200)`, testChain); err != nil {
		t.Fatal(err)
	}
	return s, fc, m
}

func mustReconcile(t *testing.T, s *Service) Report {
	t.Helper()
	rep, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func requireClean(t *testing.T, stage string, rep Report) {
	t.Helper()
	if !rep.Clean || rep.SkippedChainChecks != 0 {
		t.Fatalf("%s: clean=%v skipped=%d failures=%+v", stage, rep.Clean, rep.SkippedChainChecks, rep.Failures())
	}
	for _, c := range rep.Checks {
		if c.Skipped {
			t.Fatalf("%s: %s was skipped", stage, c.Name)
		}
	}
}

func hasAdjusted(rep Report, name string) bool {
	for _, c := range rep.Checks {
		if c.Name == name && strings.Contains(c.Detail, "adjusted") {
			return true
		}
	}
	return false
}

// attempt records a transaction of ours at a fresh nonce of the shard, owned by (kind, id).
func attempt(t *testing.T, s *Service, addr, kind, id, hash, txKind string, nonce int) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Pool.Exec(ctx, `INSERT INTO evm_nonce_allocations (chain, address, nonce, owner_kind, owner_id, status) VALUES ($1,$2,$3,$4,$5,'broadcast') ON CONFLICT DO NOTHING`,
		testChain, addr, nonce, kind, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO evm_tx_attempts (tx_hash, chain, address, nonce, kind) VALUES ($1,$2,$3,$4,$5)`, hash, testChain, addr, nonce, txKind); err != nil {
		t.Fatal(err)
	}
}

// A sweep is explained at every stage, whatever it moved, and the explanation is the settlement's: after the real settlement the report is still clean.
func TestReconcileEVMSweepMinedAndUnsettled(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		expected int64
		moved    int64 // what the chain moved (the Swept events)
		reverted bool
	}{
		{"exact", 100, 100, false},
		{"more than expected", 100, 130, false},
		{"less than expected", 100, 60, false},
		{"nothing moved", 100, 0, false},
		{"reverted", 100, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fc, m := evmWorld(t)
			hot := s.Cfg.HotShards[0].Hex()
			credited := tc.expected
			if tc.moved > credited {
				credited = tc.moved // the extra deposit was credited after the sweep was planned
			}
			if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('c1',$1,'0xADDR',0,'forwarder')`, testChain); err != nil {
				t.Fatal(err)
			}
			if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
				return s.transfer(ctx, tx, "pre", depAcct(testChain, "ETH"), custAcct("c1", testChain, "ETH"), big.NewInt(credited), nil)
			}); err != nil {
				t.Fatal(err)
			}
			m.add("0xADDR", "ETH", credited)
			setupSweep(t, s, "sw1", "ETH", tc.expected)
			requireClean(t, "planned", mustReconcile(t, s))

			// Sent and booked at broadcast, not mined: the books are ahead of the chain.
			attempt(t, s, hot, "sweep", "sw1", "0xtx", "send", 0)
			if err := s.RecordSweepBroadcast(ctx, "sw1", "0xtx"); err != nil {
				t.Fatal(err)
			}
			rep := mustReconcile(t, s)
			requireClean(t, "in the mempool", rep)
			if !hasAdjusted(rep, "deposit_addresses") {
				t.Fatalf("the broadcast booking was not taken out for the comparison: %+v", rep.Checks)
			}

			// Mined and unsettled: the chain is ahead of the books.
			var movedAssets []chain.MovedAsset
			if !tc.reverted && tc.moved > 0 {
				movedAssets = []chain.MovedAsset{{Address: "0xADDR", Asset: "ETH", Amount: big.NewInt(tc.moved)}}
			}
			fc.moved = movedAssets
			m.rc["0xtx"] = Receipt{Block: 90, Success: !tc.reverted, Fee: big.NewInt(7)}
			m.add("0xADDR", "ETH", -tc.moved)
			m.add(hot, "ETH", tc.moved-7)
			rep = mustReconcile(t, s)
			requireClean(t, "mined, not settled", rep)
			if !hasAdjusted(rep, "hot") {
				t.Fatalf("no adjustment for the mined sweep: %+v", rep.Checks)
			}
			// 1 wei that nothing explains is still caught.
			m.add(hot, "ETH", 1)
			if rep := mustReconcile(t, s); rep.Clean || len(rep.Failures()) != 1 || rep.Failures()[0].Name != "hot" {
				t.Fatalf("1 wei behind our back: clean=%v %+v", rep.Clean, rep.Failures())
			}
			m.add(hot, "ETH", -1)

			// Settled by the real code: still clean, and nothing is left to explain.
			st := chain.TxConfirmed
			if tc.reverted {
				st = chain.TxFailed
			}
			if err := s.SettleSweep(ctx, "sw1", "0xtx", st); err != nil {
				t.Fatal(err)
			}
			rep = mustReconcile(t, s)
			requireClean(t, "settled", rep)
			if rep.InFlight != 0 {
				t.Fatalf("in flight %d", rep.InFlight)
			}
		})
	}
}

// A reverted move settled before its block is final: the books have its fee, the chain at the pinned height does not yet.
func TestReconcileEVMRevertSettledBeforeItIsFinal(t *testing.T) {
	ctx := context.Background()
	s, _, m := evmWorld(t)
	hot := s.Cfg.HotShards[0].Hex()
	if _, err := s.Pool.Exec(ctx, `INSERT INTO cold_moves (id, chain, asset, partition_id, to_address, amount, status) VALUES ('cm1',$1,'ETH',$2,'0xC0LD',5,'signing')`,
		testChain, s.Cfg.PartitionKey("ETH", 0).String()); err != nil {
		t.Fatal(err)
	}
	attempt(t, s, hot, OwnerKindToCold, "cm1", "0xmv", "send", 0)
	if err := s.RecordColdMoveBroadcast(ctx, "cm1", "0xmv"); err != nil {
		t.Fatal(err)
	}
	m.rc["0xmv"] = Receipt{Block: 105, Success: false, Fee: big.NewInt(7)} // reverted above the safe height (100)
	if err := s.SettleColdMove(ctx, "cm1", "0xmv", chain.TxFailed); err != nil {
		t.Fatal(err)
	}
	rep := mustReconcile(t, s)
	requireClean(t, "reverted above the safe height, settled", rep) // the fee is not on the chain at 100 yet
	if !hasAdjusted(rep, "hot") {
		t.Fatalf("the early fee was not taken out: %+v", rep.Checks)
	}
	// The safe height reaches the block: the chain has the fee, and the books too.
	m.head = 105
	m.add(hot, "ETH", -7)
	requireClean(t, "reverted at the safe height, settled", mustReconcile(t, s))
	// A fee the books do not have is a difference.
	m.add(hot, "ETH", -1)
	if rep := mustReconcile(t, s); rep.Clean {
		t.Fatal("1 wei of gas the books never booked was not caught")
	}
}

// The books changing during the read leads to a new read, not to a false ALERT.
func TestReconcileEVMReadsAgainWhenTheBooksChangeDuringTheRead(t *testing.T) {
	ctx := context.Background()
	s, _, m := evmWorld(t)
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	hot := s.Cfg.HotShards[0].Hex()
	n := 0
	m.onBalance = func() {
		if n == 0 { // the first read of the chain: the operator funds the hot wallet, in the books and on the chain, in the middle of it
			n++
			if err := s.FundHot(ctx, "mid-read", 0, big.NewInt(1000)); err != nil {
				t.Error(err)
			}
			m.add(hot, "ETH", 1000)
		}
	}
	rep := mustReconcile(t, s)
	requireClean(t, "after the books changed during the read", rep)
	if strings.Contains(logs.String(), "ALERT") {
		t.Fatalf("a false ALERT: %s", logs.String())
	}
	if n != 1 {
		t.Fatal("the books did not change during the read")
	}
}

// A comparison that cannot be made is counted and the report is not Clean: three reads that each straddle a change, a reader without receipts,
// and a chain cell that cannot read balances.
func TestReconcileEVMSkipsMakeTheReportNotClean(t *testing.T) {
	ctx := context.Background()
	t.Run("the books keep changing", func(t *testing.T) {
		s, _, m := evmWorld(t)
		i := 0
		m.onBalance = func() { i++; _ = s.FundHot(ctx, fmt.Sprintf("again-%d", i), 0, big.NewInt(1)) }
		rep := mustReconcile(t, s)
		if rep.Clean || rep.SkippedChainChecks != 1 || len(rep.Failures()) != 0 {
			t.Fatalf("clean=%v skipped=%d failures=%+v", rep.Clean, rep.SkippedChainChecks, rep.Failures())
		}
	})
	t.Run("a reader without receipts", func(t *testing.T) {
		s, _, _ := evmWorld(t)
		s.Reader = fakeReader{block: 100}
		rep := mustReconcile(t, s)
		if rep.Clean || rep.SkippedChainChecks != 1 {
			t.Fatalf("clean=%v skipped=%d", rep.Clean, rep.SkippedChainChecks)
		}
	})
	t.Run("a chain cell that cannot read balances", func(t *testing.T) {
		s, _, m := evmWorld(t)
		m.noBalance = true
		rep := mustReconcile(t, s)
		if rep.Clean || rep.SkippedChainChecks == 0 {
			t.Fatalf("clean=%v skipped=%d", rep.Clean, rep.SkippedChainChecks)
		}
	})
}
