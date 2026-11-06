package custody

import (
	"context"
	"errors"
	"math/big"
	"strconv"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// A deposit that is final but not yet spendable (a coinbase output) is stored and credited once, by the scan that covers its
// release height; the hashes of the blocks read are stored with the cursor.
func TestDeferredDepositIsCreditedWhenTheScanCoversItsHeight(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('c1',$1,'0xADDR',0,'forwarder')`, testChain); err != nil {
		t.Fatal(err)
	}
	d := chain.ObservedDeposit{Chain: testChain, Asset: "ETH", Address: "0xADDR", Amount: big.NewInt(700), BlockHeight: 3, TxHash: "cb", DedupKey: testChain + ":cb:0"}
	res := chain.ScanResult{SafeHeadHeight: 5, Blocks: []chain.ScannedBlock{{Height: 5, Hash: "h5"}},
		Deferred: []chain.DeferredDeposit{{Deposit: d, ReleaseAt: 9}}}
	if n, err := s.ApplyScan(ctx, 0, res); err != nil || n != 0 {
		t.Fatalf("credited %d: %v", n, err)
	}
	expectPosted(t, s, custAcct("c1", testChain, "ETH"), 0)
	var h string
	if err := s.Pool.QueryRow(ctx, `SELECT hash FROM scanned_blocks WHERE chain=$1 AND height=5`, testChain).Scan(&h); err != nil || h != "h5" {
		t.Fatalf("block hash %q %v", h, err)
	}
	// A scan that stops short of the release height credits nothing; the one that covers it credits once.
	if n, err := s.ApplyScan(ctx, 6, chain.ScanResult{SafeHeadHeight: 8}); err != nil || n != 0 {
		t.Fatalf("credited %d before release: %v", n, err)
	}
	if n, err := s.ApplyScan(ctx, 9, chain.ScanResult{SafeHeadHeight: 9}); err != nil || n != 1 {
		t.Fatalf("credited %d at release: %v", n, err)
	}
	if n, err := s.ApplyScan(ctx, 10, chain.ScanResult{SafeHeadHeight: 12}); err != nil || n != 0 {
		t.Fatalf("credited %d again: %v", n, err)
	}
	expectPosted(t, s, custAcct("c1", testChain, "ETH"), 700)
	var left int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM deferred_deposits`).Scan(&left)
	if left != 0 {
		t.Fatalf("%d deferred rows left", left)
	}
	if err := ledger.CheckInvariants(ctx, s.Pool); err != nil {
		t.Fatal(err)
	}
}

type reorgChain struct {
	*fakeChain
	err error
}

func (r reorgChain) Scan(context.Context, uint64) (chain.ScanResult, error) { return chain.ScanResult{}, r.err }

// A reorganization deeper than the safe depth stops scanning, keeps every credit, and stays stopped until an operator deletes the row.
func TestDeepReorgHaltsScanningAndKeepsCredits(t *testing.T) {
	ctx := context.Background()
	s, fc := newSvc(t)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	s.Pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('c1',$1,'0xADDR',0,'forwarder')`, testChain)
	d := chain.ObservedDeposit{Chain: testChain, Asset: "ETH", Address: "0xADDR", Amount: big.NewInt(100), BlockHeight: 1, TxHash: "t", DedupKey: testChain + ":t:0"}
	if _, err := s.ApplyScan(ctx, 0, chain.ScanResult{SafeHeadHeight: 4, Deposits: []chain.ObservedDeposit{d}}); err != nil {
		t.Fatal(err)
	}
	s.Chain = reorgChain{fakeChain: fc, err: chain.ErrReorgTooDeep}
	if _, err := s.ScanOnce(ctx); !errors.Is(err, ErrScanHalted) {
		t.Fatalf("first pass: %v", err)
	}
	// Even a chain that answers again is not asked while halted.
	s.Chain = reorgChain{fakeChain: fc, err: errors.New("must not be called")}
	if _, err := s.ScanOnce(ctx); !errors.Is(err, ErrScanHalted) {
		t.Fatalf("second pass: %v", err)
	}
	expectPosted(t, s, custAcct("c1", testChain, "ETH"), 100)
	if cur, _ := s.Cursor(ctx); cur != 5 {
		t.Fatalf("cursor %d", cur)
	}
	// The operator clears the halt.
	s.Pool.Exec(ctx, `DELETE FROM scan_halts WHERE chain=$1`, testChain)
	if _, err := s.ScanOnce(ctx); errors.Is(err, ErrScanHalted) {
		t.Fatal("still halted after the row was deleted")
	}
}

type indexChain struct{ *fakeChain }

func (indexChain) DeriveDepositAddress(_ context.Context, c string, i uint64) (chain.DepositAddress, error) {
	return chain.DepositAddress{Chain: testChain, Address: "addr-" + strconv.Itoa(int(i)), Kind: chain.KindXpub, DerivationIndex: i}, nil
}

// Each customer gets the next derivation index of the chain, once.
func TestIndexedFamilyGivesEachCustomerItsOwnIndex(t *testing.T) {
	ctx := context.Background()
	s, fc := newSvc(t)
	s.Chain = indexChain{fc}
	s.Cfg.Family = FamilyBTC
	for _, c := range []string{"a", "b", "c"} {
		if _, _, err := s.CreateCustomer(ctx, "ops", c, ""); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]string{}
	for _, c := range []string{"a", "b", "a", "c"} {
		d, err := s.EnsureDepositAddress(ctx, "ops", c, testChain)
		if err != nil {
			t.Fatal(err)
		}
		if prev, ok := got[c]; ok && prev != d.Address {
			t.Fatalf("customer %s got %s then %s", c, prev, d.Address)
		}
		got[c] = d.Address
	}
	if got["a"] != "addr-0" || got["b"] != "addr-1" || got["c"] != "addr-2" {
		t.Fatalf("%v", got)
	}
}
