package custody

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func rebalFile(mut func(*File)) File {
	cf := File{
		Chain: ChainFile{Name: testChain, ChainID: 1, Factory: "0x00000000000000000000000000000000000000f1",
			SweepDestination: "0x00000000000000000000000000000000000000a1",
			HotShards:        []string{"0x00000000000000000000000000000000000000a1", "0x00000000000000000000000000000000000000a2"},
			MaxTxFeeWei:      "1000000000000000000",
			Assets: map[string]AssetFile{
				"ETH":  {Decimals: 18, PriceWei: "1"},
				"USDT": {Address: "0x00000000000000000000000000000000000000c1", Decimals: 6, MinDeposit: "1000", PriceWei: "1000"},
			}},
		Withdrawal: WithdrawalFile{Tiers: map[string][]TierFile{"ETH": {{MinAmount: "0", Approvals: 1, Auto: true}}}},
		Cold: ColdFile{
			Addresses: map[string]string{"omnibus/native": "0x00000000000000000000000000000000000000d1", "omnibus/token": "0x00000000000000000000000000000000000000d1"},
			Limits:    map[string]LimitFile{"ETH": {Low: "100", High: "1000", Target: "500"}},
			Rebalance: RebalanceFile{Targets: map[string]string{"ETH": "300", "USDT": "5000"}},
		},
	}
	if mut != nil {
		mut(&cf)
	}
	return cf
}

func TestRebalanceConfig(t *testing.T) {
	c, err := rebalFile(nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RebalanceTargets[c.PartitionKey("ETH", 1).String()]; got == nil || got.Int64() != 300 {
		t.Fatalf("ETH shard 1 target = %v", got)
	}
	// A per-shard entry overrides the per-asset one.
	c, err = rebalFile(func(f *File) { f.Cold.Rebalance.Targets["ETH/1"] = "250" }).Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RebalanceTargets[c.PartitionKey("ETH", 1).String()]; got.Int64() != 250 {
		t.Fatalf("override = %v", got)
	}
	if got := c.RebalanceTargets[c.PartitionKey("ETH", 0).String()]; got.Int64() != 300 {
		t.Fatalf("shard 0 = %v", got)
	}
	// No targets: the feature is off.
	if c, err = rebalFile(func(f *File) { f.Cold.Rebalance = RebalanceFile{} }).Build(); err != nil || len(c.RebalanceTargets) != 0 {
		t.Fatalf("off: %v %v", err, c.RebalanceTargets)
	}
}

func TestRebalanceConfigRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(*File)
		want string
	}{
		"target above the cold target: a rebalance could push a shard over its high mark": {
			func(f *File) { f.Cold.Rebalance.Targets["ETH"] = "501" }, "must lie between"},
		"target below the low-water mark": {
			func(f *File) { f.Cold.Rebalance.Targets["ETH"] = "99" }, "must lie between"},
		"one shard only": {
			func(f *File) { f.Chain.HotShards = f.Chain.HotShards[:1] }, "at least two hot shards"},
		"unknown asset": {
			func(f *File) { f.Cold.Rebalance.Targets["DOGE"] = "1" }, "unknown asset"},
		"shard out of range": {
			func(f *File) { f.Cold.Rebalance.Targets["ETH/2"] = "300" }, "shard must be"},
		"a shard left without a target": {
			func(f *File) {
				f.Cold.Rebalance.Targets = map[string]string{"ETH/0": "300"}
			}, "no target for shard 1"},
		"not a number": {
			func(f *File) { f.Cold.Rebalance.Targets["ETH"] = "lots" }, "rebalance target"},
	} {
		_, err := rebalFile(tc.mut).Build()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}
}

// A cold address that already is a customer's deposit forwarder is refused at start, and a new deposit address that equals a cold
// address is not issued.
func TestColdAddressIsNotAForwarder(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if err := s.checkColdNotForwarder(ctx); err != nil {
		t.Fatalf("no cold address configured: %v", err)
	}
	cold := "0x00000000000000000000000000000000000000d1"
	c, err := rebalFile(nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	s.Cfg = c
	if err := s.checkColdNotForwarder(ctx); err != nil {
		t.Fatalf("no forwarder yet: %v", err)
	}
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", "CA"); err != nil {
		t.Fatal(err)
	}
	// The stored form may differ in case from the config's.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('c1',$1,upper($2),0,'forwarder')`, testChain, cold); err != nil {
		t.Fatal(err)
	}
	if err := s.checkColdNotForwarder(ctx); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "deposit forwarder") {
		t.Fatalf("err = %v", err)
	}
	if err := s.Bootstrap(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Bootstrap = %v", err)
	}
}
