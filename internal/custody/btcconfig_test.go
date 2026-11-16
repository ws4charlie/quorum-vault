package custody

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

func xpubFor(t *testing.T, p *chaincfg.Params) string {
	t.Helper()
	m, err := hdkeychain.NewMaster(make([]byte, 32), p)
	if err != nil {
		t.Fatal(err)
	}
	k, err := m.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	return k.String()
}

func btcFile(network, xpub string) File {
	return File{Chain: ChainFile{Family: "btc", Name: "btc-reg", BTC: &BTCFile{Network: network, RPCURL: "http://127.0.0.1:18443", AccountXpub: xpub},
		Assets: map[string]AssetFile{"BTC": {Decimals: 8, MinDeposit: "1000"}}}}
}

func TestBTCConfig(t *testing.T) {
	c, err := btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if c.Family != FamilyBTC || c.Native != "BTC" || c.AssetList[0] != "BTC" || c.BTC.Confirmations != 6 && c.BTC.Confirmations != 0 {
		t.Fatalf("%+v", c)
	}
	// A key of another network refuses to start.
	if _, err := btcFile("regtest", xpubFor(t, &chaincfg.MainNetParams)).Build(); err == nil || !strings.Contains(err.Error(), "another network") {
		t.Fatalf("mainnet key on regtest: %v", err)
	}
	if _, err := btcFile("mainnet", xpubFor(t, &chaincfg.RegressionNetParams)).Build(); err == nil {
		t.Fatal("regtest key on mainnet accepted")
	}
	f := btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams))
	f.Chain.BTC.HotAddresses = []string{"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"}
	if _, err := f.Build(); err == nil {
		t.Fatal("a mainnet hot address in a regtest config accepted")
	}
	f = btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams))
	f.Chain.BTC = nil
	if _, err := f.Build(); err == nil {
		t.Fatal("no btc section accepted")
	}
	f = btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams))
	f.Chain.Assets["ETH"] = AssetFile{Decimals: 18}
	if _, err := f.Build(); err == nil {
		t.Fatal("a second asset accepted")
	}
}

// Bitcoin keeps one hot shard per pool, and the core serves the omnibus pool only: a second hot shard refuses to start, naming the pool.
func TestBTCConfigRefusesTwoHotShardsInOnePool(t *testing.T) {
	xpub := xpubFor(t, &chaincfg.RegressionNetParams)
	one, _ := btc.DeriveHotAddress("regtest", xpub, 0)
	two, _ := btc.DeriveHotAddress("regtest", xpub, 1)
	f := btcFile("regtest", xpub)
	f.Chain.BTC.HotShards = []BTCShardFile{{Address: one, Path: []uint32{1, 0}}}
	if _, err := f.Build(); err != nil {
		t.Fatalf("one hot shard: %v", err)
	}
	f.Chain.BTC.HotShards = append(f.Chain.BTC.HotShards, BTCShardFile{Address: two, Path: []uint32{1, 1}})
	if _, err := f.Build(); err == nil || !strings.Contains(err.Error(), `pool "omnibus" has two hot shards`) {
		t.Fatalf("two hot shards in the omnibus pool: %v", err)
	}
}

// Consolidation: consolidate_above 0 turns it off; when on, it must exceed max_inputs, and consolidate_max_fee_rate must be positive and not above
// sweep_max_fee_rate. Each bad value refuses to start and names the setting.
func TestBTCConfigConsolidation(t *testing.T) {
	xpub := xpubFor(t, &chaincfg.RegressionNetParams)
	build := func(change func(b *BTCFile)) error {
		f := btcFile("regtest", xpub)
		f.Chain.BTC.MaxInputs, f.Chain.BTC.MaxFeeRate, f.Chain.BTC.SweepMaxFeeRate = 20, 100, 50
		change(f.Chain.BTC)
		_, err := f.Build()
		return err
	}
	if err := build(func(b *BTCFile) {}); err != nil {
		t.Fatalf("off by default: %v", err)
	}
	if err := build(func(b *BTCFile) { b.ConsolidateAbove, b.ConsolidateMaxFeeRate = 0, 0 }); err != nil {
		t.Fatalf("off: %v", err)
	}
	if err := build(func(b *BTCFile) { b.ConsolidateAbove, b.ConsolidateMaxFeeRate = 21, 50 }); err != nil {
		t.Fatalf("on: %v", err)
	}
	for name, tc := range map[string]struct {
		change func(b *BTCFile)
		want   string
	}{
		"at max_inputs":           {func(b *BTCFile) { b.ConsolidateAbove, b.ConsolidateMaxFeeRate = 20, 10 }, "consolidate_above (20) must exceed max_inputs (20)"},
		"below max_inputs":        {func(b *BTCFile) { b.ConsolidateAbove, b.ConsolidateMaxFeeRate = 5, 10 }, "must exceed max_inputs"},
		"negative":                {func(b *BTCFile) { b.ConsolidateAbove, b.ConsolidateMaxFeeRate = -1, 10 }, "must not be negative"},
		"no fee rate":             {func(b *BTCFile) { b.ConsolidateAbove = 30 }, "consolidate_max_fee_rate is required"},
		"above sweep ceiling":     {func(b *BTCFile) { b.ConsolidateAbove, b.ConsolidateMaxFeeRate = 30, 51 }, "above sweep_max_fee_rate"},
		"default max_inputs 20":   {func(b *BTCFile) { b.MaxInputs, b.ConsolidateAbove, b.ConsolidateMaxFeeRate = 0, 20, 10 }, "must exceed max_inputs"},
		"ceiling defaults to max": {func(b *BTCFile) { b.SweepMaxFeeRate, b.ConsolidateAbove, b.ConsolidateMaxFeeRate = 0, 30, 101 }, "above sweep_max_fee_rate"},
	} {
		if err := build(tc.change); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error saying %q", name, err, tc.want)
		}
	}
}

// Batching is off unless a config turns it on; its settings default, are read per shard, and the fee caps must reach the rate ceiling for the largest batch.
func TestBTCConfigBatching(t *testing.T) {
	xpub := xpubFor(t, &chaincfg.RegressionNetParams)
	one, _ := btc.DeriveHotAddress("regtest", xpub, 0)
	build := func(b *BatchingFile, shard *BatchingFile, change func(*BTCFile)) (*Config, error) {
		f := btcFile("regtest", xpub)
		f.Chain.BTC.HotShards = []BTCShardFile{{Address: one, Path: []uint32{1, 0}, Batching: shard}}
		f.Chain.BTC.Batching = b
		f.Chain.BTC.MaxTxFeeSats = 300_000 // the default 150,000 cannot reach 100 sat/vB for 20 inputs and 20 payments: that is refused below
		if change != nil {
			change(f.Chain.BTC)
		}
		return f.Build()
	}
	c, err := build(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := c.PartitionKey("BTC", 0).String()
	if c.BatchingOf(p).Enabled || c.BatchingOf(p).Active() {
		t.Fatal("batching is on without being asked")
	}
	c, err = build(&BatchingFile{Enabled: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := c.BatchingOf(p); !b.Active() || b.MaxOutputs != 20 || b.MaxWait.Minutes() != 10 || b.MaxInFlight != 1 {
		t.Fatalf("defaults: %+v", b)
	}
	// max_wait 0 is one withdrawal per transaction: on, but not active.
	c, err = build(&BatchingFile{Enabled: true, MaxWait: "0s"}, nil, nil)
	if err != nil || c.BatchingOf(p).Active() {
		t.Fatalf("max_wait 0: %v %+v", err, c.BatchingOf(p))
	}
	// A shard overrides the section.
	c, err = build(&BatchingFile{Enabled: true, MaxOutputs: 5}, &BatchingFile{Enabled: false}, nil)
	if err != nil || c.BatchingOf(p).Enabled {
		t.Fatalf("override: %v %+v", err, c.BatchingOf(p))
	}
	if _, err := build(&BatchingFile{Enabled: true, MaxWait: "soon"}, nil, nil); err == nil {
		t.Fatal("a max_wait that is not a duration was accepted")
	}
	if _, err := build(&BatchingFile{Enabled: true, MaxOutputs: -1}, nil, nil); err == nil {
		t.Fatal("max_outputs -1 was accepted")
	}
	// 50 payments and 20 inputs at 100 sat/vB need 355,200 sats of fee cap: 300,000 is refused at start-up, naming the size.
	_, err = build(&BatchingFile{Enabled: true, MaxOutputs: 50}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "50 payment output(s)") {
		t.Fatalf("a fee cap that cannot reach the rate ceiling for a full batch: %v", err)
	}
	if _, err := build(&BatchingFile{Enabled: true, MaxOutputs: 50}, nil, func(b *BTCFile) { b.MaxTxFeeSats = 400_000 }); err != nil {
		t.Fatal(err)
	}
}
