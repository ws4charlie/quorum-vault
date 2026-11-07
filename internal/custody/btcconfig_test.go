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
