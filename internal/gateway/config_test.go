package gateway

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleConfigParses(t *testing.T) {
	cfg, err := LoadConfig("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Chains) == 0 || len(cfg.Approvers) == 0 {
		t.Fatal("example is empty")
	}
	b, _ := os.ReadFile("config.example.json")
	if !strings.Contains(string(b), "PLACEHOLDER") {
		t.Fatal("example must be marked as placeholders")
	}
}

func TestConfigRefusesBadFiles(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file accepted")
	}
	good, _ := os.ReadFile("config.example.json")
	var f map[string]any
	json.Unmarshal(good, &f)
	mutate := func(fn func(m map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal(good, &m)
		fn(m)
		b, _ := json.Marshal(m)
		return b
	}
	chain := func(m map[string]any) map[string]any {
		return m["chains"].(map[string]any)["evm-example"].(map[string]any) // the example also has a btc chain (TestExampleBTCChain)
	}
	cases := map[string][]byte{
		"not json":         []byte("{"),
		"empty":            []byte("{}"),
		"unknown field":    mutate(func(m map[string]any) { m["trust_the_database"] = true }),
		"bad approver key": mutate(func(m map[string]any) { m["approvers"].(map[string]any)["alice"].(map[string]any)["public_key"] = "zz" }),
		"no tiers": mutate(func(m map[string]any) {
			chain(m)["assets"].(map[string]any)["ETH"].(map[string]any)["tiers"] = []any{}
		}),
		"zero approvals in first tier": mutate(func(m map[string]any) {
			chain(m)["assets"].(map[string]any)["ETH"].(map[string]any)["tiers"] = []any{map[string]any{"min_amount": "0", "approvals": 0}}
		}),
		"more approvals than approvers": mutate(func(m map[string]any) {
			chain(m)["assets"].(map[string]any)["ETH"].(map[string]any)["tiers"] = []any{map[string]any{"min_amount": "0", "approvals": 9}}
		}),
		"missing asset policy": mutate(func(m map[string]any) { delete(chain(m)["assets"].(map[string]any), "ETH") }),
		"cap below per tx cap": mutate(func(m map[string]any) {
			chain(m)["assets"].(map[string]any)["ETH"].(map[string]any)["daily_cap"] = "1"
		}),
		"two actors share a key": mutate(func(m map[string]any) {
			a := m["approvers"].(map[string]any)
			a["bob"].(map[string]any)["public_key"] = a["alice"].(map[string]any)["public_key"]
		}),
		"bad sign_timeout":   mutate(func(m map[string]any) { m["sign_timeout"] = "-1s" }),
		"bad max_intent_age": mutate(func(m map[string]any) { m["max_intent_age"] = "soon" }),
		"no fee cap":         mutate(func(m map[string]any) { chain(m)["evm"].(map[string]any)["max_tx_fee_wei"] = "0" }),
	}
	sig2 := func(m map[string]any) map[string]any {
		return m["signers"].(map[string]any)["PLACEHOLDER-partition-2of3"].(map[string]any)
	}
	coords := func(m map[string]any) []any { return sig2(m)["coordinators"].([]any) }
	cases["2of3: unknown scheme"] = mutate(func(m map[string]any) { sig2(m)["scheme"] = "ecdsa-3of5" })
	cases["2of3: no keyset"] = mutate(func(m map[string]any) { delete(sig2(m), "keyset_id") })
	cases["2of3: no public key"] = mutate(func(m map[string]any) { delete(sig2(m), "public_key") })
	cases["2of3: no coordinators"] = mutate(func(m map[string]any) { sig2(m)["coordinators"] = []any{} })
	cases["2of3: with key_id"] = mutate(func(m map[string]any) { sig2(m)["key_id"] = "k" })
	cases["2of3: B first"] = mutate(func(m map[string]any) { c := coords(m); c[0], c[1] = c[1], c[0] })
	cases["2of3: twice A"] = mutate(func(m map[string]any) { coords(m)[1].(map[string]any)["name"] = "A" })
	cases["2of3: party C as coordinator"] = mutate(func(m map[string]any) { coords(m)[1].(map[string]any)["name"] = "C" })
	cases["2of3: no pin"] = mutate(func(m map[string]any) { delete(coords(m)[0].(map[string]any), "server_pin") })
	for name, b := range cases {
		if _, err := ParseConfig(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExample2of3Signer(t *testing.T) {
	cfg, err := LoadConfig("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	sf := cfg.Signers["PLACEHOLDER-partition-2of3"]
	if sf.Scheme != "ecdsa-2of3" || len(sf.Coordinators) != 2 || sf.Coordinators[0].Name != "A" || sf.Coordinators[1].Name != "B" {
		t.Fatalf("%+v", sf)
	}
}

func TestRequiredApprovals(t *testing.T) {
	h := newHarness(t)
	p := h.cfg.Chains[testChain].Assets["ETH"]
	for amount, want := range map[int64]int{0: 1, 999: 1, 1000: 2, 5000: 2} {
		if got := p.RequiredApprovals(big.NewInt(amount)); got != want {
			t.Errorf("amount %d: %d approvals, want %d", amount, got, want)
		}
	}
}

// The example's btc chain loads, and its checks are real: a key of another network, a hot shard off its path and a missing cap refuse.
func TestExampleBTCChain(t *testing.T) {
	cfg, err := LoadConfig("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.Chains["btc-example"]
	if cc == nil || cc.Family != FamilyBTC || cc.BTC.Network != "regtest" || len(cc.BTC.HotShards) != 2 || cc.Assets["BTC"].AnyDestination {
		t.Fatalf("%+v", cc)
	}
	good, _ := os.ReadFile("config.example.json")
	mutate := func(fn func(c map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal(good, &m)
		fn(m["chains"].(map[string]any)["btc-example"].(map[string]any)["btc"].(map[string]any))
		b, _ := json.Marshal(m)
		return b
	}
	for name, b := range map[string][]byte{
		"mainnet network, regtest key": mutate(func(c map[string]any) { c["network"] = "mainnet" }),
		"hot shard off its path": mutate(func(c map[string]any) {
			c["hot_shards"].(map[string]any)["qv-us/btc-example/BTC/hot/omnibus/0"].(map[string]any)["path"] = []any{1, 5}
		}),
		"no fee cap":   mutate(func(c map[string]any) { delete(c, "max_tx_fee_sats") }),
		"no input cap": mutate(func(c map[string]any) { delete(c, "max_inputs") }),
		"mainnet cold address": mutate(func(c map[string]any) {
			c["cold_addresses"] = map[string]any{"omnibus/native": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"}
		}),
	} {
		if _, err := ParseConfig(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Bitcoin keeps one hot shard per pool: two in one pool refuse to load, and the message names the pool. A shard in each of two pools loads.
func TestBTCConfigRefusesTwoHotShardsInOnePool(t *testing.T) {
	good, _ := os.ReadFile("config.example.json")
	build := func(second string) []byte {
		var m map[string]any
		json.Unmarshal(good, &m)
		shards := m["chains"].(map[string]any)["btc-example"].(map[string]any)["btc"].(map[string]any)["hot_shards"].(map[string]any)
		one := shards["qv-us/btc-example/BTC/hot/segregated:acme/0"]
		delete(shards, "qv-us/btc-example/BTC/hot/segregated:acme/0")
		shards[second] = one
		b, _ := json.Marshal(m)
		return b
	}
	if _, err := ParseConfig(build("qv-us/btc-example/BTC/hot/omnibus/1")); err == nil || !strings.Contains(err.Error(), `pool "omnibus" has two hot shards`) {
		t.Fatalf("two shards in the omnibus pool: %v", err)
	}
	if _, err := ParseConfig(build("qv-us/btc-example/BTC/hot/segregated:acme/0")); err != nil {
		t.Fatalf("one shard in each of two pools: %v", err)
	}
}

// consolidations_per_hour: the example sets it, a negative value refuses to load, and a Bitcoin chain that leaves it out refuses every consolidation (0).
func TestBTCConfigConsolidationsPerHour(t *testing.T) {
	good, _ := os.ReadFile("config.example.json")
	build := func(v any) []byte {
		var m map[string]any
		json.Unmarshal(good, &m)
		chainCfg := m["chains"].(map[string]any)["btc-example"].(map[string]any)
		if v == nil {
			delete(chainCfg, "consolidations_per_hour")
		} else {
			chainCfg["consolidations_per_hour"] = v
		}
		b, _ := json.Marshal(m)
		return b
	}
	cfg, err := ParseConfig(build(3))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Chains["btc-example"].ConsolidationsPerHour; got != 3 {
		t.Fatalf("consolidations_per_hour = %d", got)
	}
	cfg, err = ParseConfig(build(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Chains["btc-example"].ConsolidationsPerHour; got != 0 {
		t.Fatalf("left out: %d, want 0 (refuse them all)", got)
	}
	if _, err := ParseConfig(build(-1)); err == nil || !strings.Contains(err.Error(), "rate limits must be >= 0") {
		t.Fatalf("a negative limit: %v", err)
	}
}
