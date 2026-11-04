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
		for _, c := range m["chains"].(map[string]any) {
			return c.(map[string]any)
		}
		return nil
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
		"no fee cap": mutate(func(m map[string]any) { chain(m)["evm"].(map[string]any)["max_tx_fee_wei"] = "0" }),
	}
	for name, b := range cases {
		if _, err := ParseConfig(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
