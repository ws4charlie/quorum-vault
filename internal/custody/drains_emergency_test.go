package custody

import (
	"math/big"
	"testing"
)

func emergencyCfg() *Config {
	c := &Config{Native: "ETH", AssetList: []string{"ETH", "USDC", "WBTC"}, Assets: map[string]Asset{
		"ETH":  {Symbol: "ETH", PriceWei: big.NewInt(1)},
		"USDC": {Symbol: "USDC", PriceWei: big.NewInt(300_000_000_000)}, // worth 3e11 wei per base unit
		"WBTC": {Symbol: "WBTC", PriceWei: big.NewInt(1_000_000_000_000_000)},
	}}
	c.EVM.MaxTxFeeWei = big.NewInt(1000)
	return c
}

func bal(eth, usdc, wbtc int64) map[string]*big.Int {
	return map[string]*big.Int{"ETH": big.NewInt(eth), "USDC": big.NewInt(usdc), "WBTC": big.NewInt(wbtc)}
}

func TestPickDrainAssetPlannedKeepsTheListOrderAndNativeLast(t *testing.T) {
	c := emergencyCfg()
	a, n := (&Service{}).pickDrainAsset(c, bal(10_000_000_000_000_000, 5, 1), big.NewInt(10), false)
	if a != "USDC" || n.Int64() != 5 {
		t.Fatalf("planned drain picked %s %s", a, n)
	}
	a, n = (&Service{}).pickDrainAsset(c, bal(5000, 0, 0), big.NewInt(10), false)
	if a != "ETH" || n.Int64() != 4990 {
		t.Fatalf("native only: %s %s", a, n)
	}
	if a, _ = (&Service{}).pickDrainAsset(c, bal(10, 0, 0), big.NewInt(10), false); a != "" {
		t.Fatalf("dust: %s", a)
	}
}

func TestPickDrainAssetEmergencyMovesTheMostValueFirst(t *testing.T) {
	c := emergencyCfg()
	s := &Service{}
	// Native holds the most: it goes first, minus its own last gas and the gas of the two token transfers still to come (10 + 2*1000).
	a, n := s.pickDrainAsset(c, bal(9_000_000_000_000_000_000, 100, 1), big.NewInt(10), true)
	if a != "ETH" || n.String() != "8999999999999997990" {
		t.Fatalf("native largest: %s %s", a, n)
	}
	// A token is worth more: the largest token first (WBTC 1e15 per unit beats USDC 100 * 3e11).
	a, n = s.pickDrainAsset(c, bal(1_000_000, 100, 1), big.NewInt(10), true)
	if a != "WBTC" || n.Int64() != 1 {
		t.Fatalf("largest token: %s %s", a, n)
	}
	// Native would be largest but cannot pay for the transfers still to come: a token goes first.
	a, _ = s.pickDrainAsset(c, bal(1500, 0, 1), big.NewInt(10), true)
	if a != "WBTC" {
		t.Fatalf("no spare native: %s", a)
	}
	// Tokens gone: the native balance less the last transfer's gas.
	a, n = s.pickDrainAsset(c, bal(5000, 0, 0), big.NewInt(10), true)
	if a != "ETH" || n.Int64() != 4990 {
		t.Fatalf("native last: %s %s", a, n)
	}
	// Nothing above dust: drained.
	if a, _ = s.pickDrainAsset(c, bal(10, 0, 0), big.NewInt(10), true); a != "" {
		t.Fatalf("dust: %s", a)
	}
}
