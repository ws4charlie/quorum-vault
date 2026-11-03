package partition

import "testing"

func TestRoundTrip(t *testing.T) {
	for _, k := range []Key{
		{"qv-us", "eth", "ETH", TierHot, PoolOmnibus, 0},
		{"qv-us", "eth", "USDC", TierHot, "segregated:acme", 3},
		{"qv-us", "btc", "BTC", TierCold, PoolOmnibus, 0},
	} {
		got, err := Parse(k.String())
		if err != nil || got != k {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", k.String(), got, err, k)
		}
	}
}

func TestString(t *testing.T) {
	k := Key{"qv-us", "eth", "USDC", TierHot, "segregated:acme", 3}
	if want := "qv-us/eth/USDC/hot/segregated:acme/3"; k.String() != want {
		t.Errorf("String() = %q, want %q", k.String(), want)
	}
}

func TestParseRejects(t *testing.T) {
	for _, s := range []string{
		"", "a/b/c", "qv-us/eth/ETH/hot/omnibus", "qv-us/eth/ETH/hot/omnibus/x",
		"qv-us/eth/ETH/warm/omnibus/0", "qv-us/eth/ETH/hot/shared/0",
		"qv-us/eth/ETH/hot/segregated:/0", "qv-us/eth/ETH/hot/omnibus/-1", "/eth/ETH/hot/omnibus/0",
	} {
		if k, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) = %+v, want error", s, k)
		}
	}
}

func TestValidateRejectsSeparator(t *testing.T) {
	if err := (Key{"qv/us", "eth", "ETH", TierHot, PoolOmnibus, 0}).Validate(); err == nil {
		t.Error("want error for entity containing /")
	}
}
