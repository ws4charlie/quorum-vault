package signjob

import (
	"encoding/hex"
	"testing"
)

var base = Intent{Kind: "withdrawal", ID: "w1", PartitionID: "qv-us/eth/ETH/hot/omnibus/0",
	Chain: "eth", Asset: "ETH", To: "0xabc", Amount: "100"}

func TestCanonicalStable(t *testing.T) {
	const want = "71762d696e74656e742d76310a" + // "qv-intent-v1\n"
		"0000000a" + "7769746864726177616c" + // withdrawal
		"00000002" + "7731" + // w1
		"0000001b" + "71762d75732f6574682f4554482f686f742f6f6d6e696275732f30" + // partition
		"00000003" + "657468" + // eth
		"00000003" + "455448" + // ETH
		"00000000" + // From (empty)
		"00000005" + "3078616263" + // 0xabc
		"00000003" + "313030" // 100
	if got := hex.EncodeToString(base.Canonical()); got != want {
		t.Errorf("Canonical = %s\nwant        %s", got, want)
	}
}

func TestHashPinned(t *testing.T) {
	const want = "4e3e53f425c1a47d25e998097099081455b814e00d7abe8699d1f3f8b8f271cc" // cross-checked with Python hashlib
	if got := hex.EncodeToString(func() []byte { h := base.Hash(); return h[:] }()); got != want {
		t.Errorf("Hash = %s", got)
	}
}

func TestFieldBoundaryMatters(t *testing.T) {
	a := base
	a.From, a.To = "ab", "c"
	b := base
	b.From, b.To = "a", "bc"
	if a.Hash() == b.Hash() {
		t.Error("moving a byte between From and To did not change the hash")
	}
	c, d := base, base
	c.Asset, c.From = "ETH", ""
	d.Asset, d.From = "ET", "H"
	if c.Hash() == d.Hash() {
		t.Error("moving a byte between Asset and From did not change the hash")
	}
}
