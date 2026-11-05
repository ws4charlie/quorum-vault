package evm

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

const (
	partETH  = "qv-us/evm-test/ETH/hot/omnibus/0"
	partUSDT = "qv-us/evm-test/USDT/hot/omnibus/0"
)

var tCold = common.HexToAddress("0x00000000000000000000000000000000000c01d0")

func coldCfg() Config {
	c := testCfg()
	c.HotAddresses = map[string]common.Address{partETH: tHot, partUSDT: tHot}
	c.ColdAddresses = map[string]common.Address{"omnibus/native": tCold, "omnibus/token": tCold}
	return c
}

func coldVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(coldCfg())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func toCold(t *testing.T, part string, to common.Address, value *big.Int, data []byte) chain.UnsignedTx {
	u := mkUnsigned(t, to, value, data, nil)
	u.KeyRef.PartitionID = part
	return u
}

func toColdIntent(part, asset, to, amount string) signjob.Intent {
	return signjob.Intent{Kind: "to-cold", ID: "m1", PartitionID: part, Chain: "evm-test", Asset: asset, To: to, Amount: amount}
}

func TestToColdAcceptsNativeAndTokenToTheConfiguredColdAddress(t *testing.T) {
	v := coldVerifier(t)
	if err := v.Verify(toCold(t, partETH, tCold, big.NewInt(900), nil), toColdIntent(partETH, "ETH", tCold.Hex(), "900")); err != nil {
		t.Fatalf("native to-cold refused: %v", err)
	}
	data, _ := packTransfer(tCold, big.NewInt(5_000_000))
	if err := v.Verify(toCold(t, partUSDT, tToken, new(big.Int), data), toColdIntent(partUSDT, "USDT", tCold.Hex(), "5000000")); err != nil {
		t.Fatalf("token to-cold refused: %v", err)
	}
}

func TestToColdRefusals(t *testing.T) {
	v := coldVerifier(t)
	other := common.HexToAddress("0x00000000000000000000000000000000000bAd01")
	tokData := func(to common.Address, n int64) []byte { d, _ := packTransfer(to, big.NewInt(n)); return d }
	cases := []struct {
		name string
		u    chain.UnsignedTx
		i    signjob.Intent
		want string
	}{
		{"intent names another destination, transaction matches it", toCold(t, partETH, other, big.NewInt(900), nil),
			toColdIntent(partETH, "ETH", other.Hex(), "900"), "not the configured cold address"},
		{"intent names the cold address, transaction pays someone else", toCold(t, partETH, other, big.NewInt(900), nil),
			toColdIntent(partETH, "ETH", tCold.Hex(), "900"), "to-cold transfer is to"},
		{"native value differs from the amount", toCold(t, partETH, tCold, big.NewInt(901), nil),
			toColdIntent(partETH, "ETH", tCold.Hex(), "900"), "to-cold transfer is to"},
		{"native transfer carries data", toCold(t, partETH, tCold, big.NewInt(900), []byte{1}),
			toColdIntent(partETH, "ETH", tCold.Hex(), "900"), "to-cold transfer is to"},
		{"token transfer to someone else, intent names cold", toCold(t, partUSDT, tToken, new(big.Int), tokData(other, 5)),
			toColdIntent(partUSDT, "USDT", tCold.Hex(), "5"), "calldata is not transfer"},
		{"token call to another contract", toCold(t, partUSDT, other, new(big.Int), tokData(tCold, 5)),
			toColdIntent(partUSDT, "USDT", tCold.Hex(), "5"), "is not the USDT token"},
		{"token transfer carries value", toCold(t, partUSDT, tToken, big.NewInt(1), tokData(tCold, 5)),
			toColdIntent(partUSDT, "USDT", tCold.Hex(), "5"), "carries value"},
		{"zero amount", toCold(t, partETH, tCold, new(big.Int), nil), toColdIntent(partETH, "ETH", tCold.Hex(), "0"), "zero amount"},
		{"intent has a source address", toCold(t, partETH, tCold, big.NewInt(900), nil),
			func() signjob.Intent {
				i := toColdIntent(partETH, "ETH", tCold.Hex(), "900")
				i.From = tUser.Hex()
				return i
			}(), "source address"},
		{"partition outside any configured pool", toCold(t, "p-hot", tCold, big.NewInt(900), nil),
			toColdIntent("p-hot", "ETH", tCold.Hex(), "900"), "no hot address configured"},
	}
	for _, c := range cases {
		err := v.Verify(c.u, c.i)
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want a rejection containing %q", c.name, err, c.want)
		}
	}
}

func TestToColdNeedsAColdAddressInConfig(t *testing.T) {
	c := coldCfg()
	c.ColdAddresses = nil
	v, err := NewVerifier(c)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(toCold(t, partETH, tCold, big.NewInt(900), nil), toColdIntent(partETH, "ETH", tCold.Hex(), "900"))
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "no cold address configured") {
		t.Fatalf("err = %v", err)
	}
}

func TestColdAddressConfigIsValidated(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"hot address as cold":  func(c *Config) { c.ColdAddresses["omnibus/native"] = tHot },
		"zero cold address":    func(c *Config) { c.ColdAddresses["omnibus/native"] = common.Address{} },
		"factory as cold":      func(c *Config) { c.ColdAddresses["omnibus/native"] = tFactory },
		"key without a class":  func(c *Config) { c.ColdAddresses["omnibus"] = tCold },
		"key with a bad class": func(c *Config) { c.ColdAddresses["omnibus/nft"] = tCold },
	} {
		c := coldCfg()
		mut(&c)
		if _, err := NewVerifier(c); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}
