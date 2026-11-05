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

// Rebalance: a move from one hot shard to another hot shard of the same pool and asset, from the signing zone's own list.

const (
	rbSrcETH   = "qv-us/evm-test/ETH/hot/omnibus/0"
	rbSibETH   = "qv-us/evm-test/ETH/hot/omnibus/1"
	rbSrcUSDT  = "qv-us/evm-test/USDT/hot/omnibus/0"
	rbSibUSDT  = "qv-us/evm-test/USDT/hot/omnibus/1"
	rbOtherPl  = "qv-us/evm-test/ETH/hot/segregated:acme/0"
	rbOtherAst = "qv-us/evm-test/USDT/hot/omnibus/2" // same pool, other asset class of the shard list: not a sibling of the ETH shard
)

var (
	tSib       = common.HexToAddress("0x0000000000000000000000000000000000005a01")
	tOtherPool = common.HexToAddress("0x0000000000000000000000000000000000005a03")
	tOtherAst  = common.HexToAddress("0x0000000000000000000000000000000000005a04")
)

func rebalCfg() Config {
	c := testCfg()
	c.HotAddresses = map[string]common.Address{rbSrcETH: tHot, rbSibETH: tSib, rbSrcUSDT: tHot, rbSibUSDT: tSib, rbOtherPl: tOtherPool, rbOtherAst: tOtherAst}
	return c
}

func rebalVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(rebalCfg())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func rebalIntent(part, asset, to, amount string) signjob.Intent {
	return signjob.Intent{Kind: "rebalance", ID: "rb1", PartitionID: part, Chain: "evm-test", Asset: asset, To: to, Amount: amount}
}

func TestRebalanceAcceptsNativeAndTokenToASiblingShard(t *testing.T) {
	v := rebalVerifier(t)
	if err := v.Verify(toCold(t, rbSrcETH, tSib, big.NewInt(900), nil), rebalIntent(rbSrcETH, "ETH", tSib.Hex(), "900")); err != nil {
		t.Fatalf("native rebalance refused: %v", err)
	}
	data, _ := packTransfer(tSib, big.NewInt(5_000_000))
	if err := v.Verify(toCold(t, rbSrcUSDT, tToken, new(big.Int), data), rebalIntent(rbSrcUSDT, "USDT", tSib.Hex(), "5000000")); err != nil {
		t.Fatalf("token rebalance refused: %v", err)
	}
}

func TestRebalanceRefusals(t *testing.T) {
	v := rebalVerifier(t)
	other := common.HexToAddress("0x00000000000000000000000000000000000bAd01")
	tokData := func(to common.Address, n int64) []byte { d, _ := packTransfer(to, big.NewInt(n)); return d }
	cases := []struct {
		name string
		u    chain.UnsignedTx
		i    signjob.Intent
		want string
	}{
		{"destination outside the pinned shards, intent and transaction agree", toCold(t, rbSrcETH, other, big.NewInt(900), nil),
			rebalIntent(rbSrcETH, "ETH", other.Hex(), "900"), "not the hot address of another shard"},
		{"the cold address is not a shard", toCold(t, rbSrcETH, tCold, big.NewInt(900), nil),
			rebalIntent(rbSrcETH, "ETH", tCold.Hex(), "900"), "not the hot address of another shard"},
		{"the sweep destination is not a shard", toCold(t, rbSrcETH, tUser, big.NewInt(900), nil),
			rebalIntent(rbSrcETH, "ETH", tUser.Hex(), "900"), "not the hot address of another shard"},
		{"a shard of another pool", toCold(t, rbSrcETH, tOtherPool, big.NewInt(900), nil),
			rebalIntent(rbSrcETH, "ETH", tOtherPool.Hex(), "900"), "not the hot address of another shard"},
		{"a shard of another asset", toCold(t, rbSrcETH, tOtherAst, big.NewInt(900), nil),
			rebalIntent(rbSrcETH, "ETH", tOtherAst.Hex(), "900"), "not the hot address of another shard"},
		{"the source itself", toCold(t, rbSrcETH, tHot, big.NewInt(900), nil),
			rebalIntent(rbSrcETH, "ETH", tHot.Hex(), "900"), "is the source"},
		{"intent names a shard, transaction pays someone else", toCold(t, rbSrcETH, other, big.NewInt(900), nil),
			rebalIntent(rbSrcETH, "ETH", tSib.Hex(), "900"), "rebalance transfer is to"},
		{"native value differs from the amount", toCold(t, rbSrcETH, tSib, big.NewInt(901), nil),
			rebalIntent(rbSrcETH, "ETH", tSib.Hex(), "900"), "rebalance transfer is to"},
		{"native transfer carries data", toCold(t, rbSrcETH, tSib, big.NewInt(900), []byte{1}),
			rebalIntent(rbSrcETH, "ETH", tSib.Hex(), "900"), "rebalance transfer is to"},
		{"token transfer to someone else, intent names a shard", toCold(t, rbSrcUSDT, tToken, new(big.Int), tokData(other, 5)),
			rebalIntent(rbSrcUSDT, "USDT", tSib.Hex(), "5"), "calldata is not transfer"},
		{"token call to another contract", toCold(t, rbSrcUSDT, other, new(big.Int), tokData(tSib, 5)),
			rebalIntent(rbSrcUSDT, "USDT", tSib.Hex(), "5"), "is not the USDT token"},
		{"token transfer carries value", toCold(t, rbSrcUSDT, tToken, big.NewInt(1), tokData(tSib, 5)),
			rebalIntent(rbSrcUSDT, "USDT", tSib.Hex(), "5"), "carries value"},
		{"zero amount", toCold(t, rbSrcETH, tSib, new(big.Int), nil), rebalIntent(rbSrcETH, "ETH", tSib.Hex(), "0"), "zero amount"},
		{"intent has a source address", toCold(t, rbSrcETH, tSib, big.NewInt(900), nil),
			func() signjob.Intent {
				i := rebalIntent(rbSrcETH, "ETH", tSib.Hex(), "900")
				i.From = tUser.Hex()
				return i
			}(), "source address"},
		{"partition that is not well formed", toCold(t, "p-hot", tSib, big.NewInt(900), nil),
			rebalIntent("p-hot", "ETH", tSib.Hex(), "900"), "no hot address configured"},
	}
	for _, c := range cases {
		err := v.Verify(c.u, c.i)
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want a rejection containing %q", c.name, err, c.want)
		}
	}
}

// A single-shard pool has nowhere to rebalance to.
func TestRebalanceNeedsASecondShard(t *testing.T) {
	c := testCfg()
	c.HotAddresses = map[string]common.Address{rbSrcETH: tHot}
	v, err := NewVerifier(c)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(toCold(t, rbSrcETH, tSib, big.NewInt(900), nil), rebalIntent(rbSrcETH, "ETH", tSib.Hex(), "900"))
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not the hot address of another shard") {
		t.Fatalf("err = %v", err)
	}
}
