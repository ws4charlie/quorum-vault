package btc

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
)

// The BIP84 test vector: account 0 of "abandon ... about" on mainnet. The zpub is converted to the xpub form (same key, other
// version bytes), which is what mpc-party's Node gives us.
const (
	bip84Zpub  = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
	bip84Addr0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	bip84Addr1 = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
)

func zpubToXpub(t *testing.T, z string) string {
	t.Helper()
	raw, ver, err := base58.CheckDecode(z)
	if err != nil {
		t.Fatal(err)
	}
	_ = ver
	// CheckDecode strips one version byte; the extended key has four, so rebuild from the full payload.
	full := append([]byte{ver}, raw...)
	copy(full[:4], []byte{0x04, 0x88, 0xb2, 0x1e})
	return base58.CheckEncode(full[1:], full[0])
}

func TestAddressesFromAnXpubMatchBIP84(t *testing.T) {
	v, err := Config{Chain: "btc", Network: "mainnet", AccountXpub: zpubToXpub(t, bip84Zpub)}.validated()
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{bip84Addr0, bip84Addr1} {
		got, err := v.addressAt(uint32(i))
		if err != nil || got != want {
			t.Fatalf("index %d: %q %v, want %q", i, got, err, want)
		}
	}
}

func TestAKeyOrAddressOfAnotherNetworkRefuses(t *testing.T) {
	xpub := zpubToXpub(t, bip84Zpub)
	for _, nw := range []string{"regtest", "testnet3", "signet"} {
		if err := (Config{Chain: "btc", Network: nw, AccountXpub: xpub}).Validate(); err == nil || !strings.Contains(err.Error(), "another network") {
			t.Fatalf("a mainnet xpub on %s: %v", nw, err)
		}
	}
	// A testnet key under network mainnet.
	tpub := XpubFromNodeForTest(t)
	if err := (Config{Chain: "btc", Network: "mainnet", AccountXpub: tpub}).Validate(); err == nil {
		t.Fatal("a regtest xpub on mainnet was accepted")
	}
	if err := (Config{Chain: "btc", Network: "regtest", AccountXpub: tpub}).Validate(); err != nil {
		t.Fatalf("a regtest xpub on regtest: %v", err)
	}
	// A hot address of the wrong network.
	err := Config{Chain: "btc", Network: "regtest", AccountXpub: tpub, HotAddresses: []string{bip84Addr0}}.Validate()
	if err == nil {
		t.Fatal("a mainnet address in a regtest config was accepted")
	}
	if err := (Config{Chain: "btc", Network: "nonsense", AccountXpub: tpub}).Validate(); err == nil {
		t.Fatal("unknown network accepted")
	}
	if err := (Config{Chain: "btc", Network: "regtest"}).Validate(); err == nil {
		t.Fatal("no xpub accepted")
	}
}

// XpubFromNodeForTest builds a regtest account xpub from the mainnet vector's key, as XpubFromNode does for mpc-party's answer.
func XpubFromNodeForTest(t *testing.T) string {
	t.Helper()
	main, err := Config{Chain: "btc", Network: "mainnet", AccountXpub: zpubToXpub(t, bip84Zpub)}.validated()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := main.account.ECPubKey()
	x, err := XpubFromNode("regtest", pub.SerializeCompressed(), main.account.ChainCode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestXpubFromNodeIsTheSameKeyOnRegtest(t *testing.T) {
	v, err := Config{Chain: "btc", Network: "regtest", AccountXpub: XpubFromNodeForTest(t)}.validated()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := v.addressAt(0)
	main, _ := Config{Chain: "btc", Network: "mainnet", AccountXpub: zpubToXpub(t, bip84Zpub)}.validated()
	pub, _ := main.branch.Derive(0)
	k, _ := pub.ECPubKey()
	want, _ := P2WPKH(k.SerializeCompressed(), &chaincfg.RegressionNetParams)
	if got != want || !strings.HasPrefix(got, "bcrt1") {
		t.Fatalf("%s want %s", got, want)
	}
}

func TestSats(t *testing.T) {
	for in, want := range map[string]string{"0.00000001": "1", "1.00000000": "100000000", "50": "5000000000", "0.1": "10000000", "21000000.00000000": "2100000000000000"} {
		got, err := Sats(in)
		if err != nil || got.String() != want {
			t.Fatalf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "1e-8", "-1", "0.000000001", "x"} {
		if _, err := Sats(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
