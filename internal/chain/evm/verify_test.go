package evm

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

var (
	tFactory = common.HexToAddress("0x00000000000000000000000000000000000fAc70")
	tDest    = common.HexToAddress("0x000000000000000000000000000000000000De57")
	tHot     = common.HexToAddress("0x0000000000000000000000000000000000000407")
	tToken   = common.HexToAddress("0x00000000000000000000000000000000000070C3")
	tUser    = common.HexToAddress("0x00000000000000000000000000000000000c0DE5")
)

func testCfg() Config {
	return Config{
		Chain: "evm-test", ChainID: 31337, Confirmations: 2,
		Factory: tFactory, SweepDestination: tDest,
		HotAddresses: map[string]common.Address{"p-hot": tHot},
		Assets:       map[string]Token{"USDT": {Address: tToken, Decimals: 6}},
		MaxTxFeeWei:  big.NewInt(300_000_000_000_000), // = 100000 gas x 3 gwei, the fee of mkUnsigned
	}
}

func mustVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(testCfg())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mkUnsigned(t *testing.T, to common.Address, value *big.Int, data []byte, mut func(*Payload)) chain.UnsignedTx {
	return mkUnsignedFee(t, to, value, data, 100000, big.NewInt(1e9), big.NewInt(3e9), mut)
}

func mkUnsignedFee(t *testing.T, to common.Address, value *big.Int, data []byte, gas uint64, tip, feeCap *big.Int, mut func(*Payload)) chain.UnsignedTx {
	t.Helper()
	p := eth.TxParams{
		ChainID: big.NewInt(31337), Nonce: 7, To: to, Value: value, Data: data,
		Gas: gas, GasTipCap: tip, GasFeeCap: feeCap,
	}
	_, d, err := eth.BuildTx(p)
	if err != nil {
		t.Fatal(err)
	}
	pl := newPayload(31337, tHot, p)
	if mut != nil {
		mut(&pl)
	}
	b, err := pl.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return chain.UnsignedTx{Chain: "evm-test", Digest: d[:], Payload: b, KeyRef: chain.KeyRef{PartitionID: "p-hot"}}
}

func nativeWithdrawal(t *testing.T) (chain.UnsignedTx, signjob.Intent) {
	u := mkUnsigned(t, tUser, big.NewInt(1500), nil, nil)
	return u, signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: "p-hot", Chain: "evm-test", Asset: "ETH", To: tUser.Hex(), Amount: "1500"}
}

func tokenWithdrawal(t *testing.T) (chain.UnsignedTx, signjob.Intent) {
	data, err := packTransfer(tUser, big.NewInt(2_000_000))
	if err != nil {
		t.Fatal(err)
	}
	u := mkUnsigned(t, tToken, new(big.Int), data, nil)
	return u, signjob.Intent{Kind: "withdrawal", ID: "w2", PartitionID: "p-hot", Chain: "evm-test", Asset: "USDT", To: tUser.Hex(), Amount: "2000000"}
}

func sweep(t *testing.T, tokens []common.Address, asset string) (chain.UnsignedTx, signjob.Intent) {
	salt := DeriveSalt("cust-1", 3)
	data, err := packDeployAndFlush(salt, tokens)
	if err != nil {
		t.Fatal(err)
	}
	u := mkUnsigned(t, tFactory, new(big.Int), data, nil)
	from := PredictAddress(tFactory, tDest, salt)
	return u, signjob.Intent{Kind: "sweep", ID: "s1", PartitionID: "p-hot", Chain: "evm-test", Asset: asset, From: from.Hex(), To: tDest.Hex(), Amount: "5"}
}

func TestVerifyAccepts(t *testing.T) {
	v := mustVerifier(t)
	for name, mk := range map[string]func() (chain.UnsignedTx, signjob.Intent){
		"native":      func() (chain.UnsignedTx, signjob.Intent) { return nativeWithdrawal(t) },
		"token":       func() (chain.UnsignedTx, signjob.Intent) { return tokenWithdrawal(t) },
		"sweep-eth":   func() (chain.UnsignedTx, signjob.Intent) { return sweep(t, nil, "ETH") },
		"sweep-token": func() (chain.UnsignedTx, signjob.Intent) { return sweep(t, []common.Address{tToken}, "USDT") },
	} {
		u, i := mk()
		if err := v.Verify(u, i); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every rejection path has a tampered payload (or intent) below.
func TestVerifyRejects(t *testing.T) {
	v := mustVerifier(t)
	other := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	otherTokData, _ := packTransfer(other, big.NewInt(2_000_000))
	moreData, _ := packTransfer(tUser, big.NewInt(2_000_001))

	type tc struct {
		name string
		mk   func() (chain.UnsignedTx, signjob.Intent)
	}
	withdrawNative := func(f func(*chain.UnsignedTx, *signjob.Intent)) func() (chain.UnsignedTx, signjob.Intent) {
		return func() (chain.UnsignedTx, signjob.Intent) { u, i := nativeWithdrawal(t); f(&u, &i); return u, i }
	}
	withdrawToken := func(f func(*chain.UnsignedTx, *signjob.Intent)) func() (chain.UnsignedTx, signjob.Intent) {
		return func() (chain.UnsignedTx, signjob.Intent) { u, i := tokenWithdrawal(t); f(&u, &i); return u, i }
	}
	sweepEth := func(f func(*chain.UnsignedTx, *signjob.Intent)) func() (chain.UnsignedTx, signjob.Intent) {
		return func() (chain.UnsignedTx, signjob.Intent) { u, i := sweep(t, nil, "ETH"); f(&u, &i); return u, i }
	}
	// replaced swaps in a new transaction (consistent digest) so only the
	// content check can catch it.
	replaced := func(to common.Address, value *big.Int, data []byte) chain.UnsignedTx {
		return mkUnsigned(t, to, value, data, nil)
	}
	noop := func(*chain.UnsignedTx, *signjob.Intent) {}
	_ = noop

	cases := []tc{
		{"wrong unsigned chain", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) { u.Chain = "other" })},
		{"wrong intent chain", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Chain = "other" })},
		{"payload not json", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) { u.Payload = []byte("nope") })},
		{"payload unknown field", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), "{", `{"extra":1,`, 1))
		})},
		{"payload trailing data", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) { u.Payload = append(u.Payload, []byte(` {}`)...) })},
		{"payload chain id", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), `"chain_id":31337`, `"chain_id":1`, 1))
		})},
		{"payload bad address", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), `"to":"`, `"to":"zz`, 1))
		})},
		{"payload value tampered (digest stale)", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), `"value":"1500"`, `"value":"9999"`, 1))
		})},
		{"payload to tampered (digest stale)", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), tUser.Hex(), other.Hex(), 1))
		})},
		{"payload nonce tampered (digest stale)", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), `"nonce":7`, `"nonce":8`, 1))
		})},
		{"digest flipped", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) { u.Digest[0] ^= 1 })},
		{"digest short", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) { u.Digest = u.Digest[:31] })},
		{"fee tip above cap", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), `"max_priority_fee_per_gas":"1000000000"`, `"max_priority_fee_per_gas":"9000000000"`, 1))
		})},
		{"key partition differs", withdrawNative(func(u *chain.UnsignedTx, _ *signjob.Intent) { u.KeyRef.PartitionID = "p-other" })},
		{"unknown partition", withdrawNative(func(u *chain.UnsignedTx, i *signjob.Intent) { u.KeyRef.PartitionID, i.PartitionID = "nope", "nope" })},
		{"sender is not the hot address", func() (chain.UnsignedTx, signjob.Intent) {
			u, i := nativeWithdrawal(t)
			u = mkUnsigned(t, tUser, big.NewInt(1500), nil, func(p *Payload) { p.From = other.Hex() })
			return u, i
		}},
		{"amount leading zero", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "01500" })},
		{"amount plus sign", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "+1500" })},
		{"amount minus sign", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "-1500" })},
		{"amount whitespace", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = " 1500" })},
		{"amount trailing space", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "1500 " })},
		{"amount decimal point", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "1500.0" })},
		{"amount exponent", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "1e3" })},
		{"amount empty", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "" })},
		{"amount over 256 bits", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "1" + strings.Repeat("0", 77) })},
		{"amount zero", func() (chain.UnsignedTx, signjob.Intent) {
			u := mkUnsigned(t, tUser, new(big.Int), nil, nil)
			return u, signjob.Intent{Kind: "withdrawal", ID: "w", PartitionID: "p-hot", Chain: "evm-test", Asset: "ETH", To: tUser.Hex(), Amount: "0"}
		}},
		{"unknown asset", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Asset = "DOGE" })},
		{"unknown kind", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Kind = "refund" })},
		{"withdrawal with source", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.From = tUser.Hex() })},
		{"native amount differs", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "1501" })},
		{"native destination differs", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.To = other.Hex() })},
		{"destination not hex", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.To = "alice" })},
		{"destination no 0x", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.To = tUser.Hex()[2:] })},
		{"destination bad checksum", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) {
			// Flip the case of the first letter: still mixed case, checksum now wrong.
			b := []byte(tUser.Hex())
			for k := 2; k < len(b); k++ {
				if b[k] >= 'a' && b[k] <= 'f' {
					b[k] -= 32
					break
				}
				if b[k] >= 'A' && b[k] <= 'F' {
					b[k] += 32
					break
				}
			}
			i.To = string(b)
		})},
		{"destination zero address", withdrawNative(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.To = (common.Address{}).Hex() })},
		{"native carries data", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := nativeWithdrawal(t)
			return replaced(tUser, big.NewInt(1500), []byte{1}), i
		}},
		{"contract creation", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := nativeWithdrawal(t)
			u := mkUnsigned(t, tUser, big.NewInt(1500), nil, func(p *Payload) { p.To = (common.Address{}).Hex() })
			return u, i
		}},
		{"token call to wrong contract", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := tokenWithdrawal(t)
			return replaced(other, new(big.Int), otherTokData), i
		}},
		{"token transfer carries value", func() (chain.UnsignedTx, signjob.Intent) {
			u, i := tokenWithdrawal(t)
			_ = u
			d, _ := packTransfer(tUser, big.NewInt(2_000_000))
			return replaced(tToken, big.NewInt(1), d), i
		}},
		{"token recipient differs", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := tokenWithdrawal(t)
			return replaced(tToken, new(big.Int), otherTokData), i
		}},
		{"token amount differs", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := tokenWithdrawal(t)
			return replaced(tToken, new(big.Int), moreData), i
		}},
		{"token calldata has trailing byte", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := tokenWithdrawal(t)
			d, _ := packTransfer(tUser, big.NewInt(2_000_000))
			return replaced(tToken, new(big.Int), append(d, 0)), i
		}},
		{"token call is not transfer", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := tokenWithdrawal(t)
			d, _ := packTransfer(tUser, big.NewInt(2_000_000))
			d = append([]byte{}, d...)
			d[0] ^= 1
			return replaced(tToken, new(big.Int), d), i
		}},
		{"token intent asked for native", withdrawToken(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Asset = "ETH" })},
		{"sweep to wrong contract", func() (chain.UnsignedTx, signjob.Intent) {
			u, i := sweep(t, nil, "ETH")
			pl, _ := decodePayload(u.Payload)
			d, _ := packDeployAndFlush(DeriveSalt("cust-1", 3), nil)
			_ = pl
			return replaced(other, new(big.Int), d), i
		}},
		{"sweep carries value", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "ETH")
			d, _ := packDeployAndFlush(DeriveSalt("cust-1", 3), nil)
			return replaced(tFactory, big.NewInt(1), d), i
		}},
		{"sweep calldata not deployAndFlush", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "ETH")
			return replaced(tFactory, new(big.Int), []byte{0xde, 0xad, 0xbe, 0xef}), i
		}},
		{"sweep calldata trailing byte", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "ETH")
			d, _ := packDeployAndFlush(DeriveSalt("cust-1", 3), nil)
			return replaced(tFactory, new(big.Int), append(d, 0)), i
		}},
		{"sweep calldata truncated", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "ETH")
			d, _ := packDeployAndFlush(DeriveSalt("cust-1", 3), nil)
			return replaced(tFactory, new(big.Int), d[:len(d)-5]), i
		}},
		{"sweep salt of another customer", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "ETH")
			d, _ := packDeployAndFlush(DeriveSalt("cust-2", 3), nil)
			return replaced(tFactory, new(big.Int), d), i
		}},
		{"sweep extra token for ETH", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "ETH")
			d, _ := packDeployAndFlush(DeriveSalt("cust-1", 3), []common.Address{tToken})
			return replaced(tFactory, new(big.Int), d), i
		}},
		{"sweep wrong token", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "USDT")
			d, _ := packDeployAndFlush(DeriveSalt("cust-1", 3), []common.Address{other})
			return replaced(tFactory, new(big.Int), d), i
		}},
		{"sweep token asset without token", func() (chain.UnsignedTx, signjob.Intent) {
			u, i := sweep(t, nil, "ETH")
			i.Asset = "USDT"
			return u, i
		}},
		{"sweep two tokens", func() (chain.UnsignedTx, signjob.Intent) {
			_, i := sweep(t, nil, "USDT")
			d, _ := packDeployAndFlush(DeriveSalt("cust-1", 3), []common.Address{tToken, tToken})
			return replaced(tFactory, new(big.Int), d), i
		}},
		{"sweep source differs", sweepEth(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.From = other.Hex() })},
		{"sweep source empty", sweepEth(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.From = "" })},
		{"sweep destination differs", sweepEth(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.To = other.Hex() })},
		{"sweep destination empty", sweepEth(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.To = "" })},
		{"sweep amount non-canonical", sweepEth(func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "05" })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, i := c.mk()
			err := v.Verify(u, i)
			if err == nil {
				t.Fatal("tampered transaction accepted")
			}
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("error does not wrap ErrRejected: %v", err)
			}
		})
	}
}

func cancelTx(t *testing.T, gas uint64) (chain.UnsignedTx, signjob.Intent) {
	u := mkUnsignedFee(t, tHot, new(big.Int), nil, gas, big.NewInt(1e9), big.NewInt(3e9), nil)
	return u, signjob.Intent{Kind: "cancel", ID: "w1", PartitionID: "p-hot", Chain: "evm-test", Asset: "ETH", To: tHot.Hex(), Amount: "0"}
}

func TestVerifyCancel(t *testing.T) {
	v := mustVerifier(t)
	u, i := cancelTx(t, 21000)
	if err := v.Verify(u, i); err != nil {
		t.Fatal(err)
	}
	reject := map[string]func() (chain.UnsignedTx, signjob.Intent){
		"gas not 21000": func() (chain.UnsignedTx, signjob.Intent) { return cancelTx(t, 21001) },
		"to is not the sender": func() (chain.UnsignedTx, signjob.Intent) {
			_, i := cancelTx(t, 21000)
			return mkUnsignedFee(t, tUser, new(big.Int), nil, 21000, big.NewInt(1e9), big.NewInt(3e9), nil), i
		},
		"carries value": func() (chain.UnsignedTx, signjob.Intent) {
			_, i := cancelTx(t, 21000)
			return mkUnsignedFee(t, tHot, big.NewInt(1), nil, 21000, big.NewInt(1e9), big.NewInt(3e9), nil), i
		},
		"carries data": func() (chain.UnsignedTx, signjob.Intent) {
			_, i := cancelTx(t, 21000)
			return mkUnsignedFee(t, tHot, new(big.Int), []byte{1}, 21000, big.NewInt(1e9), big.NewInt(3e9), nil), i
		},
		"intent amount not 0": func() (chain.UnsignedTx, signjob.Intent) { u, i := cancelTx(t, 21000); i.Amount = "1"; return u, i },
		"intent has source": func() (chain.UnsignedTx, signjob.Intent) {
			u, i := cancelTx(t, 21000)
			i.From = tHot.Hex()
			return u, i
		},
		"intent to is not the hot address": func() (chain.UnsignedTx, signjob.Intent) {
			u, i := cancelTx(t, 21000)
			i.To = tUser.Hex()
			return u, i
		},
		"fee cap exceeded": func() (chain.UnsignedTx, signjob.Intent) {
			_, i := cancelTx(t, 21000)
			return mkUnsignedFee(t, tHot, new(big.Int), nil, 21000, big.NewInt(1e9), new(big.Int).Mul(big.NewInt(3e9), big.NewInt(1000)), nil), i
		},
	}
	for name, mk := range reject {
		u, i := mk()
		if err := v.Verify(u, i); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// The hot wallet pays the fee and the intent does not mention it, so the
// Verifier caps gas x max_fee_per_gas (Config.MaxTxFeeWei).
func TestVerifyFeeCap(t *testing.T) {
	v := mustVerifier(t) // cap = 100000 x 3 gwei exactly
	_, i := nativeWithdrawal(t)
	mk := func(gas uint64, tip, feeCap *big.Int) chain.UnsignedTx {
		return mkUnsignedFee(t, tUser, big.NewInt(1500), nil, gas, tip, feeCap, nil)
	}
	if err := v.Verify(mk(100000, big.NewInt(1e9), big.NewInt(3e9)), i); err != nil {
		t.Fatalf("fee exactly at the cap rejected: %v", err)
	}
	for name, u := range map[string]chain.UnsignedTx{
		"gas one over":                           mk(100001, big.NewInt(1e9), big.NewInt(3e9)),
		"fee cap one over":                       mk(100000, big.NewInt(1e9), big.NewInt(3e9+1)),
		"huge priority fee (cap raised with it)": mk(100000, big.NewInt(9e12), big.NewInt(9e12)),
	} {
		if err := v.Verify(u, i); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "cap") {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// Tampered gas / fee fields without recomputing the digest.
	for name, f := range map[string]func(string) string{
		"tampered gas": func(p string) string { return strings.Replace(p, `"gas":100000`, `"gas":100000000`, 1) },
		"tampered fee cap": func(p string) string {
			return strings.Replace(p, `"max_fee_per_gas":"3000000000"`, `"max_fee_per_gas":"3000000000000"`, 1)
		},
		"tampered tip": func(p string) string {
			return strings.Replace(p, `"max_priority_fee_per_gas":"1000000000"`, `"max_priority_fee_per_gas":"2000000000"`, 1)
		},
	} {
		u, i := nativeWithdrawal(t)
		u.Payload = []byte(f(string(u.Payload)))
		if err := v.Verify(u, i); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	bad := testCfg()
	bad.MaxTxFeeWei = nil
	if _, err := NewVerifier(bad); err == nil {
		t.Fatal("config without MaxTxFeeWei accepted")
	}
}

func TestVerifierNeedsNoRPC(t *testing.T) {
	cfg := testCfg()
	cfg.RPCURL = ""
	if _, err := NewVerifier(cfg); err != nil {
		t.Fatal(err)
	}
	bad := testCfg()
	bad.Factory = common.Address{}
	if _, err := NewVerifier(bad); err == nil {
		t.Fatal("config without factory accepted")
	}
}

func TestUnknownAssetIsError(t *testing.T) {
	if _, _, err := testCfg().withDefaults().asset("DOGE"); !errors.Is(err, ErrUnknownAsset) {
		t.Fatalf("got %v", err)
	}
}

func TestDeriveIsDeterministicAndDistinct(t *testing.T) {
	a := &Adapter{cfg: testCfg().withDefaults()}
	x, _ := a.DeriveDepositAddress(nil, "cust-1", 0)
	y, _ := a.DeriveDepositAddress(nil, "cust-1", 0)
	if x != y || x.Kind != chain.KindForwarder || x.Chain != "evm-test" {
		t.Fatalf("not deterministic: %+v %+v", x, y)
	}
	seen := map[string]bool{x.Address: true}
	for _, c := range []struct {
		id  string
		idx uint64
	}{{"cust-1", 1}, {"cust-2", 0}, {"cust-", 10}, {"cust-1", 10}} {
		d, _ := a.DeriveDepositAddress(nil, c.id, c.idx)
		if seen[d.Address] {
			t.Fatalf("collision for %+v", c)
		}
		seen[d.Address] = true
	}
	if _, err := a.DeriveDepositAddress(nil, "", 0); err == nil {
		t.Fatal("empty customer accepted")
	}
}
