package evm

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The Circle USDC on Base Sepolia (chain 84532): its EIP-712 domain, read from the contract on 2026-11-24 with eth_call against the public RPC
// https://sepolia.base.org (read-only): name() = "USDC", version() = "2", DOMAIN_SEPARATOR() = baseSepoliaUSDCDomainSeparator. Circle's documentation lists
// the address (https://developers.circle.com/stablecoins/usdc-contract-addresses). docs/evm.md repeats this with the source.
var (
	baseSepoliaUSDC                = common.HexToAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e")
	baseSepoliaUSDCDomainSeparator = common.HexToHash("0x71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818")
)

const tAsset = "USDC"

var tPayee = common.HexToAddress("0x00000000000000000000000000000000000FAc01")

func x402Cfg() Config {
	c := testCfg()
	c.Assets = map[string]Token{tAsset: {Address: tToken, Decimals: 6}}
	c.X402 = map[string]X402Token{tAsset: {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: big.NewInt(1_000_000)}}
	return c
}

func x402Verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(x402Cfg())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func nonceOf(n byte) [32]byte { var b [32]byte; b[31] = n; return b }

// auth builds a valid job and intent; mut changes the typed data before the digest is taken, so the digest always matches what is sent.
func auth(t *testing.T, mut func(*Payload3009)) (chain.UnsignedTx, signjob.Intent) {
	t.Helper()
	cfg := x402Cfg()
	raw, _, err := cfg.NewPayload3009(tAsset, tHot, tPayee, big.NewInt(250_000), 1000, 1300, nonceOf(1))
	if err != nil {
		t.Fatal(err)
	}
	if mut != nil {
		var p Payload3009
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		mut(&p)
		if raw, err = json.Marshal(p); err != nil {
			t.Fatal(err)
		}
	}
	d := digestOfJSON(t, raw)
	u := chain.UnsignedTx{Chain: "evm-test", Digest: d[:], Payload: raw, KeyRef: chain.KeyRef{PartitionID: "p-hot"}}
	return u, signjob.Intent{Kind: KindEIP3009, ID: "x1", PartitionID: "p-hot", Chain: "evm-test", Asset: tAsset, To: tPayee.Hex(), Amount: "250000"}
}

// digestOfJSON recomputes the digest the way a signer would, from the fields of the payload as written (domain from the payload itself, not the config).
func digestOfJSON(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	var p Payload3009
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	val, _ := new(big.Int).SetString(p.Message.Value, 10)
	va, _ := new(big.Int).SetString(p.Message.ValidAfter, 10)
	vb, _ := new(big.Int).SetString(p.Message.ValidBefore, 10)
	var n [32]byte
	if b, err := hex.DecodeString(strings.TrimPrefix(p.Message.Nonce, "0x")); err == nil && len(b) == 32 {
		copy(n[:], b) // a malformed nonce keeps a zero digest nonce: the zone refuses on the shape before it compares digests
	}
	if val == nil || va == nil || vb == nil {
		return [32]byte{}
	}
	return Digest712(p.Domain.Name, p.Domain.Version, p.Domain.ChainID, common.HexToAddress(p.Domain.VerifyingContract),
		common.HexToAddress(p.Message.From), common.HexToAddress(p.Message.To), val, va.Uint64(), vb.Uint64(), n)
}

func TestTypeHashesMatchTheSpecAndTheTestToken(t *testing.T) {
	// The constants hard-coded in contracts/test/mocks/Tokens.sol (Eip3009Token) are the same hashes.
	want := common.HexToHash("0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267")
	if TransferWithAuthorizationTypeHash != want {
		t.Fatalf("TransferWithAuthorization typehash %s, EIP-3009 says %s", TransferWithAuthorizationTypeHash, want)
	}
	if domainTypeHash != common.HexToHash("0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f") {
		t.Fatalf("EIP712Domain typehash %s", domainTypeHash)
	}
}

func TestDomainSeparatorIsTheBaseSepoliaUSDCOne(t *testing.T) {
	got := DomainSeparator("USDC", "2", 84532, baseSepoliaUSDC)
	if common.Hash(got) != baseSepoliaUSDCDomainSeparator {
		t.Fatalf("domain separator %x, the contract's DOMAIN_SEPARATOR() is %s", got, baseSepoliaUSDCDomainSeparator)
	}
	if common.Hash(DomainSeparator("USD Coin", "2", 84532, baseSepoliaUSDC)) == baseSepoliaUSDCDomainSeparator {
		t.Fatal("a wrong name gives the same separator")
	}
}

func TestDigestAgreesWithGethTypedDataHasher(t *testing.T) {
	cfg := x402Cfg()
	raw, digest, err := cfg.NewPayload3009(tAsset, tHot, tPayee, big.NewInt(250_000), 1000, 1300, nonceOf(9))
	if err != nil {
		t.Fatal(err)
	}
	var p Payload3009
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	td := apitypes.TypedData{
		Types:       apitypes.Types{"EIP712Domain": {{Name: "name", Type: "string"}, {Name: "version", Type: "string"}, {Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"}}, "TransferWithAuthorization": {{Name: "from", Type: "address"}, {Name: "to", Type: "address"}, {Name: "value", Type: "uint256"}, {Name: "validAfter", Type: "uint256"}, {Name: "validBefore", Type: "uint256"}, {Name: "nonce", Type: "bytes32"}}},
		PrimaryType: "TransferWithAuthorization",
		Domain:      apitypes.TypedDataDomain{Name: p.Domain.Name, Version: p.Domain.Version, ChainId: math.NewHexOrDecimal256(int64(p.Domain.ChainID)), VerifyingContract: p.Domain.VerifyingContract},
		Message:     apitypes.TypedDataMessage{"from": p.Message.From, "to": p.Message.To, "value": p.Message.Value, "validAfter": p.Message.ValidAfter, "validBefore": p.Message.ValidBefore, "nonce": p.Message.Nonce},
	}
	want, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(digest[:]) {
		t.Fatalf("digest %x, go-ethereum computes %x", digest, want)
	}
}

func TestVerifyAcceptsAValidAuthorization(t *testing.T) {
	u, i := auth(t, nil)
	if err := x402Verifier(t).Verify(u, i); err != nil {
		t.Fatal(err)
	}
	a, err := x402Verifier(t).DecodeAuthorization(u.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if a.From != tHot || a.To != tPayee || a.Value.Int64() != 250_000 || a.Asset != tAsset || a.Token != tToken || a.ValidAfter != 1000 || a.ValidBefore != 1300 {
		t.Fatalf("decoded %+v", a)
	}
	if a.Claim() != "eip3009:"+strings.ToLower(tToken.Hex())+":"+strings.ToLower(tHot.Hex())+":"+strings.Repeat("00", 31)+"01" {
		t.Fatalf("claim %q", a.Claim())
	}
}

// Every refusal. A mutation of the typed data comes with a digest recomputed from the changed data (a signer would sign that one), so only the zone's own rules can refuse.
func TestVerifyRefusals(t *testing.T) {
	other := common.HexToAddress("0x00000000000000000000000000000000000BaD01").Hex()
	cases := []struct {
		name string
		mut  func(*Payload3009)
		fix  func(*chain.UnsignedTx, *signjob.Intent)
		want string
	}{
		{"wrong chain id in the domain", func(p *Payload3009) { p.Domain.ChainID = 1 }, nil, "domain chain id"},
		{"base sepolia domain on another chain's zone", func(p *Payload3009) { p.Domain.ChainID = 84532 }, nil, "domain chain id"},
		{"another token contract", func(p *Payload3009) { p.Domain.VerifyingContract = other }, nil, "not a configured token"},
		{"wrong domain name", func(p *Payload3009) { p.Domain.Name = "USD Coin" }, nil, "domain is"},
		{"wrong domain version", func(p *Payload3009) { p.Domain.Version = "1" }, nil, "domain is"},
		{"payer is not the hot wallet", func(p *Payload3009) { p.Message.From = other }, nil, "not the hot address"},
		{"payee differs from the intent", func(p *Payload3009) { p.Message.To = other }, nil, "typed data pays"},
		{"value differs from the intent", func(p *Payload3009) { p.Message.Value = "250001" }, nil, "typed data value"},
		{"value over the per-payment limit", func(p *Payload3009) { p.Message.Value = "1000001" }, func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "1000001" }, "per-payment limit"},
		{"zero value", func(p *Payload3009) { p.Message.Value = "0" }, func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Amount = "0" }, "typed data value"},
		{"window longer than allowed", func(p *Payload3009) { p.Message.ValidBefore = "1601" }, nil, "longer than"},
		{"empty window", func(p *Payload3009) { p.Message.ValidBefore = "1000" }, nil, "window is empty"},
		{"inverted window", func(p *Payload3009) { p.Message.ValidBefore = "999" }, nil, "window is empty"},
		{"another primary type", func(p *Payload3009) { p.PrimaryType = "Permit" }, nil, "primary type"},
		{"a changed type definition", func(p *Payload3009) { p.Types["TransferWithAuthorization"] = p.Types["TransferWithAuthorization"][:5] }, nil, "not the EIP-3009 definition"},
		{"an extra type", func(p *Payload3009) { p.Types["Mail"] = []TypedField{{"a", "string"}} }, nil, "not the EIP-3009 definition"},
		{"a short nonce", func(p *Payload3009) { p.Message.Nonce = "0x01" }, nil, "nonce"},
		{"a non-canonical value", func(p *Payload3009) { p.Message.Value = "0250000" }, nil, "value"},
		{"a bad checksum", func(p *Payload3009) { p.Message.To = "0x00000000000000000000000000000000000FaC01" }, nil, "checksum"},
		{"another intent asset", nil, func(_ *chain.UnsignedTx, i *signjob.Intent) { i.Asset = "ETH" }, "typed data is for"},
		{"an intent with a source", nil, func(_ *chain.UnsignedTx, i *signjob.Intent) { i.From = tHot.Hex() }, "source address"},
		{"another partition", nil, func(_ *chain.UnsignedTx, i *signjob.Intent) { i.PartitionID = "p-other" }, "partition"},
		{"another chain", nil, func(u *chain.UnsignedTx, _ *signjob.Intent) { u.Chain = "other" }, "chain"},
		{"digest of something else", nil, func(u *chain.UnsignedTx, _ *signjob.Intent) { u.Digest[0] ^= 1 }, "digest does not match"},
		{"trailing data", nil, func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = append(append([]byte{}, u.Payload...), []byte(" {}")...)
		}, "trailing"},
		{"an unknown field", nil, func(u *chain.UnsignedTx, _ *signjob.Intent) {
			u.Payload = []byte(strings.Replace(string(u.Payload), `"primaryType"`, `"extra":1,"primaryType"`, 1))
		}, "unknown field"},
	}
	v := x402Verifier(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, i := auth(t, c.mut)
			if c.fix != nil {
				c.fix(&u, &i)
			}
			err := v.Verify(u, i)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a refusal containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestConfigRejectsAnX402EntryForAnUnknownTokenOrWithoutLimits(t *testing.T) {
	c := x402Cfg()
	c.X402["DAI"] = c.X402[tAsset]
	if _, err := NewVerifier(c); err == nil {
		t.Fatal("x402 entry for an unconfigured token accepted")
	}
	c = x402Cfg()
	c.X402[tAsset] = X402Token{Name: "USDC", Version: "2", MaxWindowSeconds: 600}
	if _, err := NewVerifier(c); err == nil {
		t.Fatal("x402 entry without a per-payment limit accepted")
	}
}

func TestSignatureRSVIsWhatTheTokenWants(t *testing.T) {
	key, _ := crypto.GenerateKey()
	for n := 0; n < 40; n++ {
		d := crypto.Keccak256Hash([]byte{byte(n)})
		sig65, err := crypto.Sign(d[:], key)
		if err != nil {
			t.Fatal(err)
		}
		// A signer may return the high-s form; SignatureRSV normalises it.
		s := new(big.Int).SetBytes(sig65[32:64])
		hi := new(big.Int).Sub(crypto.S256().Params().N, s)
		sig := signer.Signature{R: new(big.Int).SetBytes(sig65[:32]), S: hi}
		r, ss, v, err := SignatureRSV(d, sig, &key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if v != 27 && v != 28 {
			t.Fatalf("v = %d", v)
		}
		if new(big.Int).SetBytes(ss[:]).Cmp(new(big.Int).Rsh(crypto.S256().Params().N, 1)) > 0 {
			t.Fatal("s is in the upper half")
		}
		rec := append(append(append([]byte{}, r[:]...), ss[:]...), v-27)
		pub, err := crypto.SigToPub(d[:], rec)
		if err != nil || crypto.PubkeyToAddress(*pub) != crypto.PubkeyToAddress(key.PublicKey) {
			t.Fatalf("recover: %v", err)
		}
	}
	// A signature of another digest is an error, never a guessed v.
	d := crypto.Keccak256Hash([]byte("a"))
	sig65, _ := crypto.Sign(d[:], key)
	other := crypto.Keccak256Hash([]byte("b"))
	if _, _, _, err := SignatureRSV(other, signer.Signature{R: new(big.Int).SetBytes(sig65[:32]), S: new(big.Int).SetBytes(sig65[32:64])}, &key.PublicKey); err == nil {
		t.Fatal("a signature of another digest was accepted")
	}
}
