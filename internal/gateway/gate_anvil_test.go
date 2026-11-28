package gateway

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/chain/eth/ethtest"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm/evmtest"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A Gate-governed wallet on a local node that stands in for Base Sepolia (chain 84532), through the whole zone path with the Gate credential rule
// and an operator-signed setting: with a credential minted by the TEST ONLY key, a native transfer and a token transfer are signed, broadcast and
// mined, and an EIP-3009 authorization is signed and accepted by the token; without a credential, with every approval, nothing is signed.
// Run: QV_REQUIRE_CHAIN=1 QV_ANVIL_RPC=http://127.0.0.1:18546 (make test-e2e-x402; the test sets the node's chain id to 84532 and restores it).
func TestGateCredentialPaymentsLandOnAnvil(t *testing.T) {
	node := evmtest.Anvil(t, evmtest.BaseSepoliaChainID)
	token := node.DeployToken(t, "USDC")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	z := newGateZone(t, evmtest.BaseSepoliaChainID)
	cc := z.cfg.Chains[testChain]
	cc.EVM.Assets["USDT"] = evm.Token{Address: token.Address, Decimals: 6}
	z.gw = z.newGateway("w-gate-anvil")
	z.limits = map[string]GateLimitFile{"ETH": {PerPayment: "1000000", PerHour: "5000000", PerDay: "5000000"},
		"USDT": {PerPayment: "500000", PerHour: "2000000", PerDay: "2000000"}}
	// The zone's clock is the node's (the node may be ahead of the wall clock).
	z.mu.Lock()
	z.now = time.Unix(int64(node.BlockTime(t)), 0)
	z.mu.Unlock()
	z.govern()

	if err := node.RPC.CallContext(ctx, nil, "anvil_setBalance", z.hot, (*hexutil.Big)(big.NewInt(1e18))); err != nil {
		t.Fatalf("fund the hot address: %v", err)
	}
	token.Mint(t, z.hot, 1_000_000)
	cl, err := ethtest.Dial(ctx, node.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	nonce, tip, feeCap, err := cl.Suggest(ctx, z.hot)
	if err != nil {
		t.Fatal(err)
	}
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	balance := func() *big.Int {
		var b hexutil.Big
		if err := node.RPC.CallContext(ctx, &b, "eth_getBalance", payee, "latest"); err != nil {
			t.Fatal(err)
		}
		return b.ToInt()
	}
	before := balance()

	// A withdrawal job as the signing API would enqueue it, with the node's nonce and fees.
	withdrawal := func(id, asset string, spec txSpec, amount *big.Int, credential string, approvers ...string) signjob.Job {
		in := signjob.Intent{Kind: "withdrawal", RequestedBy: "agentgate", ID: "w-" + id, Asset: asset, To: payee.Hex(), Amount: amount.String(), Credential: credential}
		return z.job(id, in, spec, approvers...)
	}
	mine := func(j signjob.Job, spec txSpec) {
		t.Helper()
		d := z.mustSign(j)
		tx, _, err := eth.BuildTx(eth.TxParams{ChainID: cl.ChainID(), Nonce: spec.nonce, To: spec.to, Value: spec.value, Data: spec.data,
			Gas: spec.gas, GasTipCap: spec.tip, GasFeeCap: spec.feeCap})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := ethtest.Assemble(tx, signer.Signature{R: new(big.Int).SetBytes(d.Sig[:32]), S: new(big.Int).SetBytes(d.Sig[32:])}, z.signer.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		hash, err := cl.Broadcast(ctx, signed.Raw)
		if err != nil {
			t.Fatalf("broadcast: %v", err)
		}
		if rc, err := cl.WaitReceipt(ctx, hash, 100*time.Millisecond); err != nil || rc.Status != 1 {
			t.Fatalf("receipt %+v %v", rc, err)
		}
	}

	// Without a credential, with every approval: refused, nothing signed.
	wei := big.NewInt(900_000)
	spec := txSpec{nonce: nonce, to: payee, value: wei, gas: 21000, tip: tip, feeCap: feeCap}
	z.mustReject(withdrawal("no-cred", "ETH", spec, wei, "", "alice", "bob", "carol"), string(gatecred.CredentialMissing))

	// Native transfer with a credential: signed and mined.
	mine(withdrawal("native", "ETH", spec, wei, z.cred(gatecred.NativeAsset, payee.Hex(), wei, nil)), spec)
	if after := balance(); new(big.Int).Sub(after, before).Cmp(wei) != 0 {
		t.Fatalf("payee balance %s -> %s", before, after)
	}

	// Token transfer with a credential: signed and mined.
	units := big.NewInt(400_000)
	data, err := erc20.Pack("transfer", payee, units)
	if err != nil {
		t.Fatal(err)
	}
	tspec := txSpec{nonce: nonce + 1, to: token.Address, data: data, value: new(big.Int), gas: 100000, tip: tip, feeCap: feeCap}
	mine(withdrawal("token", "USDT", tspec, units, z.cred(strings.ToLower(token.Address.Hex()), payee.Hex(), units, nil)), tspec)
	if got := token.BalanceOf(t, payee); got.Cmp(units) != 0 {
		t.Fatalf("payee holds %s of the token", got)
	}

	// EIP-3009 authorization with a credential: signed, and the token accepts it from the facilitator.
	z.mu.Lock()
	z.now = time.Unix(int64(node.BlockTime(t)), 0)
	z.mu.Unlock()
	now := z.clock().Unix()
	auth := big.NewInt(300_000)
	cred := z.cred(strings.ToLower(token.Address.Hex()), payee.Hex(), auth, nil) // issued now-10, expires now+590
	j := z.authorization("auth", payee, auth, now-5, now+300, cred)
	d := z.mustSign(j)
	a, err := evm.NewVerifierForTest(cc.EVM).DecodeAuthorization(j.Payload)
	if err != nil {
		t.Fatal(err)
	}
	r, s, v, err := evm.SignatureRSV(a.Digest, signer.Signature{R: new(big.Int).SetBytes(d.Sig[:32]), S: new(big.Int).SetBytes(d.Sig[32:])}, z.signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if rc, err := token.Submit(t, a, v, r, s); err != nil || rc.Status != 1 {
		t.Fatalf("the token refused the authorization: %v %+v", err, rc)
	}
	if got := token.BalanceOf(t, payee); got.Cmp(new(big.Int).Add(units, auth)) != 0 {
		t.Fatalf("payee holds %s of the token after the authorization", got)
	}
	if n := z.signer.calls.Load(); n != 3 {
		t.Fatalf("the signer was called %d times, want 3", n)
	}
}
