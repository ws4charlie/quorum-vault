package gateway

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm/evmtest"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// The whole zone path against a token on a local node that stands in for Base Sepolia (chain 84532): the zone decodes and checks the typed data, signs the
// EIP-712 digest with the hot key, and the token accepts the signature in transferWithAuthorization, submitted by another account (the facilitator).
// Run: QV_REQUIRE_CHAIN=1 QV_ANVIL_RPC=http://127.0.0.1:18545 (the test sets the node's chain id to 84532).
func TestEIP3009SignedByTheZoneIsAcceptedByTheToken(t *testing.T) {
	node := evmtest.Anvil(t, evmtest.BaseSepoliaChainID)
	token := node.DeployToken(t, "USDC")

	rule := &testRule{allow: true}
	h := newHarnessWith(t, evmtest.BaseSepoliaChainID, true)
	cc := h.cfg.Chains[testChain]
	cc.EVM.Assets["USDT"] = evm.Token{Address: token.Address, Decimals: 6}
	cc.EVM.X402 = map[string]evm.X402Token{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: big.NewInt(1_000_000)}}
	gw, err := New(h.cfg, nil, map[string]signer.Signer{testPartition: h.signer, testColdPartition: h.signer}, h.guard, h.biz,
		Options{WorkerID: "w-anvil", Lease: 60e9, Now: h.clock, PaymentRule: rule})
	if err != nil {
		t.Fatal(err)
	}
	h.gw = gw
	t.Cleanup(func() { gw.Wait(10e9) })

	// The domain the zone signs under is the token's own.
	if got, want := evm.DomainSeparator("USDC", "2", evmtest.BaseSepoliaChainID, token.Address), token.DomainSeparator(t); got != want {
		t.Fatalf("domain separator %x, the token says %x", got, want)
	}
	token.Mint(t, h.hot, 1_000_000)

	// The zone's clock is the node's: validAfter and validBefore are around the latest block's time (the node's clock may be ahead of the wall clock).
	h.mu.Lock()
	h.now = time.Unix(int64(node.BlockTime(t)), 0)
	h.mu.Unlock()
	j := h.x402Job("anvil1", x402Spec{nonce: 1, after: -60, ttl: 300})
	d := h.mustSign(j)
	a, err := evm.NewVerifierForTest(cc.EVM).DecodeAuthorization(j.Payload)
	if err != nil {
		t.Fatal(err)
	}
	r, s, v, err := evm.SignatureRSV(a.Digest, signer.Signature{R: new(big.Int).SetBytes(d.Sig[:32]), S: new(big.Int).SetBytes(d.Sig[32:])}, h.signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	rc, err := token.Submit(t, a, v, r, s)
	if err != nil || rc.Status != 1 {
		t.Fatalf("the token refused the zone's signature: %v %+v", err, rc)
	}
	if got := token.BalanceOf(t, addrPayee); got.Int64() != 250_000 {
		t.Fatalf("payee holds %s", got)
	}
	if got := token.BalanceOf(t, h.hot); got.Int64() != 750_000 {
		t.Fatalf("the hot wallet holds %s", got)
	}
	if !token.Used(t, common.HexToAddress(a.From.Hex()), a.Nonce) {
		t.Fatal("the token did not record the nonce")
	}
	// The same authorization cannot be submitted twice, whoever submits it.
	if rc, err := token.Submit(t, a, v, r, s); err == nil && rc.Status == 1 {
		t.Fatal("the token accepted the same authorization twice")
	}
}
