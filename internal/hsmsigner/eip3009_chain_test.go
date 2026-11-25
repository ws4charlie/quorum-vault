package hsmsigner_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm/evmtest"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// The HSM signs the 32-byte EIP-712 digest of a transferWithAuthorization with the key it holds (no transaction around it), and a token on a local node
// that stands in for Base Sepolia (chain 84532) accepts r, s, v: the token recovers the HSM key's address as the payer. Run:
// QV_REQUIRE_CHAIN=1 QV_REQUIRE_HSM=1 QV_ANVIL_RPC=http://127.0.0.1:18546 (the test sets the node chain id to 84532 and restores it).
func TestHSMSignedEIP712DigestIsAcceptedByTheToken(t *testing.T) {
	ctx := context.Background()
	node := evmtest.Anvil(t, evmtest.BaseSepoliaChainID)
	token := node.DeployToken(t, "USDC")

	tok := hsmtest.Token(t, "quorumvault")
	gen := hsmsigner.NewGenerator(tok)
	k, err := gen.Generate(ctx, "x402-hot", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tok.DestroyPrivateKey(ctx, k.HSMKeyID) })
	s, err := hsmsigner.New(tok, k)
	if err != nil {
		t.Fatal(err)
	}
	hot := common.HexToAddress(k.Address)
	token.Mint(t, hot, 1_000_000)

	payee := common.HexToAddress("0x00000000000000000000000000000000000fac01")
	cfg := evm.Config{Chain: "base-sepolia", ChainID: evmtest.BaseSepoliaChainID, Factory: common.HexToAddress("0xf1"), SweepDestination: common.HexToAddress("0xd1"),
		HotAddresses: map[string]common.Address{"p-hot": hot}, Assets: map[string]evm.Token{"USDC": {Address: token.Address, Decimals: 6}},
		MaxTxFeeWei: big.NewInt(1), X402: map[string]evm.X402Token{"USDC": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: big.NewInt(1_000_000)}}}
	now := node.BlockTime(t)
	for n := byte(1); n <= 3; n++ { // several signatures: r, s and v come out differently every time, and every one is accepted
		var nonce [32]byte
		nonce[31] = n
		payload, digest, err := cfg.NewPayload3009("USDC", hot, payee, big.NewInt(100_000), now-60, now+300, nonce)
		if err != nil {
			t.Fatal(err)
		}
		a, err := evm.NewVerifierForTest(cfg).DecodeAuthorization(payload)
		if err != nil || a.Digest != digest {
			t.Fatalf("decode: %v", err)
		}
		res, err := s.SignDigest(ctx, digest, signer.SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		r, ss, v, err := evm.SignatureRSV(digest, res.Sig, s.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		rc, err := token.Submit(t, a, v, r, ss)
		if err != nil || rc.Status != 1 {
			t.Fatalf("nonce %d: the token refused the HSM's signature (v=%d): %v %+v", n, v, err, rc)
		}
		if !token.Used(t, hot, nonce) {
			t.Fatalf("nonce %d not recorded", n)
		}
	}
	if got := token.BalanceOf(t, payee); got.Int64() != 300_000 {
		t.Fatalf("payee holds %s", got)
	}
	if got := token.BalanceOf(t, hot); got.Int64() != 700_000 {
		t.Fatalf("hot holds %s", got)
	}
}
