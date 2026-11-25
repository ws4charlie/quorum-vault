package custody

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm/evmtest"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The liability accounting against a real token on a local node that stands in for Base Sepolia (chain 84532), read through the real EVMReader: an
// authorization the facilitator uses is booked as a payment, one nobody uses is released once a block is past its validBefore, and Reconcile compares
// the books with the token's balances and stays clean at every step. Run: QV_REQUIRE_CHAIN=1 QV_ANVIL_RPC=http://127.0.0.1:18545 (the test sets the
// node's chain id to 84532).
func TestX402LiabilityOnALocalBaseSepolia(t *testing.T) {
	node := evmtest.Anvil(t, evmtest.BaseSepoliaChainID)
	token := node.DeployToken(t, "USDC")
	ctx := context.Background()

	key, _ := crypto.GenerateKey()
	payer := crypto.PubkeyToAddress(key.PublicKey)
	cfg := testConfig(t)
	cfg.EVM.ChainID, cfg.EVM.RPCURL, cfg.EVM.Confirmations = evmtest.BaseSepoliaChainID, node.URL, 0
	cfg.HotShards[0] = payer
	for _, sym := range cfg.AssetList {
		cfg.EVM.HotAddresses[cfg.PartitionKey(sym, 0).String()] = payer
	}
	a := cfg.Assets["USDT"]
	a.Address = token.Address
	cfg.Assets["USDT"] = a
	cfg.EVM.Assets["USDT"] = evm.Token{Address: token.Address, Decimals: 6}
	cfg.EVM.X402 = map[string]evm.X402Token{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: big.NewInt(500_000)}}
	cfg.X402Shard = map[string]int{"USDT": 0}
	rd, err := NewEVMReader(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	pool := dbtest.New(t)
	s := New(pool, cfg, &fakeChain{fee: big.NewInt(7), statuses: map[string]chain.TxStatus{}}, rd)
	s.Now = func() time.Time { return time.Unix(int64(node.BlockTime(t)), 0) }
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO chain_cursors (chain, next_height) VALUES ($1, 1000000000)`, testChain); err != nil {
		t.Fatal(err)
	}
	token.Mint(t, payer, 1_000_000)
	if err := s.FundHotAsset(ctx, "seed", 0, "USDT", big.NewInt(1_000_000)); err != nil {
		t.Fatal(err)
	}
	requireClean(t, "funded", mustReconcile(t, s))

	req := func(id string, amount int64, nonce byte, ttl uint64) X402Authorization {
		now := node.BlockTime(t)
		var n [32]byte
		n[31] = nonce
		au, _, err := s.RequestX402(ctx, X402Request{ID: id, Asset: "USDT", Payee: "0x00000000000000000000000000000000000fac01", Amount: big.NewInt(amount),
			ValidAfter: now - 30, ValidBefore: now + ttl, Nonce: n})
		if err != nil {
			t.Fatal(err)
		}
		return au
	}
	sign := func(id string) (evm.Authorization, byte, [32]byte, [32]byte) {
		job, err := signjob.Get(ctx, pool, "x402:"+id)
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := crypto.Sign(job.Digest, key)
		if _, err := pool.Exec(ctx, `UPDATE sign_jobs SET status='done', signature=$2 WHERE id=$1`, "x402:"+id, sig[:64]); err != nil {
			t.Fatal(err)
		}
		r, err := s.X402(ctx, id)
		if err != nil || r.Status != X402Signed {
			t.Fatalf("result %+v %v", r, err)
		}
		au, err := evm.NewVerifierForTest(cfg.EVM).DecodeAuthorization(job.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return au, r.V, r.R, r.S
	}

	// 1. Used. Signed and open: the token still holds everything, the ledger has the liability as a hold.
	req("c1", 200_000, 1, 300)
	au, v, r, ss := sign("c1")
	requireClean(t, "signed", mustReconcile(t, s))
	// The facilitator submits it; the books have not seen it yet: Reconcile explains it from the token's event.
	if rc, err := token.Submit(t, au, v, r, ss); err != nil || rc.Status != 1 {
		t.Fatalf("the token refused the authorization: %v %+v", err, rc)
	}
	rep := mustReconcile(t, s)
	requireClean(t, "paid, not booked", rep)
	if !hasAdjusted(rep, "hot") {
		t.Fatal("the hot check does not say it was adjusted")
	}
	res, err := s.SettleX402(ctx)
	if err != nil || res.Used != 1 {
		t.Fatalf("settle %+v %v", res, err)
	}
	requireClean(t, "booked", mustReconcile(t, s))
	expectPosted(t, s, x402Acct(testChain, "USDT"), -200_000)
	if res, err := s.SettleX402(ctx); err != nil || res != (X402Settled{}) {
		t.Fatalf("seen twice: %+v %v", res, err)
	}
	requireClean(t, "seen twice", mustReconcile(t, s))

	// 2. Expired. Nobody submits it; the node's clock passes validBefore.
	req("c2", 100_000, 2, 60)
	sign("c2")
	if res, err := s.SettleX402(ctx); err != nil || res.Expired != 0 {
		t.Fatalf("released while a block could still include it: %+v %v", res, err)
	}
	node.Warp(t, 120)
	res, err = s.SettleX402(ctx)
	if err != nil || res.Expired != 1 {
		t.Fatalf("settle %+v %v", res, err)
	}
	requireClean(t, "expired", mustReconcile(t, s))
	if got := token.BalanceOf(t, payer); got.Int64() != 800_000 {
		t.Fatalf("the payer holds %s", got)
	}
	// The token agrees the expired one is dead: submitting it now is refused.
	job2, _ := signjob.Get(ctx, pool, "x402:c2")
	au2, err := evm.NewVerifierForTest(cfg.EVM).DecodeAuthorization(job2.Payload)
	if err != nil {
		t.Fatal(err)
	}
	r2, s2, v2, err := evm.SignatureRSVFor(au2.Digest, signer.Signature{R: new(big.Int).SetBytes(job2.Signature[:32]), S: new(big.Int).SetBytes(job2.Signature[32:])}, payer)
	if err != nil {
		t.Fatal(err)
	}
	if rc, err := token.Submit(t, au2, v2, r2, s2); err == nil && rc.Status == 1 {
		t.Fatal("the token accepted an authorization past its validBefore")
	}
}
