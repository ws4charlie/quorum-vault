package gateway

import (
	"context"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A transaction signed by the gateway mines on a local anvil node (chain ID
// 11155111). Run: QV_REQUIRE_CHAIN=1 QV_ANVIL_RPC=http://127.0.0.1:18545.
func TestSignedTransactionsMineOnAnvil(t *testing.T) {
	if os.Getenv("QV_REQUIRE_CHAIN") != "1" {
		t.Skip("QV_REQUIRE_CHAIN != 1")
	}
	rpcURL := os.Getenv("QV_ANVIL_RPC")
	if rpcURL == "" {
		rpcURL = "http://127.0.0.1:18545"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h := newHarnessChainID(t, 11155111)

	raw, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		t.Fatalf("dial anvil: %v", err)
	}
	defer raw.Close()
	if err := raw.CallContext(ctx, nil, "anvil_setBalance", h.hot, (*hexutil.Big)(big.NewInt(1e18))); err != nil {
		t.Fatalf("fund hot address: %v", err)
	}
	cl, err := eth.Dial(ctx, rpcURL)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if cl.ChainID().Uint64() != 11155111 {
		t.Fatalf("chain id %s", cl.ChainID())
	}
	nonce, tip, feeCap, err := cl.Suggest(ctx, h.hot)
	if err != nil {
		t.Fatal(err)
	}

	mine := func(j signjob.Job, spec txSpec) {
		t.Helper()
		d := h.mustSign(j)
		tx, digest, err := eth.BuildTx(eth.TxParams{ChainID: cl.ChainID(), Nonce: spec.nonce, To: spec.to, Value: spec.value, Data: spec.data,
			Gas: spec.gas, GasTipCap: spec.tip, GasFeeCap: spec.feeCap})
		if err != nil {
			t.Fatal(err)
		}
		if string(digest[:]) != string(j.Digest) {
			t.Fatal("digest mismatch")
		}
		sig := signer.Signature{R: new(big.Int).SetBytes(d.Sig[:32]), S: new(big.Int).SetBytes(d.Sig[32:])}
		signed, err := eth.Assemble(tx, sig, h.signer.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		hash, err := cl.Broadcast(ctx, signed.Raw)
		if err != nil {
			t.Fatalf("broadcast: %v", err)
		}
		rcpt, err := cl.WaitReceipt(ctx, hash, 200*time.Millisecond)
		if err != nil || rcpt.Status != 1 {
			t.Fatalf("receipt %+v err %v", rcpt, err)
		}
		t.Logf("%s mined: tx %s block %d", j.ID, hash, rcpt.BlockNumber)
	}

	spec := txSpec{nonce: nonce, to: addrUser, value: big.NewInt(500), gas: 21000, tip: tip, feeCap: feeCap}
	in := signjob.Intent{Kind: "withdrawal", ID: "w-anvil", Asset: "ETH", To: addrUser.Hex(), Amount: "500"}
	mine(h.job("anvil-w", in, spec, "alice"), spec)

	cspec := txSpec{nonce: nonce + 1, to: h.hot, value: new(big.Int), gas: 21000, tip: tip, feeCap: feeCap}
	cin := signjob.Intent{Kind: "cancel", ID: "c-anvil", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}
	mine(h.job("anvil-c", cin, cspec), cspec)
}
