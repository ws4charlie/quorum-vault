package evm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

func (e *tenv) sweep(id, asset string, from common.Address, amt int64) string {
	e.t.Helper()
	tx, err := e.pool.Begin(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: id, Asset: asset, From: from.Hex(), ToPartition: "hot-0", Amount: big.NewInt(amt)})
	if err != nil {
		_ = tx.Rollback(e.ctx)
		e.t.Fatal(err)
	}
	if err := tx.Commit(e.ctx); err != nil {
		e.t.Fatal(err)
	}
	h := e.mustBroadcast(u)
	e.receipt(common.HexToHash(h))
	return h
}

// MovedAssets reports exactly what the sweep moved, including ETH that rode
// along with a token sweep and a token that was not swept stays out.
func TestMovedAssetsAndTxFee(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-m", 0)
	eth := new(big.Int).Mul(big.NewInt(2), ether)
	e.send(e.deployer, &addr, eth, nil)
	e.mint(e.usdt, addr, 4_000_000)
	e.mint(e.dai, addr, 99)

	hash := e.sweep("sw-m1", "USDT", addr, 1) // expected 1, moves all 4,000,000 (and the ETH)
	moved, err := e.ad.MovedAssets(e.ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*big.Int{}
	for _, m := range moved {
		if m.Address != addr.Hex() {
			t.Fatalf("address %s", m.Address)
		}
		got[m.Asset] = m.Amount
	}
	if len(moved) != 2 || got["ETH"].Cmp(eth) != 0 || got["USDT"].Int64() != 4_000_000 {
		t.Fatalf("moved %+v", moved)
	}

	r := e.receipt(common.HexToHash(hash))
	fee, err := e.ad.TxFee(e.ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.EffectiveGasPrice)
	if fee.Cmp(want) != 0 || fee.Sign() <= 0 {
		t.Fatalf("fee %s want %s", fee, want)
	}

	// A flush with nothing left emits nothing.
	hash2 := e.sweep("sw-m2", "USDT", addr, 1)
	if moved, err = e.ad.MovedAssets(e.ctx, hash2); err != nil || len(moved) != 0 {
		t.Fatalf("empty flush moved %+v err %v", moved, err)
	}
	if _, err := e.ad.MovedAssets(e.ctx, common.Hash{1}.Hex()); err == nil {
		t.Fatal("unknown tx must error")
	}
}

// A contract that emits Swept itself is not a known forwarder and is ignored.
func TestMovedAssetsIgnoresUnknownEmitters(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-n", 0)
	e.mint(e.usdt, addr, 10)
	hash := e.sweep("sw-n", "USDT", addr, 10)
	// Forget the customer: the forwarder is no longer one we know.
	if _, err := e.pool.Exec(e.ctx, `DELETE FROM deposit_addresses WHERE address=$1`, addr.Hex()); err != nil {
		t.Fatal(err)
	}
	moved, err := e.ad.MovedAssets(e.ctx, hash)
	if err != nil || len(moved) != 0 {
		t.Fatalf("events from an unknown emitter counted: %+v err %v", moved, err)
	}
}

// A reverted transaction moved nothing but still paid a fee.
func TestRevertedSweepMovesNothingButPaysFee(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-r", 0)
	e.mint(e.usdt, addr, 10)
	// Freeze: the build would refuse, so craft a call that reverts on chain: flush a non-contract token.
	tx := e.sendRaw(e.hotKey, &e.cfg.Factory, new(big.Int), mustPack(t, DeriveSalt("cust-r", 0), []common.Address{crypto.PubkeyToAddress(e.hotKey.PublicKey)}), 300000)
	r := e.receipt(tx.Hash())
	if r.Status != 0 {
		t.Fatal("expected a revert")
	}
	moved, err := e.ad.MovedAssets(e.ctx, tx.Hash().Hex())
	if err != nil || len(moved) != 0 {
		t.Fatalf("moved %+v err %v", moved, err)
	}
	if fee, err := e.ad.TxFee(e.ctx, tx.Hash().Hex()); err != nil || fee.Sign() <= 0 {
		t.Fatalf("fee %v err %v", fee, err)
	}
}

func mustPack(t *testing.T, salt [32]byte, tokens []common.Address) []byte {
	t.Helper()
	b, err := packDeployAndFlush(salt, tokens)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
