package gateway

import (
	"context"
	_ "embed"
	"math/big"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// store_v1.sql is the guard schema as it was before the chain seam (P6b): nonce_claims, nonce, tip and fee_cap columns.
//
//go:embed testdata/store_v1.sql
var storeV1SQL string

// A guard database written by the nonce-only schema keeps working after the upgrade: the old claim still holds its
// nonce, the old fees still decide replacements, and the old signature is still replayed, not signed again.
func TestGuardUpgradeKeepsOldRowsWorking(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A database as the previous version left it: one signed withdrawal at nonce 7 (tip 1e9, cap 3e9).
	old := newGuardDB(t)
	if _, err := old.Exec(ctx, storeV1SQL); err != nil {
		t.Fatal(err)
	}
	in := signjob.Intent{Kind: "withdrawal", ID: "w-old", Asset: "ETH", To: addrUser.Hex(), Amount: "500", Chain: testChain,
		PartitionID: testPartition, NotAfter: h.clock().Add(time.Hour).Unix()}
	spec := txSpec{nonce: 7, to: addrUser, value: big.NewInt(500), gas: 21000}
	signedJob := h.job("old1", in, spec, "auto")
	sig, err := h.gw.signWith(ctx, h.signer, signedJob.Digest, signer.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hash := in.Hash()
	now := h.clock()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO signed_intents (intent_id, intent_hash, kind, chain, asset, amount, sender, nonce, created_at) VALUES ($1,$2,'withdrawal',$3,'ETH',500,$4,7,$5)`,
			[]any{in.ID, hash[:], testChain, h.hot.Hex(), now}},
		{`INSERT INTO signed_digests (digest, intent_id, nonce, tip, fee_cap, signature, reserved_at, signed_at) VALUES ($1,$2,7,1000000000,3000000000,$3,$4,$4)`,
			[]any{signedJob.Digest, in.ID, sig, now}},
		{`INSERT INTO nonce_claims (chain, sender, nonce, intent_id, kind) VALUES ($1,$2,7,$3,'withdrawal')`,
			[]any{testChain, h.hot.Hex(), in.ID}},
	} {
		if _, err := old.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}

	// Upgrade, twice: it is idempotent.
	for i := 0; i < 2; i++ {
		g, err := OpenGuard(ctx, old)
		if err != nil {
			t.Fatalf("upgrade %d: %v", i, err)
		}
		h.guard, h.guardDB = g, old
	}
	h.gw = h.newGateway("w2")
	var legacy bool
	old.QueryRow(ctx, `SELECT to_regclass('nonce_claims') IS NOT NULL`).Scan(&legacy)
	if legacy {
		t.Fatal("the old nonce_claims table is still there")
	}

	// 1. The old claim holds: another intent at nonce 7 is refused.
	other := signjob.Intent{Kind: "withdrawal", ID: "w-other", Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
	h.mustReject(h.job("up1", other, h.ethTx(addrUser, 100, 7), "auto"), ReasonNonceTaken)
	// 2. The old intent cannot move to another nonce.
	h.mustReject(h.job("up2", in, h.ethTx(addrUser, 500, 8), "auto"), ReasonNonceChanged)
	// 3. The old fees decide replacements: the same fees are not higher; higher ones are signed.
	same := spec
	same.gas = 22000
	h.mustReject(h.job("up3", in, same, "auto"), ReasonFeeNotHigher)
	bump := spec
	bump.tip, bump.feeCap = big.NewInt(2e9), big.NewInt(6e9)
	h.mustSign(h.job("up4", in, bump, "auto"))
	// 4. The old signature is replayed, never made again.
	before := h.signer.calls.Load()
	d := h.mustSign(h.job("up5", in, spec, "auto"))
	if d.Outcome != OutcomeReplayed || h.signer.calls.Load() != before {
		t.Fatalf("old digest: outcome %s, signer calls %d -> %d", d.Outcome, before, h.signer.calls.Load())
	}
	// 5. A cancel may take the old claim, and then the intent is gone.
	cancel := signjob.Intent{Kind: "cancel", ID: "c-old", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}
	cj := h.job("up6", cancel, h.cancelTx(7))
	h.mustSign(cj)
	again := bump
	again.tip, again.feeCap = big.NewInt(3e9), big.NewInt(9e9)
	h.mustReject(h.job("up7", in, again, "auto"), ReasonNonceCancel)
}
