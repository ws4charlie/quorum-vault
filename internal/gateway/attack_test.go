package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Each test writes to the business database the way an attacker with full
// write access would, and asserts the rejection code and that nothing was signed.

func TestAttackNoApprovals(t *testing.T) {
	h := newHarness(t)
	h.mustReject(h.withdrawal("na1", addrEvil, 100, 0), ReasonApprovals)

	// Junk approval from a configured actor name.
	j := h.withdrawal("na2", addrEvil, 100, 0)
	j.Approvals = []signjob.Approval{{Actor: "alice", Signature: make([]byte, 64)}}
	h.mustReject(j, ReasonApprovals)
}

func TestAttackMarkedDoneOrApprovedBySQL(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Marked done with a made-up signature: the gateway never touches a done job, and signs nothing.
	j := h.withdrawal("sql1", addrEvil, 100, 0)
	h.put(j)
	if _, err := h.biz.Exec(ctx, `UPDATE sign_jobs SET status='done', signature='\xdeadbeef' WHERE id='sql1'`); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := h.gw.RunOnce(ctx); ok {
		t.Fatal("gateway claimed a done job")
	}
	// Marked approved through an invented approvals column and status reset to pending: still no valid approval.
	j2 := h.withdrawal("sql2", addrEvil, 100, 1)
	h.put(j2)
	if _, err := h.biz.Exec(ctx, `UPDATE sign_jobs SET approvals='[{"Actor":"alice","Signature":"AAAA"},{"actor":"alice","signature":"AAAA"}]'::jsonb WHERE id='sql2'`); err != nil {
		t.Fatal(err)
	}
	d, ok, err := h.gw.RunOnce(ctx)
	if err != nil || !ok || d.Outcome != OutcomeRejected || !hasPrefix(d.Reason, ReasonApprovals+":") {
		t.Fatalf("decision = %+v ok=%v err=%v", d, ok, err)
	}
	if h.signer.calls.Load() != 0 {
		t.Fatal("signer was called")
	}
}

func TestAttackDestinationChangedAfterApproval(t *testing.T) {
	h := newHarness(t)
	// Approvers signed "pay addrUser"; the attacker rewrites the intent's destination only.
	good := h.withdrawal("dc0", addrUser, 100, 0, "auto")
	j := good
	j.ID = "dc1"
	in := mustIntent(good.Intent)
	in.To = addrEvil.Hex()
	j.Intent = mustJSON(in)
	h.mustReject(j, ReasonTx) // payload still pays addrUser

	// Intent and payload both rewritten, approvals kept: they sign a different hash.
	j2 := h.job("dc2", in, h.ethTx(addrEvil, 100, 0))
	j2.Approvals = good.Approvals
	h.mustReject(j2, ReasonApprovals)
}

func TestAttackPayloadChanged(t *testing.T) {
	h := newHarness(t)
	in := signjob.Intent{Kind: "withdrawal", ID: "w-pc", Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
	for name, spec := range map[string]txSpec{
		"destination": h.ethTx(addrEvil, 100, 0),
		"amount":      h.ethTx(addrUser, 900, 0),
		"token":       h.tokenTx(addrUser, 100, 0),
	} {
		// The digest is recomputed for the tampered payload, so only the intent comparison can catch it.
		h.mustReject(h.job("pc-"+name, in, spec, "auto"), ReasonTx)
	}
	// Token withdrawal turned into a native transfer, and a different token contract.
	tin := signjob.Intent{Kind: "withdrawal", ID: "w-pc2", Asset: "USDT", To: addrUser.Hex(), Amount: "100"}
	h.mustReject(h.job("pc-native", tin, h.ethTx(addrUser, 100, 0), "auto"), ReasonTx)
	bad := h.tokenTx(addrUser, 100, 0)
	bad.to = addrEvil
	h.mustReject(h.job("pc-contract", tin, bad, "auto"), ReasonTx)
}

func TestAttackUnconfiguredOrDisabledApprover(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// The attacker plants their key in a business-database table and in the job itself.
	if _, err := h.biz.Exec(ctx, `CREATE TABLE approver_keys (actor text, public_key bytea)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.biz.Exec(ctx, `INSERT INTO approver_keys VALUES ('mallory', $1)`, []byte(pub)); err != nil {
		t.Fatal(err)
	}
	in := signjob.Intent{Kind: "withdrawal", ID: "w-ua", Asset: "ETH", To: addrEvil.Hex(), Amount: "100"}
	hash := in.Hash()
	j := h.job("ua1", in, h.ethTx(addrEvil, 100, 0))
	j.Approvals = []signjob.Approval{{Actor: "mallory", Signature: ed25519.Sign(priv, hash[:])}}
	h.mustReject(j, ReasonApprovals)

	// Mallory signs under the name of a configured actor: wrong key.
	j2 := h.job("ua2", in, h.ethTx(addrEvil, 100, 0))
	j2.Approvals = []signjob.Approval{{Actor: "alice", Signature: ed25519.Sign(priv, hash[:])}}
	h.mustReject(j2, ReasonApprovals)

	// A configured key that is disabled does not count.
	j3 := h.job("ua3", in, h.ethTx(addrEvil, 100, 0), "dave")
	h.mustReject(j3, ReasonApprovals)
}

func TestAttackRepeatedApproverReachesQuorum(t *testing.T) {
	h := newHarness(t)
	in := signjob.Intent{Kind: "withdrawal", ID: "w-rq", Asset: "ETH", To: addrUser.Hex(), Amount: "2000"} // needs 2
	h.mustReject(h.job("rq1", in, h.ethTx(addrUser, 2000, 0), "alice", "alice", "alice"), ReasonTier)
	h.mustReject(h.job("rq2", in, h.ethTx(addrUser, 2000, 0), "alice", "dave"), ReasonTier)
	// Two distinct approvers pass.
	h.mustSign(h.job("rq3", in, h.ethTx(addrUser, 2000, 0), "alice", "bob"))
}

func TestAttackDoubleWithdrawalNewJobNextNonce(t *testing.T) {
	h := newHarness(t)
	first := h.withdrawal("dw1", addrUser, 500, 0, "auto")
	h.mustSign(first)
	// Same approved intent and approvals, new job ID, nonce + 1: a second payout on the same approval.
	in := mustIntent(first.Intent)
	again := h.job("dw2", in, h.ethTx(addrUser, 500, 1))
	again.Approvals = first.Approvals
	calls := h.signer.calls.Load()
	h.mustReject(again, ReasonNonceChanged)
	// Same, but the attacker also rewinds to the original nonce with a different gas limit: not a fee bump.
	spec := h.ethTx(addrUser, 500, 0)
	spec.gas = 22000
	third := h.job("dw3", in, spec)
	third.Approvals = first.Approvals
	h.mustReject(third, ReasonFeeNotHigher)
	if h.signer.calls.Load() != calls {
		t.Fatal("signed again")
	}
	// Resubmitting the identical transaction under a new job ID returns the stored signature.
	dup := first
	dup.ID = "dw4"
	d := h.mustSign(dup)
	if d.Outcome != OutcomeReplayed || h.signer.calls.Load() != calls {
		t.Fatalf("outcome %s, signer calls %d", d.Outcome, h.signer.calls.Load())
	}
}

func TestAttackIntentIDReuseWithDifferentBody(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.withdrawal("ir1", addrUser, 500, 0, "auto"))
	// Same intent ID, different amount, validly approved by the compromised auto key.
	in := signjob.Intent{Kind: "withdrawal", ID: "w-ir1", Asset: "ETH", To: addrUser.Hex(), Amount: "600"}
	h.mustReject(h.job("ir2", in, h.ethTx(addrUser, 600, 1), "auto"), ReasonIntentChanged)
}

func TestAttackHugeFee(t *testing.T) {
	h := newHarness(t)
	in := signjob.Intent{Kind: "withdrawal", ID: "w-fee", Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
	spec := h.ethTx(addrUser, 100, 0)
	spec.feeCap, spec.tip = big.NewInt(1000e9), big.NewInt(1000e9) // 21000 gas x 1000 gwei > cap
	h.mustReject(h.job("fee1", in, spec, "auto"), ReasonTx)
}

func TestAttackSplitAcrossJobsHitsDailyCap(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// 900 each is under the per-transaction cap and needs one approval. 8 x 900 = 7200 <= 8000.
	for i := 0; i < 8; i++ {
		h.mustSign(h.withdrawal(fmt.Sprintf("sp%d", i), addrUser, 900, uint64(i), "auto"))
	}
	h.mustReject(h.withdrawal("sp8", addrUser, 900, 8, "auto"), ReasonDailyCap)

	// Wiping and rewriting the business history does not reset the cap.
	if _, err := h.biz.Exec(ctx, `DELETE FROM sign_jobs`); err != nil {
		t.Fatal(err)
	}
	h.mustReject(h.withdrawal("sp9", addrUser, 900, 8, "auto"), ReasonDailyCap)

	// The rolling window moves with time: after 24 hours the old intents no longer count.
	h.advance(24*time.Hour + time.Minute)
	h.mustSign(h.withdrawal("sp10", addrUser, 900, 9, "auto"))
}

func TestPerTxCapAndTierBoundaries(t *testing.T) {
	h := newHarness(t)
	h.mustReject(h.withdrawal("cap1", addrUser, 5001, 0, "alice", "bob", "carol"), ReasonPerTxCap)
	h.mustReject(h.withdrawal("cap2", addrUser, 1000, 0, "alice"), ReasonTier) // 1000 is the tier boundary
	h.mustSign(h.withdrawal("cap3", addrUser, 999, 0, "alice"))
	h.mustSign(h.withdrawal("cap4", addrUser, 5000, 1, "alice", "bob"))
}

func TestAttackSweepToUnconfiguredDestination(t *testing.T) {
	h := newHarness(t)
	spec, from := h.sweepTx("cust-1", 0)
	in := signjob.Intent{Kind: "sweep", ID: "s-bad", Asset: "ETH", From: from.Hex(), To: addrEvil.Hex(), Amount: "5"}
	h.mustReject(h.job("sw-bad", in, spec), ReasonTx)
}

func TestSweepRateLimit(t *testing.T) {
	h := newHarness(t)
	sweep := func(n int) signjob.Job {
		spec, from := h.sweepTx(fmt.Sprintf("cust-%d", n), uint64(n))
		in := signjob.Intent{Kind: "sweep", ID: fmt.Sprintf("s-%d", n), Asset: "ETH", From: from.Hex(), To: addrDest.Hex(), Amount: "5"}
		return h.job(fmt.Sprintf("sw%d", n), in, spec) // no approvals needed
	}
	h.mustSign(sweep(0))
	h.mustSign(sweep(1))
	h.mustReject(sweep(2), ReasonSweepRate) // limit is 2 per hour
	h.advance(61 * time.Minute)
	h.mustSign(sweep(3))
}

func mustIntent(b []byte) signjob.Intent {
	in, err := parseIntent(signjob.Job{Intent: b, Chain: testChain, PartitionID: testPartition})
	if err != nil {
		panic(err)
	}
	return in
}
