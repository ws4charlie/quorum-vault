package gateway

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

func TestHappyWithdrawalsAndSweep(t *testing.T) {
	h := newHarness(t)
	d := h.mustSign(h.withdrawal("hw1", addrUser, 500, 0, "alice"))
	if d.Outcome != OutcomeSigned {
		t.Fatal(d.Outcome)
	}
	tin := signjob.Intent{Kind: "withdrawal", ID: "w-tok", Asset: "USDT", To: addrUser.Hex(), Amount: "2000000"}
	h.mustSign(h.job("hw2", tin, h.tokenTx(addrUser, 2000000, 1), "alice", "bob"))
	spec, from := h.sweepTx("cust-9", 2)
	sin := signjob.Intent{Kind: "sweep", ID: "s-ok", Asset: "ETH", From: from.Hex(), To: addrDest.Hex(), Amount: "7"}
	h.mustSign(h.job("hw3", sin, spec))
}

func TestStepOrder(t *testing.T) {
	h := newHarness(t)
	// Step 1 before everything: chain mismatch between job and intent.
	j := h.withdrawal("so1", addrUser, 500, 0, "alice")
	j.Chain = "other"
	h.mustReject(j, ReasonIntent)
	// Step 1: garbage intent, unknown kind.
	j = h.withdrawal("so2", addrUser, 500, 0, "alice")
	j.Intent = []byte(`{"Kind":"mint"}`)
	h.mustReject(j, ReasonIntent)
	// Step 2 before step 3: a bad tx with no approvals reports tx_mismatch.
	in := signjob.Intent{Kind: "withdrawal", ID: "w-so3", Asset: "ETH", To: addrUser.Hex(), Amount: "1"}
	h.mustReject(h.job("so3", in, h.ethTx(addrEvil, 1, 0)), ReasonTx)
	// Step 3 before step 4: over the cap and unapproved reports approval_invalid.
	h.mustReject(h.withdrawal("so4", addrUser, 9999, 0), ReasonApprovals)
	// Step 4 before step 5: over the cap at a nonce that is already taken reports the cap.
	h.mustSign(h.withdrawal("so5", addrUser, 500, 0, "alice"))
	h.mustReject(h.withdrawal("so6", addrUser, 9999, 0, "alice", "bob"), ReasonPerTxCap)
	// Step 5: another approved intent at a signed nonce.
	h.mustReject(h.withdrawal("so7", addrUser, 400, 0, "alice"), ReasonNonceTaken)
}

func TestReplacementAtSameNonce(t *testing.T) {
	h := newHarness(t)
	first := h.withdrawal("rp1", addrUser, 500, 0, "auto")
	d1 := h.mustSign(first)
	in := mustIntent(first.Intent)

	bump := func(id string, tip, cap int64) signjob.Job {
		spec := h.ethTx(addrUser, 500, 0)
		spec.tip, spec.feeCap = big.NewInt(tip), big.NewInt(cap)
		j := h.job(id, in, spec)
		j.Approvals = first.Approvals
		return j
	}
	d2 := h.mustSign(bump("rp2", 2e9, 6e9))
	if d2.Outcome != OutcomeSigned || string(d2.Sig) == string(d1.Sig) {
		t.Fatalf("replacement outcome %s", d2.Outcome)
	}
	h.mustReject(bump("rp3", 2e9, 6e9-1), ReasonFeeNotHigher) // fee cap lower than the last signed
	same := bump("rp4", 2e9, 6e9)                             // same fees as the last signed, different gas limit: a new digest, not a bump
	same.Payload, same.Digest = h.payloadFor(txSpec{nonce: 0, to: addrUser, value: big.NewInt(500), gas: 22000, tip: big.NewInt(2e9), feeCap: big.NewInt(6e9)})
	h.mustReject(same, ReasonFeeNotHigher)
	h.mustSign(bump("rp5", 3e9, 9e9))
	// The replacement did not count a second time against the daily cap.
	var sum string
	h.guardDB.QueryRow(context.Background(), `SELECT sum(amount)::text FROM signed_intents`).Scan(&sum)
	if sum != "500" {
		t.Fatalf("recorded amount %s, want 500", sum)
	}
	// Re-sending the first digest gives back its stored signature.
	again := first
	again.ID = "rp6"
	if d := h.mustSign(again); d.Outcome != OutcomeReplayed || string(d.Sig) != string(d1.Sig) {
		t.Fatalf("outcome %s", d.Outcome)
	}
}

func TestCancelConsumesNonce(t *testing.T) {
	h := newHarness(t)
	w := h.withdrawal("cn1", addrUser, 500, 4, "auto")
	h.mustSign(w)

	cin := signjob.Intent{Kind: "cancel", ID: "c-4", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}
	h.mustSign(h.job("cn2", cin, h.cancelTx(4))) // no approvals; replaces the stuck withdrawal

	// The withdrawal can no longer be re-signed, replaced, or re-issued at that nonce.
	again := w
	again.ID = "cn3"
	h.mustReject(again, ReasonNonceCancel)
	h.mustReject(h.withdrawal("cn4", addrUser, 400, 4, "auto"), ReasonNonceCancel)
	spec := h.ethTx(addrUser, 500, 4)
	spec.tip, spec.feeCap = big.NewInt(5e9), big.NewInt(9e9)
	bumped := h.job("cn5", mustIntent(w.Intent), spec)
	bumped.Approvals = w.Approvals
	h.mustReject(bumped, ReasonNonceCancel)

	// A cancel at a nonce nothing was signed at (the nonce of a refused job) is fine; the rate limit is 3 per hour.
	h.mustSign(h.job("cn6", signjob.Intent{Kind: "cancel", ID: "c-5", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}, h.cancelTx(5)))
	h.mustSign(h.job("cn7", signjob.Intent{Kind: "cancel", ID: "c-6", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}, h.cancelTx(6)))
	h.mustReject(h.job("cn8", signjob.Intent{Kind: "cancel", ID: "c-7", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}, h.cancelTx(7)), ReasonCancelRate)
	// A second cancel of the same nonce by another intent is refused.
	h.advance(2 * time.Hour)
	c2 := h.cancelTx(4)
	c2.tip, c2.feeCap = big.NewInt(5e9), big.NewInt(9e9)
	h.mustReject(h.job("cn9", signjob.Intent{Kind: "cancel", ID: "c-4b", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}, c2), ReasonNonceCancel)
	// A cancel to someone else's address is not a cancel.
	h.mustReject(h.job("cn10", signjob.Intent{Kind: "cancel", ID: "c-x", Asset: "ETH", To: addrEvil.Hex(), Amount: "0"}, h.cancelTx(8)), ReasonTx)
}

func TestCrashAfterClaimReturnsSameSignature(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Crash after signing, before completing: the guard committed, the job row was not updated.
	j := h.withdrawal("cr1", addrUser, 500, 0, "auto")
	h.put(j)
	claimed, err := signjob.Claim(ctx, h.biz, "w1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	crashed := h.gw.decide(ctx, claimed)
	if crashed.Outcome != OutcomeSigned {
		t.Fatalf("outcome %s %s", crashed.Outcome, crashed.Reason)
	}
	// While the lease is live nobody else can take it.
	if _, ok, _ := h.newGateway("w2").RunOnce(ctx); ok {
		t.Fatal("job reclaimed before its lease expired")
	}
	h.biz.Exec(ctx, `UPDATE sign_jobs SET locked_at = now() - interval '5 minutes' WHERE id='cr1'`)
	d, ok, err := h.newGateway("w2").RunOnce(ctx)
	if err != nil || !ok || d.Outcome != OutcomeReplayed || string(d.Sig) != string(crashed.Sig) {
		t.Fatalf("reclaim: %+v ok=%v err=%v", d, ok, err)
	}
	if n := h.signer.calls.Load(); n != 1 {
		t.Fatalf("signer called %d times, want 1", n)
	}
	got, _ := signjob.Get(ctx, h.biz, "cr1")
	if got.Status != signjob.StatusDone || string(got.Signature) != string(crashed.Sig) {
		t.Fatalf("job = %+v", got)
	}

	// Crash right after claiming, before anything was signed: the reclaim signs, once.
	j2 := h.withdrawal("cr2", addrUser, 500, 1, "auto")
	h.put(j2)
	if _, err := signjob.Claim(ctx, h.biz, "w1", time.Minute); err != nil {
		t.Fatal(err)
	}
	h.biz.Exec(ctx, `UPDATE sign_jobs SET locked_at = now() - interval '5 minutes' WHERE id='cr2'`)
	if d, _, _ := h.newGateway("w2").RunOnce(ctx); d.Outcome != OutcomeSigned {
		t.Fatalf("outcome %s", d.Outcome)
	}
	if n := h.signer.calls.Load(); n != 2 {
		t.Fatalf("signer called %d times, want 2", n)
	}
	// The stale first worker finishing late loses: it no longer holds the job.
	if err := signjob.Complete(ctx, h.biz, "cr2", "w1", []byte{1}); err == nil {
		t.Fatal("stale worker completed a job it lost")
	}
}

func TestTwoGatewaysRaceOnOneJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	j := h.withdrawal("race1", addrUser, 500, 0, "auto")
	h.put(j)
	claimed, err := signjob.Claim(ctx, h.biz, "w1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Both instances decide on the very same job at once (as after a lease expiry on a slow worker).
	const n = 8
	gws := []*Gateway{h.newGateway("a"), h.newGateway("b")}
	sigs := make([][]byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := gws[i%2].decide(ctx, claimed)
			if d.Outcome != OutcomeSigned && d.Outcome != OutcomeReplayed {
				t.Errorf("outcome %s %s", d.Outcome, d.Reason)
			}
			sigs[i] = d.Sig
		}()
	}
	wg.Wait()
	if c := h.signer.calls.Load(); c != 1 {
		t.Fatalf("signer called %d times, want exactly 1", c)
	}
	for _, s := range sigs {
		if string(s) != string(sigs[0]) {
			t.Fatal("instances returned different signatures")
		}
	}
	var rows int
	h.guardDB.QueryRow(ctx, `SELECT count(*) FROM signed_digests`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("guard has %d signature rows", rows)
	}
}

func TestTwoGatewaysDrainQueueOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const n = 12
	for i := 0; i < n; i++ {
		h.put(h.withdrawal(fmt.Sprintf("dq%d", i), addrUser, 100, uint64(i), "auto"))
	}
	var wg sync.WaitGroup
	for _, w := range []string{"a", "b", "c"} {
		gw := h.newGateway(w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, ok, err := gw.RunOnce(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if !ok {
					return
				}
			}
		}()
	}
	wg.Wait()
	if c := h.signer.calls.Load(); c != n {
		t.Fatalf("signer called %d times for %d jobs", c, n)
	}
	var done int
	h.biz.QueryRow(ctx, `SELECT count(*) FROM sign_jobs WHERE status='done'`).Scan(&done)
	if done != n {
		t.Fatalf("%d jobs done", done)
	}
}

// The unique keys of the guard refuse a double release even if the chain lock were bypassed.
func TestGuardUniqueKeysBackstopTheLock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	rel := Release{IntentID: "i1", IntentHash: []byte{1}, Kind: "withdrawal", Asset: "ETH", Amount: big.NewInt(1), Sender: "s",
		Nonce: 3, Digest: []byte{9}, Tip: big.NewInt(1), FeeCap: big.NewInt(2), Signature: []byte{5}, At: time.Now(), NewIntent: true}
	err := h.guard.Do(ctx, testChain, func(gt *GuardTx) error { return gt.Record(ctx, rel) })
	if err != nil {
		t.Fatal(err)
	}
	rel.IntentID = "i2"
	rel.Digest = []byte{8}
	if err := h.guard.Do(ctx, testChain, func(gt *GuardTx) error { return gt.Record(ctx, rel) }); err == nil {
		t.Fatal("a second intent claimed the same nonce")
	}
}
