package gateway

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// --- finding 1: the signer runs outside the lock and outside any transaction ---

func claim(t *testing.T, h *harness, j signjob.Job, worker string) signjob.Job {
	t.Helper()
	h.put(j)
	c, err := signjob.Claim(context.Background(), h.biz, worker, time.Minute)
	if err != nil || c.ID != j.ID {
		t.Fatalf("claim %s: %+v %v", j.ID, c.ID, err)
	}
	return c
}

func TestSlowSignerDoesNotBlockOtherJobsOnTheChain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := claim(t, h, h.withdrawal("slowA", addrUser, 100, 0, "auto"), "wa")
	b := claim(t, h, h.withdrawal("slowB", addrUser, 100, 1, "auto"), "wb")
	release := make(chan struct{})
	entered := make(chan struct{})
	h.signer.setBefore(func(d [32]byte) error {
		if string(d[:]) == string(a.Digest) {
			close(entered)
			<-release
		}
		return nil
	})
	doneA := make(chan Decision, 1)
	go func() { doneA <- h.newGateway("wa").Process(ctx, a) }()
	<-entered // A is inside the signer now
	start := time.Now()
	if d := h.newGateway("wb").Process(ctx, b); d.Outcome != OutcomeSigned {
		t.Fatalf("B: %s %s", d.Outcome, d.Reason)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("B waited for A")
	}
	close(release)
	if d := <-doneA; d.Outcome != OutcomeSigned {
		t.Fatalf("A: %s %s", d.Outcome, d.Reason)
	}
}

func TestSignerTimeoutFailsJobAndGatewayKeepsWorking(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.cfg.SignTimeout = 300 * time.Millisecond
	hang := make(chan struct{})
	defer close(hang)
	h.signer.setBefore(func(d [32]byte) error { <-hang; return nil }) // ignores its context
	bad := h.withdrawal("to1", addrUser, 100, 0, "auto")
	start := time.Now()
	d := h.run(bad)
	if d.Outcome != OutcomeFailed || time.Since(start) > 3*time.Second {
		t.Fatalf("outcome %s %s after %s", d.Outcome, d.Reason, time.Since(start))
	}
	if j, _ := signjob.Get(ctx, h.biz, "to1"); j.Status != signjob.StatusFailed {
		t.Fatalf("job status %s", j.Status)
	}
	// The reservation stays: its amount still counts and its nonce is taken.
	var n int
	h.guardDB.QueryRow(ctx, `SELECT count(*) FROM signed_digests WHERE signature IS NULL`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d reservations", n)
	}
	// The gateway keeps working with a healthy signer.
	h.signer.setBefore(func(d [32]byte) error { return nil })
	h.mustSign(h.withdrawal("to2", addrUser, 100, 1, "auto"))
	// A signer error behaves the same: failed job, reservation kept, a cancel can release the nonce.
	h.signer.setBefore(func(d [32]byte) error { return errors.New("hsm offline") })
	if d := h.run(h.withdrawal("to3", addrUser, 100, 2, "auto")); d.Outcome != OutcomeFailed {
		t.Fatalf("outcome %s", d.Outcome)
	}
	h.signer.setBefore(nil)
	h.signer.before.Store(nil)
	h.mustSign(h.job("to4", signjob.Intent{Kind: "cancel", ID: "c-2", Asset: "ETH", To: h.hot.Hex(), Amount: "0"}, h.cancelTx(2)))
	// Cap usage of the failed withdrawals stayed counted (3 x 100 recorded).
	var sum string
	h.guardDB.QueryRow(ctx, `SELECT sum(amount)::text FROM signed_intents WHERE kind='withdrawal'`).Scan(&sum)
	if sum != "300" {
		t.Fatalf("counted %s, want 300", sum)
	}
}

func TestTwoGatewaysOnReservedDigestOneSignsOtherRetries(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	j := claim(t, h, h.withdrawal("res1", addrUser, 100, 0, "auto"), "w1")
	release, entered := make(chan struct{}), make(chan struct{})
	h.signer.setBefore(func(d [32]byte) error { close(entered); <-release; return nil })
	first := make(chan Decision, 1)
	go func() { first <- h.newGateway("a").decide(ctx, j) }()
	<-entered
	if d := h.newGateway("b").decide(ctx, j); d.Outcome != OutcomeRetry {
		t.Fatalf("second gateway: %s %s, want retry", d.Outcome, d.Reason)
	}
	close(release)
	d1 := <-first
	if d1.Outcome != OutcomeSigned {
		t.Fatalf("first gateway: %s %s", d1.Outcome, d1.Reason)
	}
	if d := h.newGateway("b").decide(ctx, j); d.Outcome != OutcomeReplayed || string(d.Sig) != string(d1.Sig) {
		t.Fatalf("later: %s", d.Outcome)
	}
	if n := h.signer.calls.Load(); n != 1 {
		t.Fatalf("signer called %d times", n)
	}
}

func TestCrashAfterReserveBeforeSign(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	j := claim(t, h, h.withdrawal("cs1", addrUser, 100, 0, "auto"), "w1")
	// A worker reserved the digest and died: no signer call, no signature.
	h.signer.setBefore(func(d [32]byte) error { return errors.New("process died") })
	if d := h.gw.decide(ctx, j); d.Outcome != OutcomeFailed {
		t.Fatalf("setup: %s", d.Outcome)
	}
	h.signer.before.Store(nil)
	before := h.signer.calls.Load()

	// Younger than sign_timeout: someone may still be signing.
	if d := h.newGateway("w2").decide(ctx, j); d.Outcome != OutcomeRetry {
		t.Fatalf("fresh reservation: %s %s", d.Outcome, d.Reason)
	}
	h.advance(h.cfg.SignTimeout + time.Second)
	d := h.newGateway("w2").decide(ctx, j)
	if d.Outcome != OutcomeSigned {
		t.Fatalf("stale reservation: %s %s", d.Outcome, d.Reason)
	}
	h.checkSig(j.Digest, d.Sig)
	if n := h.signer.calls.Load() - before; n != 1 {
		t.Fatalf("signed %d times after the crash, want 1", n)
	}
	if d2 := h.newGateway("w3").decide(ctx, j); d2.Outcome != OutcomeReplayed || string(d2.Sig) != string(d.Sig) {
		t.Fatalf("after: %s", d2.Outcome)
	}
}

func TestRacedSignaturesStoreOneAndBothCallersGetIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	j := claim(t, h, h.withdrawal("fin1", addrUser, 100, 0, "auto"), "w1")
	// Reserve only.
	h.signer.setBefore(func(d [32]byte) error { return errors.New("stop") })
	h.gw.decide(ctx, j)
	h.signer.before.Store(nil)

	sigs := [][]byte{make([]byte, 64), make([]byte, 64)}
	sigs[0][0], sigs[1][0] = 1, 2
	got := make([][]byte, 2)
	var wg sync.WaitGroup
	for i := range sigs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if got[i], err = h.guard.Finish(ctx, j.Digest, sigs[i], time.Now()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if string(got[0]) != string(got[1]) {
		t.Fatal("callers got different signatures")
	}
	if _, err := h.guard.Finish(ctx, []byte("nope"), sigs[0], time.Now()); err == nil {
		t.Fatal("finished a digest that was never reserved")
	}
}

func TestReplacementCannotUndercutAnUnsignedReservation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	first := h.withdrawal("ru1", addrUser, 100, 0, "auto")
	h.put(first)
	c, _ := signjob.Claim(ctx, h.biz, "w1", time.Minute)
	h.signer.setBefore(func(d [32]byte) error { return errors.New("stop") })
	h.gw.decide(ctx, c) // reserved, unsigned, failed
	h.signer.before.Store(nil)
	spec := h.ethTx(addrUser, 100, 0)
	spec.gas = 22000 // new digest, same fees
	low := h.job("ru2", mustIntent(first.Intent), spec)
	low.Approvals = first.Approvals
	h.mustReject(low, ReasonFeeNotHigher)
}

// Signatures per second on one chain, 8 concurrent gateway workers, signer latency 100 ms.
func TestThroughputOneChainSlowSigner(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.signer.setBefore(func(d [32]byte) error { time.Sleep(100 * time.Millisecond); return nil })
	const jobs, workers = 48, 8
	for i := 0; i < jobs; i++ {
		h.put(h.withdrawal("tp"+string(rune('A'+i/26))+string(rune('a'+i%26)), addrUser, 1, uint64(i), "auto"))
	}
	var done atomic.Int32
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < workers; w++ {
		gw := h.newGateway("tp" + string(rune('0'+w)))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				d, ok, err := gw.RunOnce(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if !ok {
					return
				}
				if d.Outcome != OutcomeSigned {
					t.Errorf("outcome %s %s", d.Outcome, d.Reason)
				}
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	el := time.Since(start)
	rate := float64(done.Load()) / el.Seconds()
	t.Logf("THROUGHPUT: %d signatures in %s = %.1f signatures/s (8 workers, 100 ms signer, one chain)", done.Load(), el.Round(time.Millisecond), rate)
	if done.Load() != jobs || rate < 30 {
		t.Fatalf("done %d, %.1f/s: signing is serialized", done.Load(), rate)
	}
}

// --- finding 2: approvals expire ---

func TestAttackExpiredApprovedIntentReenqueued(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Approved, then the customer cancelled before signing: nothing was signed, so the guard has no record.
	in := signjob.Intent{Kind: "withdrawal", ID: "w-old", Asset: "ETH", To: addrEvil.Hex(), Amount: "100", NotAfter: h.clock().Add(time.Hour).Unix()}
	old := h.job("ex0", in, h.ethTx(addrEvil, 100, 0), "auto")
	h.put(old)
	h.biz.Exec(ctx, `DELETE FROM sign_jobs`) // the hold was voided and the job dropped
	h.advance(2 * time.Hour)
	again := old
	again.ID = "ex1"
	h.mustReject(again, ReasonExpired)
	if h.signer.calls.Load() != 0 {
		t.Fatal("signed")
	}
}

func TestIntentNotAfterBounds(t *testing.T) {
	h := newHarness(t)
	now := h.clock()
	mk := func(id string, na int64, nonce uint64) signjob.Job {
		in := signjob.Intent{Kind: "withdrawal", ID: "w-" + id, Asset: "ETH", To: addrUser.Hex(), Amount: "100", NotAfter: na}
		h.noExpiry = na == 0
		defer func() { h.noExpiry = false }()
		return h.job(id, in, h.ethTx(addrUser, 100, nonce), "auto")
	}
	h.mustReject(mk("nb0", 0, 0), ReasonExpired)
	h.mustReject(mk("nb1", now.Add(-time.Second).Unix(), 0), ReasonExpired)
	h.mustReject(mk("nb2", now.Add(25*time.Hour).Unix(), 0), ReasonExpired)
	h.mustSign(mk("nb3", now.Add(23*time.Hour).Unix(), 0))
}

func TestReplacementOfKnownExpiredIntentIsAccepted(t *testing.T) {
	h := newHarness(t)
	first := h.withdrawal("kx1", addrUser, 500, 0, "auto")
	h.mustSign(first)
	h.advance(48 * time.Hour) // far past not_after
	spec := h.ethTx(addrUser, 500, 0)
	spec.tip, spec.feeCap = big.NewInt(2e9), big.NewInt(6e9)
	bump := h.job("kx2", mustIntent(first.Intent), spec)
	bump.Approvals = first.Approvals
	if d := h.mustSign(bump); d.Outcome != OutcomeSigned {
		t.Fatalf("outcome %s", d.Outcome)
	}
	// It still may not move to another nonce.
	spec = h.ethTx(addrUser, 500, 1)
	spec.tip, spec.feeCap = big.NewInt(3e9), big.NewInt(9e9)
	moved := h.job("kx3", mustIntent(first.Intent), spec)
	moved.Approvals = first.Approvals
	h.mustReject(moved, ReasonNonceChanged)
}
