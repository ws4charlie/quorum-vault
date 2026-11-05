package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

type unavailableErr struct{}

func (unavailableErr) Error() string           { return "service down" }
func (unavailableErr) SignerUnavailable() bool { return true }

// An availability failure of the signer never finishes the job: no failed, no rejected, nothing signed. The job is left to
// its lease and completes by itself, with one signature, when the signer is back. An HSM-style error still fails the job.
func TestSignerOutageLeavesJobPendingAndRecovers(t *testing.T) {
	h := newHarness(t)
	h.advance(0)
	j := h.withdrawal("outage-1", addrUser, 500, 0, "alice")
	var down = true
	h.signer.setBefore(func([32]byte) error {
		if down {
			return unavailableErr{}
		}
		return nil
	})
	h.put(j)
	d, ok, err := h.gw.RunOnce(context.Background())
	if err != nil || !ok {
		t.Fatalf("RunOnce: %v %v", ok, err)
	}
	if d.Outcome != OutcomeRetry {
		t.Fatalf("outcome %s (%s), want retry", d.Outcome, d.Reason)
	}
	got, _ := signjob.Get(context.Background(), h.biz, j.ID)
	if got.Status != signjob.StatusSigning || len(got.Signature) != 0 {
		t.Fatalf("job row %+v: an outage must leave the job signing, unsigned", got)
	}
	// more attempts during the same outage: still no terminal state, and only one ALERT per chain
	for i := 0; i < 3; i++ {
		d = h.gw.Process(context.Background(), got)
		if d.Outcome != OutcomeRetry {
			t.Fatalf("attempt %d: %s", i, d.Outcome)
		}
	}
	if n := len(h.gw.outages); n != 1 {
		t.Fatalf("outage state for %d chains, want 1", n)
	}
	// the signer returns; the reservation is stale after sign_timeout, so the same digest is signed again
	down = false
	h.advance(h.cfg.SignTimeout + 1)
	d = h.gw.Process(context.Background(), got)
	if d.Outcome != OutcomeSigned {
		t.Fatalf("after the outage: %s (%s)", d.Outcome, d.Reason)
	}
	h.checkSig(j.Digest, d.Sig)
	row, _ := signjob.Get(context.Background(), h.biz, j.ID)
	if row.Status != signjob.StatusDone {
		t.Fatalf("job not done: %+v", row)
	}
	if len(h.gw.outages) != 0 {
		t.Fatal("resume not recorded")
	}
	// A plain signer error (HSM path) still fails the job, as before.
	j2 := h.withdrawal("hsm-fail", addrUser, 500, 1, "alice")
	h.signer.setBefore(func([32]byte) error { return errors.New("CKR_DEVICE_ERROR") })
	if d := h.run(j2); d.Outcome != OutcomeFailed {
		t.Fatalf("HSM-style error: %s, want failed", d.Outcome)
	}
}
