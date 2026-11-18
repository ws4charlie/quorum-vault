package btce2e

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Manual CPFP: an operator starts the child of a stuck send at once (POST /v2/withdrawals/{id}/cpfp). The zone's CPFP check is the same as for the
// automatic child; the route is audited by the core. cpfp_after is off in these tests: the manual call needs no automatic trigger.

// manualOpts: one replacement, then RBF is exhausted; no automatic child.
func manualOpts() opts {
	return opts{withdraw: true, noEstimate: true, fallbackRate: 1, stuckAfter: "3s", maxReplacements: 1}
}

// startCPFP is the operator's call for the withdrawal's child.
func (s *system) startCPFP(actor, wdID string) (int, map[string]any) {
	s.t.Helper()
	return s.callWith("POST", "/v2/withdrawals/"+wdID+"/cpfp", map[string]string{"X-Actor": actor}, map[string]any{})
}

// childJob is the child's first job in an answer of the route.
func childJob(t *testing.T, out map[string]any) (job string, existing bool) {
	t.Helper()
	c, _ := out["child"].(map[string]any)
	job, _ = c["child_job"].(string)
	existing, _ = c["existing"].(bool)
	if job == "" {
		t.Fatalf("no child in the answer: %v", out)
	}
	return job, existing
}

// With cpfp_after off, the call starts the child now; the pair confirms and is booked as an automatic child is; a repeat returns the same child.
func TestCPFPManualPullsAStuckWithdrawalIn(t *testing.T) {
	s := newSystem(t, manualOpts())
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitAttempts("send", 2, 60*time.Second) // the one replacement
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	if c := s.confs(parent); c != 0 {
		t.Fatalf("the parent has %d confirmations: the miner must leave it in the mempool", c)
	}
	// The roles and the kind of caller are checked before anything else: a requester cannot.
	if code, out := s.startCPFP("ini", w.ID); code != http.StatusForbidden {
		t.Fatalf("a requester started a child: %d %v", code, out)
	}
	if n := s.attempts("cpfp"); n != 0 {
		t.Fatalf("%d children before the call", n)
	}
	code, out := s.startCPFP("ops", w.ID)
	if code != http.StatusAccepted {
		t.Fatalf("start the child: %d %v", code, out)
	}
	job, existing := childJob(t, out)
	if existing {
		t.Fatal("the first call found a child")
	}
	child, cp := s.childOf(parent)
	s.assertChild(cp, parent)
	// Repeat: the same child, no second one.
	code, out = s.startCPFP("ops", w.ID)
	if job2, existing := childJob(t, out); code != http.StatusAccepted || job2 != job || !existing {
		t.Fatalf("the repeat: %d %v (want the child %s, existing)", code, out, job)
	}
	pf, cf := s.attemptFee(parent), s.attemptFee(child)
	s.node.mine(1, "")
	if s.confs(parent) < 1 || s.confs(child) < 1 {
		t.Fatalf("the parent (%d) and the child (%d) must be in the same block", s.confs(parent), s.confs(child))
	}
	s.node.mine(1, "")
	got := s.waitWd(w.ID, "confirmed", 90*time.Second)
	if got.Tx != parent {
		t.Fatalf("the withdrawal confirmed as %s, the parent is %s", got.Tx, parent)
	}
	if fee := s.withdrawalFee(w.ID); fee != pf+cf {
		t.Fatalf("booked fee %d, want the parent's %d plus the child's %d", fee, pf, cf)
	}
	if n := s.attempts("cpfp"); n != 1 {
		t.Fatalf("%d children: one child per parent", n)
	}
	// Decided: a call now is refused.
	if code, out := s.startCPFP("ops", w.ID); code != http.StatusConflict {
		t.Fatalf("a call after confirmation: %d %v", code, out)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// A batch is pulled in by the call for any of its members.
func TestCPFPManualPullsABatchIn(t *testing.T) {
	s := batchSystem(t, manualOpts(), batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	s.waitAttempts("send", 2, 60*time.Second)
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	if code, out := s.startCPFP("ops", ws[1].ID); code != http.StatusAccepted {
		t.Fatalf("start the child: %d %v", code, out)
	}
	child, cp := s.childOf(parent)
	s.assertChild(cp, parent)
	if code, out := s.startCPFP("ops", ws[0].ID); code != http.StatusAccepted {
		t.Fatalf("the repeat through the other member: %d %v", code, out)
	} else if _, existing := childJob(t, out); !existing {
		t.Fatalf("the repeat built a second child: %v", out)
	}
	s.node.mine(1, "")
	if s.confs(parent) < 1 || s.confs(child) < 1 {
		t.Fatal("the batch and its child must be in the same block")
	}
	got := s.mineBatch(b.ID)
	if want := s.attemptFee(parent) + s.attemptFee(child); got.Fee != want || got.Tx != parent {
		t.Fatalf("batch %+v, want fee %d (batch and child together) in %s", got, want, parent)
	}
	if n := s.attempts("cpfp"); n != 1 {
		t.Fatalf("%d children", n)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// A withdrawal that is not broadcast (it waits in the batch queue) has nothing to pull in.
func TestCPFPManualRefusedWhenNotBroadcast(t *testing.T) {
	s := batchSystem(t, manualOpts(), batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	w := s.payQ(5_000_000)
	code, out := s.startCPFP("ops", w.ID)
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), "not broadcast") {
		t.Fatalf("a queued withdrawal: %d %v", code, out)
	}
	if code, _ := s.startCPFP("ops", "no-such-withdrawal"); code != http.StatusNotFound {
		t.Fatalf("an unknown withdrawal: %d", code)
	}
}

// A send that already pays the rate ceiling has no room for a child that raises the package rate: 409 with the reason, and nothing was built.
func TestCPFPManualRefusedWithNoRoom(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, noEstimate: true, fallbackRate: 1, maxFeeRate: 1})
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 10_000_000)
	s.waitAttempts("send", 1, 60*time.Second)
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	code, out := s.startCPFP("ops", w.ID)
	if msg, _ := out["error"].(string); code != http.StatusConflict || !(strings.Contains(msg, "room") || strings.Contains(msg, "does not raise")) {
		t.Fatalf("no room: %d %v", code, out)
	}
	if n := s.attempts("cpfp"); n != 0 {
		t.Fatalf("%d children", n)
	}
}
