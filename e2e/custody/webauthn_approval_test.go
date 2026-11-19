package custody_test

import (
	"strings"
	"testing"
	"time"
)

// A withdrawal is approved by one Ed25519 approver and one WebAuthn approver (a SIMULATED software authenticator; no hardware) through the core's
// API, and is signed and settles. An assertion made over another withdrawal's intent hash is accepted by the core (it does not judge it) and
// refused by the signing zone: nothing is paid and the hold is voided.
func TestWebAuthnApprovalThroughTheCoreAPI(t *testing.T) {
	s, _ := funded(t, opts{webauthn: true}, "c-wa", 8)

	dest := randAddr()
	w := s.withdraw("initiator", "k-wa-ok", "c-wa", "ETH", dest, eth(2)) // tier 2: two approvals
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	if code, out := s.approve("alice", w.ID); code != 200 {
		t.Fatalf("alice: %d %v", code, out)
	}
	if code, out := s.approveWebAuthn("dave", w.ID, w.ID); code != 200 {
		t.Fatalf("dave (WebAuthn): %d %v", code, out)
	}
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if s.ethBalance(dest).Cmp(eth(2)) != 0 {
		t.Fatalf("destination = %s", s.ethBalance(dest))
	}

	// The zone checks the challenge: dave's assertion over the first withdrawal's hash does not approve a second one.
	dest2 := randAddr()
	w2 := s.withdraw("initiator", "k-wa-wrong", "c-wa", "ETH", dest2, eth(2))
	if code, out := s.approve("alice", w2.ID); code != 200 {
		t.Fatalf("alice: %d %v", code, out)
	}
	if code, out := s.approveWebAuthn("dave", w2.ID, w.ID); code != 200 { // the core stores it
		t.Fatalf("dave (wrong hash): %d %v", code, out)
	}
	got := s.waitWd(w2.ID, "failed", 90*time.Second)
	if !strings.Contains(got.Reason, "gateway refused") {
		t.Fatalf("reason %q", got.Reason)
	}
	if s.ethBalance(dest2).Sign() != 0 {
		t.Fatal("paid out on an assertion over another withdrawal's hash")
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}
