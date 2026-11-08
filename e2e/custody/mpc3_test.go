package custody_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Degraded running of the 2-of-3 signer (E23-3): with any ONE of the three parties down, withdrawals keep going. The gateway calls party A
// first and party B when A is down; A uses B and then C; B uses C. Where the degraded period shows:
//
//	A down: the gateway logs "ALERT mpc signer degraded" once when it starts signing through B (and an INFO "mpc signer recovered" once when A signs again)
//	B or C down: the parties that dial it log "ALERT mpc party link down" once (A for B; A and B for C), and Health of every party shows
//	             peers[].reachable=false for it.
//
// Per transition, never per withdrawal.
func TestMPCOnePartyDownWithdrawalsContinue(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{}, "c-one", 40)
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("one party down, at " + current)
		}
	})
	mpc := s.mpc
	for vi, victim := range []string{"A", "B", "C"} {
		current = victim + " down"
		degraded := s.gwLogCount("ALERT mpc signer degraded")
		recovered := s.gwLogCount("mpc signer recovered")
		linkA := mpc.A.CountLog("ALERT mpc party link down")
		linkB := mpc.B.CountLog("ALERT mpc party link down")

		mpc.Party(victim).Kill()
		for i := 0; i < 4; i++ { // several withdrawals: the alert must still be ONE per transition
			id, dest := s.startPayment("c-one", fmt.Sprintf("k-one-%d-%d", vi, i))
			s.mustPayOnce(id, dest, 150*time.Second)
		}
		switch victim {
		case "A":
			if got := s.gwLogCount("ALERT mpc signer degraded") - degraded; got != 1 {
				t.Fatalf("A down: %d degraded ALERTs from the gateway for 4 withdrawals, want exactly 1", got)
			}
		case "B":
			s.waitFor(30*time.Second, "A to log that B is unreachable", func() bool { return mpc.A.CountLog("ALERT mpc party link down") > linkA })
			if got := mpc.A.CountLog("ALERT mpc party link down") - linkA; got != 1 {
				t.Fatalf("B down: %d link ALERTs from A, want exactly 1", got)
			}
		case "C":
			s.waitFor(30*time.Second, "A and B to log that C is unreachable", func() bool {
				return mpc.A.CountLog("ALERT mpc party link down") > linkA && mpc.B.CountLog("ALERT mpc party link down") > linkB
			})
			if a, b := mpc.A.CountLog("ALERT mpc party link down")-linkA, mpc.B.CountLog("ALERT mpc party link down")-linkB; a != 1 || b != 1 {
				t.Fatalf("C down: link ALERTs A %d B %d, want 1 and 1", a, b)
			}
		}
		if victim != "A" {
			if got := s.gwLogCount("ALERT mpc signer degraded") - degraded; got != 0 {
				t.Fatalf("%s down: the gateway logged %d degraded ALERTs although party A coordinated", victim, got)
			}
			// the other parties' Health shows it, which is what operators look at
			h, err := mpc.Health()
			if err != nil {
				t.Fatal(err)
			}
			seen := false
			for _, p := range h.Peers {
				if p.Name == victim && !p.Reachable {
					seen = true
				}
			}
			if !seen {
				t.Fatalf("A's Health does not show %s unreachable: %v", victim, h.Peers)
			}
		}
		if n := s.badJobs(); n != 0 {
			t.Fatalf("%s down: %d sign jobs failed or were rejected; one party down must not even delay", victim, n)
		}
		s.finish()

		// the party comes back; withdrawals go on, the first coordinator is used again (one INFO for A)
		mpc.Party(victim).Start(t)
		mpc.WaitReady(120 * time.Second)
		id, dest := s.startPayment("c-one", fmt.Sprintf("k-one-%d-back", vi))
		s.mustPayOnce(id, dest, 150*time.Second)
		if victim == "A" {
			// the gateway's connection to A reconnects within seconds; keep paying until it signs through A again
			for i := 0; s.gwLogCount("mpc signer recovered")-recovered == 0 && i < 20; i++ {
				id, dest := s.startPayment("c-one", fmt.Sprintf("k-one-%d-back-%d", vi, i))
				s.mustPayOnce(id, dest, 150*time.Second)
			}
			if got := s.gwLogCount("mpc signer recovered") - recovered; got != 1 {
				t.Fatalf("A back: %d recovered lines, want exactly 1", got)
			}
		}
		s.finish()
		t.Logf("%s down: 4 withdrawals settled once each, no failed job, one degraded alert, Reconcile clean; back: signing continues", victim)
	}
}

// A restarts while C is down: A reconciles with B alone (the pairwise reconciliation of E23-2) and signs; C returns and is reconciled.
func TestMPCRestartOfAWhileCIsDown(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{}, "c-ra", 20)
	mpc := s.mpc
	mpc.C.Kill()
	mpc.A.Kill()
	mpc.A.Start(t)
	mpc.WaitSigning(90 * time.Second)
	var ids []string
	for i := 0; i < 3; i++ {
		id, dest := s.startPayment("c-ra", fmt.Sprintf("k-ra-%d", i))
		ids = append(ids, id)
		s.mustPayOnce(id, dest, 150*time.Second)
	}
	if !strings.Contains(mpc.A.Output(), "keyset reconciled with one member only") {
		t.Fatal("A did not reconcile with B alone")
	}
	mpc.C.Start(t)
	mpc.WaitReady(120 * time.Second) // C is reconciled across all three
	id, dest := s.startPayment("c-ra", "k-ra-after")
	s.mustPayOnce(id, dest, 150*time.Second)
	s.finish()
	_ = ids
}
