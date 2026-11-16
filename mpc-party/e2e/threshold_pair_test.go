package e2e

import (
	"strings"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// B and C reconcile a 2-of-3 keyset with each other while A is down, when nothing can be pending from A (treconcile.go). B leads,
// C follows; both mark the keyset partial, and A's full reconciliation runs when it is back.

const (
	pairLogB = `keyset reconciled with one member only`
	// B waits this long without A before it tries (pairGrace); the tests wait a bit more than that for a refusal to show.
	pairWait = 15 * time.Second
)

// waitLog waits until a party's stderr contains s.
func (cl *cluster3) waitLog(t *testing.T, role, s string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(cl.procs[role].stderr.String(), s) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("party %s never logged %q:\n%s", role, s, tail(cl.procs[role].stderr.String()))
}

// aBack starts A again and checks that its full reconciliation ran: all three resolved on one generation, A logged the proof, every
// pair signs.
func (cl *cluster3) aBack(t *testing.T, id string, pub []byte, tag string) uint64 {
	t.Helper()
	cl.start(t, "A")
	cl.waitReady(t)
	g := cl.waitConverged3(t, id, true)
	cl.waitLog(t, "A", `keyset reconciled and proven`, 20*time.Second)
	cl.signEveryPair(t, id, pub, tag)
	return g
}

// A down, B restarts, then C restarts: each becomes resolved with the other member, B+C sign; A returns and reconciles all three.
func TestThresholdBCReconcileAfterRestart(t *testing.T) {
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, nil)
		pub := cl.dkg(t, "k")
		cl.sign(t, "A", "k", "a1", 1, pub)
		g0 := cl.waitConverged3(t, "k", true)
		cl.stop("A")
		for i, member := range []string{"B", "C"} {
			cl.restart(t, member)
			cl.waitUp(t, member)
			// B coordinates: with B restarted it reconciles with C itself; with C restarted B learns at the first signature that C is
			// unresolved and reconciles again.
			cl.signUntil(t, "B", "k", "bc-"+member, 20+i, pub)
			if !strings.Contains(cl.procs["B"].stderr.String(), pairLogB) {
				t.Fatalf("B did not log the pair reconciliation after %s restarted:\n%s", member, tail(cl.procs["B"].stderr.String()))
			}
			// C is resolved too (it only follows), on the same generation
			hc := statusOf(cl.health(t)["C"], "k")
			if hc == nil || !hc.Resolved || hc.Generation != g0 {
				t.Fatalf("after %s restarted C is %v, want resolved on generation %d", member, hc, g0)
			}
		}
		if g := cl.aBack(t, "k", pub, "pair"); g != g0 {
			t.Fatalf("generation %d after the pair reconciliations, want %d", g, g0)
		}
	})
}

// With A up, B's restart is reconciled by A, not by the pair: B waits for A.
func TestThresholdBCDoesNotPairWhileAIsUp(t *testing.T) {
	cl := newCluster3(t, nil)
	pub := cl.dkg(t, "k")
	cl.restart(t, "B")
	cl.waitReady(t)
	cl.waitConverged3(t, "k", true)
	cl.sign(t, "A", "k", "after-b", 2, pub)
	cl.restart(t, "C")
	cl.waitReady(t)
	cl.waitConverged3(t, "k", true)
	time.Sleep(pairWait) // past B's grace: nothing is unresolved, and nothing was reconciled by the pair
	if s := cl.procs["B"].stderr.String(); strings.Contains(s, pairLogB) || strings.Contains(s, "pair reconciliation with C pending") {
		t.Fatalf("B reconciled with C while A was up:\n%s", tail(s))
	}
}

// A down with a refresh candidate on B or on C: B+C do not reconcile (A may have decided it), say why, keep the keyset unresolved;
// when A returns it reconciles all three and signing resumes. Each member: the candidate stored and the process killed at that point
// of A's refresh, A killed, the members restarted.
func TestThresholdBCRefusesWithCandidate(t *testing.T) {
	for _, holder := range []string{"B", "C"} {
		holder := holder
		t.Run("candidate on "+holder, func(t *testing.T) {
			cl := newCluster3(t, nil)
			pub := cl.dkg(t, "k")
			g0 := cl.waitConverged3(t, "k", true)
			fp := map[string]string{"B": "b_after_candidate_stored", "C": "c_after_candidate_stored"}[holder]
			cl.armed(t, holder, fp)
			cl.waitConverged3(t, "k", true)
			cl.client["A"].Refresh(ctx(t, 3*time.Minute), &pb.RefreshRequest{KeysetId: "k", Admin: cl.env.Admin("refresh", "k")})
			cl.diedAt(t, holder)
			cl.stop("A")
			// both members restart and are unresolved; B stores its candidate before C, so B holds one in both cases
			cl.restart(t, "C")
			cl.restart(t, "B")
			cl.waitUp(t, "B")
			cl.waitUp(t, "C")
			cl.waitLog(t, "B", "a commit may be unfinished", pairWait+10*time.Second)
			for _, role := range []string{"B", "C"} {
				ks := statusOf(cl.health(t)[role], "k")
				if ks == nil || ks.Resolved {
					t.Fatalf("party %s is %v, want unresolved (a candidate is pending)", role, ks)
				}
			}
			if _, err := cl.signRaw("B", "k", "must-wait", 5); err == nil {
				t.Fatal("B signed with a candidate pending and A down")
			} else {
				wantKind(t, err, pb.ErrorKind_ERROR_KIND_UNAVAILABLE)
			}
			if strings.Contains(cl.procs["B"].stderr.String(), pairLogB) {
				t.Fatal("B reconciled with C with a candidate pending")
			}
			// A returns: it decides the candidate's fate, all three converge on the old or the new generation
			cl.start(t, "A")
			cl.waitReady(t)
			g1 := cl.waitConverged3(t, "k", true)
			if g1 != g0 && g1 != g0+1 {
				t.Fatalf("generation %d is neither %d nor %d", g1, g0, g0+1)
			}
			cl.waitLog(t, "A", `keyset reconciled and proven`, 20*time.Second)
			cl.signEveryPair(t, "k", pub, "after-candidate")
		})
	}
}

// A down and B restored from a backup older than C: B refuses to reconcile with C and stays out; C is not touched. A returns and
// flags the stale member as it always did.
func TestThresholdBCRefusesStaleRestore(t *testing.T) {
	cl := newCluster3(t, nil)
	pub := cl.dkg(t, "k")
	cl.sign(t, "A", "k", "a1", 1, pub)
	cl.stop("B")
	old := copyDir(t, cl.cfgs["B"].DataDir)
	cl.start(t, "B")
	cl.waitReady(t)
	cl.waitConverged3(t, "k", true)
	cl.refresh(t, "k")
	cl.waitConverged3(t, "k", true)
	cl.stop("A")
	cl.stop("B")
	replaceDir(t, cl.cfgs["B"].DataDir, old)
	cl.start(t, "B")
	cl.waitUp(t, "B")
	cl.waitLog(t, "B", "generations 1 and 2", pairWait+10*time.Second)
	hb := statusOf(cl.health(t)["B"], "k")
	hc := statusOf(cl.health(t)["C"], "k")
	if hb == nil || hb.Resolved || hb.Generation != 1 {
		t.Fatalf("the stale B must stay unresolved on generation 1, got %v", hb)
	}
	if hc == nil || !hc.Resolved || hc.Generation != 2 {
		t.Fatalf("C must be untouched (resolved, generation 2), got %v", hc)
	}
	if _, err := cl.signRaw("B", "k", "stale", 6); err == nil {
		t.Fatal("the stale B signed")
	}
	// A returns: it refuses the stale member (the alert names it), and A+C sign
	cl.start(t, "A")
	cl.waitReady(t)
	cl.waitLog(t, "A", "ALERT keyset cannot be reconciled", 20*time.Second)
	cl.signUntil(t, "A", "k", "ac-after-stale", 7, pub)
	hc = statusOf(cl.health(t)["C"], "k")
	if hc == nil || !hc.Resolved || hc.Generation != 2 {
		t.Fatalf("C after A returned: %v", hc)
	}
}

// Crash at each step of the pair reconciliation: B dies after the plan, B dies before the confirmation, C dies after the plan. The
// pair reconciliation changes nothing durable, so after the restart it runs again and B+C sign; A returns and reconciles all three.
func TestThresholdBCCrashMatrix(t *testing.T) {
	steps := []struct{ name, role, what string }{
		{"pair_lead_after_plan", "B", "B sent the plan, before the self-test"},
		{"pair_follow_after_plan", "C", "C accepted the plan, before the self-test"},
		{"pair_lead_before_confirm", "B", "both proved the key, B did not confirm"},
	}
	for _, st := range steps {
		st := st
		t.Run(st.name+"@"+st.role, func(t *testing.T) {
			cl := newCluster3(t, nil)
			pub := cl.dkg(t, "k")
			g0 := cl.waitConverged3(t, "k", true)
			cl.stop("A")
			// C restarted first, so that B's restart makes both unresolved; the armed one dies when the pair reconciliation reaches the step
			if st.role == "C" {
				cl.restart(t, "C", "QV_FAILPOINT="+st.name)
				cl.restart(t, "B")
			} else {
				cl.restart(t, "C")
				cl.restart(t, "B", "QV_FAILPOINT="+st.name)
			}
			cl.waitUp(t, "B")
			cl.waitUp(t, "C")
			cl.diedAt(t, st.role)
			t.Logf("died at %s (%s)", st.name, st.what)
			cl.restart(t, st.role)
			cl.waitUp(t, st.role)
			cl.signUntil(t, "B", "k", "after-pair-crash", 8, pub)
			for _, role := range []string{"B", "C"} {
				ks := statusOf(cl.health(t)[role], "k")
				if ks == nil || !ks.Resolved || ks.Generation != g0 || ks.Frozen {
					t.Fatalf("party %s after the crash: %v", role, ks)
				}
			}
			if g := cl.aBack(t, "k", pub, "crash"); g != g0 {
				t.Fatalf("generation %d, want %d", g, g0)
			}
		})
	}
}
