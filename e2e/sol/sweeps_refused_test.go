package sole2e

import (
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

// A sweep the zone refuses by a rule, before anything is reserved or signed (here the zone's hourly sweep limit), ends as a failed sweep that the planner
// plans again: its nonce account is released unused, nothing is cancelled and nothing is parked for an operator (it used to be: the core asked for a cancel
// that the zone had to refuse, "ALERT: the gateway refused to cancel a nonce"). A refusal that goes on is not planned for ever: after six in a row the
// address is tried once a day, with one ALERT.
func TestSwFaultsRefusedByARuleIsReleasedAndBounded(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 4, minSweep: "5000000", batch: 3, sweepRetry: "1s", gwTweak: func(gf *gateway.File) {
		for k, c := range gf.Chains {
			c.SweepsPerHour = 1
			gf.Chains[k] = c
		}
	}})
	a := s.depositAddr("rf-a")
	s.paySOL(a, 2*oneSOL)
	s.waitDeposits("rf-a", 2*oneSOL, 0)
	s.waitSwept("the first sweep of the hour", "SOL", a)

	b := s.depositAddr("rf-b")
	s.paySOL(b, 2*oneSOL)
	s.waitDeposits("rf-b", 2*oneSOL, 0)
	refused := func() int {
		return s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND status='failed' AND failure_reason LIKE 'gateway refused: policy_sweep_rate%'`, s.chain)
	}
	s.waitFor(6*time.Minute, "six sweeps refused by the zone's hourly limit", func() bool { return refused() >= 6 })

	// nothing was parked, no nonce account is held, no cancel was asked for, and the refused jobs are rejected, never signed
	if n := s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND failure_reason LIKE 'parked:%'`, s.chain); n != 0 {
		t.Fatalf("%d sweeps parked for an operator", n)
	}
	if n := s.count(`SELECT count(*) FROM sol_nonce_allocations WHERE chain=$1 AND status IN ('allocated','broadcast')`, s.chain); n != 0 {
		t.Fatalf("%d nonce accounts are still held", n)
	}
	if n := s.count(`SELECT count(*) FROM sol_nonce_allocations WHERE chain=$1 AND status='released'`, s.chain); n < 6 {
		t.Fatalf("%d nonce accounts were released, want at least 6", n)
	}
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE starts_with(id, 'cancel:sweep:')`); n != 0 {
		t.Fatalf("%d cancel jobs for refused sweeps", n)
	}
	if fileContains(s.worker.log, "ALERT: the gateway refused to cancel a nonce") || fileContains(s.worker.log, "ALERT: parked for an operator") {
		t.Fatal("the worker parked a refused sweep")
	}
	// the bound: one ALERT, and no seventh sweep follows soon
	s.waitFor(30*time.Second, "the ALERT for sweeps that are refused every time", func() bool {
		return fileContains(s.worker.log, "the signing zone has refused the last sweeps of a deposit address every time")
	})
	before := len(s.sweeps())
	s.holds(20*time.Second, "no further sweep is planned for the address", func() bool { return len(s.sweeps()) == before })
	if s.lamports(b) != 2*oneSOL {
		t.Fatalf("the deposit address of a refused sweep holds %d lamports", s.lamports(b))
	}
	for _, w := range s.sweeps() {
		if strings.HasPrefix(w.Reason, "parked:") {
			t.Fatalf("sweep %s parked: %s", w.ID, w.Reason)
		}
	}
	s.reconcileClean("after the refused sweeps")
}
