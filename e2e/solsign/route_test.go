package solsign_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	st "github.com/ws4charlie/quorum-vault/internal/chain/sol/soltest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
)

// The routing of 2-of-3 signatures for Solana (MPC-routing): the operators' signed preferred pair and the health-driven fallback, with the
// Ed25519 hot shard. The same router as for EVM; these tests show it end to end on the validator.

func (s *stack) pairs() (pref, eff string) {
	b, _ := os.ReadFile(s.metrics)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasSuffix(line, " 1") {
			for _, p := range mpcsigner.PairOrder {
				if strings.HasPrefix(line, fmt.Sprintf(`qv_mpc_preferred_pair{pair=%q}`, string(p))) {
					pref = string(p)
				}
				if strings.HasPrefix(line, fmt.Sprintf(`qv_mpc_effective_pair{pair=%q}`, string(p))) {
					eff = string(p)
				}
			}
		}
	}
	return pref, eff
}

func (s *stack) waitPairs(pref, eff string, d time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(d)
	var gp, ge string
	for time.Now().Before(deadline) {
		if gp, ge = s.pairs(); gp == pref && ge == eff {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.t.Fatalf("waited %s for preferred %s and effective %s; metrics say %q and %q\n%s", d, pref, eff, gp, ge, tailOf(s.gw.Output()))
}

// setPair applies a change signed by the zone's approver, as qv-route does.
func (s *stack) setPair(pair mpcsigner.Pair) {
	s.t.Helper()
	pool, err := pgxpool.New(context.Background(), s.gwGuard)
	if err != nil {
		s.t.Fatal(err)
	}
	defer pool.Close()
	g, err := gateway.OpenGuard(context.Background(), pool)
	if err != nil {
		s.t.Fatal(err)
	}
	cur, _, err := g.CurrentRoute(context.Background(), s.gwCfg)
	if err != nil {
		s.t.Fatal(err)
	}
	now := time.Now()
	if err := g.ApplyRoute(context.Background(), s.gwCfg, gateway.SignRoute(s.appr, "alice", pair, cur.Seq+1, now), now); err != nil {
		s.t.Fatalf("the approver's change was refused: %v", err)
	}
}

// waitBack waits until the restarted party answers and every keyset of A and of that party is reconciled again. (Stack3.WaitReady compares the
// keysets of all three parties, and C does not hold the 2-party deposit keyset.)
func (s *stack) waitBack(role string) {
	s.t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		ok := true
		for _, r := range []string{"A", role} {
			h, err := s.mpc.HealthOf(r)
			if err != nil {
				ok = false
				break
			}
			for _, p := range h.Peers {
				ok = ok && p.Reachable
			}
			for _, k := range h.Keysets {
				ok = ok && k.Resolved
			}
		}
		if ok {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.t.Fatalf("party %s is not back and reconciled", role)
}

func (s *stack) waitHealthy(party string) {
	s.t.Helper()
	want := fmt.Sprintf(`qv_mpc_party_healthy{party=%q} 1`, party)
	for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if b, _ := os.ReadFile(s.metrics); strings.Contains(string(b), want) {
			return
		}
	}
	s.t.Fatalf("party %s never became healthy in the metrics", party)
}

// withdraw signs and lands one SOL withdrawal from the hot shard.
func (s *stack) withdraw(id string) {
	s.t.Helper()
	dest := st.NewKey()
	const amount = 1_000_000
	in := s.intent("withdrawal", "w-"+id, "SOL", partSOL, "", dest.Address(), amount)
	msg := s.wdMsg(st.SetLimit(10_000), st.Transfer(s.hotPub, dest.Pub, amount))
	sig := s.sign("j-"+id, in, msg, sol.PathHot, nil)
	s.n.land(st.Assemble(msg, sig))
	if got := s.n.lamports(dest.Pub); got != amount {
		s.t.Fatalf("%s: destination holds %d", id, got)
	}
}

// Preferred A+C with B dead for good, then B+C with A dead: the transaction lands each time, and the gateway never says it degraded (the
// route is exactly what the operators chose).
func TestPreferredPairSignsWithTheTwoPartiesOnly(t *testing.T) {
	s := newStack(t, optsT{route: true})
	s.waitPairs("A+B", "A+B", 30*time.Second)
	s.withdraw("ab")

	s.mpc.B.Kill()
	s.setPair(mpcsigner.PairAC)
	s.withdraw("ac1")
	s.withdraw("ac2")
	s.waitPairs("A+C", "A+C", 30*time.Second)

	s.mpc.B.Start(t)
	s.waitBack("B")
	s.waitHealthy("B") // the gateway trusts a returning party only after the configured good checks; choosing B+C before that would be degraded on purpose
	s.mpc.A.Kill()
	s.setPair(mpcsigner.PairBC)
	s.withdraw("bc1")
	s.withdraw("bc2")
	s.waitPairs("B+C", "B+C", 30*time.Second)
	if strings.Contains(s.gw.Output(), "ALERT mpc route differs") {
		t.Fatalf("a route the operators chose was reported as degraded:\n%s", tailOf(s.gw.Output()))
	}
}

// A party dies: after N failed checks the route moves and the jobs keep landing; when it is back, the route returns after M good checks.
func TestRouteFollowsHealthOnSolana(t *testing.T) {
	s := newStack(t, optsT{route: true})
	s.waitPairs("A+B", "A+B", 30*time.Second)
	s.mpc.B.Kill()
	s.withdraw("during")
	s.waitPairs("A+B", "A+C", 60*time.Second)
	s.withdraw("moved")
	s.mpc.B.Start(t)
	s.waitBack("B")
	s.waitPairs("A+B", "A+B", 60*time.Second)
	s.withdraw("back")
	if n := strings.Count(s.gw.Output(), "ALERT mpc route differs"); n != 1 {
		t.Fatalf("%d route alerts, want exactly 1", n)
	}
}
