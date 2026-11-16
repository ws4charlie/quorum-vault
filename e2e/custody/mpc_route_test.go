package custody_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
)

// The routing of 2-of-3 signatures (MPC-routing): the operators' signed preferred pair, and the gateway's health checks with hysteresis.
// They run only with QV_CUSTODY_SIGNER=mpc, through real withdrawals; the gateway writes its route metrics to a file the tests read.

var fastRoute = &routeOpts{interval: "500ms", failCount: 3, window: "10s", recoverCount: 4}

// metrics parses the gateway's metrics file: "name{labels}" -> value.
func (s *system) metrics() map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(readFile(s.metricsPath), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndex(line, " ")
		if v, err := strconv.ParseFloat(line[i+1:], 64); err == nil {
			out[line[:i]] = v
		}
	}
	return out
}

// pairs reads (preferred, effective) from the metrics file; "" when the file is not there yet.
func (s *system) pairs() (pref, eff string) {
	m := s.metrics()
	for _, p := range mpcsigner.PairOrder {
		if m[fmt.Sprintf(`qv_mpc_preferred_pair{pair=%q}`, string(p))] == 1 {
			pref = string(p)
		}
		if m[fmt.Sprintf(`qv_mpc_effective_pair{pair=%q}`, string(p))] == 1 {
			eff = string(p)
		}
	}
	return pref, eff
}

func (s *system) waitPairs(pref, eff string, d time.Duration) {
	s.t.Helper()
	var gp, ge string
	s.waitFor(d, fmt.Sprintf("preferred %s and effective %s in the metrics", pref, eff), func() bool {
		gp, ge = s.pairs()
		return gp == pref && ge == eff
	})
}

// routeGuard opens the gateway's guard database from the test, with the zone's own config: what an operator's tool (qv-route) does.
func (s *system) routeGuard() (*gateway.Guard, *gateway.Config) {
	s.t.Helper()
	cfg, err := gateway.LoadConfig(s.gwPath)
	if err != nil {
		s.t.Fatal(err)
	}
	pool, err := pgxpool.New(s.ctx, s.guardDSN)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(pool.Close)
	g, err := gateway.OpenGuard(s.ctx, pool)
	if err != nil {
		s.t.Fatal(err)
	}
	return g, cfg
}

// setPair applies a change signed by an approver of the zone, the way an operator would; it must be accepted.
func (s *system) setPair(pair mpcsigner.Pair) {
	s.t.Helper()
	g, cfg := s.routeGuard()
	cur, _, err := g.CurrentRoute(s.ctx, cfg)
	if err != nil {
		s.t.Fatal(err)
	}
	now := time.Now()
	if err := g.ApplyRoute(s.ctx, cfg, gateway.SignRoute(s.approv["alice"], "alice", pair, cur.Seq+1, now), now); err != nil {
		s.t.Fatalf("an approver's signed change was refused: %v", err)
	}
}

func (s *system) routeAudits() int {
	return s.guardCount(`SELECT count(*) FROM audit_log WHERE type = 'mpc.route.changed'`)
}

func (s *system) guardCount(q string) int {
	s.t.Helper()
	pool, err := pgxpool.New(s.ctx, s.guardDSN)
	if err != nil {
		s.t.Fatal(err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(s.ctx, q).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func (s *system) payThrice(customer, key string) {
	s.t.Helper()
	for i := 0; i < 3; i++ {
		id, dest := s.startPayment(customer, fmt.Sprintf("%s-%d", key, i))
		s.mustPayOnce(id, dest, 150*time.Second)
	}
}

// The preferred pair is a signed, audited, hot-switchable operator setting. A+C signs with A and C only (B is dead and stays dead), B+C
// with B and C only (A is dead), and an unsigned or wrongly signed change moves nothing.
func TestMPCRoutePreferredPairIsSignedAuditedAndHotSwitchable(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{route: fastRoute}, "c-rt1", 60)
	mpc := s.mpc
	s.waitPairs("A+B", "A+B", 60*time.Second)
	s.payThrice("c-rt1", "k-rt1-ab")

	// A change nobody signed, or a stranger signed, is refused and the route stays.
	g, cfg := s.routeGuard()
	now := time.Now()
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]gateway.RouteChange{
		"unsigned":        {Pair: "A+C", Seq: 1, SignedAt: now.Unix()},
		"a stranger":      gateway.SignRoute(stranger, "alice", mpcsigner.PairAC, 1, now), // a configured name, the wrong key
		"an unknown name": gateway.SignRoute(stranger, "mallory", mpcsigner.PairAC, 1, now),
	} {
		if err := g.ApplyRoute(s.ctx, cfg, c, now); err == nil {
			t.Fatalf("%s: the change was applied", name)
		}
	}
	s.payThrice("c-rt1", "k-rt1-refused")
	if pref, eff := s.pairs(); pref != "A+B" || eff != "A+B" || s.routeAudits() != 0 {
		t.Fatalf("refused changes moved the route: preferred %s effective %s, %d audit events", pref, eff, s.routeAudits())
	}

	// A+C, with B gone for good: the next job uses it, and B is never needed.
	mpc.B.Kill()
	s.setPair(mpcsigner.PairAC)
	s.payThrice("c-rt1", "k-rt1-ac")
	s.waitPairs("A+C", "A+C", 30*time.Second)

	// B+C, with A gone as well as B back: A is never needed.
	mpc.B.Start(t)
	mpc.WaitReady(120 * time.Second)
	mpc.A.Kill()
	s.setPair(mpcsigner.PairBC)
	s.payThrice("c-rt1", "k-rt1-bc")
	s.waitPairs("B+C", "B+C", 30*time.Second)

	// back to A+B, A restarted
	mpc.A.Start(t)
	mpc.WaitReady(120 * time.Second)
	s.setPair(mpcsigner.PairAB)
	s.payThrice("c-rt1", "k-rt1-back")
	s.waitPairs("A+B", "A+B", 30*time.Second)

	if got := s.routeAudits(); got != 3 {
		t.Fatalf("%d audit events for 3 applied changes", got)
	}
	if got := s.gwLogCount("mpc preferred pair changed"); got != 3 {
		t.Fatalf("%d 'preferred pair changed' lines, want 3", got)
	}
	if n := s.badJobs(); n != 0 {
		t.Fatalf("%d sign jobs failed or were rejected while the route moved", n)
	}
	s.finish()
}

// A party that dies is routed away from after N failed checks, not before, and jobs keep signing meanwhile; when it is back the route returns
// only after M good checks. The preferred pair never changes by itself.
func TestMPCRouteFollowsHealthWithHysteresis(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{route: fastRoute}, "c-rt2", 60)
	mpc := s.mpc
	s.waitPairs("A+B", "A+B", 60*time.Second)

	mpc.B.Kill()
	id, dest := s.startPayment("c-rt2", "k-rt2-during") // while the checks are still counting: signed through the in-call rescue or the new route
	s.mustPayOnce(id, dest, 150*time.Second)
	s.waitPairs("A+B", "A+C", 60*time.Second)
	if s.metrics()[`qv_mpc_party_healthy{party="B"}`] != 0 {
		t.Fatal("B is routed away from but the metrics show it healthy")
	}
	if got := s.gwLogCount("ALERT mpc route differs from the preferred pair"); got != 1 {
		t.Fatalf("%d route alerts, want exactly 1 per transition", got)
	}
	s.payThrice("c-rt2", "k-rt2-moved")

	mpc.B.Start(t)
	mpc.WaitReady(120 * time.Second)
	s.waitPairs("A+B", "A+B", 60*time.Second)
	if s.metrics()[`qv_mpc_party_healthy{party="B"}`] != 1 {
		t.Fatal("B is back on the route but the metrics show it unhealthy")
	}
	if got := s.gwLogCount("mpc route is back on the preferred pair"); got != 1 {
		t.Fatalf("%d recovery lines, want 1", got)
	}
	s.payThrice("c-rt2", "k-rt2-back")
	if pref, _ := s.pairs(); pref != "A+B" || s.routeAudits() != 0 {
		t.Fatal("health changed the operators' preferred pair")
	}
	if n := s.badJobs(); n != 0 {
		t.Fatalf("%d sign jobs failed or were rejected while a party died and came back", n)
	}
	s.finish()
}

// One failed signature moves nothing: the link between A and B is cut under a signing job; the job waits and completes after the heal, and the
// route is the preferred pair throughout, with no route alert.
func TestMPCRouteOneFailedSignatureDoesNotMoveIt(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{route: fastRoute, mpcProxy: true}, "c-rt3", 30)
	s.waitPairs("A+B", "A+B", 60*time.Second)
	before := s.gwLogCount("ALERT signer unavailable")
	s.mpc.Proxy.Partition()
	id, dest := s.startPayment("c-rt3", "k-rt3-1")
	s.waitOutageSeen(before, "the links between the parties are cut")
	time.Sleep(3 * time.Second) // several health checks pass while signatures fail; the callers' ports are fine
	if pref, eff := s.pairs(); pref != "A+B" || eff != "A+B" {
		t.Fatalf("a failed signature moved the route: preferred %s effective %s", pref, eff)
	}
	if got := s.gwLogCount("ALERT mpc route differs"); got != 0 {
		t.Fatalf("%d route alerts after one failed signature", got)
	}
	s.mpc.Proxy.Heal()
	s.mustPayOnce(id, dest, 150*time.Second)
	s.finish()
}

var _ = context.Background
