package mpcsigner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// Pair is the two parties that make one 2-of-3 signature. Every pair has a coordinator the gateway calls and a peer the coordinator signs
// with: A+B is (A, B), A+C is (A, C), B+C is (B, C). Party A only ever coordinates, and every pair includes B or C with their own cosigner.
type Pair string

const (
	PairAB Pair = "A+B" // the default
	PairAC Pair = "A+C"
	PairBC Pair = "B+C"
)

// PairOrder is the fixed order of the pairs: the first healthy one after the operator's preferred pair is used.
var PairOrder = []Pair{PairAB, PairAC, PairBC}

// ParsePair accepts "A+B", "AB" and "a+b".
func ParsePair(s string) (Pair, error) {
	n := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "+", ""))
	for _, p := range PairOrder {
		if strings.ReplaceAll(string(p), "+", "") == n {
			return p, nil
		}
	}
	return "", fmt.Errorf("unknown pair %q: use A+B, A+C or B+C", s)
}

func (p Pair) Valid() bool { _, err := ParsePair(string(p)); return err == nil && len(p) == 3 }

// Coordinator is the party the gateway calls for this pair.
func (p Pair) Coordinator() string { return string(p)[:1] }

// Peer is the party the coordinator signs with.
func (p Pair) Peer() string { return string(p)[2:] }

// Parties are the two parties of the pair.
func (p Pair) Parties() [2]string { return [2]string{p.Coordinator(), p.Peer()} }

// link is the dialed link the pair needs: the coordinator's link to its peer.
func (p Pair) link() string { return p.Coordinator() + ">" + p.Peer() }

// Plan is the route of one job: the pairs to try in order. The first is the effective pair; the others are the in-call fallbacks of the
// fallback rule (taken only on an availability failure before signing started).
type Plan struct {
	Preferred Pair
	Effective Pair
	Steps     []Pair
}

// RouterConfig is what a Router needs.
type RouterConfig struct {
	// Health says whether a pair can sign right now (hysteresis already applied). Nil: every pair can.
	Health interface{ PairUsable(Pair) bool }
	// Preferred returns the operator's current choice; it is called for every job, so a change takes effect on the next one. An error keeps
	// the last good value. Nil: A+B.
	Preferred func(context.Context) (Pair, error)
	Logger    *slog.Logger
}

// Router decides which pair a job signs with: the operator's preferred pair unless health rules it out, then the next healthy pair in the
// fixed order. It never changes what a pair may sign: every pair runs the same checks on the parties, so a route can only reduce availability.
type Router struct {
	cfg RouterConfig
	log *slog.Logger

	mu       sync.Mutex
	pref     Pair
	eff      Pair
	prefErr  bool
	degraded bool
}

func NewRouter(cfg RouterConfig) *Router {
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &Router{cfg: cfg, log: lg, pref: PairAB, eff: PairAB}
}

func (r *Router) usable(p Pair) bool { return r.cfg.Health == nil || r.cfg.Health.PairUsable(p) }

// Route is the pure choice: the plan for a preferred pair under the current health.
func (r *Router) Route(pref Pair) Plan {
	cands := []Pair{pref}
	for _, p := range PairOrder {
		if p != pref {
			cands = append(cands, p)
		}
	}
	var steps []Pair
	for _, p := range cands {
		if r.usable(p) {
			steps = append(steps, p)
		}
	}
	if len(steps) == 0 {
		// Nothing looks healthy (the checks may be stale or wrong): stay on the preferred pair and let the in-call rule try the rest. The jobs
		// then fail as unavailable and are retried, which is what they would do anyway.
		return Plan{Preferred: pref, Effective: pref, Steps: cands}
	}
	return Plan{Preferred: pref, Effective: steps[0], Steps: steps}
}

// Plan is the route of the next job. It reads the operator's current choice, so a change applies to the next job and never to one that
// already started.
func (r *Router) Plan(ctx context.Context) Plan {
	pref := r.preferred(ctx)
	p := r.Route(pref)
	r.note(p)
	return p
}

func (r *Router) preferred(ctx context.Context) Pair {
	r.mu.Lock()
	last := r.pref
	r.mu.Unlock()
	if r.cfg.Preferred == nil {
		return last
	}
	p, err := r.cfg.Preferred(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || !p.Valid() {
		if !r.prefErr {
			r.prefErr = true
			r.log.Error("ALERT mpc route: cannot read the preferred pair, keeping the last one", "pair", string(r.pref), "error", fmt.Sprint(err))
		}
		return r.pref
	}
	r.prefErr = false
	if p != r.pref {
		r.log.Warn("mpc preferred pair changed", "from", string(r.pref), "to", string(p))
		r.pref = p
	}
	return p
}

// note logs the transitions of the effective route, one line per transition, never per job.
func (r *Router) note(p Plan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.eff
	r.eff = p.Effective
	switch {
	case p.Effective != p.Preferred && !r.degraded:
		r.degraded = true
		r.log.Error("ALERT mpc route differs from the preferred pair: health checks rule the preferred pair out", "preferred", string(p.Preferred), "effective", string(p.Effective))
	case p.Effective == p.Preferred && r.degraded:
		r.degraded = false
		r.log.Info("mpc route is back on the preferred pair", "pair", string(p.Preferred))
	case p.Effective != prev:
		r.log.Warn("mpc effective pair changed", "from", string(prev), "to", string(p.Effective))
	}
}

// WriteMetrics writes the route's metrics in the Prometheus text format (for a node-exporter textfile collector: the gateway opens no port).
// m may be nil when no health monitor runs.
func (r *Router) WriteMetrics(ctx context.Context, w io.Writer, m *Monitor) {
	p := r.Plan(ctx)
	fmt.Fprintln(w, "# HELP qv_mpc_preferred_pair The signing pair the operators chose (1 for the chosen pair).")
	fmt.Fprintln(w, "# TYPE qv_mpc_preferred_pair gauge")
	for _, q := range PairOrder {
		fmt.Fprintf(w, "qv_mpc_preferred_pair{pair=%q} %d\n", string(q), b2i(q == p.Preferred))
	}
	fmt.Fprintln(w, "# HELP qv_mpc_effective_pair The pair the next job signs with (1 for that pair).")
	fmt.Fprintln(w, "# TYPE qv_mpc_effective_pair gauge")
	for _, q := range PairOrder {
		fmt.Fprintf(w, "qv_mpc_effective_pair{pair=%q} %d\n", string(q), b2i(q == p.Effective))
	}
	fmt.Fprintln(w, "# HELP qv_mpc_route_degraded 1 when the effective pair is not the preferred one.")
	fmt.Fprintln(w, "# TYPE qv_mpc_route_degraded gauge")
	fmt.Fprintf(w, "qv_mpc_route_degraded %d\n", b2i(p.Effective != p.Preferred))
	if m != nil {
		m.writeMetrics(w)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
