package mpcsigner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// PartyEndpoint is a party's caller port, which the gateway probes with the parties' own Health RPC (no separate health service).
type PartyEndpoint struct {
	Name       string // "A", "B" or "C"
	Address    string
	ClientCert tls.Certificate
	ServerPin  string
}

// MonitorConfig configures the gateway's own health checks.
type MonitorConfig struct {
	Parties    []PartyEndpoint // A, B and C
	Interval   time.Duration   // between two rounds of checks; default 5 s
	Timeout    time.Duration   // of one check; default 3 s
	Thresholds Thresholds      // zero value: DefaultThresholds
	Logger     *slog.Logger
	Now        func() time.Time // tests
	Dial       func(addr string, creds credentials.TransportCredentials) (*grpc.ClientConn, error)
}

// Monitor probes every party and every dialed link, and keeps the hysteresis state of each. A party is "healthy" while its Health RPC
// answers; a link (A>B, A>C, B>C) is "healthy" while the dialing party reports the peer reachable. A pair can sign when both its parties and
// its link are healthy.
type Monitor struct {
	cfg   MonitorConfig
	log   *slog.Logger
	conns []*grpc.ClientConn
	cls   map[string]pb.MpcPartyClient

	mu       sync.Mutex
	trackers map[string]*tracker // "A", "B", "C" and "A>B", "A>C", "B>C"
	lastOK   map[string]time.Time
}

var linkNames = []string{"A>B", "A>C", "B>C"}

// NewMonitor dials the parties. Nothing is probed until Run (or Probe) is called.
func NewMonitor(cfg MonitorConfig) (*Monitor, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Thresholds == (Thresholds{}) {
		cfg.Thresholds = DefaultThresholds()
	}
	if err := cfg.Thresholds.Validate(cfg.Interval); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	m := &Monitor{cfg: cfg, log: lg, cls: map[string]pb.MpcPartyClient{}, trackers: map[string]*tracker{}, lastOK: map[string]time.Time{}}
	dial := cfg.Dial
	if dial == nil {
		dial = func(addr string, c credentials.TransportCredentials) (*grpc.ClientConn, error) {
			return grpc.NewClient(addr, grpc.WithTransportCredentials(c))
		}
	}
	for _, p := range cfg.Parties {
		if p.Name != "A" && p.Name != "B" && p.Name != "C" || p.Address == "" {
			m.Close()
			return nil, fmt.Errorf("a monitored party needs the name A, B or C and an address (got %q)", p.Name)
		}
		if m.cls[p.Name] != nil {
			m.Close()
			return nil, fmt.Errorf("party %s is listed twice", p.Name)
		}
		creds, err := pinnedCreds(p.ClientCert, p.ServerPin)
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("party %s: %w", p.Name, err)
		}
		conn, err := dial(p.Address, creds)
		if err != nil {
			m.Close()
			return nil, err
		}
		m.conns = append(m.conns, conn)
		m.cls[p.Name] = pb.NewMpcPartyClient(conn)
		m.trackers[p.Name] = newTracker(cfg.Thresholds)
	}
	for _, n := range []string{"A", "B", "C"} {
		if m.cls[n] == nil {
			m.Close()
			return nil, fmt.Errorf("party %s is missing: the health checks need all three", n)
		}
	}
	for _, l := range linkNames {
		m.trackers[l] = newTracker(cfg.Thresholds)
	}
	return m, nil
}

func (m *Monitor) Close() {
	for _, c := range m.conns {
		c.Close()
	}
}

// Interval is the time between two rounds.
func (m *Monitor) Interval() time.Duration { return m.cfg.Interval }

// Run probes until ctx ends. onRound (may be nil) runs after every round.
func (m *Monitor) Run(ctx context.Context, onRound func()) {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	for {
		m.Probe(ctx)
		if onRound != nil {
			onRound()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Probe runs one round: Health on every party, in parallel.
func (m *Monitor) Probe(ctx context.Context) {
	type result struct {
		name string
		resp *pb.HealthResponse
		err  error
	}
	out := make(chan result, 3)
	for _, n := range []string{"A", "B", "C"} {
		go func(n string) {
			x, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
			defer cancel()
			r, err := m.cls[n].Health(x, &pb.HealthRequest{})
			out <- result{n, r, err}
		}(n)
	}
	var rs []result
	for i := 0; i < 3; i++ {
		rs = append(rs, <-out)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].name < rs[j].name })
	if ctx.Err() != nil {
		return
	}
	now := m.cfg.Now()
	for _, r := range rs {
		ok := r.err == nil && r.resp != nil
		m.observe(r.name, ok, now, r.err)
		if !ok {
			continue // its links are unknown while it does not answer: they keep their state
		}
		for _, p := range r.resp.Peers {
			l := r.name + ">" + p.Name
			if m.trackers[l] != nil {
				m.observe(l, p.Reachable, now, nil)
			}
		}
	}
}

func (m *Monitor) observe(name string, ok bool, now time.Time, cause error) {
	m.mu.Lock()
	t := m.trackers[name]
	changed := t.observe(ok, now)
	if ok {
		m.lastOK[name] = now
	}
	healthy := t.healthy
	m.mu.Unlock()
	if !changed {
		return
	}
	what := "party"
	if len(name) == 3 {
		what = "link"
	}
	if healthy {
		m.log.Info("mpc health: back to healthy after consecutive good checks", "kind", what, "name", name, "good_checks", m.cfg.Thresholds.RecoverCount)
		return
	}
	m.log.Error("ALERT mpc health: routed away after repeated failed checks", "kind", what, "name", name, "failed_checks", m.cfg.Thresholds.FailCount,
		"window", m.cfg.Thresholds.Window.String(), "last_error", fmt.Sprint(cause))
}

// Healthy reports one party or link by name ("A", "B", "C", "A>B", "A>C", "B>C").
func (m *Monitor) Healthy(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.trackers[name]
	return t != nil && t.healthy
}

// PairUsable: both parties and the coordinator's link to its peer are healthy.
func (m *Monitor) PairUsable(p Pair) bool {
	if !p.Valid() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range []string{p.Coordinator(), p.Peer(), p.link()} {
		if t := m.trackers[n]; t == nil || !t.healthy {
			return false
		}
	}
	return true
}

func (m *Monitor) writeMetrics(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	th := m.cfg.Thresholds
	fmt.Fprintln(w, "# HELP qv_mpc_party_healthy 1 while the party passes the gateway's health checks (after hysteresis).")
	fmt.Fprintln(w, "# TYPE qv_mpc_party_healthy gauge")
	for _, n := range []string{"A", "B", "C"} {
		fmt.Fprintf(w, "qv_mpc_party_healthy{party=%q} %d\n", n, b2i(m.trackers[n].healthy))
	}
	fmt.Fprintln(w, "# HELP qv_mpc_link_healthy 1 while the dialing party reports its link to the peer up (after hysteresis).")
	fmt.Fprintln(w, "# TYPE qv_mpc_link_healthy gauge")
	for _, l := range linkNames {
		fmt.Fprintf(w, "qv_mpc_link_healthy{from=%q,to=%q} %d\n", l[:1], l[2:], b2i(m.trackers[l].healthy))
	}
	fmt.Fprintln(w, "# HELP qv_mpc_party_failed_checks Failed checks of the party inside the current window.")
	fmt.Fprintln(w, "# TYPE qv_mpc_party_failed_checks gauge")
	now := m.cfg.Now()
	for _, n := range []string{"A", "B", "C"} {
		t, c := m.trackers[n], 0
		for _, f := range t.fails {
			if now.Sub(f) < th.Window {
				c++
			}
		}
		fmt.Fprintf(w, "qv_mpc_party_failed_checks{party=%q} %d\n", n, c)
	}
	fmt.Fprintln(w, "# HELP qv_mpc_party_good_checks Consecutive good checks of a party that is routed away from (counting towards recover_count).")
	fmt.Fprintln(w, "# TYPE qv_mpc_party_good_checks gauge")
	for _, n := range []string{"A", "B", "C"} {
		fmt.Fprintf(w, "qv_mpc_party_good_checks{party=%q} %d\n", n, m.trackers[n].good)
	}
	fmt.Fprintln(w, "# HELP qv_mpc_party_last_ok_timestamp_seconds Unix time of the last good health check of the party.")
	fmt.Fprintln(w, "# TYPE qv_mpc_party_last_ok_timestamp_seconds gauge")
	for _, n := range []string{"A", "B", "C"} {
		fmt.Fprintf(w, "qv_mpc_party_last_ok_timestamp_seconds{party=%q} %d\n", n, m.lastOK[n].Unix())
	}
	fmt.Fprintln(w, "# HELP qv_mpc_health_threshold The configured health rules: fail_count (N), fail_window_seconds (T), recover_count (M), probe_interval_seconds.")
	fmt.Fprintln(w, "# TYPE qv_mpc_health_threshold gauge")
	fmt.Fprintf(w, "qv_mpc_health_threshold{name=\"fail_count\"} %d\n", th.FailCount)
	fmt.Fprintf(w, "qv_mpc_health_threshold{name=\"fail_window_seconds\"} %g\n", th.Window.Seconds())
	fmt.Fprintf(w, "qv_mpc_health_threshold{name=\"recover_count\"} %d\n", th.RecoverCount)
	fmt.Fprintf(w, "qv_mpc_health_threshold{name=\"probe_interval_seconds\"} %g\n", m.cfg.Interval.Seconds())
}
