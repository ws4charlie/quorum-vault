package mpcsigner

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/internal/signer"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// ---- hysteresis ----

func th(n int, window time.Duration, m int) Thresholds {
	return Thresholds{FailCount: n, Window: window, RecoverCount: m}
}

func TestTrackerNFailuresWithinTRouteAway(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := newTracker(th(3, 30*time.Second, 2))
	for i, at := range []int{0, 10} { // two failures: still healthy
		if tr.observe(false, t0.Add(time.Duration(at)*time.Second)) || !tr.healthy {
			t.Fatalf("failure %d changed the state", i+1)
		}
	}
	if !tr.observe(false, t0.Add(29*time.Second)) || tr.healthy { // the third inside T: unhealthy
		t.Fatal("N failures within T must route away")
	}
}

func TestTrackerFailuresOutsideTDoNotAdd(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := newTracker(th(3, 30*time.Second, 2))
	tr.observe(false, t0)
	tr.observe(false, t0.Add(10*time.Second))
	if tr.observe(false, t0.Add(31*time.Second)) || !tr.healthy {
		t.Fatal("the first failure is older than T and must not count")
	}
	// exactly T apart: the window is (now-T, now], so the oldest one has aged out
	tr = newTracker(th(2, 30*time.Second, 2))
	tr.observe(false, t0)
	if tr.observe(false, t0.Add(30*time.Second)) || !tr.healthy {
		t.Fatal("a failure exactly T old is outside the window")
	}
	if !tr.observe(false, t0.Add(40*time.Second)) {
		t.Fatal("two failures 10 s apart must route away")
	}
}

func TestTrackerOneFailureNeverMoves(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := newTracker(th(3, 30*time.Second, 2))
	if tr.observe(false, t0) || !tr.healthy {
		t.Fatal("one failed check moved the state")
	}
	for i := 1; i < 50; i++ { // good checks around it
		tr.observe(true, t0.Add(time.Duration(i)*time.Second))
	}
	if !tr.healthy {
		t.Fatal("unhealthy without N failures")
	}
}

func TestTrackerRecoveryNeedsMConsecutiveGood(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := newTracker(th(2, 30*time.Second, 3))
	tr.observe(false, t0)
	tr.observe(false, t0.Add(time.Second))
	if tr.healthy {
		t.Fatal("setup: must be unhealthy")
	}
	step := func(ok bool, s int) bool { return tr.observe(ok, t0.Add(time.Duration(2+s)*time.Second)) }
	step(true, 0)
	step(true, 1)
	if tr.healthy {
		t.Fatal("two good checks are not M=3")
	}
	step(false, 2) // a failure resets the streak
	step(true, 3)
	step(true, 4)
	if tr.healthy {
		t.Fatal("the streak must restart after a failure")
	}
	if !step(true, 5) || !tr.healthy {
		t.Fatal("three consecutive good checks must bring it back")
	}
}

// A party that flaps (fail, ok, fail, ok, ...) at probe rate must not oscillate: it goes unhealthy once and stays there until M good in a row.
func TestTrackerFlappingDoesNotOscillate(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := newTracker(th(3, 30*time.Second, 4))
	changes := 0
	for i := 0; i < 60; i++ {
		if tr.observe(i%2 == 1, t0.Add(time.Duration(i)*2*time.Second)) { // fail, ok, fail, ok ... every 2 s
			changes++
		}
	}
	if changes != 1 || tr.healthy {
		t.Fatalf("flapping: %d state changes, healthy=%v: want one change to unhealthy and no coming back", changes, tr.healthy)
	}
}

func TestThresholdsValidate(t *testing.T) {
	if err := DefaultThresholds().Validate(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		th Thresholds
		iv time.Duration
	}{
		"zero N":      {th(0, time.Minute, 2), time.Second},
		"zero M":      {th(2, time.Minute, 0), time.Second},
		"zero window": {th(2, 0, 2), time.Second},
		"never fits":  {th(5, 10*time.Second, 2), 5 * time.Second}, // 4 gaps of 5 s do not fit in 10 s
	} {
		if c.th.Validate(c.iv) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- the route choice ----

type fakeHealth map[Pair]bool

func (f fakeHealth) PairUsable(p Pair) bool { return f[p] }

func TestRouteTable(t *testing.T) {
	all := fakeHealth{PairAB: true, PairAC: true, PairBC: true}
	without := func(ps ...Pair) fakeHealth {
		h := fakeHealth{}
		for k, v := range all {
			h[k] = v
		}
		for _, p := range ps {
			h[p] = false
		}
		return h
	}
	cases := []struct {
		pref  Pair
		h     fakeHealth
		eff   Pair
		steps []Pair
	}{
		{PairAB, all, PairAB, []Pair{PairAB, PairAC, PairBC}},
		{PairAC, all, PairAC, []Pair{PairAC, PairAB, PairBC}},
		{PairBC, all, PairBC, []Pair{PairBC, PairAB, PairAC}},
		{PairAB, without(PairAB), PairAC, []Pair{PairAC, PairBC}},
		{PairAB, without(PairAB, PairAC), PairBC, []Pair{PairBC}},
		{PairAC, without(PairAC), PairAB, []Pair{PairAB, PairBC}},
		{PairAC, without(PairAC, PairAB), PairBC, []Pair{PairBC}},
		{PairBC, without(PairBC), PairAB, []Pair{PairAB, PairAC}},
		// the preferred pair is healthy again: back on it (the pair is chosen from health NOW; hysteresis lives in the health state)
		{PairBC, without(PairAB), PairBC, []Pair{PairBC, PairAC}},
		// nothing healthy: stay on the preferred pair and let the in-call rule try everything
		{PairAC, without(PairAB, PairAC, PairBC), PairAC, []Pair{PairAC, PairAB, PairBC}},
	}
	for _, c := range cases {
		r := NewRouter(RouterConfig{Health: c.h})
		p := r.Route(c.pref)
		if p.Effective != c.eff || strings.Join(pairStrings(p.Steps), ",") != strings.Join(pairStrings(c.steps), ",") || p.Preferred != c.pref {
			t.Errorf("preferred %s health %v: got effective %s steps %v, want %s %v", c.pref, c.h, p.Effective, p.Steps, c.eff, c.steps)
		}
	}
}

func pairStrings(ps []Pair) []string {
	var o []string
	for _, p := range ps {
		o = append(o, string(p))
	}
	return o
}

func TestPairs(t *testing.T) {
	for in, want := range map[string]Pair{"A+B": PairAB, "ab": PairAB, " a+c ": PairAC, "BC": PairBC} {
		if got, err := ParsePair(in); err != nil || got != want {
			t.Errorf("ParsePair(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "A+A", "C+A", "A+B+C", "D+A"} {
		if _, err := ParsePair(bad); err == nil {
			t.Errorf("ParsePair(%q) accepted", bad)
		}
	}
	if PairAC.Coordinator() != "A" || PairAC.Peer() != "C" || PairBC.Coordinator() != "B" || PairBC.Peer() != "C" {
		t.Fatal("coordinator and peer")
	}
	// the safety shape of every pair: A never follows (it is a coordinator or absent), and B or C is always there to run its cosigner
	for _, p := range PairOrder {
		if p.Peer() == "A" || !(strings.Contains(string(p), "B") || strings.Contains(string(p), "C")) {
			t.Errorf("pair %s breaks the shape", p)
		}
	}
}

// The preferred pair is read for every job and its change shows on the next plan; a read error keeps the last value.
func TestRouterReadsPreferredEveryJob(t *testing.T) {
	var mu sync.Mutex
	cur, fail := PairAB, false
	r := NewRouter(RouterConfig{Preferred: func(context.Context) (Pair, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return "", context.DeadlineExceeded
		}
		return cur, nil
	}})
	ctx := context.Background()
	if r.Plan(ctx).Effective != PairAB {
		t.Fatal("default")
	}
	mu.Lock()
	cur = PairAC
	mu.Unlock()
	if r.Plan(ctx).Effective != PairAC {
		t.Fatal("a change must apply to the next plan")
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	if r.Plan(ctx).Effective != PairAC {
		t.Fatal("a read error must keep the last preferred pair")
	}
}

// ---- the signer with a router: which party is called, with which wanted peer ----

type party struct {
	pb.UnimplementedMpcPartyServer
	name       string
	signs      atomic.Int32
	peers      []string // the Peer of every Sign request, in order
	mu         sync.Mutex
	failSign   func(n int) error
	signedWith func(peer string) string // what SignResponse.signed_with says; nil: the peer asked for
	healthy    atomic.Bool
	links      map[string]bool // peer name -> reachable, as Health reports
	der        []byte
}

func (p *party) Sign(_ context.Context, r *pb.SignRequest) (*pb.SignResponse, error) {
	n := int(p.signs.Add(1))
	p.mu.Lock()
	p.peers = append(p.peers, r.Peer)
	p.mu.Unlock()
	if p.failSign != nil {
		if err := p.failSign(n); err != nil {
			return nil, err
		}
	}
	with := r.Peer
	if p.signedWith != nil {
		with = p.signedWith(r.Peer)
	}
	return &pb.SignResponse{Signature: p.der, SignedWith: with}, nil
}

func (p *party) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	if !p.healthy.Load() {
		return nil, typedCode(codes.Unavailable, pb.ErrorKind_ERROR_KIND_UNAVAILABLE, 0, "down")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h := &pb.HealthResponse{Role: p.name}
	for _, n := range []string{"B", "C"} {
		if r, ok := p.links[n]; ok {
			h.Peers = append(h.Peers, &pb.PeerStatus{Name: n, Reachable: r})
		}
	}
	return h, nil
}

func (p *party) lastPeers() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.peers...)
}

type rig struct {
	parties map[string]*party
	mon     *Monitor
	router  *Router
	signer  *ThresholdSigner
	now     atomic.Int64 // fake clock of the monitor, unix seconds
	pref    atomic.Value // Pair
	logs    *logBuf
}

func newRig(t *testing.T, thr Thresholds) *rig {
	t.Helper()
	key, _ := crypto.GenerateKey()
	n := crypto.S256().Params().N
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(77), new(big.Int).Sub(n, big.NewInt(9))})
	r := &rig{parties: map[string]*party{}, logs: &logBuf{}}
	r.now.Store(1_000_000)
	r.pref.Store(PairAB)
	pin := "00000000000000000000000000000000000000000000000000000000000000aa"
	var eps []PartyEndpoint
	var coords []Coordinator
	for _, name := range []string{"A", "B", "C"} {
		p := &party{name: name, der: der, links: map[string]bool{}}
		p.healthy.Store(true)
		switch name {
		case "A":
			p.links["B"], p.links["C"] = true, true
		case "B":
			p.links["C"] = true
		}
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := grpc.NewServer()
		pb.RegisterMpcPartyServer(srv, p)
		go srv.Serve(lis)
		t.Cleanup(srv.Stop)
		r.parties[name] = p
		eps = append(eps, PartyEndpoint{Name: name, Address: lis.Addr().String(), ClientCert: tls.Certificate{}, ServerPin: pin})
		if name != "C" {
			coords = append(coords, Coordinator{Name: name, Address: lis.Addr().String(), ClientCert: tls.Certificate{}, ServerPin: pin})
		}
	}
	dial := func(addr string, _ credentials.TransportCredentials) (*grpc.ClientConn, error) {
		return grpc.NewClient(addr, grpc.WithTransportCredentials(insecureCreds()))
	}
	lg := slog.New(slog.NewTextHandler(r.logs, nil))
	mon, err := NewMonitor(MonitorConfig{Parties: eps, Interval: time.Second, Timeout: time.Second, Thresholds: thr, Logger: lg, Dial: dial,
		Now: func() time.Time { return time.Unix(r.now.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mon.Close)
	r.mon = mon
	r.router = NewRouter(RouterConfig{Health: mon, Logger: lg, Preferred: func(context.Context) (Pair, error) { return r.pref.Load().(Pair), nil }})
	pub := crypto.FromECDSAPub(&key.PublicKey)
	s, err := NewThreshold(ThresholdConfig{PartitionID: "p", KeysetID: "k", PublicKey: pub, Coordinators: coords, MaxRetries: 1, Timeout: 10 * time.Second,
		Router: r.router, Logger: lg, Dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	r.signer = s
	return r
}

// round advances the fake clock by one probe interval and probes once.
func (r *rig) round() {
	r.now.Add(1)
	r.mon.Probe(context.Background())
}

func (r *rig) sign(job string) (Pair, error) {
	res, err := r.signer.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{JobID: job, IntentPackage: []byte("pkg")})
	if err != nil {
		return "", err
	}
	return Pair(res.Meta["pair"].(string)), nil
}

func TestRouterSignerUsesThePreferredPair(t *testing.T) {
	for _, c := range []struct {
		pref      Pair
		coord     string
		peer      string
		untouched []string
	}{{PairAB, "A", "B", []string{"B", "C"}}, {PairAC, "A", "C", []string{"B", "C"}}, {PairBC, "B", "C", []string{"A", "C"}}} {
		r := newRig(t, th(2, 10*time.Second, 2))
		r.pref.Store(c.pref)
		got, err := r.sign("job-" + string(c.pref))
		if err != nil || got != c.pref {
			t.Fatalf("%s: signed on %q, %v", c.pref, got, err)
		}
		if p := r.parties[c.coord].lastPeers(); len(p) != 1 || p[0] != c.peer {
			t.Fatalf("%s: coordinator %s was asked with peers %v, want [%s]", c.pref, c.coord, p, c.peer)
		}
		for _, u := range c.untouched {
			if n := r.parties[u].signs.Load(); n != 0 {
				t.Fatalf("%s: party %s got %d Sign calls, want none (the gateway calls the coordinator only)", c.pref, u, n)
			}
		}
	}
}

// B down entirely, preferred A+C: signing works, and B is never called.
func TestRouterSignerPreferredACWithBDown(t *testing.T) {
	r := newRig(t, th(2, 10*time.Second, 2))
	r.pref.Store(PairAC)
	r.parties["B"].healthy.Store(false)
	r.parties["A"].links["B"] = false
	for i := 0; i < 4; i++ {
		r.round()
	}
	for i := 0; i < 5; i++ {
		if got, err := r.sign("j" + string(rune('a'+i))); err != nil || got != PairAC {
			t.Fatalf("job %d: pair %q err %v", i, got, err)
		}
	}
	if r.parties["B"].signs.Load() != 0 {
		t.Fatal("B was called")
	}
}

// A job already signing finishes on its pair: the plan is taken once per job (here: a mid-protocol failure pins the retries to the same pair
// even though the operator changes the preferred pair meanwhile).
func TestRouterSignerPreferredChangeDoesNotMoveInFlightJob(t *testing.T) {
	r := newRig(t, th(2, 10*time.Second, 2))
	var once sync.Once
	r.parties["A"].failSign = func(n int) error {
		var err error
		once.Do(func() {
			r.pref.Store(PairBC) // the operator switches while the job is signing
			err = errStarted(pb.ErrorKind_ERROR_KIND_TRANSPORT)
		})
		return err
	}
	got, err := r.sign("inflight")
	if err != nil || got != PairAB {
		t.Fatalf("in-flight job: pair %q err %v, want to finish on A+B", got, err)
	}
	if r.parties["B"].signs.Load() != 0 {
		t.Fatal("the job moved to B+C although signing had started on A+B")
	}
	if got, err := r.sign("next"); err != nil || got != PairBC {
		t.Fatalf("next job: pair %q err %v, want B+C", got, err)
	}
}

// Never move on after a refusal (REFUSED) or other final errors, whatever the route; one failed signature never changes the route.
func TestRouterOneFailedSignatureDoesNotMoveTheRoute(t *testing.T) {
	r := newRig(t, th(3, 30*time.Second, 2))
	n := 0
	r.parties["A"].failSign = func(int) error {
		n++
		if n == 1 {
			return errBefore(pb.ErrorKind_ERROR_KIND_UNAVAILABLE) // the in-call rule rescues this job
		}
		return nil
	}
	got, err := r.sign("rescued")
	if err != nil || got != PairAC {
		t.Fatalf("the in-call rescue: pair %q err %v (A+B failed before signing, the next pair is A+C)", got, err)
	}
	if p := r.router.Plan(context.Background()); p.Effective != PairAB || p.Preferred != PairAB {
		t.Fatalf("one failed signature moved the route to %s", p.Effective)
	}
	if got, err := r.sign("after"); err != nil || got != PairAB {
		t.Fatalf("the next job: pair %q err %v, want A+B again", got, err)
	}
	// a refusal ends the job at once, nobody else is asked
	r2 := newRig(t, th(3, 30*time.Second, 2))
	r2.parties["A"].failSign = func(int) error { return typedCode(codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED, 0, "no") }
	if _, err := r2.sign("refused"); err == nil || r2.parties["B"].signs.Load() != 0 || r2.parties["A"].signs.Load() != 1 {
		t.Fatalf("refusal: err %v, A %d B %d", err, r2.parties["A"].signs.Load(), r2.parties["B"].signs.Load())
	}
}

// Health drives the route: N failed checks move it, M good checks bring it back, and not before.
func TestRouterHealthMovesAndRestoresTheRoute(t *testing.T) {
	r := newRig(t, th(3, 10*time.Second, 4))
	eff := func() Pair { return r.router.Plan(context.Background()).Effective }
	r.parties["B"].healthy.Store(false) // B is killed
	r.round()
	r.round()
	if eff() != PairAB {
		t.Fatal("two failed checks (N=3) must not move the route")
	}
	if got, err := r.sign("while-b-failing"); err != nil || got != PairAB && got != PairAC {
		t.Fatalf("jobs must keep signing: %q %v", got, err)
	}
	r.round() // third failed check
	if eff() != PairAC {
		t.Fatalf("after N failed checks the route must move to A+C, got %s", eff())
	}
	if got, err := r.sign("after-move"); err != nil || got != PairAC {
		t.Fatalf("after the move: pair %q err %v", got, err)
	}
	r.parties["B"].healthy.Store(true) // B is back
	for i := 0; i < 3; i++ {
		r.round()
	}
	if eff() != PairAC {
		t.Fatal("three good checks (M=4) must not move the route back")
	}
	r.round()
	if eff() != PairAB {
		t.Fatalf("after M good checks the route must return to the preferred pair, got %s", eff())
	}
	if r.logs.count("ALERT mpc route differs from the preferred pair") != 1 || r.logs.count("mpc route is back on the preferred pair") != 1 {
		t.Fatalf("one alert and one recovery line per transition: %s", r.logs.b.String())
	}
}

// A party that answers Health but reports the link to its peer down rules that pair out, and no other.
func TestRouterLinkDownRulesOutOnlyThatPair(t *testing.T) {
	r := newRig(t, th(2, 10*time.Second, 2))
	r.parties["A"].mu.Lock()
	r.parties["A"].links["B"] = false
	r.parties["A"].mu.Unlock()
	r.round()
	r.round()
	if r.mon.PairUsable(PairAB) || !r.mon.PairUsable(PairAC) || !r.mon.PairUsable(PairBC) {
		t.Fatalf("usable: AB %v AC %v BC %v", r.mon.PairUsable(PairAB), r.mon.PairUsable(PairAC), r.mon.PairUsable(PairBC))
	}
}

// No silent swap: an old party that ignores the wanted peer and signs with B is refused when A+C was asked for.
func TestRouterRefusesAPartyThatSignedWithAnotherPeer(t *testing.T) {
	r := newRig(t, th(2, 10*time.Second, 2))
	r.pref.Store(PairAC)
	r.parties["A"].signedWith = func(string) string { return "" } // an old party names nobody
	if _, err := r.sign("swap"); err == nil || !strings.Contains(err.Error(), "not releasing") {
		t.Fatalf("A+C answered by a party that did not name C: %v", err)
	}
	r.parties["A"].signedWith = func(string) string { return "B" }
	if _, err := r.sign("swap2"); err == nil {
		t.Fatal("a party that says it signed with B when C was asked for must be refused")
	}
	// A+B against an old party (no signed_with) is fine: the old order is the same pair
	r.pref.Store(PairAB)
	r.parties["A"].signedWith = func(string) string { return "" }
	if _, err := r.sign("old-ok"); err != nil {
		t.Fatalf("A+B with a party that predates the field must keep working: %v", err)
	}
}

func TestMetrics(t *testing.T) {
	r := newRig(t, th(2, 10*time.Second, 2))
	r.pref.Store(PairBC)
	r.parties["A"].healthy.Store(false)
	r.round()
	r.round()
	var b strings.Builder
	r.router.WriteMetrics(context.Background(), &b, r.mon)
	out := b.String()
	for _, want := range []string{
		`qv_mpc_preferred_pair{pair="B+C"} 1`, `qv_mpc_preferred_pair{pair="A+B"} 0`, `qv_mpc_effective_pair{pair="B+C"} 1`, `qv_mpc_route_degraded 0`,
		`qv_mpc_party_healthy{party="A"} 0`, `qv_mpc_party_healthy{party="B"} 1`, `qv_mpc_link_healthy{from="A",to="B"}`,
		`qv_mpc_health_threshold{name="fail_count"} 2`, `qv_mpc_health_threshold{name="recover_count"} 2`, `qv_mpc_health_threshold{name="fail_window_seconds"} 10`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}
}
