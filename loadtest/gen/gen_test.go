package gen

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShippedScenariosAreValid(t *testing.T) {
	files, _ := filepath.Glob("../scenarios/*.json")
	if len(files) == 0 {
		t.Fatal("no scenarios found")
	}
	for _, f := range files {
		if _, err := LoadScenario(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestScenarioRefusals(t *testing.T) {
	ok := Scenario{Name: "x", Mode: "open", HoldS: 1, DrainS: 1, Setup: Setup{WithdrawCustomers: 1, FundEachETH: 1}, Streams: []Stream{{Op: "withdraw", Tier: "auto", Rate: 1, AmountETH: [2]float64{1, 2}}}}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Scenario){
		"no streams":         func(s *Scenario) { s.Streams = nil },
		"bad tier":           func(s *Scenario) { s.Streams[0].Tier = "x" },
		"no funds":           func(s *Scenario) { s.Setup = Setup{} },
		"steps without time": func(s *Scenario) { s.Steps = []float64{1} },
		"closed no users":    func(s *Scenario) { s.Mode = "closed" },
		"reversed amounts":   func(s *Scenario) { s.Streams[0].AmountETH = [2]float64{2, 1} },
	} {
		s := ok
		s.Streams = append([]Stream(nil), ok.Streams...)
		mod(&s)
		if s.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScaleAt(t *testing.T) {
	s := Scenario{RampS: 10, StepS: 20, Steps: []float64{1, 4}}
	if sc, st := s.scaleAt(5); sc != 0.5 || st != -1 {
		t.Errorf("ramp: %v %v", sc, st)
	}
	if sc, st := s.scaleAt(15); sc != 1 || st != 0 {
		t.Errorf("step 0: %v %v", sc, st)
	}
	if sc, st := s.scaleAt(35); sc != 4 || st != 1 {
		t.Errorf("step 1: %v %v", sc, st)
	}
}

func TestQuantiles(t *testing.T) {
	v := make([]int64, 100)
	for i := range v {
		v[i] = int64(i + 1)
	}
	q := quant(v)
	if q.P50 != 50 || q.P95 != 95 || q.P99 != 99 || q.Max != 100 || q.N != 100 {
		t.Errorf("%+v", q)
	}
	if quant(nil).N != 0 {
		t.Error("empty")
	}
}

func TestSummariseAndViolations(t *testing.T) {
	var recs []*OpRecord
	for i := 0; i < 10; i++ {
		r := &OpRecord{N: i, Key: "withdraw:auto", Stages: map[string]int64{"approved": 100, "broadcast": 400, "confirmed": int64(1000 + i*1000)}}
		if i == 9 {
			r.Err = "timeout"
		}
		recs = append(recs, r)
	}
	m := summarise(recs, func(*OpRecord) bool { return true }, 10)
	s := m["withdraw:auto"]
	if s.Offered != 10 || s.OK != 9 || s.Errors["timeout"] != 1 || s.AchievedPS != 0.9 {
		t.Fatalf("%+v", s)
	}
	if s.Latency["approved_to_broadcast"].P50 != 300 {
		t.Errorf("approved_to_broadcast %+v", s.Latency["approved_to_broadcast"])
	}
	v := violations(Objectives{WithdrawP95MS: 5000, ErrorRate: 0.05}, m)
	if len(v) != 2 {
		t.Errorf("violations %v", v)
	}
	if v := violations(Objectives{WithdrawP95MS: 60000, ErrorRate: 0.2}, m); len(v) != 0 {
		t.Errorf("violations %v", v)
	}
}

// the open loop's arrival count follows the rate and the scale
func TestThinningCount(t *testing.T) {
	s := &Scenario{RampS: 0, StepS: 100, Steps: []float64{1, 3}}
	rng := rand.New(rand.NewSource(1))
	rate, maxScale := 10.0, 3.0
	next, counts := 0.0, [2]int{}
	for {
		next += rng.ExpFloat64() / (rate * maxScale)
		if next >= 200 {
			break
		}
		sc, st := s.scaleAt(next)
		if rng.Float64() >= sc/maxScale {
			continue
		}
		counts[st]++
	}
	for i, want := range []float64{1000, 3000} {
		if math.Abs(float64(counts[i])-want) > 5*math.Sqrt(want) {
			t.Errorf("step %d: %d arrivals, want about %.0f", i, counts[i], want)
		}
	}
}

func TestRoute(t *testing.T) {
	for in, want := range map[string]string{"/v2/withdrawals/wd-1": "/v2/withdrawals/:id", "/v2/withdrawals/wd-1/approvals": "/v2/withdrawals/:id/approvals",
		"/v2/customers/c1/balances": "/v2/customers/:id/balances", "/v2/reconcile": "/v2/reconcile", "/v2/withdrawals": "/v2/withdrawals"} {
		if got := route(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestResultWrite(t *testing.T) {
	r := &Runner{S: &Scenario{Name: "x", Mode: "open", RampS: 1, HoldS: 2, DrainS: 1}, Obs: NewObserver("r1"), RunID: "r1"}
	r.records = []*OpRecord{{N: 1, Key: "deposit:ETH", Step: 0, Stages: map[string]int64{"credited": 300, "swept": 900}}}
	r.checks = []CheckResult{{Name: "a", OK: true}, {Name: "b", OK: false, Warn: true}}
	res := r.result(r.t0, r.t0)
	if !res.Pass || res.Total["deposit:ETH"].Latency["total"].P50 != 900 {
		t.Fatalf("%+v", res.Total)
	}
	dir := t.TempDir()
	if err := res.Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"result.json", "ops.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
	r.checks = append(r.checks, CheckResult{Name: "c", OK: false})
	if r.result(r.t0, r.t0).Pass {
		t.Error("a failed check must fail the run")
	}
}

func TestRateScaleIsValidated(t *testing.T) {
	for _, x := range []float64{0, -1, -0.001, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if ValidateRateScale(x) == nil {
			t.Errorf("%v accepted", x)
		}
	}
	for _, x := range []float64{0.001, 1, 8} {
		if err := ValidateRateScale(x); err != nil {
			t.Errorf("%v: %v", x, err)
		}
	}
}

// every arrival loop stops at the same moment, and the stop time is when it was seen, not the schedule of an arrival
func TestEveryLoopStopsTogether(t *testing.T) {
	r := &Runner{S: &Scenario{MaxInflight: 3}, Obs: NewObserver("r"), t0: time.Now().Add(-10 * time.Second), logf: func(string, ...any) {}}
	for i := 0; i < 3; i++ {
		r.Obs.opOffered("a")
	}
	if r.shouldStop(1) {
		t.Fatal("stopped at the limit, not over it")
	}
	r.Obs.opOffered("b")
	if !r.shouldStop(2) {
		t.Fatal("not stopped over the limit")
	}
	at := r.stopT
	// the open operations end: no loop may start again, and the record stays
	for i := 0; i < 4; i++ {
		r.Obs.opEnd("a", "")
	}
	if !r.shouldStop(3) || r.stopT != at || r.stopStep != 2 || at < 9.9 {
		t.Fatalf("stop record changed: %v %d (first %v)", r.stopT, r.stopStep, at)
	}
}

// a deposit credited to the wrong customer, or twice, or not at all, must fail the credit check, whatever the generator saw
func TestDepositCreditsAreCheckedBothWays(t *testing.T) {
	avail := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			fmt.Fprint(w, "tok")
			return
		}
		parts := strings.Split(r.URL.Path, "/") // /v2/customers/{id}/balances
		fmt.Fprintf(w, `{"balances":[{"asset":"ETH","available":%q,"held":"0","posted":"0"}]}`, avail[parts[3]])
	}))
	defer srv.Close()
	tg := &Target{API: []string{srv.URL}, Token: TokenCfg{Kind: "endpoint", URL: srv.URL + "/token"}}
	run := func(a1, a2 string) (ok bool, detail string) {
		avail["c1"], avail["c2"] = a1, a2
		obs := NewObserver("r")
		cl, err := NewClient(tg, obs)
		if err != nil {
			t.Fatal(err)
		}
		r := &Runner{S: &Scenario{SettleS: 0.001}, C: cl, T: &Target{Actors: tg.Actors}, Obs: obs, logf: func(string, ...any) {}, dcusts: []*dcust{{id: "c1"}, {id: "c2"}}}
		credits := map[string]credit{"c1": {big.NewInt(100), new(big.Int)}, "c2": {big.NewInt(50), big.NewInt(20)}}
		r.checkDepositCredits(context.Background(), credits)
		c := r.checks[len(r.checks)-1]
		return c.OK, c.Detail
	}
	for _, tc := range []struct {
		a1, a2 string
		ok     bool
	}{
		{"100", "50", true},
		{"100", "70", true},  // c2's unknown payment landed
		{"100", "60", true},  // within the unknown range
		{"101", "50", false}, // a credit too large: booked here though paid elsewhere
		{"100", "49", false}, // too small
		{"100", "71", false}, // above everything paid
		{"0", "50", false},   // not credited at all
	} {
		if ok, d := run(tc.a1, tc.a2); ok != tc.ok {
			t.Errorf("c1=%s c2=%s: ok=%v, want %v (%s)", tc.a1, tc.a2, ok, tc.ok, d)
		}
	}
}

// an alert that fired during the run and cleared is found: the question is asked over the whole run, not at the end
func TestAlertHistoryIsAskedOverTheRun(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("query")
		fmt.Fprint(w, `{"status":"success","data":{"result":[{"metric":{"alertname":"QVSweepStuck"}},{"metric":{"alertname":"QVSweepStuck"}}]}}`)
	}))
	defer srv.Close()
	names, err := firingAlerts(context.Background(), srv.URL, 5*time.Minute)
	if err != nil || len(names) != 1 || names[0] != "QVSweepStuck" {
		t.Fatalf("%v %v", names, err)
	}
	if !strings.Contains(query, "max_over_time") || !strings.Contains(query, "[330s]") {
		t.Errorf("query %q does not cover the run", query)
	}
}
