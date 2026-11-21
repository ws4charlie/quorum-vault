package gen

import (
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
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
