package gen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SetupInfo describes the books made before the load.
type SetupInfo struct {
	WithdrawCustomers int     `json:"withdraw_customers"`
	DepositCustomers  int     `json:"deposit_customers"`
	FundEachETH       float64 `json:"fund_each_eth"`
	DurationS         float64 `json:"duration_s"`
}

// OpSummary is what happened to one kind of operation in one slice of the run (the whole run, or one step).
type OpSummary struct {
	Offered    int                  `json:"offered"`
	OK         int                  `json:"ok"`
	Errors     map[string]int       `json:"errors,omitempty"` // by kind
	OfferedPS  float64              `json:"offered_per_s"`
	AchievedPS float64              `json:"achieved_per_s"` // operations that arrived in the slice and ended well, per second of the slice
	Latency    map[string]Quantiles `json:"latency_ms"`     // by stage: ms since the scheduled arrival; "total" is the last stage
}

// StepSummary is one hold step.
type StepSummary struct {
	Step       int                   `json:"step"` // -1: the ramp
	Scale      float64               `json:"scale"`
	DurationS  float64               `json:"duration_s"`
	Partial    bool                  `json:"partial,omitempty"` // arrivals were stopped inside this step: its rates rest on fewer seconds
	Ops        map[string]*OpSummary `json:"ops"`
	Violations []string              `json:"violations,omitempty"` // objectives broken in this step
}

// Stopped says where a run's arrivals were stopped.
type Stopped struct {
	AtS      float64 `json:"at_s"`
	Step     int     `json:"step"`
	Inflight int64   `json:"inflight"`
}

// Window is a slice of the run in time, by completion time: the latency curve over the run.
type Window struct {
	T   float64 `json:"t"`
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
}

// Result is the machine-readable file of a run (result.json).
type Result struct {
	Schema    int                   `json:"schema"`
	RunID     string                `json:"run_id"`
	Scenario  *Scenario             `json:"scenario"`
	Meta      map[string]string     `json:"meta,omitempty"`
	Started   time.Time             `json:"started"`
	LoadEnded time.Time             `json:"load_ended"`
	Setup     SetupInfo             `json:"setup"`
	Total     map[string]*OpSummary `json:"total"`
	Steps     []StepSummary         `json:"steps"`
	Series    []SeriesPoint         `json:"series"`
	Windows   map[string][]Window   `json:"windows"`
	Reconcile []ReconcileProbe      `json:"reconcile_probes,omitempty"`
	Checks    []CheckResult         `json:"checks"`
	Generator struct {
		Dropped       int64   `json:"dropped"`
		MaxLatenessMS float64 `json:"max_lateness_ms"`
	} `json:"generator"`
	Pass bool `json:"pass"` // every check that is not a warning passed
	// FirstLimit: the first step whose objectives broke (empty if none did)
	FirstLimit string `json:"first_limit,omitempty"`
	// StoppedEarly: arrivals were stopped because more than max_inflight operations were open (when, in which step, how many).
	StoppedEarly *Stopped `json:"stopped_early,omitempty"`
	// Ops is the file with every operation (ops.jsonl next to this file), not part of this document.
	Ops []*OpRecord `json:"-"`
}

var stageOrder = []string{"request", "approvals", "approved", "signing", "broadcast", "confirmed", "sent", "credited", "swept"}

func (r *Runner) result(started, loadEnd time.Time) *Result {
	res := &Result{Schema: 1, RunID: r.RunID, Scenario: r.S, Meta: r.Meta, Started: started, LoadEnded: loadEnd, Setup: r.setup, Series: r.series, Checks: r.checks,
		Reconcile: r.bgRec, Windows: map[string][]Window{}}
	res.Generator.Dropped = r.dropped.Load()
	res.Generator.MaxLatenessMS = r.Obs.late * 1000
	recs := append([]*OpRecord(nil), r.records...)
	sort.Slice(recs, func(i, j int) bool { return recs[i].N < recs[j].N })
	res.Ops = recs

	arrive := r.S.ArrivalDuration().Seconds()
	if r.stopped.Load() {
		res.StoppedEarly = &Stopped{AtS: r.stopT, Step: r.stopStep, Inflight: r.stopIn}
		arrive = r.stopT
	}
	res.Total = summarise(recs, func(*OpRecord) bool { return true }, arrive)
	// steps: the ramp (-1) and each hold step; without steps, the ramp and one hold
	steps := []int{-1}
	nsteps := len(r.S.Steps)
	if nsteps == 0 {
		nsteps = 1
	}
	for i := 0; i < nsteps; i++ {
		steps = append(steps, i)
	}
	for _, st := range steps {
		dur, scale := r.S.RampS, 0.0
		if st >= 0 {
			dur = r.S.HoldS
			scale = 1
			if len(r.S.Steps) > 0 {
				dur, scale = r.S.StepS, r.S.Steps[st]
			}
		} else if len(r.S.Steps) > 0 {
			scale = r.S.Steps[0] / 2
		} else {
			scale = 0.5
		}
		partial := false
		if r.stopped.Load() { // steps after the stop did not run; the step it stopped in ran only until then
			if st > r.stopStep {
				continue
			}
			if st == r.stopStep {
				begin := 0.0
				if st >= 0 {
					begin = r.S.RampS
					if len(r.S.Steps) > 0 {
						begin += float64(st) * r.S.StepS
					}
				}
				if d := r.stopT - begin; d < dur {
					dur, partial = d, true
				}
			}
		}
		if dur <= 0 {
			continue
		}
		ss := StepSummary{Step: st, Scale: scale, DurationS: dur, Partial: partial, Ops: summarise(recs, func(o *OpRecord) bool { return o.Step == st }, dur)}
		ss.Violations = violations(r.S.Objectives, ss.Ops)
		res.Steps = append(res.Steps, ss)
		if res.FirstLimit == "" && st >= 0 && len(ss.Violations) > 0 {
			res.FirstLimit = fmt.Sprintf("step %d (scale %g): %s", st, scale, strings.Join(ss.Violations, "; "))
		}
	}
	// latency over time per kind, by completion time, 5 s windows
	byKey := map[string][]*OpRecord{}
	for _, o := range recs {
		if o.Err == "" {
			byKey[o.Key] = append(byKey[o.Key], o)
		}
	}
	for k, os := range byKey {
		last := lastStage(k)
		w := map[int][]int64{}
		for _, o := range os {
			l := last
			if _, ok := o.Stages[l]; !ok {
				l = "credited"
			}
			end := float64(o.StartMS)/1000 + float64(o.Stages[l])/1000
			w[int(end/5)] = append(w[int(end/5)], o.Stages[l])
		}
		var idx []int
		for i := range w {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		for _, i := range idx {
			q := quant(w[i])
			res.Windows[k] = append(res.Windows[k], Window{T: float64(i)*5 + 2.5, N: q.N, P50: q.P50, P95: q.P95})
		}
	}
	res.Pass = true
	for _, c := range res.Checks {
		if !c.OK && !c.Warn {
			res.Pass = false
		}
	}
	return res
}

func lastStage(key string) string {
	if strings.HasPrefix(key, "deposit") {
		return "swept"
	}
	return "confirmed"
}

func summarise(recs []*OpRecord, in func(*OpRecord) bool, seconds float64) map[string]*OpSummary {
	out := map[string]*OpSummary{}
	stages := map[string]map[string][]int64{}
	for _, o := range recs {
		if !in(o) {
			continue
		}
		s := out[o.Key]
		if s == nil {
			s = &OpSummary{Errors: map[string]int{}, Latency: map[string]Quantiles{}}
			out[o.Key] = s
			stages[o.Key] = map[string][]int64{}
		}
		s.Offered++
		if o.Err != "" {
			s.Errors[o.Err]++
			continue
		}
		s.OK++
		for st, ms := range o.Stages {
			stages[o.Key][st] = append(stages[o.Key][st], ms)
		}
		last := lastStage(o.Key)
		if _, ok := o.Stages[last]; !ok && strings.HasPrefix(o.Key, "deposit") {
			last = "credited" // a deposit that ended at credited (stream option until)
		}
		stages[o.Key]["total"] = append(stages[o.Key]["total"], o.Stages[last])
		if a, b := o.Stages["approved"], o.Stages["broadcast"]; a > 0 && b > 0 {
			stages[o.Key]["approved_to_broadcast"] = append(stages[o.Key]["approved_to_broadcast"], b-a)
		}
	}
	for k, s := range out {
		for st, v := range stages[k] {
			s.Latency[st] = quant(v)
		}
		if seconds > 0 {
			s.OfferedPS = float64(s.Offered) / seconds
			s.AchievedPS = float64(s.OK) / seconds
		}
		if len(s.Errors) == 0 {
			s.Errors = nil
		}
	}
	return out
}

func violations(o Objectives, ops map[string]*OpSummary) []string {
	var v []string
	var keys []string
	for k := range ops {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := ops[k]
		if s.Offered == 0 {
			continue
		}
		if o.ErrorRate > 0 && float64(s.Offered-s.OK)/float64(s.Offered) > o.ErrorRate {
			v = append(v, fmt.Sprintf("%s error rate %.1f%% over %.1f%%", k, 100*float64(s.Offered-s.OK)/float64(s.Offered), 100*o.ErrorRate))
		}
		if o.AchievedOfOffered > 0 && float64(s.OK)/float64(s.Offered) < o.AchievedOfOffered {
			v = append(v, fmt.Sprintf("%s only %.0f%% of what arrived ended well", k, 100*float64(s.OK)/float64(s.Offered)))
		}
		lat := func(stage string, limit float64, what string) {
			if limit > 0 {
				if q, ok := s.Latency[stage]; ok && q.P95 > limit {
					v = append(v, fmt.Sprintf("%s %s p95 %.0f ms over %.0f ms", k, what, q.P95, limit))
				}
			}
		}
		if strings.HasPrefix(k, "withdraw") {
			lat("total", o.WithdrawP95MS, "request to confirmed")
			lat("approved_to_broadcast", o.ApprovedToBroadcastP95MS, "approved to broadcast")
		} else {
			lat("credited", o.DepositCreditP95MS, "sent to credited")
			lat("swept", o.SweepP95MS, "sent to swept")
		}
	}
	return v
}

// Write writes result.json and ops.jsonl into dir.
func (res *Result) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(res, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "result.json"), b, 0o644); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, "ops.jsonl"))
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, o := range res.Ops {
		if err := enc.Encode(o); err != nil {
			return err
		}
	}
	return nil
}
