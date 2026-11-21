// Package report makes the static page of a run from its result file: a small HTML document with inline SVG charts, no scripts and no external
// services, so a run can be read later without the stack.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ws4charlie/quorum-vault/loadtest/gen"
)

// StackSeries is what the stack's own sampler records during a run (stack.json next to the result): process CPU and memory, database connections
// and lock waits, queue depths. The generator does not write it; the test that brings the stack up does.
type StackSeries struct {
	IntervalS float64              `json:"interval_s"`
	T         []float64            `json:"t"`
	Series    map[string][]float64 `json:"series"`
}

const css = `:root{--bg:#fff;--fg:#1d2330;--mut:#5b6472;--line:#d9dde4;--ok:#1a7f37;--bad:#c62828;--warn:#9a6700;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#10141b;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2a313c;--ok:#4ac26b;--bad:#ff6b6b;--warn:#e3b341;--card:#171c25}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:880px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:.2em 0}h2{font-size:17px;margin:1.6em 0 .4em}table{border-collapse:collapse;width:100%;font-size:13px;margin:.4em 0}
th,td{border-bottom:1px solid var(--line);padding:4px 8px;text-align:right}th:first-child,td:first-child{text-align:left}th{color:var(--mut);font-weight:600}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.muted{color:var(--mut)}code{background:var(--card);padding:1px 4px;border-radius:3px}
figure{margin:.8em 0}figcaption{font-weight:600;font-size:13px}svg{width:100%;height:auto}svg .grid{stroke:var(--line);stroke-width:1}svg .mark{stroke:var(--mut);stroke-dasharray:4 3;stroke-width:1}
svg .tick{fill:var(--mut);font-size:11px}.card{background:var(--card);padding:8px 12px;border-radius:6px}`

// stackCheck is one line of stack-checks.json, written by the test that brought the stack up: what only the stack's own database and logs can show.
type stackCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn"`
	Detail string `json:"detail"`
}

// MergeStackChecks puts the checks of the stack (stack-checks.json) into the result: the saved result, its verdict and the page all say whether the run was
// correct, whoever made the check. Merging twice does nothing more (the names are prefixed "stack: " and replaced).
func MergeStackChecks(res *gen.Result, dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "stack-checks.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var sc []stackCheck
	if err := json.Unmarshal(b, &sc); err != nil {
		return err
	}
	var keep []gen.CheckResult
	for _, c := range res.Checks {
		if !strings.HasPrefix(c.Name, "stack: ") {
			keep = append(keep, c)
		}
	}
	for _, c := range sc {
		keep = append(keep, gen.CheckResult{Name: "stack: " + c.Name, OK: c.OK, Warn: c.Warn, Detail: c.Detail})
	}
	res.Checks = keep
	res.Recompute()
	return res.WriteJSON(dir)
}

// Write writes DIR/report.html (after merging the stack's checks into the result).
func Write(res *gen.Result, dir string) error {
	if err := MergeStackChecks(res, dir); err != nil {
		return err
	}
	var st *StackSeries
	if b, err := os.ReadFile(filepath.Join(dir, "stack.json")); err == nil {
		var s StackSeries
		if json.Unmarshal(b, &s) == nil {
			st = &s
		}
	}
	return os.WriteFile(filepath.Join(dir, "report.html"), []byte(Render(res, st)), 0o644)
}

func Render(res *gen.Result, st *StackSeries) string {
	var b strings.Builder
	s := res.Scenario
	verdict := `<span class="ok">passed</span>`
	if !res.Pass {
		verdict = `<span class="bad">FAILED: a correctness check did not hold</span>`
	}
	fmt.Fprintf(&b, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Load run %s</title><style>%s</style><body>`, esc(res.RunID), css)
	fmt.Fprintf(&b, `<h1>Load run %s: %s</h1><p class="muted">%s loop, seed %d, started %s. Correctness: %s.</p>`, esc(res.RunID), esc(s.Name), s.Mode, s.Seed, res.Started.Format("2006-01-02 15:04:05 MST"), verdict)
	if s.Note != "" {
		fmt.Fprintf(&b, `<p>%s</p>`, esc(s.Note))
	}
	if len(res.Meta) > 0 {
		var ks []string
		for k := range res.Meta {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		b.WriteString(`<p class="card muted">`)
		for _, k := range ks {
			fmt.Fprintf(&b, `%s: <code>%s</code> &nbsp; `, esc(k), esc(res.Meta[k]))
		}
		b.WriteString(`</p>`)
	}

	b.WriteString(`<h2>Correctness after the run</h2><table><tr><th>Check</th><th>Result</th><th style="text-align:left">Detail</th></tr>`)
	for _, c := range res.Checks {
		cls, txt := "ok", "ok"
		if !c.OK {
			cls, txt = "bad", "FAILED"
			if c.Warn {
				cls, txt = "warn", "warning"
			}
		}
		fmt.Fprintf(&b, `<tr><td>%s</td><td class="%s">%s</td><td style="text-align:left">%s</td></tr>`, esc(c.Name), cls, txt, esc(c.Detail))
	}
	b.WriteString(`</table>`)

	b.WriteString(`<h2>Operations</h2>`)
	b.WriteString(opTable(res.Total))
	if res.FirstLimit != "" {
		fmt.Fprintf(&b, `<p class="card"><b>First objective broken:</b> %s</p>`, esc(res.FirstLimit))
	}
	if len(res.Steps) > 1 {
		b.WriteString(`<h2>Steps</h2><table><tr><th>Step</th><th>Rate scale</th><th>Operation</th><th>Offered /s</th><th>Ended well /s</th><th>Errors</th><th>Total p50 ms</th><th>Total p95 ms</th><th style="text-align:left">Objectives broken</th></tr>`)
		for _, sp := range res.Steps {
			name := fmt.Sprint(sp.Step)
			if sp.Step < 0 {
				name = "ramp"
			}
			if sp.Partial {
				name += fmt.Sprintf(" (stopped after %.0f s)", sp.DurationS)
			}
			keys := sortedKeys(sp.Ops)
			for i, k := range keys {
				o := sp.Ops[k]
				q := o.Latency["total"]
				v := ""
				if i == 0 {
					v = esc(strings.Join(sp.Violations, "; "))
				}
				fmt.Fprintf(&b, `<tr><td>%s</td><td>%g</td><td style="text-align:left">%s</td><td>%.2f</td><td>%.2f</td><td>%d</td><td>%.0f</td><td>%.0f</td><td style="text-align:left" class="bad">%s</td></tr>`,
					name, sp.Scale, esc(k), o.OfferedPS, o.AchievedPS, o.Offered-o.OK, q.P50, q.P95, v)
			}
		}
		b.WriteString(`</table>`)
	}

	b.WriteString(`<h2>The run over time</h2>`)
	var marks []float64
	if len(s.Steps) > 0 {
		for i := 0; i <= len(s.Steps); i++ {
			marks = append(marks, s.RampS+float64(i)*s.StepS)
		}
	} else {
		marks = []float64{s.RampS, s.RampS + s.HoldS}
	}
	b.WriteString(rateChart(res, marks))
	b.WriteString(inflightChart(res, marks))
	b.WriteString(latencyChart(res, marks))
	if st != nil {
		b.WriteString(`<h2>What the stack did</h2><p class="muted">Sampled by the test that brought the stack up, every ` + fmt.Sprintf("%.0f", st.IntervalS) + ` s. The time axis is seconds since the arrivals began.</p>`)
		b.WriteString(stackTable(res, st))
		b.WriteString(stackCharts(res, st, marks))
	}
	b.WriteString(`<p class="muted">Made by <code>qv-load report</code> from <code>result.json</code>. Latencies run from the scheduled arrival of an operation to the stage named.</p></body></html>`)
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

var stageCols = []string{"request", "approvals", "approved", "signing", "broadcast", "confirmed", "approved_to_broadcast", "sent", "credited", "swept", "total"}

func opTable(m map[string]*gen.OpSummary) string {
	var b strings.Builder
	b.WriteString(`<table><tr><th>Operation</th><th>Offered</th><th>Ended well</th><th>Errors by kind</th><th>Stage</th><th>n</th><th>p50 ms</th><th>p95 ms</th><th>p99 ms</th><th>max ms</th></tr>`)
	for _, k := range sortedKeys(m) {
		o := m[k]
		errs := "none"
		if len(o.Errors) > 0 {
			var p []string
			for _, ek := range sortedKeys(o.Errors) {
				p = append(p, fmt.Sprintf("%s %d", ek, o.Errors[ek]))
			}
			errs = strings.Join(p, ", ")
		}
		first := true
		for _, st := range stageCols {
			q, ok := o.Latency[st]
			if !ok || q.N == 0 {
				continue
			}
			if first {
				fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td>`, esc(k), o.Offered, o.OK, esc(errs))
				first = false
			} else {
				b.WriteString(`<tr><td></td><td></td><td></td><td></td>`)
			}
			fmt.Fprintf(&b, `<td>%s</td><td>%d</td><td>%.0f</td><td>%.0f</td><td>%.0f</td><td>%.0f</td></tr>`, st, q.N, q.P50, q.P95, q.P99, q.Max)
		}
		if first {
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td colspan="6" class="muted">no operation ended well</td></tr>`, esc(k), o.Offered, o.OK, esc(errs))
		}
	}
	b.WriteString(`</table>`)
	return b.String()
}

func diff(prev, cur map[string]int64, k string) float64 { return float64(cur[k] - prev[k]) }

func rateChart(res *gen.Result, marks []float64) string {
	keys := map[string]bool{}
	for _, p := range res.Series {
		for k := range p.Offered {
			keys[k] = true
		}
	}
	var ls []Line
	for _, k := range sortedKeys(keys) {
		var x, off, done []float64
		prev := gen.SeriesPoint{Offered: map[string]int64{}, Done: map[string]int64{}}
		// 5-point moving window to smooth Poisson arrivals
		var offs, dones []float64
		for _, p := range res.Series {
			offs = append(offs, diff(prev.Offered, p.Offered, k))
			dones = append(dones, diff(prev.Done, p.Done, k))
			prev = p
			x = append(x, p.T)
		}
		off, done = smooth(offs, 5), smooth(dones, 5)
		ls = append(ls, Line{Name: k + " offered", X: x, Y: off}, Line{Name: k + " ended well", X: x, Y: done})
	}
	return lineChart("Offered and completed operations per second (5 s average)", "per second", ls, marks)
}

func smooth(v []float64, w int) []float64 {
	out := make([]float64, len(v))
	for i := range v {
		lo := i - w + 1
		if lo < 0 {
			lo = 0
		}
		var s float64
		for j := lo; j <= i; j++ {
			s += v[j]
		}
		out[i] = s / float64(i-lo+1)
	}
	return out
}

func inflightChart(res *gen.Result, marks []float64) string {
	keys := map[string]bool{}
	for _, p := range res.Series {
		for k := range p.Inflight {
			keys[k] = true
		}
	}
	var ls []Line
	for _, k := range sortedKeys(keys) {
		l := Line{Name: k}
		for _, p := range res.Series {
			l.X = append(l.X, p.T)
			l.Y = append(l.Y, float64(p.Inflight[k]))
		}
		ls = append(ls, l)
	}
	return lineChart("Operations in flight (a queue that grows is a system that cannot keep up)", "operations", ls, marks)
}

func latencyChart(res *gen.Result, marks []float64) string {
	var ls []Line
	for _, k := range sortedKeys(res.Windows) {
		p50, p95 := Line{Name: k + " p50"}, Line{Name: k + " p95"}
		for _, w := range res.Windows[k] {
			p50.X, p95.X = append(p50.X, w.T), append(p95.X, w.T)
			p50.Y, p95.Y = append(p50.Y, w.P50), append(p95.Y, w.P95)
		}
		ls = append(ls, p50, p95)
	}
	return lineChart("Latency from arrival to the final state, by completion time (5 s windows)", "milliseconds", ls, marks)
}

func stackCharts(res *gen.Result, st *StackSeries, marks []float64) string {
	groups := map[string][]string{}
	for name := range st.Series {
		g, _, _ := strings.Cut(name, ":")
		groups[g] = append(groups[g], name)
	}
	titles := map[string]string{"cpu": "CPU per process (percent of one core)", "rss": "Resident memory per process (MB)", "queue": "Queues and open work (count)",
		"db": "Postgres: connections and waits (count)", "chain": "Chain"}
	var b strings.Builder
	for _, g := range []string{"cpu", "rss", "queue", "db", "chain"} {
		names := groups[g]
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		var ls []Line
		for _, n := range names {
			ls = append(ls, Line{Name: strings.TrimPrefix(n, g+":"), X: st.T, Y: st.Series[n]})
		}
		b.WriteString(lineChart(titles[g], "", ls, marks))
	}
	return b.String()
}

// stackTable: the mean of every sampled series in each step of the run: which process or queue grows with the rate.
func stackTable(res *gen.Result, st *StackSeries) string {
	s := res.Scenario
	type win struct {
		name   string
		lo, hi float64
	}
	var ws []win
	if s.RampS > 0 {
		ws = append(ws, win{"ramp", 0, s.RampS})
	}
	if len(s.Steps) > 0 {
		for i, sc := range s.Steps {
			lo := s.RampS + float64(i)*s.StepS
			hi := lo + s.StepS
			if res.StoppedEarly != nil && res.StoppedEarly.Step < i {
				break
			}
			if res.StoppedEarly != nil && res.StoppedEarly.Step == i && res.StoppedEarly.AtS < hi {
				hi = res.StoppedEarly.AtS
			}
			ws = append(ws, win{fmt.Sprintf("x%g", sc), lo, hi})
		}
	} else {
		ws = append(ws, win{"hold", s.RampS, s.RampS + s.HoldS})
	}
	var b strings.Builder
	b.WriteString(`<table><tr><th>Mean over the step</th>`)
	for _, w := range ws {
		fmt.Fprintf(&b, `<th>%s</th>`, esc(w.name))
	}
	b.WriteString(`</tr>`)
	for _, name := range sortedKeys(st.Series) {
		if strings.HasPrefix(name, "rss:") {
			continue
		}
		var cells []string
		any := false
		for _, w := range ws {
			var sum float64
			n := 0
			for i, t := range st.T {
				if t >= w.lo && t < w.hi && i < len(st.Series[name]) {
					sum += st.Series[name][i]
					n++
				}
			}
			if n == 0 {
				cells = append(cells, "-")
				continue
			}
			v := sum / float64(n)
			if v >= 1 {
				any = true
			}
			cells = append(cells, fmtNum(v))
		}
		if !any {
			continue
		}
		fmt.Fprintf(&b, `<tr><td>%s</td>`, esc(strings.Replace(name, ":", " ", 1)))
		for _, c := range cells {
			fmt.Fprintf(&b, `<td>%s</td>`, c)
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</table>`)
	return b.String()
}
