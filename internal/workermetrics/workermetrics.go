// Package workermetrics is the metrics endpoint of qv-worker.
//
// The Temporal SDK reports its own metrics (workflow and activity outcomes and latencies, schedule-to-start latency = task-queue lag, poller and slot gauges)
// to any client.MetricsHandler. Registry is one, in memory, written as Prometheus text: no new dependency and no second registry (the SDK's usual
// handler, contrib/tally, would bring a metrics library into a module that has none). SDK names "temporal_x" are published as "qv_worker_x"
// ("_total" on counters, "_seconds" histograms on timers), with the SDK's tags as labels (namespace, task_queue, workflow_type, activity_type, ...).
// None of them carries an address, key or amount.
//
// The worker's own state (ready, stopping since SIGTERM, the stop timeout) and the certificate expiry (pki.Source) are added by Handler.
// The SDK creates a counter at its first event, so a series is absent until then: rules use the form in monitoring/README of the first-event rules.
package workermetrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// timerBuckets are the upper limits in seconds of the timer histograms: from a fast database call to a queue that is minutes behind.
var timerBuckets = []float64{0.01, 0.05, 0.25, 1, 5, 15, 30, 60, 300}

type series struct {
	labels string // rendered {a="b",...} sorted by key; empty for none
	c      int64
	g      float64
	// timer: cumulative counts per bucket limit, total count and sum in seconds
	b   []int64
	n   int64
	sum float64
}

type family struct {
	kind string // counter, gauge, histogram
	s    map[string]*series
}

// Registry implements client.MetricsHandler. The zero value is not ready: use New.
type Registry struct {
	mu       sync.Mutex
	fam      map[string]*family
	ready    atomic.Bool
	stopping atomic.Bool
	stopTO   time.Duration
	started  time.Time
}

var _ client.MetricsHandler = (*Registry)(nil)

// New returns a Registry; stopTimeout is the worker's -stop-timeout, published as a gauge.
func New(stopTimeout time.Duration) *Registry {
	return &Registry{fam: map[string]*family{}, stopTO: stopTimeout, started: time.Now()}
}

// SetReady records whether the worker is polling (the readiness probe's answer).
func (r *Registry) SetReady(v bool) { r.ready.Store(v) }

// SetStopping records that SIGTERM arrived: the worker polls no more and waits for its running activities.
func (r *Registry) SetStopping() { r.stopping.Store(true) }

type counterFunc func(int64)
type gaugeFunc func(float64)
type timerFunc func(time.Duration)

func (f counterFunc) Inc(d int64)          { f(d) }
func (f gaugeFunc) Update(v float64)       { f(v) }
func (f timerFunc) Record(d time.Duration) { f(d) }

type handle struct {
	r    *Registry
	tags map[string]string
}

func (r *Registry) WithTags(t map[string]string) client.MetricsHandler { return handle{r, t} }
func (r *Registry) Counter(n string) client.MetricsCounter {
	return handle{r, nil}.Counter(n)
}
func (r *Registry) Gauge(n string) client.MetricsGauge { return handle{r, nil}.Gauge(n) }
func (r *Registry) Timer(n string) client.MetricsTimer { return handle{r, nil}.Timer(n) }

func (h handle) WithTags(t map[string]string) client.MetricsHandler {
	m := make(map[string]string, len(h.tags)+len(t))
	for k, v := range h.tags {
		m[k] = v
	}
	for k, v := range t {
		m[k] = v
	}
	return handle{h.r, m}
}

func (h handle) Counter(n string) client.MetricsCounter {
	return counterFunc(func(d int64) { h.with(promName(n, "counter"), "counter", func(s *series) { s.c += d }) })
}
func (h handle) Gauge(n string) client.MetricsGauge {
	return gaugeFunc(func(v float64) { h.with(promName(n, "gauge"), "gauge", func(s *series) { s.g = v }) })
}
func (h handle) Timer(n string) client.MetricsTimer {
	return timerFunc(func(d time.Duration) {
		h.with(promName(n, "histogram"), "histogram", func(s *series) {
			v := d.Seconds()
			if s.b == nil {
				s.b = make([]int64, len(timerBuckets))
			}
			for i, le := range timerBuckets {
				if v <= le {
					s.b[i]++
				}
			}
			s.n++
			s.sum += v
		})
	})
}

func (h handle) with(name, kind string, f func(*series)) {
	lb := renderLabels(h.tags)
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	fm := h.r.fam[name]
	if fm == nil {
		fm = &family{kind: kind, s: map[string]*series{}}
		h.r.fam[name] = fm
	}
	s := fm.s[lb]
	if s == nil {
		s = &series{labels: lb}
		fm.s[lb] = s
	}
	f(s)
}

// promName turns an SDK metric name into the published one.
func promName(n, kind string) string {
	n = strings.TrimPrefix(n, "temporal_")
	out := make([]byte, 0, len(n))
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	n = "qv_worker_" + string(out)
	switch kind {
	case "counter":
		if !strings.HasSuffix(n, "_total") {
			n += "_total"
		}
	case "histogram":
		n += "_seconds"
	}
	return n
}

func renderLabels(t map[string]string) string {
	if len(t) == 0 {
		return ""
	}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", labelName(k), t[k])
	}
	b.WriteByte('}')
	return b.String()
}

func labelName(k string) string {
	out := []byte(k)
	for i, c := range out {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			out[i] = '_'
		}
	}
	return string(out)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Write writes the worker's own state and every SDK metric seen so far.
func (r *Registry) Write(w io.Writer) {
	fmt.Fprintf(w, "# TYPE qv_worker_ready gauge\nqv_worker_ready %g\n", b2f(r.ready.Load()))
	fmt.Fprintf(w, "# TYPE qv_worker_stopping gauge\nqv_worker_stopping %g\n", b2f(r.stopping.Load()))
	fmt.Fprintf(w, "# TYPE qv_worker_stop_timeout_seconds gauge\nqv_worker_stop_timeout_seconds %g\n", r.stopTO.Seconds())
	fmt.Fprintf(w, "# TYPE qv_worker_start_time_seconds gauge\nqv_worker_start_time_seconds %d\n", r.started.Unix())
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.fam))
	for n := range r.fam {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fm := r.fam[n]
		fmt.Fprintf(w, "# TYPE %s %s\n", n, fm.kind)
		lbs := make([]string, 0, len(fm.s))
		for l := range fm.s {
			lbs = append(lbs, l)
		}
		sort.Strings(lbs)
		for _, l := range lbs {
			s := fm.s[l]
			switch fm.kind {
			case "counter":
				fmt.Fprintf(w, "%s%s %d\n", n, l, s.c)
			case "gauge":
				if math.IsNaN(s.g) || math.IsInf(s.g, 0) {
					continue
				}
				fmt.Fprintf(w, "%s%s %g\n", n, l, s.g)
			default:
				for i, le := range timerBuckets {
					fmt.Fprintf(w, "%s_bucket%s %d\n", n, withLE(l, fmt.Sprint(le)), s.b[i])
				}
				fmt.Fprintf(w, "%s_bucket%s %d\n%s_sum%s %g\n%s_count%s %d\n", n, withLE(l, "+Inf"), s.n, n, l, s.sum, n, l, s.n)
			}
		}
	}
}

func withLE(l, le string) string {
	if l == "" {
		return `{le="` + le + `"}`
	}
	return l[:len(l)-1] + `,le="` + le + `"}`
}

// Handler serves /metrics: the registry, then the certificate metrics of srcs (nil entries are skipped).
func (r *Registry) Handler(srcs ...*pki.Source) http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.Write(w)
	})
	return pki.WithMetrics(h, srcs...)
}

// RuleMetrics are the SDK metrics that monitoring/worker.rules.yml reads: published name -> the name the SDK reports it under. They are spelled out here
// because Registry builds names at run time, and so the metric-name test of monitoring/ (which looks for the literal name in program source) can see them;
// TestRuleMetricsExistInSDK checks every SDK name against the SDK's own constants, and TestRuleMetricsArePublishedNames that the mapping is what promName does.
var RuleMetrics = map[string]string{
	"qv_worker_workflow_failed_total":                           "temporal_workflow_failed",
	"qv_worker_workflow_task_schedule_to_start_latency_seconds": "temporal_workflow_task_schedule_to_start_latency",
	"qv_worker_activity_schedule_to_start_latency_seconds":      "temporal_activity_schedule_to_start_latency",
}
