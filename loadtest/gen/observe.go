package gen

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Observer counts what the generator does and serves it as Prometheus text (the live dashboard of a run). Names start with qvload_.
type Observer struct {
	mu       sync.Mutex
	RunID    string
	req      map[string]*hist // "METHOD route" -> latency
	reqErr   map[string]int64 // "METHOD route|kind"
	offered  map[string]int64 // op key
	done     map[string]int64
	failed   map[string]int64 // op key|kind
	inflight map[string]int64
	stage    map[string]*hist // op key|stage -> seconds since the operation began
	scale    float64
	late     float64 // largest lateness of a scheduled arrival, seconds
	phase    string
}

var buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

type hist struct {
	n   []int64
	sum float64
	cnt int64
}

func newHist() *hist { return &hist{n: make([]int64, len(buckets))} }
func (h *hist) add(s float64) {
	h.sum += s
	h.cnt++
	for i, b := range buckets {
		if s <= b {
			h.n[i]++
		}
	}
}

func NewObserver(runID string) *Observer {
	return &Observer{RunID: runID, req: map[string]*hist{}, reqErr: map[string]int64{}, offered: map[string]int64{}, done: map[string]int64{}, failed: map[string]int64{},
		inflight: map[string]int64{}, stage: map[string]*hist{}, phase: "setup"}
}

// route turns /v2/withdrawals/abc/approvals into /v2/withdrawals/:id/approvals so a metric has few series.
func route(p string) string {
	parts := strings.Split(p, "/")
	for i := 2; i < len(parts); i++ {
		if parts[i-1] == "withdrawals" || parts[i-1] == "customers" {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

func (o *Observer) request(method, path string, d time.Duration, err error) {
	if o == nil {
		return
	}
	k := method + " " + route(path)
	o.mu.Lock()
	defer o.mu.Unlock()
	h := o.req[k]
	if h == nil {
		h = newHist()
		o.req[k] = h
	}
	h.add(d.Seconds())
	if err != nil {
		o.reqErr[k+"|"+kindOf(err)]++
	}
}

func (o *Observer) setPhase(p string)  { o.mu.Lock(); o.phase = p; o.mu.Unlock() }
func (o *Observer) setScale(s float64) { o.mu.Lock(); o.scale = s; o.mu.Unlock() }
func (o *Observer) opOffered(k string) {
	o.mu.Lock()
	o.offered[k]++
	o.inflight[k]++
	o.mu.Unlock()
}
func (o *Observer) opStage(k, stage string, d time.Duration) {
	o.mu.Lock()
	h := o.stage[k+"|"+stage]
	if h == nil {
		h = newHist()
		o.stage[k+"|"+stage] = h
	}
	h.add(d.Seconds())
	o.mu.Unlock()
}
func (o *Observer) opEnd(k, errKind string) {
	o.mu.Lock()
	o.inflight[k]--
	if errKind == "" {
		o.done[k]++
	} else {
		o.failed[k+"|"+errKind]++
	}
	o.mu.Unlock()
}
func (o *Observer) opLate(s float64) {
	o.mu.Lock()
	if s > o.late {
		o.late = s
	}
	o.mu.Unlock()
}

func esc(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) }

func writeHist(w io.Writer, name, labels string, h *hist) {
	sep := ""
	if labels != "" {
		sep = ","
	}
	for i, b := range buckets {
		fmt.Fprintf(w, "%s_bucket{%s%sle=\"%g\"} %d\n", name, labels, sep, b, h.n[i])
	}
	fmt.Fprintf(w, "%s_bucket{%s%sle=\"+Inf\"} %d\n%s_sum{%s} %g\n%s_count{%s} %d\n", name, labels, sep, h.cnt, name, labels, h.sum, name, labels, h.cnt)
}

// WriteProm writes the metrics in the Prometheus text format.
func (o *Observer) WriteProm(w io.Writer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	run := fmt.Sprintf(`run="%s"`, esc(o.RunID))
	fmt.Fprintf(w, "# TYPE qvload_phase_info gauge\nqvload_phase_info{%s,phase=\"%s\"} 1\n", run, esc(o.phase))
	fmt.Fprintf(w, "# TYPE qvload_rate_scale gauge\nqvload_rate_scale{%s} %g\n# TYPE qvload_max_lateness_seconds gauge\nqvload_max_lateness_seconds{%s} %g\n", run, o.scale, run, o.late)
	keys := func(m map[string]int64) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	fmt.Fprintf(w, "# TYPE qvload_ops_offered_total counter\n")
	for _, k := range keys(o.offered) {
		fmt.Fprintf(w, "qvload_ops_offered_total{%s,op=\"%s\"} %d\n", run, esc(k), o.offered[k])
	}
	fmt.Fprintf(w, "# TYPE qvload_ops_completed_total counter\n")
	for _, k := range keys(o.done) {
		fmt.Fprintf(w, "qvload_ops_completed_total{%s,op=\"%s\"} %d\n", run, esc(k), o.done[k])
	}
	fmt.Fprintf(w, "# TYPE qvload_ops_failed_total counter\n")
	for _, k := range keys(o.failed) {
		op, kind, _ := strings.Cut(k, "|")
		fmt.Fprintf(w, "qvload_ops_failed_total{%s,op=\"%s\",kind=\"%s\"} %d\n", run, esc(op), esc(kind), o.failed[k])
	}
	fmt.Fprintf(w, "# TYPE qvload_ops_inflight gauge\n")
	for _, k := range keys(o.inflight) {
		fmt.Fprintf(w, "qvload_ops_inflight{%s,op=\"%s\"} %d\n", run, esc(k), o.inflight[k])
	}
	fmt.Fprintf(w, "# TYPE qvload_requests_failed_total counter\n")
	for _, k := range keys(o.reqErr) {
		r, kind, _ := strings.Cut(k, "|")
		fmt.Fprintf(w, "qvload_requests_failed_total{%s,request=\"%s\",kind=\"%s\"} %d\n", run, esc(r), esc(kind), o.reqErr[k])
	}
	fmt.Fprintf(w, "# TYPE qvload_request_seconds histogram\n")
	var rk []string
	for k := range o.req {
		rk = append(rk, k)
	}
	sort.Strings(rk)
	for _, k := range rk {
		writeHist(w, "qvload_request_seconds", fmt.Sprintf(`%s,request="%s"`, run, esc(k)), o.req[k])
	}
	fmt.Fprintf(w, "# TYPE qvload_stage_seconds histogram\n")
	var sk []string
	for k := range o.stage {
		sk = append(sk, k)
	}
	sort.Strings(sk)
	for _, k := range sk {
		op, st, _ := strings.Cut(k, "|")
		writeHist(w, "qvload_stage_seconds", fmt.Sprintf(`%s,op="%s",stage="%s"`, run, esc(op), esc(st)), o.stage[k])
	}
}

// Serve serves /metrics on addr until the process ends; it returns the address it listens on.
func (o *Observer) Serve(addr string) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		o.WriteProm(w)
	})
	return serve(addr, mux)
}
