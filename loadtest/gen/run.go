package gen

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Runner runs one scenario against one target.
type Runner struct {
	S         *Scenario
	T         *Target
	C         *Client
	Obs       *Observer
	RunID     string
	Meta      map[string]string
	chain     *chain
	approvers map[string]ed25519.PrivateKey
	wcust     []*wcust
	free      chan *dcust
	dcusts    []*dcust
	started   time.Time
	owner     map[common.Address]string // deposit address -> customer, for every address a payment may go to
	ownerMu   sync.Mutex

	t0       time.Time // start of the arrival phase
	mu       sync.Mutex
	records  []*OpRecord
	series   []SeriesPoint
	checks   []CheckResult
	n        atomic.Int64
	dropped  atomic.Int64
	stopped  atomic.Bool
	stopMu   sync.Mutex
	stopT    float64
	stopStep int
	stopIn   int64
	bgRec    []ReconcileProbe
	setup    SetupInfo
	logf     func(string, ...any)
	// salt makes the random addresses and amounts of a run depend on the run identifier as well as the seed: two runs with the same seed on one chain must not pay
	// the same destinations (the chain keeps their balances). The same seed and run identifier give the same run.
	salt int64
	// OutDir: if set, t0.txt (the start of the arrivals, RFC 3339) is written there when the load begins, so a sampler of the stack can line its series up.
	OutDir string
}

const maxInflight = 20000

func NewRunner(s *Scenario, t *Target, runID string, meta map[string]string) (*Runner, error) {
	if t.EVM == nil {
		return nil, fmt.Errorf("the target has no evm section")
	}
	obs := NewObserver(runID)
	c, err := NewClient(t, obs)
	if err != nil {
		return nil, err
	}
	if s.NeedsApprovers() && len(t.Actors.Approvers) < 2 {
		return nil, fmt.Errorf("the scenario has two-approver withdrawals and the target names fewer than two approvers")
	}
	ap, err := t.Approvers()
	if err != nil {
		return nil, err
	}
	h := fnv.New64a()
	h.Write([]byte(runID))
	return &Runner{owner: map[common.Address]string{}, S: s, T: t, C: c, Obs: obs, RunID: runID, Meta: meta, approvers: ap, logf: log.Printf, salt: int64(h.Sum64() >> 1)}, nil
}

// Run does the setup, the load and the checks, and returns the result.
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	var err error
	if r.chain, err = newChain(ctx, r.T.EVM); err != nil {
		return nil, err
	}
	startedAt := time.Now()
	r.started = startedAt
	if err := r.setupBooks(ctx); err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	r.Obs.setPhase("load")
	r.t0 = time.Now()
	if r.OutDir != "" {
		_ = os.MkdirAll(r.OutDir, 0o755)
		_ = os.WriteFile(filepath.Join(r.OutDir, "t0.txt"), []byte(r.t0.Format(time.RFC3339Nano)), 0o644)
	}
	arrive := r.S.ArrivalDuration()
	runCtx, cancel := context.WithDeadline(ctx, r.t0.Add(arrive+time.Duration(r.S.DrainS*float64(time.Second))))
	defer cancel()

	stopSeries := make(chan struct{})
	var side sync.WaitGroup
	side.Add(1)
	go func() { defer side.Done(); r.sampleSeries(stopSeries) }()
	if r.S.BackgroundReconcileS > 0 {
		side.Add(1)
		go func() { defer side.Done(); r.backgroundReconcile(runCtx, stopSeries) }()
	}

	var wg sync.WaitGroup
	if r.S.Mode == "open" {
		for i, st := range r.S.Streams {
			wg.Add(1)
			go func() { defer wg.Done(); r.arrivals(runCtx, &wg, i, st, arrive) }()
		}
	} else {
		r.closedLoop(runCtx, &wg, arrive)
	}
	wg.Wait()
	r.Obs.setPhase("checks")
	close(stopSeries)
	side.Wait()
	loadEnd := time.Now()

	r.runChecks(ctx)
	r.Obs.setPhase("done")
	return r.result(startedAt, loadEnd), nil
}

// setupBooks creates the customers and funds the withdrawing ones by deposits that it waits to see credited.
func (r *Runner) setupBooks(ctx context.Context) error {
	t := time.Now()
	su := r.S.Setup
	par := su.FundParallel
	if par <= 0 {
		par = 16
	}
	r.free = make(chan *dcust, su.DepositCustomers+1)
	fundWei := ethToWei(su.FundEachETH)
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	work := func(f func() error) {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := f(); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < su.WithdrawCustomers; i++ {
		id := fmt.Sprintf("%s-w%04d", r.RunID, i)
		c := &wcust{id: id, budget: new(big.Int).Set(fundWei), funded: new(big.Int).Set(fundWei), spent: new(big.Int)}
		r.wcust = append(r.wcust, c)
		work(func() error {
			addr, err := r.createCustomer(ctx, id)
			if err != nil {
				return err
			}
			r.setOwner(addr, id)
			if err := r.chain.send(ctx, addr, fundWei); err != nil {
				return err
			}
			return r.waitAvailable(ctx, id, fundWei)
		})
	}
	for i := 0; i < su.DepositCustomers; i++ {
		id := fmt.Sprintf("%s-d%05d", r.RunID, i)
		d := &dcust{id: id, credited: new(big.Int)}
		r.dcusts = append(r.dcusts, d)
		work(func() error {
			addr, err := r.createCustomer(ctx, id)
			d.addr = addr
			r.setOwner(addr, id)
			return err
		})
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	for _, d := range r.dcusts {
		r.free <- d
	}
	r.setup = SetupInfo{WithdrawCustomers: su.WithdrawCustomers, DepositCustomers: su.DepositCustomers, FundEachETH: su.FundEachETH, DurationS: time.Since(t).Seconds()}
	r.logf("setup: %d withdrawing and %d deposit customers in %.1fs", su.WithdrawCustomers, su.DepositCustomers, time.Since(t).Seconds())
	return nil
}

func (r *Runner) setOwner(a common.Address, id string) {
	r.ownerMu.Lock()
	r.owner[a] = id
	r.ownerMu.Unlock()
}

func (r *Runner) waitAvailable(ctx context.Context, id string, want *big.Int) error {
	dl, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		a, _, err := r.available(dl, id, "ETH")
		if err != nil {
			return err
		}
		if a.Cmp(want) >= 0 {
			return nil
		}
		if !sleepCtx(dl, 200*time.Millisecond) {
			return fmt.Errorf("customer %s was not credited %s in 3 minutes", id, want)
		}
	}
}

// arrivals is the open loop: arrivals at the stream's rate times the phase's scale, at exponential gaps from the scenario's seed, whatever the system does.
func (r *Runner) arrivals(ctx context.Context, wg *sync.WaitGroup, idx int, st Stream, arrive time.Duration) {
	rng := rand.New(rand.NewSource(r.S.Seed*1000 + int64(idx)))
	opRng := rand.New(rand.NewSource(r.S.Seed*1000 + 500 + int64(idx) + r.salt))
	// Poisson arrivals whose rate changes with the phase, made by thinning: candidates at the largest rate, each kept with probability scale/maxScale.
	maxScale := 1.0
	for _, x := range r.S.Steps {
		if x > maxScale {
			maxScale = x
		}
	}
	if len(r.S.Steps) > 0 {
		maxScale = 0
		for _, x := range r.S.Steps {
			if x > maxScale {
				maxScale = x
			}
		}
	}
	next := 0.0 // scheduled time of the next candidate, seconds since t0
	for {
		next += rng.ExpFloat64() / (st.Rate * maxScale)
		if next >= arrive.Seconds() {
			return
		}
		scale, step := r.S.scaleAt(next)
		if rng.Float64() >= scale/maxScale {
			continue
		}
		due := r.t0.Add(time.Duration(next * float64(time.Second)))
		if !sleepUntil(ctx, due) {
			return
		}
		late := time.Since(due)
		r.Obs.opLate(late.Seconds())
		if r.shouldStop(step) { // every arrival loop asks, so all of them stop at the same moment
			return
		}
		if r.inflightTotal() >= maxInflight {
			r.dropped.Add(1)
			continue
		}
		rec := &OpRecord{N: int(r.n.Add(1)), Key: opKey(st), Step: step, StartMS: int64(next * 1000), LateMS: late.Milliseconds(), Stages: map[string]int64{}}
		r.Obs.opOffered(rec.Key)
		sub := rand.New(rand.NewSource(opRng.Int63()))
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.runOp(ctx, rec, due, st, sub)
		}()
	}
}

// shouldStop is asked by every arrival loop before it starts an operation. The first time more than max_inflight operations are open it records when (now, not
// the scheduled time of the arrival) and where, and from then on every loop gets true. What is already running is not touched: it drains.
func (r *Runner) shouldStop(step int) bool {
	if r.stopped.Load() {
		return true
	}
	if r.S.MaxInflight <= 0 {
		return false
	}
	in := r.inflightTotal()
	if in <= int64(r.S.MaxInflight) {
		return false
	}
	r.stopMu.Lock()
	defer r.stopMu.Unlock()
	if r.stopped.Load() {
		return true
	}
	r.stopT, r.stopStep, r.stopIn = time.Since(r.t0).Seconds(), step, in
	r.stopped.Store(true)
	r.logf("stopping every arrival at %.0fs (step %d): %d operations open, over max_inflight %d: the system is past its limit", r.stopT, step, in, r.S.MaxInflight)
	return true
}

func sleepUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	return sleepCtx(ctx, d)
}

func (r *Runner) inflightTotal() int64 {
	r.Obs.mu.Lock()
	defer r.Obs.mu.Unlock()
	var n int64
	for _, v := range r.Obs.inflight {
		n += v
	}
	return n
}

// closedLoop: Concurrency users, each starts its next operation (picked by the streams' rates) when the last one is final.
func (r *Runner) closedLoop(ctx context.Context, wg *sync.WaitGroup, arrive time.Duration) {
	var total float64
	for _, s := range r.S.Streams {
		total += s.Rate
	}
	for u := 0; u < r.S.Concurrency; u++ {
		rng := rand.New(rand.NewSource(r.S.Seed*1000 + int64(u) + r.salt))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Since(r.t0) < arrive && ctx.Err() == nil && !r.stopped.Load() {
				x := rng.Float64() * total
				st := r.S.Streams[len(r.S.Streams)-1]
				for _, s := range r.S.Streams {
					if x < s.Rate {
						st = s
						break
					}
					x -= s.Rate
				}
				step := 0
				if len(r.S.Steps) > 0 {
					_, step = r.S.scaleAt(time.Since(r.t0).Seconds())
				}
				if r.shouldStop(step) {
					return
				}
				now := time.Now()
				rec := &OpRecord{N: int(r.n.Add(1)), Key: opKey(st), Step: step, StartMS: now.Sub(r.t0).Milliseconds(), Stages: map[string]int64{}}
				r.Obs.opOffered(rec.Key)
				r.runOp(ctx, rec, now, st, rand.New(rand.NewSource(rng.Int63())))
			}
		}()
	}
}

func opKey(st Stream) string {
	if st.Op == "deposit" {
		a := st.Asset
		if a == "" {
			a = "ETH"
		}
		return "deposit:" + a
	}
	return "withdraw:" + st.Tier
}

func (r *Runner) runOp(ctx context.Context, rec *OpRecord, t0 time.Time, st Stream, rng *rand.Rand) {
	var err error
	if st.Op == "deposit" {
		err = r.doDeposit(ctx, rec, t0, st, rng)
	} else {
		err = r.doWithdraw(ctx, rec, t0, st, rng)
	}
	kind, msg := errKind(err)
	rec.Err, rec.ErrMsg = kind, msg
	if err == nil {
		last := "confirmed"
		if st.Op == "deposit" {
			last = "swept"
			if st.Until == "credited" {
				last = "credited"
			}
		}
		r.Obs.opStage(rec.Key, "total", time.Duration(rec.Stages[last])*time.Millisecond)
	}
	r.Obs.opEnd(rec.Key, kind)
	r.mu.Lock()
	r.records = append(r.records, rec)
	r.mu.Unlock()
}

// SeriesPoint is the state of the run once a second.
type SeriesPoint struct {
	T        float64          `json:"t"`
	Scale    float64          `json:"scale"`
	Offered  map[string]int64 `json:"offered"`
	Done     map[string]int64 `json:"done"`
	Failed   map[string]int64 `json:"failed"`
	Inflight map[string]int64 `json:"inflight"`
}

func (r *Runner) sampleSeries(stop chan struct{}) {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
		}
		o := r.Obs
		sc, _ := r.S.scaleAt(time.Since(r.t0).Seconds())
		o.mu.Lock()
		o.scale = sc
		p := SeriesPoint{T: time.Since(r.t0).Seconds(), Scale: sc, Offered: cp(o.offered), Done: cp(o.done), Inflight: cp(o.inflight), Failed: map[string]int64{}}
		for k, v := range o.failed {
			op, _, _ := cut(k)
			p.Failed[op] += v
		}
		o.mu.Unlock()
		r.mu.Lock()
		r.series = append(r.series, p)
		r.mu.Unlock()
	}
}

func cut(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func cp(m map[string]int64) map[string]int64 {
	o := make(map[string]int64, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// ReconcileProbe is a Reconcile call during the load (the operator's background job): how long it took and whether the books agreed with the chain.
type ReconcileProbe struct {
	T        float64 `json:"t"`
	MS       int64   `json:"ms"`
	Clean    bool    `json:"clean"`
	InFlight int     `json:"in_flight"`
	Err      string  `json:"err,omitempty"`
	// Why: the first comparison that failed (name and the books' and the chain's figures), if the report was not clean
	Why string `json:"why,omitempty"`
}

func (r *Runner) backgroundReconcile(ctx context.Context, stop chan struct{}) {
	tk := time.NewTicker(time.Duration(r.S.BackgroundReconcileS * float64(time.Second)))
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		t := time.Now()
		_, out, err := r.C.Call(ctx, r.T.Actors.Ops, "GET", "/v2/reconcile", nil, nil)
		p := ReconcileProbe{T: time.Since(r.t0).Seconds(), MS: time.Since(t).Milliseconds()}
		if err != nil {
			p.Err = err.Error()
		} else {
			p.Clean, _ = out["clean"].(bool)
			if !p.Clean {
				cs, _ := out["checks"].([]any)
				for _, c := range cs {
					m, _ := c.(map[string]any)
					if ok, _ := m["ok"].(bool); !ok && m["skipped"] != true {
						p.Why = fmt.Sprintf("%v %v: ledger %v, chain %v", m["name"], m["subject"], m["ledger"], m["chain"])
						break
					}
					if m["skipped"] == true && p.Why == "" {
						p.Why = fmt.Sprintf("skipped: %v", m["name"])
					}
				}
			}
			if f, ok := out["in_flight"].(float64); ok {
				p.InFlight = int(f)
			}
		}
		r.mu.Lock()
		r.bgRec = append(r.bgRec, p)
		r.mu.Unlock()
	}
}

// ---- statistics ----

// Quantiles of a list of durations in milliseconds.
type Quantiles struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

func quant(v []int64) Quantiles {
	if len(v) == 0 {
		return Quantiles{}
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		if i < 0 {
			i = 0
		}
		return float64(s[i])
	}
	return Quantiles{N: len(s), P50: q(0.5), P90: q(0.9), P95: q(0.95), P99: q(0.99), Max: float64(s[len(s)-1])}
}

func addrs(a []common.Address) []string {
	out := make([]string, len(a))
	for i, x := range a {
		out[i] = x.Hex()
	}
	return out
}
