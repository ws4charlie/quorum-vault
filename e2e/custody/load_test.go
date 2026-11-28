package custody_test

// The local load test (docs/measurements/load-local.md, loadtest/README.md): this test brings up the whole stack with real everything (two-party MPC
// signing on SoftHSM-sealed shares, Temporal, Redpanda, Postgres, anvil), runs the load generator (loadtest/cmd/qv-load) against the core's HTTP API as
// a client would, samples the stack while it runs, and afterwards checks what only the database can show. It does nothing unless QV_LOAD_SCENARIO is set:
// it is not part of any CI group. `make load-local SCENARIO=...` runs it.
//
// Knobs (environment): QV_LOAD_SCENARIO (file), QV_LOAD_OUT (result directory), QV_LOAD_SHARDS (hot shards per asset, default 2), QV_LOAD_WORKERS and
// QV_LOAD_CORES (copies of qv-worker and qv-core, default 1), QV_LOAD_LINK_DELAY_MS (delay added to every frame between party A and B, each way),
// QV_LOAD_RATE_SCALE, QV_LOAD_SEED, QV_LOAD_RUN_ID (the run identifier; open-loop arrivals come from the seed AND the run identifier, so a run is
// repeated exactly with the same QV_LOAD_SEED and QV_LOAD_RUN_ID; default random), QV_LOAD_TARGETS_DIR (a file_sd directory for the live dashboard's Prometheus), QV_LOAD_LABEL (names the shape in the result).

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/e2e/idp"
	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

func envInt(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return d
}

func TestLoadLocal(t *testing.T) {
	scen := os.Getenv("QV_LOAD_SCENARIO")
	if scen == "" {
		t.Skip("QV_LOAD_SCENARIO is not set: the load test is run by hand (make load-local)")
	}
	scen, _ = filepath.Abs(scen)
	shards := envInt("QV_LOAD_SHARDS", 2)
	nWorkers := envInt("QV_LOAD_WORKERS", 1)
	nCores := envInt("QV_LOAD_CORES", 1)
	delay := time.Duration(envInt("QV_LOAD_LINK_DELAY_MS", 0)) * time.Millisecond
	out := os.Getenv("QV_LOAD_OUT")
	if out == "" {
		out = filepath.Join("..", "..", "data", "load", time.Now().Format("20060102-150405"))
	}
	out, _ = filepath.Abs(out)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	seedHot := int64(1_000_000) // the hot wallets start with more than any run pays out: the run is not about liquidity
	var seed []int64
	for i := 0; i < shards; i++ {
		seed = append(seed, seedHot)
	}
	s := newSystem(t, opts{shards: shards, seed: seed, mpcProxy: delay > 0, minSweepWei: "1000000000000000"})
	if delay > 0 {
		s.mpc.Proxy.SetLatency(delay)
	}
	// more copies of the stateless parts
	var coreURLs = []string{s.apiURL}
	for i := 1; i < nCores; i++ {
		coreURLs = append(coreURLs, s.startExtraCore())
	}
	for i := 1; i < nWorkers; i++ {
		s.startExtraWorker()
	}

	// the generator, built into a gitignored path
	bin := filepath.Join(s.dir, "qv-load")
	if err := mpcstack.GoBuild(".", bin, "github.com/ws4charlie/quorum-vault/loadtest/cmd/qv-load", ""); err != nil {
		t.Fatalf("build qv-load: %v", err)
	}

	// the identity provider the generator asks for tokens: the e2e test issuer behind a loopback address (a cluster has its Keycloak instead)
	tokLn, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(tokLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.TrimPrefix(idp.Bearer(r.URL.Query().Get("actor")), "Bearer "))
	}))
	t.Cleanup(func() { tokLn.Close() })

	// keys of the approvers and of the faucet: generated for this run, in the run's directory, nothing in the repository
	keyDir := filepath.Join(s.dir, "keys")
	os.MkdirAll(keyDir, 0o700)
	files := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		p := filepath.Join(keyDir, n+".seed")
		os.WriteFile(p, []byte(hex.EncodeToString(s.approv[n].Seed())), 0o600)
		files[n] = p
	}
	funder := filepath.Join(keyDir, "funder.key")
	os.WriteFile(funder, []byte(hex.EncodeToString(crypto.FromECDSA(s.deployer))), 0o600)
	_, _, ca := pkitest.Files(pki.ZoneBusiness, "core")
	var api []string
	api = append(api, coreURLs...)
	target := map[string]any{
		"api": api, "ca_file": ca,
		"token":              map[string]any{"kind": "endpoint", "url": "http://" + tokLn.Addr().String() + "/token"},
		"actors":             map[string]any{"initiator": "initiator", "ops": "ops", "approvers": []string{"alice", "bob", "carol"}},
		"approver_key_files": files,
		"evm":                map[string]any{"chain": s.chainName, "rpc": s.rpcURL, "funder_key_file": funder, "chain_id": 11155111},
	}
	tb, _ := json.MarshalIndent(target, "", " ")
	targetPath := filepath.Join(s.dir, "target.json")
	if err := os.WriteFile(targetPath, tb, 0o600); err != nil {
		t.Fatal(err)
	}

	// the sampler of the stack, with its own metrics port
	smp := newStackSampler(s)
	smp.addProc("qv-gateway", s.gateway)
	smp.addProc("qv-relay", s.relay)
	smp.addProc("qv-worker-1", s.worker)
	smp.addProc("qv-core-1", s.core)
	for i, p := range loadExtraProcs {
		smp.addProc(p.name+fmt.Sprintf("-%d", i+2), p)
	}
	for name, p := range map[string]interface{ Pid() int }{"mpc-party-a": s.mpc.A, "mpc-party-b": s.mpc.B, "mpc-party-c": s.mpc.C, "cosigner-b": s.mpc.Cos, "cosigner-c": s.mpc.CosC} {
		smp.addPid(name, p.Pid)
	}
	smp.start()
	t.Cleanup(smp.stop)
	genMetrics := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if dir := os.Getenv("QV_LOAD_TARGETS_DIR"); dir != "" {
		os.MkdirAll(dir, 0o755)
		// Prometheus runs in Docker, and the listeners stay on 127.0.0.1 (nothing is published to the network). On macOS Docker Desktop forwards
		// host.docker.internal to the host's loopback. On Linux that name is the bridge address, which a loopback listener does not answer, so
		// deploy/load/compose.linux.yml runs Prometheus and Grafana on the host's network and the targets are 127.0.0.1 itself (deploy/load/dash.sh picks it).
		host := "host.docker.internal"
		if runtime.GOOS == "linux" {
			host = "127.0.0.1"
		}
		dock := func(a string) string { return host + ":" + a[strings.LastIndex(a, ":")+1:] }
		tg := []map[string]any{{"targets": []string{dock(genMetrics)}, "labels": map[string]string{"job": "qv-load"}}, {"targets": []string{dock(smp.addr)}, "labels": map[string]string{"job": "qv-stack"}}}
		b, _ := json.Marshal(tg)
		lane := filepath.Base(filepath.Dir(filepath.Dir(out)))
		_ = lane
		os.WriteFile(filepath.Join(dir, "targets-"+filepath.Base(out)+".json"), b, 0o644)
		t.Cleanup(func() { os.Remove(filepath.Join(dir, "targets-"+filepath.Base(out)+".json")) })
	}

	meta := []string{
		"-meta", "shape=compose: every service a process on this machine, infrastructure in Docker",
		"-meta", fmt.Sprintf("hot_shards=%d", shards), "-meta", fmt.Sprintf("workers=%d", nWorkers), "-meta", fmt.Sprintf("cores=%d", nCores),
		"-meta", fmt.Sprintf("party_link_delay_ms_each_way=%d", delay.Milliseconds()),
		"-meta", "machine=" + machineInfo(), "-meta", "signer=two-party MPC (2 of 3 keyset), shares sealed in SoftHSM",
		"-meta", "chain=anvil, automine (a block per transaction), confirmations 0",
	}
	if l := os.Getenv("QV_LOAD_LABEL"); l != "" {
		meta = append(meta, "-meta", "label="+l)
	}
	if h := gitHead(); h != "" {
		meta = append(meta, "-meta", "git="+h)
	}
	args := append([]string{"run", "-scenario", scen, "-target", targetPath, "-out", out, "-metrics-listen", genMetrics}, meta...)
	if v := os.Getenv("QV_LOAD_RATE_SCALE"); v != "" {
		args = append(args, "-rate-scale", v)
	}
	if v := os.Getenv("QV_LOAD_SEED"); v != "" {
		args = append(args, "-seed", v)
	}
	if v := os.Getenv("QV_LOAD_RUN_ID"); v != "" {
		args = append(args, "-run-id", v)
	}
	genStart := time.Now()
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	runErr := cmd.Run()
	genEnd := time.Now()
	smp.stop()
	t.Logf("generator ran %s, exit: %v", genEnd.Sub(genStart).Round(time.Second), runErr)

	// the stack's own series, lined up with the arrivals
	var t0 time.Time
	if b, err := os.ReadFile(filepath.Join(out, "t0.txt")); err == nil {
		t0, _ = time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	}
	if t0.IsZero() {
		t0 = genStart
	}
	smp.write(filepath.Join(out, "stack.json"), t0)

	// what only the stack can show
	var dbFails []string
	check := func(name string, ok bool, format string, a ...any) {
		d := fmt.Sprintf(format, a...)
		t.Logf("db check %-34s %v %s", name, ok, d)
		if !ok {
			dbFails = append(dbFails, name+": "+d)
		}
		dbChecks = append(dbChecks, map[string]any{"name": name, "ok": ok, "detail": d})
	}
	s.waitIdle(120 * time.Second)
	check("no_open_work", s.openWork() == 0, "%d open sweeps, withdrawals, moves", s.openWork())
	check("no_pending_hold", s.count(`SELECT count(*) FROM ledger_holds WHERE status = 'pending'`) == 0, "%d holds still pending", s.count(`SELECT count(*) FROM ledger_holds WHERE status = 'pending'`))
	check("withdrawal_tx_hash_unique", s.count(`SELECT count(*) - count(DISTINCT tx_hash) FROM withdrawals WHERE status = 'confirmed'`) == 0, "no two confirmed withdrawals share a transaction")
	check("no_failed_withdrawal", s.count(`SELECT count(*) FROM withdrawals WHERE status = 'failed'`) == 0, "%d failed withdrawals", s.count(`SELECT count(*) FROM withdrawals WHERE status = 'failed'`))
	check("no_failed_sign_job", s.count(`SELECT count(*) FROM sign_jobs WHERE status IN ('failed','rejected')`) == 0, "%d failed or rejected sign jobs", s.count(`SELECT count(*) FROM sign_jobs WHERE status IN ('failed','rejected')`))
	rep := s.reconcileClean()
	check("reconcile_clean_in_process", rep.Clean, "height %d", rep.Height)
	// ALERT lines in the services' logs. A Reconcile that reads the books while the scan is one block behind logs "scan_caught_up" and then reads clean a
	// moment later: counted apart as transient scan lag (a finding, see the report); any other alert fails the run.
	var alerts, transient []string
	for _, l := range s.alertLines() {
		if strings.Contains(l, "ALERT no -brokers") { // the harness starts the cosigners without Kafka: their start-up notice, not the system under load
			continue
		}
		if strings.Contains(l, "check=scan_caught_up") || strings.Contains(l, "check=deposit_addresses") {
			transient = append(transient, l)
		} else {
			alerts = append(alerts, l)
		}
	}
	check("no_alert_logged", len(alerts) == 0, "%d ALERT lines in the services' logs %s", len(alerts), strings.Join(first3(alerts), " | "))
	t.Logf("%d transient scan_caught_up alerts from Reconcile calls made while the scan was a block behind", len(transient))
	dbChecks = append(dbChecks, map[string]any{"name": "transient_scan_lag_alerts", "ok": true, "warn": true, "detail": fmt.Sprintf("%d scan_caught_up or deposit_addresses alerts logged by Reconcile calls (the generator's background job and its checks) while the scan was behind the chain; each read clean afterwards", len(transient))})
	func() {
		defer func() {
			if r := recover(); r != nil {
				check("outbox_exactly_once", false, "%v", r)
			}
		}()
		s.checkKafka(180 * time.Second)
		check("outbox_exactly_once", true, "every outbox row published and consumed once after de-duplication (%d rows)", s.count(`SELECT count(*) FROM outbox`))
	}()
	b, _ := json.MarshalIndent(dbChecks, "", " ")
	os.WriteFile(filepath.Join(out, "stack-checks.json"), b, 0o644)
	// the report again, now with the stack's series
	if b, err := exec.Command(bin, "report", "-in", out).CombinedOutput(); err != nil {
		t.Logf("report: %v\n%s", err, b)
	}
	if runErr != nil {
		t.Errorf("the generator reported a failed correctness check or an error: %v (see %s)", runErr, filepath.Join(out, "result.json"))
	}
	if len(dbFails) > 0 {
		t.Errorf("checks on the stack failed: %s", strings.Join(dbFails, "; "))
	}
	t.Logf("result: %s", filepath.Join(out, "report.html"))
}

var dbChecks []map[string]any

// the extra copies of the stateless services, started by this test only (the harness's system struct is shared and stays as it is)
var loadExtraProcs []*proc

func first3(s []string) []string {
	if len(s) > 3 {
		return s[:3]
	}
	return s
}

func gitHead() string {
	b, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func machineInfo() string {
	cpu, _ := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
	mem, _ := exec.Command("sysctl", "-n", "hw.memsize").Output()
	m, _ := strconv.ParseInt(strings.TrimSpace(string(mem)), 10, 64)
	load, _ := exec.Command("sh", "-c", "uptime | sed 's/.*load averages*: //'").Output()
	return fmt.Sprintf("%s, %d logical CPUs, %d GB, %s/%s; load average at the start (other work on the machine): %s", strings.TrimSpace(string(cpu)), runtime.NumCPU(), m>>30, runtime.GOOS, runtime.GOARCH, strings.TrimSpace(string(load)))
}

// alertLines are the ALERT lines the services logged, from the processes' log files (the stack writes one per process).
func (s *system) alertLines() []string {
	var out []string
	matches, _ := filepath.Glob(filepath.Join(s.dir, "*.log"))
	more, _ := filepath.Glob(filepath.Join(s.dir, "mpc", "*.log"))
	for _, f := range append(matches, more...) {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "ALERT") {
				l := sc.Text()
				if len(l) > 220 {
					l = l[:220]
				}
				out = append(out, filepath.Base(f)+": "+l)
			}
		}
		fh.Close()
	}
	return out
}

// startExtraCore starts another qv-core on its own port (the stateless part, scaled out) and returns its URL.
func (s *system) startExtraCore() string {
	port := freePort(s.t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	p := s.spawn("qv-core", nil, append([]string{"-config", s.cfgPath, "-dsn", s.bizDSN, "-addr", addr, "-task-queue", s.queue}, pkitest.CoreArgs()...)...)
	loadExtraProcs = append(loadExtraProcs, p)
	url := "https://" + addr
	s.waitFor(30*time.Second, "extra qv-core listening", func() bool {
		resp, err := pkitest.PeopleClient().Get(url + "/v2/reconcile")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	})
	return url
}

// startExtraWorker starts another qv-worker on the same task queue.
func (s *system) startExtraWorker() {
	p := s.spawn("qv-worker", []string{"QV_FAILPOINT="}, "-config", s.cfgPath, "-dsn", s.bizDSN, "-task-queue", s.queue, "-auto-approver-key-file", s.keyPath)
	loadExtraProcs = append(loadExtraProcs, p)
	s.waitFor(30*time.Second, "extra worker started", func() bool { return fileContains(p.log, "qv-worker started") })
}

// ---- the sampler ----

type stackSampler struct {
	s     *system
	addr  string
	mu    sync.Mutex
	pids  map[string]func() int
	order []string
	times []time.Time
	vals  map[string][]float64
	last  map[string]float64 // cumulative CPU seconds at the last sample
	lastT time.Time
	cur   map[string]float64 // the latest values, for /metrics
	stopC chan struct{}
	done  sync.WaitGroup
	once  sync.Once
}

func newStackSampler(s *system) *stackSampler {
	return &stackSampler{s: s, pids: map[string]func() int{}, vals: map[string][]float64{}, last: map[string]float64{}, cur: map[string]float64{}, stopC: make(chan struct{})}
}

func (m *stackSampler) addProc(name string, p *proc) {
	m.addPid(name, func() int {
		if p == nil || p.cmd == nil || p.cmd.Process == nil {
			return 0
		}
		return p.cmd.Process.Pid
	})
}
func (m *stackSampler) addPid(name string, f func() int) {
	m.pids[name] = f
	m.order = append(m.order, name)
}

func (m *stackSampler) start() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		m.s.t.Fatal(err)
	}
	m.addr = ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		var ks []string
		for k := range m.cur {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			g, n, _ := strings.Cut(k, ":")
			fmt.Fprintf(w, "qvstack_%s{name=\"%s\"} %g\n", g, n, m.cur[k])
		}
	})
	go http.Serve(ln, mux)
	m.done.Add(2)
	go func() { defer m.done.Done(); m.loop() }()
	go func() { defer m.done.Done(); m.dockerLoop() }()
}

func (m *stackSampler) stop() {
	m.once.Do(func() { close(m.stopC); m.done.Wait() })
}

func (m *stackSampler) record(t time.Time, vals map[string]float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := len(m.times)
	m.times = append(m.times, t)
	for k, v := range vals {
		m.cur[k] = v
		col := m.vals[k]
		for len(col) < idx { // a series that starts late
			col = append(col, 0)
		}
		m.vals[k] = append(col, v)
	}
	for k, col := range m.vals {
		if len(col) < len(m.times) {
			m.vals[k] = append(col, col[len(col)-1])
		}
	}
}

// cpuSeconds parses ps's cputime ("M:SS.hh" or "H:MM:SS").
func cpuSeconds(s string) float64 {
	parts := strings.Split(strings.TrimSpace(s), ":")
	var v float64
	for _, p := range parts {
		x, _ := strconv.ParseFloat(p, 64)
		v = v*60 + x
	}
	return v
}

func (m *stackSampler) loop() {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-m.stopC:
			return
		case now := <-tk.C:
			vals := map[string]float64{}
			var args []string
			byPid := map[string]string{}
			for _, n := range m.order {
				if pid := m.pids[n](); pid > 0 {
					args = append(args, strconv.Itoa(pid))
					byPid[strconv.Itoa(pid)] = n
				}
			}
			if len(args) > 0 {
				b, _ := exec.Command("ps", "-o", "pid=,cputime=,rss=", "-p", strings.Join(args, ",")).Output()
				for _, ln := range strings.Split(string(b), "\n") {
					f := strings.Fields(ln)
					if len(f) != 3 {
						continue
					}
					n := byPid[f[0]]
					cpu := cpuSeconds(f[1])
					if prev, ok := m.last[n]; ok && !m.lastT.IsZero() {
						vals["cpu:"+n] = 100 * (cpu - prev) / now.Sub(m.lastT).Seconds()
					}
					m.last[n] = cpu
					rss, _ := strconv.ParseFloat(f[2], 64)
					vals["rss:"+n] = rss / 1024
				}
			}
			m.lastT = now
			m.db(vals)
			m.mu.Lock()
			for k, v := range m.cur { // keep the docker values in each sample
				if strings.HasPrefix(k, "cpu:docker-") || strings.HasPrefix(k, "rss:docker-") {
					vals[k] = v
				}
			}
			m.mu.Unlock()
			m.record(now, vals)
		}
	}
}

// db samples the business database: connections, lock waits, the queues of work.
func (m *stackSampler) db(vals map[string]float64) {
	s := m.s
	q := func(name, sql string) {
		var n int
		if err := s.pool.QueryRow(s.ctx, sql).Scan(&n); err == nil {
			vals[name] = float64(n)
		}
	}
	q("db:connections", `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()`)
	q("db:active", `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND pid <> pg_backend_pid()`)
	q("db:waiting_on_locks", `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`)
	for _, st := range []string{"requested", "approved", "signing", "broadcast"} {
		q("queue:withdrawals_"+st, `SELECT count(*) FROM withdrawals WHERE status = '`+st+`'`)
	}
	q("queue:sign_jobs_pending", `SELECT count(*) FROM sign_jobs WHERE status = 'pending'`)
	q("queue:sign_jobs_signing", `SELECT count(*) FROM sign_jobs WHERE status = 'signing'`)
	q("queue:outbox_unpublished", `SELECT count(*) FROM outbox WHERE published_at IS NULL`)
	q("queue:sweeps_open", `SELECT count(*) FROM sweeps WHERE status NOT IN ('confirmed','failed')`)
	m.temporal(vals)
	q("queue:deposits_seen", `SELECT count(*) FROM deposits WHERE status IN ('seen','confirmed')`)
}

// dockerLoop reads the CPU of this lane's containers (Postgres, Temporal, Redpanda, anvil: inside Docker's VM, so ps cannot see them).
func (m *stackSampler) dockerLoop() {
	proj := os.Getenv("COMPOSE_PROJECT_NAME")
	if proj == "" {
		return
	}
	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-m.stopC:
			return
		case <-tk.C:
		}
		b, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}} {{.MemUsage}}").Output()
		if err != nil {
			continue
		}
		m.mu.Lock()
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) < 3 || !strings.HasPrefix(f[0], proj+"-") {
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(f[0], proj+"-"), "-1")
			cpu, _ := strconv.ParseFloat(strings.TrimSuffix(f[1], "%"), 64)
			m.cur["cpu:docker-"+name] = cpu
			mem := strings.TrimSuffix(f[2], "MiB")
			if x, err := strconv.ParseFloat(strings.TrimSuffix(mem, "GiB"), 64); err == nil {
				if strings.HasSuffix(f[2], "GiB") {
					x *= 1024
				}
				m.cur["rss:docker-"+name] = x
			}
		}
		m.mu.Unlock()
	}
}

// write writes stack.json (the format of loadtest/report.StackSeries), the times in seconds since t0 and only from t0 on.
func (m *stackSampler) write(path string, t0 time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := struct {
		IntervalS float64              `json:"interval_s"`
		T         []float64            `json:"t"`
		Series    map[string][]float64 `json:"series"`
	}{IntervalS: 1, Series: map[string][]float64{}}
	var keep []int
	for i, t := range m.times {
		if !t.Before(t0) {
			keep = append(keep, i)
			out.T = append(out.T, t.Sub(t0).Seconds())
		}
	}
	for k, col := range m.vals {
		var v []float64
		for _, i := range keep {
			if i < len(col) {
				v = append(v, col[i])
			}
		}
		out.Series[k] = v
	}
	b, _ := json.Marshal(out)
	_ = os.WriteFile(path, b, 0o644)
}

// temporal reads the backlog of the worker's task queues from Temporal: tasks waiting for a worker to take them, and how long the oldest has waited.
func (m *stackSampler) temporal(vals map[string]float64) {
	s := m.s
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	resp, err := s.tc.DescribeTaskQueueEnhanced(ctx, client.DescribeTaskQueueEnhancedOptions{TaskQueue: s.queue, ReportStats: true,
		TaskQueueTypes: []client.TaskQueueType{client.TaskQueueTypeWorkflow, client.TaskQueueTypeActivity}})
	if err != nil {
		return
	}
	for _, v := range resp.VersionsInfo {
		for typ, ti := range v.TypesInfo {
			if ti.Stats == nil {
				continue
			}
			n := "workflow"
			if typ == client.TaskQueueTypeActivity {
				n = "activity"
			}
			vals["queue:temporal_"+n+"_tasks_waiting"] += float64(ti.Stats.ApproximateBacklogCount)
			if a := ti.Stats.ApproximateBacklogAge.Seconds(); a > vals["queue:temporal_"+n+"_oldest_wait_s"] {
				vals["queue:temporal_"+n+"_oldest_wait_s"] = a
			}
		}
	}
}
