// Package health is the probe endpoint of a service that runs under a container orchestrator (Kubernetes): two plain-http routes on a
// listener of their own, /livez and /readyz, that need no credentials and say nothing but "ok" or "not ready".
//
//   - live: the process runs and answers. Always 200 while the listener is up. A failing live probe restarts the process, so it never
//     looks at a dependency.
//   - ready: the process can do its job. 200 only after start-up finished, while no dependency check fails, and until the process is told
//     to stop. A failing ready probe only takes the pod out of the Service; nothing is restarted.
//
// The listener serves nothing else (no metrics, no pprof, no state) and its answer carries no detail; the reason for a failing check is
// logged once per change. It is off unless -health-listen / QV_HEALTH_LISTEN is set, and it is meant for the pod's own address
// (kubelet probes cannot reach a loopback address), so it must never be put on a route that is open to callers.
// The distroless images have no shell: the probes are httpGet probes.
package health

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// CheckTimeout bounds every dependency check, so a hung database cannot hang the probe.
const CheckTimeout = 2 * time.Second

// Flag registers -health-listen (environment QV_HEALTH_LISTEN) on fs. Empty means no health listener.
func Flag(fs *flag.FlagSet) *string {
	return fs.String("health-listen", os.Getenv("QV_HEALTH_LISTEN"),
		"serve /livez and /readyz (plain http, no credentials, no detail) on this address for container probes, e.g. 0.0.0.0:9100; off when empty (env QV_HEALTH_LISTEN)")
}

type check struct {
	name string
	fn   func(context.Context) error
}

// Probe holds the state of one service's probes.
type Probe struct {
	log    *slog.Logger
	ready  atomic.Bool
	mu     sync.Mutex
	checks []check
	failed map[string]bool // checks that failed at the last look, to log only the changes
}

// New returns a probe that is live and not ready: call SetReady(true) once start-up is complete.
func New(log *slog.Logger) *Probe {
	if log == nil {
		log = slog.Default()
	}
	return &Probe{log: log, failed: map[string]bool{}}
}

// Check adds a dependency that must answer for the service to be ready (a database ping, a Temporal health call, the certificates).
func (p *Probe) Check(name string, fn func(context.Context) error) {
	p.mu.Lock()
	p.checks = append(p.checks, check{name, fn})
	p.mu.Unlock()
}

// SetReady marks start-up complete (true) or the start of a stop (false). A stopping service must say false first, so the Service stops
// sending work while the process finishes what it has.
func (p *Probe) SetReady(v bool) { p.ready.Store(v) }

// Ready runs every check and reports the first failure. It is false before SetReady(true) and after SetReady(false).
func (p *Probe) Ready(ctx context.Context) error {
	if !p.ready.Load() {
		return errors.New("not started, or stopping")
	}
	p.mu.Lock()
	checks := append([]check(nil), p.checks...)
	p.mu.Unlock()
	var first error
	for _, c := range checks {
		cctx, cancel := context.WithTimeout(ctx, CheckTimeout)
		err := c.fn(cctx)
		cancel()
		p.note(c.name, err)
		if err != nil && first == nil {
			first = fmt.Errorf("%s: %w", c.name, err)
		}
	}
	return first
}

// note logs a check that started or stopped failing; a steady state is silent.
func (p *Probe) note(name string, err error) {
	p.mu.Lock()
	was := p.failed[name]
	p.failed[name] = err != nil
	p.mu.Unlock()
	switch {
	case err != nil && !was:
		p.log.Warn("not ready", "check", name, "error", err.Error())
	case err == nil && was:
		p.log.Info("ready again", "check", name)
	}
}

// Handler serves /livez and /readyz for GET and HEAD and answers 404 to everything else.
func (p *Probe) Handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(ok bool, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			if r.Method == http.MethodGet {
				fmt.Fprintln(w, "not ready")
			}
			return
		}
		if r.Method == http.MethodGet {
			fmt.Fprintln(w, "ok")
		}
	}
	only := func(f func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			f(w, r)
		}
	}
	mux.HandleFunc("/livez", only(func(w http.ResponseWriter, r *http.Request) { reply(true, w, r) }))
	mux.HandleFunc("/readyz", only(func(w http.ResponseWriter, r *http.Request) { reply(p.Ready(r.Context()) == nil, w, r) }))
	return mux
}

// Serve starts the listener on addr (nothing happens when addr is empty) and returns the function that stops it. When ctx ends the
// service is marked not ready at once; the listener itself stays up until stop is called, so the probe answers "not ready" (not
// "refused") while the process drains.
func (p *Probe) Serve(ctx context.Context, addr string) (stop func(), err error) {
	if addr == "" {
		return func() {}, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("-health-listen: %w", err)
	}
	srv := &http.Server{Handler: p.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.log.Error("health server stopped", "error", err.Error())
		}
	}()
	go func() {
		<-ctx.Done()
		p.SetReady(false)
	}()
	p.log.Info("health probes on", "addr", ln.Addr().String())
	return func() { srv.Close() }, nil
}

// Certs is a readiness check: every certificate source is loaded and not expired (a nil source, as in the development plain-text mode, is skipped).
func Certs(srcs ...*pki.Source) func(context.Context) error {
	return func(context.Context) error {
		for _, s := range srcs {
			if s != nil && s.SecondsToExpiry() <= 0 {
				return fmt.Errorf("certificate %s has expired", s.Name())
			}
		}
		return nil
	}
}

// Pinger is what a database pool offers.
type Pinger interface{ Ping(context.Context) error }

// Ping is a readiness check that pings a database.
func Ping(p Pinger) func(context.Context) error { return p.Ping }
