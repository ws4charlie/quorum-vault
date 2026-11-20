package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// sealerGate keeps the party "not ready" until the attested sealer holds the data keys. It runs the start-up preload in the background with
// backoff, so a broker that is down or refuses does not stop the health probe from answering: the probe says not ready, with the reason in the
// log, and the party never falls back to another sealer. Nothing that needs a key runs before the gate opens.
type sealerGate struct {
	fs  *FileStore
	as  *AttestedSealer
	log *slog.Logger
	// role is the party role, for the metric labels.
	role string

	ready atomic.Bool
	mu    sync.Mutex
	why   string
	tries uint64
}

// newSealerGate returns the gate of a store whose sealer is attested, or nil (nothing to wait for).
func newSealerGate(st any, role string, log *slog.Logger) *sealerGate {
	fs, ok := st.(*FileStore)
	if !ok {
		return nil
	}
	as, ok := fs.sealer.(*AttestedSealer)
	if !ok {
		return nil
	}
	g := &sealerGate{fs: fs, as: as, log: log, role: role, why: "the data keys have not been released yet"}
	return g
}

// sealerReady is nil when the party may use its keys.
func (s *Server) sealerReady() error {
	if s.gate == nil {
		return nil
	}
	return s.gate.err()
}

func (g *sealerGate) err() error {
	if g.ready.Load() {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return fmt.Errorf("sealer not ready: %s", g.why)
}

func (g *sealerGate) set(why string) { g.mu.Lock(); g.why = why; g.mu.Unlock() }

// run preloads until it works or ctx ends. Every failed attempt is logged with its reason; a refusal because the measurement is not allowlisted is
// a distinct ALERT line (and the metric qv_mpc_party_attest_exchanges_total{outcome="refused:allowlist"}).
func (g *sealerGate) run(ctx context.Context) {
	delay := 500 * time.Millisecond
	for {
		g.mu.Lock()
		g.tries++
		g.mu.Unlock()
		actx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := g.fs.PrepareSealer(actx)
		cancel()
		if err == nil {
			g.ready.Store(true)
			g.set("")
			g.log.Info("attested sealer: data keys released; the party is ready", "role", g.role, "keys", len(g.as.Held()))
			return
		}
		if ctx.Err() != nil {
			return
		}
		kind, code, allow := brokerKindOf(err)
		g.set(err.Error())
		switch {
		case allow:
			g.log.Error("ALERT attested sealer: the broker refused to release the data keys because this party's measurement is not allowlisted (a new image that was not added to the signed allowlist, an expired entry, or a revoked one); the party stays not ready and does NOT fall back to another sealer", "role", g.role, "broker_code", code, "retry_in", delay.String())
		case kind == "refused":
			g.log.Error("attested sealer: the broker refused to release the data keys; the party stays not ready", "role", g.role, "broker_code", code, "err", err.Error(), "retry_in", delay.String())
		case kind == "unreachable":
			g.log.Warn("attested sealer: the broker is unreachable; the party stays not ready and retries", "role", g.role, "err", err.Error(), "retry_in", delay.String())
		default:
			g.log.Error("attested sealer: cannot release the data keys; the party stays not ready", "role", g.role, "err", err.Error(), "retry_in", delay.String())
		}
		wait := delay
		if code == "rate_limited" && wait < 5*time.Second {
			wait = 5 * time.Second
		}
		wait += time.Duration(rand.Int64N(int64(wait)/4 + 1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

// writeMetrics adds the sealer's counters (no secrets) to the metrics page.
func (g *sealerGate) writeMetrics(w io.Writer) {
	v := 0
	if g.ready.Load() {
		v = 1
	}
	fmt.Fprintf(w, "# HELP qv_mpc_party_sealer_ready 1 once the attested sealer holds the data keys (the party is ready); 0 while it waits for the broker.\n# TYPE qv_mpc_party_sealer_ready gauge\nqv_mpc_party_sealer_ready{party=%q} %d\n", g.role, v)
	st := g.as.Stats()
	keys := make([]string, 0, len(st))
	for k := range st {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# HELP qv_mpc_party_attest_exchanges_total Exchanges of this party with the attestation broker by outcome: exchange_ok:unseal and exchange_ok:create succeeded; refused:allowlist = the measurement is not allowlisted; refused:verify = the evidence did not verify; refused:rate_limited, refused:nonce, refused:other; unreachable; evidence_failed; error. Counters only grow.\n# TYPE qv_mpc_party_attest_exchanges_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(w, "qv_mpc_party_attest_exchanges_total{party=%q,outcome=%q} %d\n", g.role, k, st[k])
	}
}
