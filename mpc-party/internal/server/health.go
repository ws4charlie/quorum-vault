package server

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Probes for a container orchestrator (Kubernetes): /livez and /readyz, plain http on their own address (config of the command:
// -health-listen / QV_HEALTH_LISTEN), no credentials, no detail, nothing else on that port. The party's gRPC Health stays what it is, for
// monitoring over the mutually authenticated caller port; a kubelet cannot use it, because its gRPC probe does not speak TLS and the caller port
// is mutual TLS with pinned callers. The root module's internal/health does the same for the other services; this module cannot import it,
// so the few lines are repeated here.

// Ready says whether the party can do its job: Start finished (data directory locked, sealer open, listeners up), Shutdown has not begun, and
// its certificate is inside its validity period. It does not look at the other parties: a probe that depended on them would take every pod out
// of service at once when one is down.
func (s *Server) Ready(now time.Time) error {
	if !s.started.Load() {
		return errors.New("not started")
	}
	s.stopMu.Lock()
	stopped := s.stopped
	s.stopMu.Unlock()
	if stopped {
		return errors.New("stopping")
	}
	if err := s.sealerReady(); err != nil {
		return err
	}
	cert := s.certNow()
	if len(cert.Certificate) == 0 {
		return errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// HealthHandler serves GET and HEAD of /livez (always 200) and /readyz (200 or 503); everything else is 404 or 405.
func (s *Server) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	serve := func(ok func() bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			body := "ok\n"
			if !ok() {
				w.WriteHeader(http.StatusServiceUnavailable)
				body = "not ready\n"
			}
			if r.Method == http.MethodGet {
				w.Write([]byte(body))
			}
		}
	}
	mux.HandleFunc("/livez", serve(func() bool { return true }))
	mux.HandleFunc("/readyz", serve(func() bool { return s.Ready(time.Now()) == nil }))
	return mux
}
