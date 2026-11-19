// Command qv-approval-web serves the approval page (web/approval) from its own origin. It is a static file server and nothing else: no cookies, no
// session, no proxy to the core. It sets a strict Content-Security-Policy (no inline script, the page may talk only to itself, the identity provider
// and the core), refuses to be framed, and writes /config.json from its flags, so one build of the page works against any deployment.
//
//	qv-approval-web -listen :8443 -dir web/approval -issuer https://idp.example/realms/qv -client-id qv-approval -api https://core.example
//
// The page's origin is what an approver's passkey is bound to (the zone's rp_id and origins) and what the core's -approval-origins lists. Terminate
// TLS in front of it (or give -tls-cert and -tls-key); a passkey needs a secure context, which http://localhost also is for a developer.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qv-approval-web:", err)
		os.Exit(1)
	}
}

// pageConfig is what the page reads from /config.json.
type pageConfig struct {
	Issuer   string         `json:"issuer"`
	ClientID string         `json:"client_id"`
	API      string         `json:"api"`
	Decimals map[string]int `json:"decimals,omitempty"`
	// MaxLoginAge is how old (seconds) a sign-in may be before the page asks for a fresh one before it asks for a key touch. The core's own limit is
	// the judge; this only avoids a touch that would be wasted.
	MaxLoginAge int `json:"max_login_age"`
}

func run(args []string) error {
	fs := flag.NewFlagSet("qv-approval-web", flag.ContinueOnError)
	listen := fs.String("listen", envOr("QV_APPROVAL_LISTEN", "127.0.0.1:8090"), "listen address (env QV_APPROVAL_LISTEN)")
	dir := fs.String("dir", envOr("QV_APPROVAL_DIR", "web/approval"), "directory of the page's files (env QV_APPROVAL_DIR)")
	issuer := fs.String("issuer", os.Getenv("QV_OIDC_ISSUER"), "OIDC issuer URL the page signs in with (env QV_OIDC_ISSUER)")
	clientID := fs.String("client-id", envOr("QV_APPROVAL_CLIENT_ID", "qv-approval"), "the page's public OIDC client (authorization code with PKCE) (env QV_APPROVAL_CLIENT_ID)")
	api := fs.String("api", os.Getenv("QV_APPROVAL_API"), "origin of the core's API the page calls, e.g. https://core.example (env QV_APPROVAL_API)")
	decimals := fs.String("asset-decimals", os.Getenv("QV_APPROVAL_ASSET_DECIMALS"), "ASSET=decimals pairs the page uses to show amounts, e.g. ETH=18,USDT=6 (display only; the amount is always shown in base units too) (env QV_APPROVAL_ASSET_DECIMALS)")
	maxAge := fs.Duration("max-login-age", 4*time.Minute, "ask for a fresh sign-in before an approval when the last one is older than this; keep it under the core's -oidc-stepup-max-age")
	cert := fs.String("tls-cert", "", "serve https with this certificate (PEM); otherwise plain http, for a TLS-terminating proxy or http://localhost")
	key := fs.String("tls-key", "", "private key of -tls-cert")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := pageConfig{Issuer: strings.TrimRight(*issuer, "/"), ClientID: *clientID, API: strings.TrimRight(*api, "/"), MaxLoginAge: int(maxAge.Seconds())}
	for _, f := range []struct{ name, v string }{{"-issuer", cfg.Issuer}, {"-api", cfg.API}} {
		u, err := url.Parse(f.v)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("%s: want an http(s) URL, got %q", f.name, f.v)
		}
	}
	if (*cert == "") != (*key == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	if *decimals != "" {
		cfg.Decimals = map[string]int{}
		for _, p := range strings.Split(*decimals, ",") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); !ok || err != nil || n < 0 || n > 36 {
				return fmt.Errorf("-asset-decimals: bad pair %q", p)
			}
			cfg.Decimals[k] = n
		}
	}
	if st, err := os.Stat(*dir); err != nil || !st.IsDir() {
		return fmt.Errorf("-dir %q is not a directory", *dir)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	srv := &http.Server{Addr: *listen, Handler: Handler(*dir, cfg), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("qv-approval-web listening", "addr", *listen, "issuer", cfg.Issuer, "api", cfg.API, "tls", *cert != "")
	var err error
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// origin is scheme://host[:port] of a URL, for the policy.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// policy is the page's Content-Security-Policy: nothing but its own files; the page may fetch from itself, the identity provider and the core; no
// inline script or style, no plugins, no framing, no form posts, no other base URL.
func policy(cfg pageConfig) string {
	connect := []string{"'self'", origin(cfg.Issuer)}
	if o := origin(cfg.API); o != origin(cfg.Issuer) {
		connect = append(connect, o)
	}
	return strings.Join([]string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self'",
		"connect-src " + strings.Join(connect, " "),
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	}, "; ")
}

// Handler serves dir read-only (GET and HEAD) and /config.json. Every reply carries the security headers and no cookie.
func Handler(dir string, cfg pageConfig) http.Handler {
	files := http.FileServer(http.Dir(dir))
	body, _ := json.Marshal(cfg)
	csp := policy(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/config.json" {
			h.Set("Content-Type", "application/json")
			w.Write(body)
			return
		}
		files.ServeHTTP(w, r)
	})
}
