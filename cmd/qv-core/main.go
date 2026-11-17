// Command qv-core is the HTTP API of the closed loop (/v2). It writes the
// business database and talks to Temporal; it holds no key and has no access
// to the signing zone. Callers send an OIDC bearer token; the token's sub is the actor. The X-Actor header is accepted only with
// -dev-actor-header, which production start-up refuses (see internal/auth).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.temporal.io/sdk/client"
	sdklog "go.temporal.io/sdk/log"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/chainfactory"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("qv-core stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfgPath := flag.String("config", "", "custody config file (required)")
	addr := flag.String("addr", envOr("QV_HTTP_ADDR", "127.0.0.1:8080"), "listen address (env QV_HTTP_ADDR)")
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "business database DSN (env DATABASE_URL)")
	temporalAddr := flag.String("temporal", envOr("QV_TEMPORAL_ADDR", "127.0.0.1:7233"), "Temporal address (env QV_TEMPORAL_ADDR)")
	namespace := flag.String("namespace", "default", "Temporal namespace")
	queue := flag.String("task-queue", "", "Temporal task queue (default qv-core-<chain>, so one worker per chain cell never takes another's work)")
	oidcIssuer := flag.String("oidc-issuer", os.Getenv("QV_OIDC_ISSUER"), "OIDC issuer URL: the iss of accepted tokens (env QV_OIDC_ISSUER)")
	oidcAud := flag.String("oidc-audience", envOr("QV_OIDC_AUDIENCE", "qv-core"), "audience the tokens must carry (env QV_OIDC_AUDIENCE)")
	oidcJWKS := flag.String("oidc-jwks-url", os.Getenv("QV_OIDC_JWKS_URL"), "JWKS URL; default: discovered from the issuer (env QV_OIDC_JWKS_URL)")
	rolesClaim := flag.String("oidc-roles-claim", envOr("QV_OIDC_ROLES_CLAIM", "roles"), "claim that lists roles or groups (env QV_OIDC_ROLES_CLAIM)")
	roleMap := flag.String("oidc-role-map", os.Getenv("QV_OIDC_ROLE_MAP"), "IdP group=core role pairs, comma separated, e.g. okta-qv-approvers=approver (default: the IdP uses the core role names) (env QV_OIDC_ROLE_MAP)")
	svcClients := flag.String("oidc-service-clients", os.Getenv("QV_OIDC_SERVICE_CLIENTS"), "comma separated client ids allowed to call with a client-credentials token (env QV_OIDC_SERVICE_CLIENTS)")
	stepUpACR := flag.String("oidc-stepup-acr", envOr("QV_OIDC_STEPUP_ACR", "aal3"), "acr a step-up route needs (env QV_OIDC_STEPUP_ACR)")
	stepUpAge := flag.Duration("oidc-stepup-max-age", 5*time.Minute, "how fresh auth_time must be on a step-up route")
	maxSession := flag.Duration("oidc-max-session", 12*time.Hour, "overall session limit counted from auth_time (NIST AAL3: 12h)")
	testJWKS := flag.String("oidc-test-jwks", os.Getenv("QV_OIDC_TEST_JWKS"), "JWKS file of the TEST issuer; refused unless QV_ENV is dev or test (env QV_OIDC_TEST_JWKS)")
	devActor := flag.Bool("dev-actor-header", os.Getenv("QV_DEV_ACTOR_HEADER") == "1", "accept X-Actor with nothing verified; refused unless QV_ENV is dev or test (env QV_DEV_ACTOR_HEADER=1)")
	flag.Parse()
	if *cfgPath == "" || *dsn == "" {
		return errors.New("-config and -dsn (or DATABASE_URL) are required")
	}
	acfg := auth.Config{Issuer: *oidcIssuer, Audience: *oidcAud, JWKSURL: *oidcJWKS, RolesClaim: *rolesClaim, StepUpACR: *stepUpACR,
		StepUpMaxAge: *stepUpAge, MaxSession: *maxSession, ServiceClients: splitList(*svcClients)}
	if *roleMap != "" {
		acfg.RoleMap = map[string]auth.Role{}
		for _, kv := range splitList(*roleMap) {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("-oidc-role-map: %q is not group=role", kv)
			}
			acfg.RoleMap[k] = auth.Role(v)
		}
	}
	if *testJWKS != "" {
		b, err := os.ReadFile(*testJWKS)
		if err != nil {
			return err
		}
		acfg.StaticJWKS = b
	}
	// Start-up refuses a loose setup before anything else happens: production is the default environment.
	authn, err := auth.New(acfg, auth.EnvironmentFromEnv(), *devActor)
	if err != nil {
		return err
	}
	cfg, err := custody.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *queue == "" {
		*queue = workflow.QueueFor(cfg.Chain)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	backend, err := chainfactory.Open(ctx, cfg, pool)
	if err != nil {
		return err
	}
	defer backend.Close()
	svc := custody.New(pool, cfg, backend.Adapter, backend.Reader)
	if err := svc.Bootstrap(ctx); err != nil {
		return err
	}
	tc, err := client.DialContext(ctx, client.Options{HostPort: *temporalAddr, Namespace: *namespace, Logger: sdklog.NewStructuredLogger(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})))})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer tc.Close()

	api := custody.NewAPI(svc, workflow.Orch{C: tc, T: workflow.DefaultTimings(cfg), Queue: *queue}, log, authn)
	srv := &http.Server{Addr: *addr, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if authn.DevHeader() {
		log.Warn("DEV ONLY: X-Actor is accepted without verification")
	}
	log.Info("qv-core listening", "addr", *addr, "chain", cfg.Chain, "issuer", *oidcIssuer)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
