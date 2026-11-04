// Command qv-core is the HTTP API of the closed loop (/v2). It writes the
// business database and talks to Temporal; it holds no key and has no access
// to the signing zone. The X-Actor header names the caller (demo-grade auth).
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
	"syscall"
	"time"

	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
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
	queue := flag.String("task-queue", workflow.DefaultTaskQueue, "Temporal task queue")
	flag.Parse()
	if *cfgPath == "" || *dsn == "" {
		return errors.New("-config and -dsn (or DATABASE_URL) are required")
	}
	cfg, err := custody.LoadConfig(*cfgPath)
	if err != nil {
		return err
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
	adapter, err := evm.New(ctx, cfg.EVM, pool)
	if err != nil {
		return err
	}
	defer adapter.Close()
	reader, err := custody.NewEVMReader(ctx, cfg)
	if err != nil {
		return err
	}
	defer reader.Close()
	svc := custody.New(pool, cfg, adapter, reader)
	if err := svc.Bootstrap(ctx); err != nil {
		return err
	}
	tc, err := client.DialContext(ctx, client.Options{HostPort: *temporalAddr, Namespace: *namespace})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer tc.Close()

	api := custody.NewAPI(svc, workflow.Orch{C: tc, T: workflow.DefaultTimings(cfg), Queue: *queue}, log)
	srv := &http.Server{Addr: *addr, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("qv-core listening", "addr", *addr, "chain", cfg.Chain)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
