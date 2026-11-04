// Command qv-worker runs the Temporal worker of the business zone: deposit
// scan, sweep planning, sweep and withdrawal workflows. It reads the business
// database and the chain, and never signs: signatures arrive through the
// sign_jobs table, from the signing gateway. The one key it holds is the
// automated approver for the lowest approval tier.
//
// QV_FAILPOINT="<kind>.<name>" (tests only) makes it exit at that boundary.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"go.temporal.io/sdk/client"
	sdklog "go.temporal.io/sdk/log"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("qv-worker stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfgPath := flag.String("config", "", "custody config file (required)")
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "business database DSN (env DATABASE_URL)")
	temporalAddr := flag.String("temporal", envOr("QV_TEMPORAL_ADDR", "127.0.0.1:7233"), "Temporal address (env QV_TEMPORAL_ADDR)")
	namespace := flag.String("namespace", "default", "Temporal namespace")
	queue := flag.String("task-queue", workflow.DefaultTaskQueue, "Temporal task queue")
	autoKey := flag.String("auto-approver-key-file", os.Getenv("QV_AUTO_APPROVER_KEY_FILE"),
		"file with the automated approver's Ed25519 seed (64 hex chars); optional (env QV_AUTO_APPROVER_KEY_FILE)")
	flag.Parse()
	if *cfgPath == "" || *dsn == "" {
		return errors.New("-config and -dsn (or DATABASE_URL) are required")
	}
	cfg, err := custody.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	var key ed25519.PrivateKey
	if *autoKey != "" {
		if key, err = loadKey(*autoKey); err != nil {
			return err
		}
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
	if err := workflow.RegisterNamespace(ctx, *temporalAddr, *namespace); err != nil {
		return err
	}
	tc, err := client.DialContext(ctx, client.Options{HostPort: *temporalAddr, Namespace: *namespace, Logger: sdklog.NewStructuredLogger(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})))})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer tc.Close()

	w := workflow.NewWorker(tc, workflow.Deps{Svc: svc, Client: tc, AutoKey: key, Log: log, T: workflow.DefaultTimings(cfg), Queue: *queue})
	if err := w.Start(); err != nil {
		return err
	}
	defer w.Stop()
	if err := workflow.EnsureLoops(ctx, tc, *queue, cfg, log); err != nil {
		return err
	}
	log.Info("qv-worker started", "chain", cfg.Chain, "failpoint", os.Getenv("QV_FAILPOINT"))
	<-ctx.Done()
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auto approver key: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("auto approver key must be %d hex chars", ed25519.SeedSize*2)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
