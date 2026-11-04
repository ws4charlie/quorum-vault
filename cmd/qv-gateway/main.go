// Command qv-gateway is the signing gateway. It opens no listening port: it
// polls sign_jobs in the business database (role qv_gateway) and keeps its
// replay guard in a separate database. Trust roots come only from -config.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("qv-gateway stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	configPath := flag.String("config", "", "signing-zone config file (required)")
	jobsDSN := flag.String("jobs-dsn", os.Getenv("QV_GATEWAY_JOBS_DSN"), "business database DSN for role qv_gateway (env QV_GATEWAY_JOBS_DSN)")
	guardDSN := flag.String("guard-dsn", os.Getenv("QV_GATEWAY_GUARD_DSN"), "replay-guard database DSN, a different database (env QV_GATEWAY_GUARD_DSN)")
	interval := flag.Duration("interval", time.Second, "poll interval when the queue is empty")
	lease := flag.Duration("lease", 2*time.Minute, "how long a claimed job stays ours")
	worker := flag.String("worker-id", "", "worker id (default hostname-pid)")
	flag.Parse()

	if *configPath == "" || *jobsDSN == "" || *guardDSN == "" {
		return fmt.Errorf("-config, -jobs-dsn and -guard-dsn are required")
	}
	if same, err := sameDatabase(*jobsDSN, *guardDSN); err != nil || same {
		return fmt.Errorf("the replay guard must use a different database than the job queue (%v)", err)
	}
	cfg, err := gateway.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	lib, err := hsm.LoadLib(hsm.DefaultLibPath())
	if err != nil {
		return fmt.Errorf("load pkcs11: %w", err)
	}
	defer lib.Close()
	signers, closeSigners, err := gateway.HSMSigners(cfg, lib, os.Getenv("QV_HSM_PIN"))
	if err != nil {
		return err
	}
	defer closeSigners()

	jobs, err := pgxpool.New(ctx, *jobsDSN)
	if err != nil {
		return fmt.Errorf("open job queue: %w", err)
	}
	defer jobs.Close()
	gp, err := pgxpool.New(ctx, *guardDSN)
	if err != nil {
		return fmt.Errorf("open replay guard: %w", err)
	}
	defer gp.Close()
	guard, err := gateway.OpenGuard(ctx, gp)
	if err != nil {
		return err
	}
	id := *worker
	if id == "" {
		h, _ := os.Hostname()
		id = fmt.Sprintf("%s-%d", h, os.Getpid())
	}
	gw, err := gateway.New(cfg, nil, signers, guard, jobs, gateway.Options{WorkerID: id, Lease: *lease, Logger: log})
	if err != nil {
		return err
	}
	log.Info("qv-gateway started", "worker", id, "chains", len(cfg.Chains), "partitions", len(signers))
	if err := gw.Run(ctx, *interval); err != nil {
		return err
	}
	if !gw.Wait(cfg.SignTimeout) {
		// Closing the signers under a running call would crash inside the HSM
		// library. Nothing is lost: an unstored signature was never released.
		log.Error("a signer call is still running; exiting without closing the signers")
		os.Exit(1)
	}
	log.Info("qv-gateway stopped cleanly")
	return nil
}

// sameDatabase reports whether two DSNs name the same host, port and database.
func sameDatabase(a, b string) (bool, error) {
	key := func(dsn string) (string, error) {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", fmt.Errorf("bad DSN")
		}
		return u.Hostname() + ":" + u.Port() + "/" + strings.TrimPrefix(u.Path, "/"), nil
	}
	ka, err := key(a)
	if err != nil {
		return false, err
	}
	kb, err := key(b)
	if err != nil {
		return false, err
	}
	return ka == kb, nil
}
