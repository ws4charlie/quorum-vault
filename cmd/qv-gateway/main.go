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

	"github.com/ws4charlie/quorum-vault/internal/auditchain"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log) // the 2-of-3 signer logs its degraded/recovered transitions through the default logger
	if err := run(log); err != nil {
		log.Error("qv-gateway stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		return auditchain.VerifyCommand(context.Background(), os.Args[2:], "gateway", "QV_GATEWAY_GUARD_DSN", os.Stdout)
	}
	configPath := flag.String("config", "", "signing-zone config file (required)")
	jobsDSN := flag.String("jobs-dsn", os.Getenv("QV_GATEWAY_JOBS_DSN"), "business database DSN for role qv_gateway (env QV_GATEWAY_JOBS_DSN)")
	guardDSN := flag.String("guard-dsn", os.Getenv("QV_GATEWAY_GUARD_DSN"), "replay-guard database DSN, a different database (env QV_GATEWAY_GUARD_DSN)")
	interval := flag.Duration("interval", time.Second, "poll interval when the queue is empty")
	lease := flag.Duration("lease", 2*time.Minute, "how long a claimed job stays ours")
	worker := flag.String("worker-id", "", "worker id (default hostname-pid)")
	brokers := flag.String("brokers", os.Getenv("QV_KAFKA_BROKERS"), "Kafka brokers for publishing the head of this zone's audit chain on qv.audit.heads (optional; env QV_KAFKA_BROKERS)")
	auditSource := flag.String("audit-source", "gateway", "name this chain's heads are published under on qv.audit.heads (several deployments sharing one topic need distinct names)")
	anchorEvery := flag.Duration("anchor-interval", time.Minute, "publish the audit chain head at least this often, and at once when it changes")
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

	signers := map[string]signer.Signer{}
	if gateway.HasHSMSigners(cfg) {
		lib, err := hsm.LoadLib(hsm.DefaultLibPath())
		if err != nil {
			return fmt.Errorf("load pkcs11: %w", err)
		}
		defer lib.Close()
		hs, closeSigners, err := gateway.HSMSigners(cfg, lib, os.Getenv("QV_HSM_PIN"))
		if err != nil {
			return err
		}
		defer closeSigners()
		for k, v := range hs {
			signers[k] = v
		}
	}
	ms, closeMPC, err := gateway.MPCSigners(cfg)
	if err != nil {
		return err
	}
	defer closeMPC()
	for k, v := range ms {
		signers[k] = v
	}
	if err := gateway.CheckSigners(cfg, signers); err != nil {
		return err
	}

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
	if *brokers == "" {
		log.Error("ALERT no -brokers: this zone's audit chain heads are not published, so a truncated or rewritten chain cannot be detected from outside the database")
	}
	if *brokers != "" {
		pub, err := outbox.NewKafkaPublisher(strings.Split(*brokers, ","))
		if err != nil {
			return err
		}
		defer pub.Close()
		// Publishing the head never holds up a decision; if Kafka is down the heads catch up when it is back.
		go auditchain.PublishHeads(ctx, guard.Querier(), *auditSource, pub, auditchain.AnchorOptions{Interval: *anchorEvery, Logger: log})
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
