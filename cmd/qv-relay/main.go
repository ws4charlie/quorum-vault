// Command qv-relay publishes the transactional outbox to Kafka, at least once.
// Consumers dedupe on the record header "id".
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/auditchain"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("qv-relay stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		return auditchain.VerifyCommand(context.Background(), os.Args[2:], "core", "DATABASE_URL", os.Stdout)
	}
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "business database DSN (env DATABASE_URL)")
	brokers := flag.String("brokers", os.Getenv("QV_KAFKA_BROKERS"), "comma-separated Kafka brokers (env QV_KAFKA_BROKERS)")
	batch := flag.Int("batch", 100, "rows per batch")
	idle := flag.Duration("idle", 500*time.Millisecond, "wait when the outbox is empty")
	auditSource := flag.String("audit-source", "core", "name this chain's heads are published under on qv.audit.heads (several deployments sharing one topic need distinct names)")
	anchorEvery := flag.Duration("anchor-interval", time.Minute, "publish the audit chain head at least this often, and at once when it changes")
	pruneRetention := flag.Duration("prune-retention", 0, "keep published outbox rows this long, then delete them (0: 720h = 30 days; minimum 168h = 7 days)")
	pruneEvery := flag.Duration("prune-interval", time.Hour, "how often to delete old published outbox rows")
	pruneBatch := flag.Int("prune-batch", 1000, "rows per delete statement when pruning")
	metricsListen := flag.String("metrics-listen", "", "serve Prometheus metrics (outbox pruning) on this address, e.g. 127.0.0.1:9102; off when empty")
	flag.Parse()
	if *dsn == "" || *brokers == "" {
		return fmt.Errorf("-dsn and -brokers are required")
	}
	if _, err := outbox.NewPruner(nil, outbox.PruneOptions{Retention: *pruneRetention}); err != nil {
		return err // retention below the hard minimum: refused before anything starts
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer pool.Close()
	pruner, err := outbox.NewPruner(pool, outbox.PruneOptions{Retention: *pruneRetention, Interval: *pruneEvery, Batch: *pruneBatch, Logger: log})
	if err != nil {
		return err // retention below the hard minimum: refused at start
	}
	if *metricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", pruner.MetricsHandler())
		srv := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server stopped", "error", err.Error())
			}
		}()
		defer srv.Close()
	}
	pub, err := outbox.NewKafkaPublisher(strings.Split(*brokers, ","))
	if err != nil {
		return err
	}
	defer pub.Close()
	log.Info("qv-relay started")
	// The audit chain: one chainer appends the audit events of the outbox to the hash chain, and the head of the chain is
	// published on qv.audit.heads. Neither waits for Kafka: if it is down, chaining goes on and the heads catch up.
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		auditchain.NewChainer(pool, auditchain.ChainerOptions{Logger: log}).Run(ctx)
	}()
	go func() {
		defer wg.Done()
		auditchain.PublishHeads(ctx, pool, *auditSource, pub, auditchain.AnchorOptions{Interval: *anchorEvery, Logger: log})
	}()
	go func() {
		defer wg.Done()
		pruner.Run(ctx)
	}()
	err = outbox.NewRelay(pool, pub, outbox.RelayOptions{BatchSize: *batch, Idle: *idle, Logger: log}).Run(ctx)
	wg.Wait()
	log.Info("qv-relay stopped cleanly")
	return err
}
