// Command qv-relay publishes the transactional outbox to Kafka, at least once.
// Consumers dedupe on the record header "id".
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "business database DSN (env DATABASE_URL)")
	brokers := flag.String("brokers", os.Getenv("QV_KAFKA_BROKERS"), "comma-separated Kafka brokers (env QV_KAFKA_BROKERS)")
	batch := flag.Int("batch", 100, "rows per batch")
	idle := flag.Duration("idle", 500*time.Millisecond, "wait when the outbox is empty")
	flag.Parse()
	if *dsn == "" || *brokers == "" {
		return fmt.Errorf("-dsn and -brokers are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer pool.Close()
	pub, err := outbox.NewKafkaPublisher(strings.Split(*brokers, ","))
	if err != nil {
		return err
	}
	defer pub.Close()
	log.Info("qv-relay started")
	err = outbox.NewRelay(pool, pub, outbox.RelayOptions{BatchSize: *batch, Idle: *idle, Logger: log}).Run(ctx)
	log.Info("qv-relay stopped cleanly")
	return err
}
