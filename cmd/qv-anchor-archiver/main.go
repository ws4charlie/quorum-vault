// Command qv-anchor-archiver copies every audit head published on qv.audit.heads into a write-once S3 bucket (Object Lock, COMPLIANCE
// mode), one object per head, so the heads outlive the Kafka topic. It runs outside the signing zones and holds credentials to the
// archive only. Runbook: docs/runbooks/audit-archive.md.
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
	"syscall"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/auditchain"
	"github.com/ws4charlie/quorum-vault/internal/kafkatls"
	"github.com/ws4charlie/quorum-vault/internal/pki"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("qv-anchor-archiver stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	fs := flag.NewFlagSet("qv-anchor-archiver", flag.ContinueOnError)
	brokers := fs.String("brokers", os.Getenv("QV_KAFKA_BROKERS"), "comma-separated Kafka brokers (env QV_KAFKA_BROKERS)")
	group := fs.String("group", "qv-anchor-archiver", "consumer group; its committed offset is how far the archive is complete")
	retention := fs.Duration("retention", 7*365*24*time.Hour, "the bucket's default retention in COMPLIANCE mode must be at least this, else the archiver refuses to run (default 7 years)")
	metricsListen := fs.String("metrics-listen", "", "serve Prometheus metrics on this address, e.g. 127.0.0.1:9103; off when empty")
	archive := auditchain.ArchiveFlags(fs)
	tlsFor := pki.Flags(fs, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *brokers == "" {
		return fmt.Errorf("-brokers or QV_KAFKA_BROKERS is required")
	}
	if *retention < 24*time.Hour {
		return fmt.Errorf("-retention %s is shorter than a day: a bucket default retention is counted in days", *retention)
	}
	arch, err := archive()
	if err != nil {
		return err
	}
	if arch == nil {
		return fmt.Errorf("-archive-bucket or QV_ARCHIVE_BUCKET is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	tsrc, err := tlsFor("qv-anchor-archiver", pki.ZoneBusiness, log)
	if err != nil {
		return err
	}
	if tsrc != nil {
		go tsrc.Run(ctx.Done())
	}
	kopts, err := kafkatls.Options(tsrc)
	if err != nil {
		return err
	}
	a := auditchain.NewArchiver(arch, auditchain.ArchiverOptions{Brokers: strings.Split(*brokers, ","), Group: *group, Retention: *retention, Logger: log, KafkaOpts: kopts})
	// refuse a weak bucket before anything is consumed
	if err := a.CheckBucket(ctx); err != nil {
		return err
	}
	if *metricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", a.MetricsHandler())
		srv := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server stopped", "error", err.Error())
			}
		}()
		defer srv.Close()
	}
	err = a.Run(ctx)
	log.Info("qv-anchor-archiver stopped")
	return err
}
