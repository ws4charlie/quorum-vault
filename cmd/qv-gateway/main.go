// Command qv-gateway is the signing gateway. It opens no listening port: it
// polls sign_jobs in the business database (role qv_gateway) and keeps its
// replay guard in a separate database. Trust roots come only from -config.
package main

import (
	"bytes"
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

	"github.com/ws4charlie/quorum-vault/internal/auditchain"
	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/health"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/kafkatls"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/pki"
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
	metricsFile := flag.String("mpc-metrics-file", os.Getenv("QV_MPC_METRICS_FILE"), "write the MPC route and party health metrics here in the Prometheus text format, for a node-exporter textfile collector (the gateway opens no port; env QV_MPC_METRICS_FILE)")
	tlsFor := pki.Flags(flag.CommandLine, "")
	// The explicit link between the zones: the job queue is in the business database, so the gateway reaches it with a certificate the BUSINESS
	// authority issued to it (name business/gateway-link) and trusts only the business authority for that link. The signing zone's own
	// authority is never trusted by the business database.
	linkFor := pki.Flags(flag.CommandLine, "link-")
	healthListen := health.Flag(flag.CommandLine)
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
	// The token PIN is read once, here, before anything is opened: from the file named by QV_HSM_PIN_FILE (the same mode rule as the party's
	// pin_file). The environment form QV_HSM_PIN is refused unless QV_ENV is dev or test. Neither the PIN nor its file's content is ever logged.
	hsmPIN, err := hsmServicePIN(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	probe := health.New(log)
	stopHealth, err := probe.Serve(ctx, *healthListen)
	if err != nil {
		return err
	}
	defer stopHealth()

	tsrc, err := tlsFor("qv-gateway", pki.ZoneSigning, log)
	if err != nil {
		return err
	}
	lsrc, err := linkFor("qv-gateway-link", pki.ZoneBusiness, log)
	if err != nil {
		return err
	}
	for _, s := range []*pki.Source{tsrc, lsrc} {
		if s != nil {
			go s.Run(ctx.Done())
		}
	}
	jobs, err := db.NewPool(ctx, *jobsDSN, lsrc, pki.Allow{pki.ID(pki.ZoneBusiness, "postgres")})
	if err != nil {
		return fmt.Errorf("open job queue: %w", err)
	}
	defer jobs.Close()
	probe.Check("job queue database", health.Ping(jobs))
	probe.Check("certificates", health.Certs(tsrc, lsrc))
	gp, err := db.NewPool(ctx, *guardDSN, tsrc, pki.Allow{pki.ID(pki.ZoneSigning, "signing-db")})
	if err != nil {
		return fmt.Errorf("open replay guard: %w", err)
	}
	defer gp.Close()
	probe.Check("guard database", health.Ping(gp))
	guard, err := gateway.OpenGuard(ctx, gp)
	if err != nil {
		return err
	}

	// The routing of 2-of-3 signatures: the gateway's own health checks of the parties and the operators' signed preferred pair (mpc_route).
	var router *mpcsigner.Router
	var monitor *mpcsigner.Monitor
	if cfg.Route != nil {
		monitor, err = gateway.NewRouteMonitor(cfg, cfg.RouteFile)
		if err != nil {
			return err
		}
		defer monitor.Close()
		router = mpcsigner.NewRouter(mpcsigner.RouterConfig{Health: monitor, Logger: log,
			Preferred: guard.PreferredSource(cfg, func(n int) {
				log.Error("ALERT mpc route: rows of the preferred-pair table do not carry valid approver signatures and are ignored", "rows", n)
			})})
		go monitor.Run(ctx, func() {
			if *metricsFile != "" {
				if err := writeMetrics(ctx, *metricsFile, router, monitor); err != nil {
					log.Error("cannot write the MPC metrics file", "error", err.Error())
				}
			}
		})
	}

	if *metricsFile != "" {
		// the certificate metrics go to a sibling file of the same textfile directory, whether or not a route is configured
		tlsFile := strings.TrimSuffix(*metricsFile, ".prom") + "-tls.prom"
		drainFile := strings.TrimSuffix(*metricsFile, ".prom") + "-drain.prom" // qv_drain_refusals_total
		go func() {
			for {
				if err := pki.WriteMetricsFile(tlsFile, tsrc, lsrc); err != nil {
					log.Error("cannot write the certificate metrics file", "error", err.Error())
				}
				if err := writeDrainMetrics(drainFile, guard, cfg); err != nil {
					log.Error("cannot write the drain metrics file", "error", err.Error())
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(15 * time.Second):
				}
			}
		}()
	}

	signers := map[string]signer.Signer{}
	genSigners := []gateway.GenerationSigner{gateway.MPCGenerationSigner()} // the keys of later generations of a shard (docs/runbooks/key-replacement.md)
	if gateway.HasHSMSigners(cfg) {
		hs, hsmGen, closeSigners, err := openHSMSigners(cfg, hsmPIN)
		if err != nil {
			return err
		}
		defer closeSigners()
		genSigners = append(genSigners, hsmGen)
		for k, v := range hs {
			signers[k] = v
		}
	}
	ms, closeMPC, err := gateway.MPCSignersRouted(cfg, router)
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
	hotMsg, depositMsg, closeMsg, err := gateway.MPCMessageSignersRouted(cfg, router)
	if err != nil {
		return err
	}
	defer closeMsg()
	if err := gateway.CheckMessageSigners(cfg, hotMsg, depositMsg); err != nil {
		return err
	}

	if *brokers == "" {
		log.Error("ALERT no -brokers: this zone's audit chain heads are not published, so a truncated or rewritten chain cannot be detected from outside the database")
	}
	if *brokers != "" {
		kopts, err := kafkatls.Options(lsrc) // the business-issued link certificate: the audit heads go to the business Kafka
		if err != nil {
			return err
		}
		pub, err := outbox.NewKafkaPublisher(strings.Split(*brokers, ","), kopts...)
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
	gw, err := gateway.New(cfg, nil, signers, guard, jobs, gateway.Options{WorkerID: id, Lease: *lease, Logger: log, MessageSigners: hotMsg, DepositSigners: depositMsg,
		Generations: gateway.ComposeGenerationSigners(genSigners...)})
	if err != nil {
		return err
	}
	log.Info("qv-gateway started", "worker", id, "chains", len(cfg.Chains), "partitions", len(signers)+len(hotMsg))
	probe.SetReady(true)
	if err := gw.Run(ctx, *interval); err != nil {
		return err
	}
	// After SIGTERM the gateway claims no new job (the probe already says "not ready") and waits up to sign_timeout for the signer calls in
	// flight, so terminationGracePeriodSeconds must be at least sign_timeout plus a margin (deploy/images/README.md).
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

// writeMetrics replaces the metrics file atomically, so a collector never reads half of it.
func writeMetrics(ctx context.Context, path string, r *mpcsigner.Router, m *mpcsigner.Monitor) error {
	var b bytes.Buffer
	r.WriteMetrics(ctx, &b, m)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeDrainMetrics replaces the drain-refusal metrics file atomically.
func writeDrainMetrics(path string, g *gateway.Guard, cfg *gateway.Config) error {
	var b bytes.Buffer
	g.WriteDrainMetrics(&b, cfg, gateway.ModeGateway)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// openHSMSigners loads the PKCS#11 module, refuses SoftHSM in production and logs in to the tokens of the config's HSM signers with pin.
// Its errors never carry the PIN (the PKCS#11 wrapper's errors name the token and the return code only).
func openHSMSigners(cfg *gateway.Config, pin string) (map[string]signer.Signer, gateway.GenerationSigner, func(), error) {
	lib, err := hsm.LoadLib(hsm.DefaultLibPath())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load pkcs11: %w", err)
	}
	// SoftHSM is for development and tests: a production start (QV_ENV unset, or not dev or test) refuses it.
	if err := hsm.RefuseSoftHSM(lib, auth.EnvironmentFromEnv() == auth.Production); err != nil {
		lib.Close()
		return nil, nil, nil, err
	}
	hs, hsmGen, closeSigners, err := gateway.HSMSignersWithGenerations(cfg, lib, pin)
	if err != nil {
		lib.Close()
		return nil, nil, nil, err
	}
	return hs, hsmGen, func() { closeSigners(); lib.Close() }, nil
}

// hsmServicePIN is the token PIN for a zone with HSM signers; a zone with MPC signers only needs none.
func hsmServicePIN(cfg *gateway.Config) (string, error) {
	if !gateway.HasHSMSigners(cfg) {
		return "", nil
	}
	return hsm.ServicePIN()
}
