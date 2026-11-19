// Command qv-cosigner is the independent check that runs next to party B. It listens only on a unix socket (mode 0600),
// holds its own signing-zone config (approver keys, policy, chain verifier config) and its own replay-guard database, and
// tells party B's mpc-party whether B may join a signing session. Socket down or timeout means refusal (fail closed).
package main

import (
	"context"
	"crypto/tls"
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

	"github.com/ws4charlie/quorum-vault/internal/auditchain"
	"github.com/ws4charlie/quorum-vault/internal/cosigner"
	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/kafkatls"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/pki"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("qv-cosigner stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		return auditchain.VerifyCommand(context.Background(), os.Args[2:], "cosigner", "QV_COSIGNER_GUARD_DSN", os.Stdout)
	}
	configPath := flag.String("config", "", "signing-zone config of party B's side (required)")
	guardDSN := flag.String("guard-dsn", os.Getenv("QV_COSIGNER_GUARD_DSN"), "replay-guard database DSN of the cosigner: its own database, never the gateway's (env QV_COSIGNER_GUARD_DSN)")
	otherDSN := flag.String("gateway-guard-dsn", os.Getenv("QV_GATEWAY_GUARD_DSN"), "the gateway's guard DSN, only to refuse sharing a database with it (optional)")
	socket := flag.String("socket", "", "unix socket path to listen on (required)")
	brokers := flag.String("brokers", os.Getenv("QV_KAFKA_BROKERS"), "Kafka brokers for publishing the head of this zone's audit chain on qv.audit.heads (optional; env QV_KAFKA_BROKERS)")
	auditSource := flag.String("audit-source", "cosigner", "name this chain's heads are published under on qv.audit.heads (several deployments sharing one topic need distinct names)")
	metricsListen := flag.String("metrics-listen", os.Getenv("QV_COSIGNER_METRICS_LISTEN"), "serve Prometheus metrics (certificate expiry) in plain http on a loopback address, e.g. 127.0.0.1:9104; off when empty (env QV_COSIGNER_METRICS_LISTEN)")
	anchorEvery := flag.Duration("anchor-interval", time.Minute, "publish the audit chain head at least this often, and at once when it changes")
	sockCert := flag.String("socket-cert", os.Getenv("QV_COSIGNER_SOCKET_CERT"), "certificate (PEM) the cosigner presents on the socket (env QV_COSIGNER_SOCKET_CERT)")
	sockKey := flag.String("socket-key", os.Getenv("QV_COSIGNER_SOCKET_KEY"), "private key of -socket-cert (env QV_COSIGNER_SOCKET_KEY)")
	partyPins := flag.String("party-pins", os.Getenv("QV_COSIGNER_PARTY_PINS"), "comma-separated SHA-256 fingerprints of the certificate(s) of the ONE party this cosigner serves: nobody else may ask (env QV_COSIGNER_PARTY_PINS)")
	tlsFor := pki.Flags(flag.CommandLine, "")
	// the audit heads go to the business Kafka: the explicit link, with a certificate the business authority issued (business/cosigner-link)
	linkFor := pki.Flags(flag.CommandLine, "link-")
	flag.Parse()
	if *configPath == "" || *guardDSN == "" || *socket == "" {
		return fmt.Errorf("-config, -guard-dsn and -socket are required")
	}
	if *otherDSN != "" {
		if same, err := sameDatabase(*guardDSN, *otherDSN); err != nil || same {
			return fmt.Errorf("the cosigner's replay guard must not share a database with the gateway's (%v)", err)
		}
	}
	cfg, err := gateway.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	tsrc, err := tlsFor("qv-cosigner", pki.ZoneSigning, log)
	if err != nil {
		return err
	}
	if tsrc != nil {
		go tsrc.Run(ctx.Done())
	}
	lsrc, err := linkFor("qv-cosigner-link", pki.ZoneBusiness, log)
	if err != nil {
		return err
	}
	if lsrc != nil {
		go lsrc.Run(ctx.Done())
	}
	pool, err := db.NewPool(ctx, *guardDSN, tsrc, pki.Allow{pki.ID(pki.ZoneSigning, "signing-db")})
	if err != nil {
		return fmt.Errorf("open replay guard: %w", err)
	}
	defer pool.Close()
	guard, err := gateway.OpenGuard(ctx, pool)
	if err != nil {
		return err
	}
	if *brokers == "" {
		log.Error("ALERT no -brokers: this zone's audit chain heads are not published, so a truncated or rewritten chain cannot be detected from outside the database")
	}
	if *brokers != "" {
		kopts, err := kafkatls.Options(lsrc)
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
	if *metricsListen != "" {
		if err := pki.RequireLoopback(*metricsListen); err != nil {
			return fmt.Errorf("-metrics-listen: %w", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/metrics", pki.MetricsHandler(tsrc, lsrc))
		msrv := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := msrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server stopped", "error", err.Error())
			}
		}()
		defer msrv.Close()
	}
	c, err := cosigner.New(cfg, guard, log, nil)
	if err != nil {
		return err
	}
	// The channel to the party is mutually authenticated. Missing material stops the process; plain text only under the development switch.
	var sockTLS *tls.Config
	if *sockCert == "" && *sockKey == "" && *partyPins == "" {
		if !pki.PlaintextAllowed() {
			return fmt.Errorf("-socket-cert, -socket-key and -party-pins are required: the party and the cosigner authenticate each other (docs/runbooks/certificates.md); plain text needs QV_ALLOW_PLAINTEXT=1 and QV_ENV=dev or test, and production refuses it")
		}
		log.Warn("the cosigner socket is plain text (development switch)")
	} else {
		var pins []string
		for _, p := range strings.Split(*partyPins, ",") {
			if p = strings.TrimSpace(p); p != "" {
				pins = append(pins, p)
			}
		}
		if sockTLS, err = cosigner.SocketTLS(*sockCert, *sockKey, pins); err != nil {
			return err
		}
	}
	ln, err := cosigner.ListenUnixTLS(*socket, sockTLS)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: c.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)} // a refused handshake (an unpinned caller) shows in the log
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sc)
	}()
	log.Info("qv-cosigner started", "socket", *socket, "chains", len(cfg.Chains))
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	os.Remove(*socket)
	log.Info("qv-cosigner stopped cleanly")
	return nil
}

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
