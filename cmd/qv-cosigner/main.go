// Command qv-cosigner is the independent check that runs next to party B. It listens only on a unix socket (mode 0600),
// holds its own signing-zone config (approver keys, policy, chain verifier config) and its own replay-guard database, and
// tells party B's mpc-party whether B may join a signing session. Socket down or timeout means refusal (fail closed).
package main

import (
	"context"
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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/cosigner"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("qv-cosigner stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	configPath := flag.String("config", "", "signing-zone config of party B's side (required)")
	guardDSN := flag.String("guard-dsn", os.Getenv("QV_COSIGNER_GUARD_DSN"), "replay-guard database DSN of the cosigner: its own database, never the gateway's (env QV_COSIGNER_GUARD_DSN)")
	otherDSN := flag.String("gateway-guard-dsn", os.Getenv("QV_GATEWAY_GUARD_DSN"), "the gateway's guard DSN, only to refuse sharing a database with it (optional)")
	socket := flag.String("socket", "", "unix socket path to listen on (required)")
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
	pool, err := pgxpool.New(ctx, *guardDSN)
	if err != nil {
		return fmt.Errorf("open replay guard: %w", err)
	}
	defer pool.Close()
	guard, err := gateway.OpenGuard(ctx, pool)
	if err != nil {
		return err
	}
	c, err := cosigner.New(cfg, guard, log, nil)
	if err != nil {
		return err
	}
	ln, err := cosigner.ListenUnix(*socket)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: c.Handler(), ReadHeaderTimeout: 5 * time.Second}
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
