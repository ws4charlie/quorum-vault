// Command mpc-party runs one party (A or B) of the 2-party signer. See ../../README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// extraAuthorizers are registered by build-tagged files (devauth.go). A default build has none.
var extraAuthorizers = map[string]func(server.AuthorizerConfig) (server.Authorizer, error){}

func pickAuthorizer(c server.AuthorizerConfig) (server.Authorizer, error) {
	switch c.Type {
	case "deny-all":
		return server.DenyAll{}, nil
	case "pinned-caller":
		// Party A: its pinned caller (the gateway) already decided; party B's cosigner is the independent check.
		return server.PinnedCaller{}, nil
	case "cosigner":
		if c.Socket == "" {
			return nil, fmt.Errorf("authorizer cosigner needs authorizer.socket")
		}
		return server.NewCosignerAuthorizer(c.Socket, time.Duration(c.TimeoutMS)*time.Millisecond), nil
	case "":
		return nil, server.ErrNoAuthorizer
	}
	if f, ok := extraAuthorizers[c.Type]; ok {
		return f(c)
	}
	return nil, fmt.Errorf("authorizer %q is not available in this build (default build: deny-all only; the production authorizer arrives with P5b-3)", c.Type)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "backup" {
		backupMain(os.Args[2:])
		return
	}
	cfgPath := flag.String("config", "", "path to the JSON config file (required)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: mpc-party -config <file>")
		os.Exit(2)
	}
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		log.Error("invalid configuration, refusing to start", "err", err.Error())
		os.Exit(2)
	}
	authz, err := pickAuthorizer(cfg.Authorizer)
	if err != nil {
		log.Error("no usable authorizer, refusing to start", "err", err.Error())
		os.Exit(2)
	}
	server.Harden(log)
	srv, err := server.New(server.Options{Config: cfg, Authorizer: authz, Logger: log})
	if err != nil {
		log.Error("cannot create server", "err", err.Error())
		os.Exit(1)
	}
	if err := srv.Start(); err != nil {
		log.Error("cannot start", "err", err.Error())
		os.Exit(1)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Info("signal received, shutting down", "signal", s.String())
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Limits.ShutdownGrace())
	defer cancel()
	srv.Shutdown(ctx)
}
