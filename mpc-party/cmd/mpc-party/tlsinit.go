package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

const tlsInitUsage = `usage: mpc-party tls-init -config ENROLL.json

  Enrolment of a party that keeps its TLS key sealed (config tls_sealed). OFFLINE, once per party, on an empty or running-before data directory.
  The party proves itself to the broker like at start, makes its TLS key inside this process, seals it under its local data key and writes only
  the certificate (data_dir/tls-cert.pem) next to the sealed key (data_dir/tls-key.sealed.json). It prints the pin (SHA-256 of the public key) that
  the other parties, the gateway and the cosigner pin. Run again, it prints the same pin and changes nothing. ENROLL.json holds role, data_dir,
  tls_sealed and the sealer section; it is a different measurement than the running party's config (see docs/runbooks/tee-broker.md).
`

func tlsInitMain(args []string) {
	fs := flag.NewFlagSet("tls-init", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "enrolment config (JSON)")
	valid := fs.Duration("valid", 365*24*time.Hour, "validity of the self-signed certificate")
	if err := fs.Parse(args); err != nil || *cfgPath == "" {
		fmt.Fprint(os.Stderr, tlsInitUsage)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	server.RunningConfigPath = *cfgPath
	if server.SimulatedEnclave {
		slog.Warn(server.SimulationMarker)
	}
	cfg, err := server.LoadEnrollConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, 2*time.Minute)
	defer stop()
	pin, created, err := server.TLSInit(ctx, cfg, *valid)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if created {
		fmt.Fprintln(os.Stderr, "enrolled: the TLS key was made and sealed")
	} else {
		fmt.Fprintln(os.Stderr, "already enrolled: nothing changed")
	}
	fmt.Println(pin.String())
}
