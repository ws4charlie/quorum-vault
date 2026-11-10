// Command qv-sol-nonces creates the missing durable-nonce accounts of a Solana hot shard. Withdrawals on Solana sign the value of one of these
// accounts, so a shard cannot pay out until its pool exists. The creation is signed by the signing zone like any transaction: this command builds
// it, puts the operator's approval on its intent and waits until the network has finalized it. Run it again to complete a pool; it does nothing
// when the pool is complete.
//
//	qv-sol-nonces -config custody.json -dsn $DATABASE_URL -shard 0 -approver alice -approver-key alice.key
//
// The approver key file holds the operator's Ed25519 private key (64 bytes, hex). The approver's public key must be in the signing zone's config.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chainfactory"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("qv-sol-nonces failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfgPath := flag.String("config", "", "custody config file (required)")
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "business database DSN (env DATABASE_URL)")
	shard := flag.Int("shard", 0, "hot shard whose pool to complete")
	approver := flag.String("approver", "", "the operator's name in the signing zone's approver list (required)")
	keyFile := flag.String("approver-key", "", "file with the operator's Ed25519 private key, 64 bytes in hex (required)")
	wait := flag.Duration("wait", 2*time.Minute, "how long to wait for the signature and for finality")
	flag.Parse()
	if *cfgPath == "" || *dsn == "" || *approver == "" || *keyFile == "" {
		return errors.New("-config, -dsn, -approver and -approver-key are required")
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	kb, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(kb) != ed25519.PrivateKeySize {
		return errors.New("the approver key must be 64 bytes in hex")
	}
	cfg, err := custody.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Family != custody.FamilySOL {
		return fmt.Errorf("chain %q is not a Solana chain", cfg.Chain)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := db.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	backend, err := chainfactory.Open(ctx, cfg, pool)
	if err != nil {
		return err
	}
	defer backend.Close()
	svc := custody.New(pool, cfg, backend.Adapter, backend.Reader)
	n, err := svc.SetupNonces(ctx, *shard, *approver, ed25519.PrivateKey(kb), *wait)
	if err != nil {
		return err
	}
	if n == 0 {
		log.Info("the pool is complete", "shard", *shard)
		return nil
	}
	log.Info("nonce accounts created", "shard", *shard, "count", n)
	return nil
}
