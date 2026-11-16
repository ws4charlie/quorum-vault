// Command qv-route changes which pair of parties signs the 2-of-3 keysets, with approver signatures (internal/gateway/route.go).
//
//	qv-route show  -config C -guard-dsn D                       the current setting and sequence number
//	qv-route sign  -actor NAME -key FILE -pair A+C -seq N -out F   one approver's signature (run on the approver's machine; no database)
//	qv-route apply -config C -guard-dsn D F...                  join the signature files of one change and apply it
//
// The key file holds the approver's Ed25519 private key as hex (the 32-byte seed or the 64-byte key). The same keys sign intents: no new key type.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qv-route:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qv-route show|sign|apply (see the runbook docs/runbooks/mpc-signing-pair.md)")
	}
	switch args[0] {
	case "sign":
		return sign(args[1:])
	case "show", "apply":
		return withGuard(args[0], args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	actor := fs.String("actor", "", "approver name in the zone config")
	keyFile := fs.String("key", "", "file with the approver's Ed25519 private key, hex")
	pairS := fs.String("pair", "", "A+B, A+C or B+C")
	seq := fs.Int64("seq", 0, "sequence number: the current one from `qv-route show`, plus one")
	out := fs.String("out", "", "write the signature file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pair, err := mpcsigner.ParsePair(*pairS)
	if err != nil || *actor == "" || *keyFile == "" || *seq < 1 {
		return fmt.Errorf("-actor, -key, -pair and -seq are required (%v)", err)
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	var priv ed25519.PrivateKey
	switch {
	case err != nil:
		return fmt.Errorf("the key file must hold hex")
	case len(b) == ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(b)
	case len(b) == ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(b)
	default:
		return fmt.Errorf("the key must be a 32-byte seed or a 64-byte private key")
	}
	c := gateway.SignRoute(priv, *actor, pair, *seq, time.Now())
	j, _ := json.MarshalIndent(c, "", "  ")
	if *out == "" {
		fmt.Println(string(j))
		return nil
	}
	return os.WriteFile(*out, j, 0o600)
}

func withGuard(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "signing-zone config file")
	dsn := fs.String("guard-dsn", os.Getenv("QV_GATEWAY_GUARD_DSN"), "the gateway's guard database (env QV_GATEWAY_GUARD_DSN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *dsn == "" {
		return fmt.Errorf("-config and -guard-dsn are required")
	}
	cfg, err := gateway.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	guard, err := gateway.OpenGuard(ctx, pool)
	if err != nil {
		return err
	}
	if cmd == "show" {
		cur, skipped, err := guard.CurrentRoute(ctx, cfg)
		if err != nil {
			return err
		}
		fmt.Printf("preferred pair %s, sequence %d (next change uses sequence %d)\n", cur.Pair, cur.Seq, cur.Seq+1)
		if skipped > 0 {
			fmt.Printf("WARNING: %d newer rows carry no valid approver signatures and are ignored\n", skipped)
		}
		return nil
	}
	var parts []gateway.RouteChange
	for _, f := range fs.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var c gateway.RouteChange
		if err := json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		parts = append(parts, c)
	}
	c, err := gateway.MergeRoute(parts...)
	if err != nil {
		return err
	}
	if err := guard.ApplyRoute(ctx, cfg, c, time.Now()); err != nil {
		return err
	}
	fmt.Printf("applied: preferred pair %s, sequence %d; the next job uses it\n", c.Pair, c.Seq)
	return nil
}
