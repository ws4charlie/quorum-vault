// Command qv-route changes which pair of parties signs the 2-of-3 keysets, with approver signatures (internal/gateway/route.go).
//
//	qv-route show  -config C -guard-dsn D                       the current setting and sequence number
//	qv-route sign  -actor NAME -key FILE -pair A+C -seq N [-signed-at UNIX] -out F   the first approver (on their machine; no database)
//	qv-route sign  -actor NAME -key FILE -like FIRST.json -out F                     every later approver: signs the same change
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
	"io"
	"os"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/db"

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

func sign(args []string) error { return signTo(args, os.Stdout, os.Stderr, time.Now) }

// signTo is `sign`. What it is about to sign goes to stderr in plain words; the signature file goes to -out or stdout.
func signTo(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	actor := fs.String("actor", "", "approver name in the zone config")
	keyFile := fs.String("key", "", "file with the approver's Ed25519 private key, hex")
	pairS := fs.String("pair", "", "A+B, A+C or B+C")
	seq := fs.Int64("seq", 0, "sequence number: the current one from `qv-route show`, plus one")
	signedAt := fs.Int64("signed-at", 0, "signing time, unix seconds (default now). Every approver of one change signs the same time: pass the first approver's, or use -like")
	like := fs.String("like", "", "the signature file of the first approver: sign the same change (pair, sequence and time are copied from it; a flag that disagrees with it is refused)")
	out := fs.String("out", "", "write the signature file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *actor == "" || *keyFile == "" {
		return fmt.Errorf("-actor and -key are required")
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	pairV, sq, at := *pairS, *seq, *signedAt
	if *like != "" {
		first, err := readChange(*like)
		if err != nil {
			return err
		}
		for _, s := range first.Signatures {
			if s.Actor == *actor {
				return fmt.Errorf("%s already signed this change (%s)", *actor, *like)
			}
		}
		for _, d := range []struct {
			flag string
			diff bool
			text string
		}{
			{"pair", pairV != first.Pair, fmt.Sprintf("pair %q, the file has %q", pairV, first.Pair)},
			{"seq", sq != first.Seq, fmt.Sprintf("sequence %d, the file has %d", sq, first.Seq)},
			{"signed-at", at != first.SignedAt, fmt.Sprintf("signed-at %d, the file has %d", at, first.SignedAt)},
		} {
			if set[d.flag] && d.diff {
				return fmt.Errorf("-%s disagrees with %s: %s; not signing", d.flag, *like, d.text)
			}
		}
		pairV, sq, at = first.Pair, first.Seq, first.SignedAt
	} else if at == 0 {
		at = now().Unix()
	}
	pair, err := mpcsigner.ParsePair(pairV)
	if err != nil || sq < 1 {
		return fmt.Errorf("-pair and -seq are required (or -like FILE) (%v)", err)
	}
	priv, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	when := time.Unix(at, 0).UTC()
	fmt.Fprintf(stderr, "signing as %s: prefer the signing pair %s, sequence %d, signing time %s (unix %d, %s ago).\n"+
		"Check these against what you agreed; the change must be applied within max_change_age of that time.\n",
		*actor, pair, sq, when.Format(time.RFC3339), at, now().Sub(when).Round(time.Second))
	c := gateway.SignRoute(priv, *actor, pair, sq, when)
	j, _ := json.MarshalIndent(c, "", "  ")
	if *out == "" {
		fmt.Fprintln(stdout, string(j))
		return nil
	}
	return os.WriteFile(*out, j, 0o600)
}

// readChange reads a signature file and checks its shape. It cannot check the signatures (the tool has no approver keys); apply does.
func readChange(path string) (gateway.RouteChange, error) {
	var c gateway.RouteChange
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := mpcsigner.ParsePair(c.Pair); err != nil || c.Seq < 1 || c.SignedAt <= 0 || len(c.Signatures) == 0 {
		return c, fmt.Errorf("%s is not a signed route change (pair, seq, signed_at and a signature are needed)", path)
	}
	for _, s := range c.Signatures {
		if sig, err := hex.DecodeString(s.Signature); s.Actor == "" || err != nil || len(sig) != ed25519.SignatureSize {
			return c, fmt.Errorf("%s: the signature of %q is malformed", path, s.Actor)
		}
	}
	return c, nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	switch {
	case err != nil:
		return nil, fmt.Errorf("the key file must hold hex")
	case len(b) == ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case len(b) == ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("the key must be a 32-byte seed or a 64-byte private key")
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
	pool, err := db.NewPool(ctx, *dsn, nil, nil)
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
