// Command qv-fee-caps changes the Bitcoin fee caps (max_tx_fee_sats, max_fee_rate) of a chain with approver signatures (internal/chain/btc/feecaps.go).
//
//	qv-fee-caps show    -config C -chain NAME -guard-dsn gateway=D [-guard-dsn cosigner-b=D ...] [-core-dsn D]
//	qv-fee-caps sign    -actor NAME -key FILE -chain NAME -max-tx-fee-sats N -max-fee-rate N -seq N [-signed-at UNIX] -out F   (the first approver; on their machine, no database)
//	qv-fee-caps sign    -actor NAME -key FILE -like FIRST.json -out F                                                          (every later approver: signs the same change)
//	qv-fee-caps apply   -config C -guard-dsn ... [-core-dsn D] F...      join the signature files of one change and apply it to every database
//	qv-fee-caps metrics -config C -chain NAME -guard-dsn ... [-core-dsn D] -out FILE   write the Prometheus text file for a node-exporter collector
//
// One signed change goes into the guard database of the gateway and of every cosigner, and into the core's database, so that the core and the zone
// read the same record. Each of them checks the signatures again on every read; the writer is not trusted. -config is the signing-zone config (its
// approvers and its fee_caps_change bounds); the file holds the approver's Ed25519 private key as hex (the 32-byte seed or the 64-byte key), the same
// keys that sign intents.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qv-fee-caps:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qv-fee-caps show|sign|apply|metrics (see the runbook docs/runbooks/btc-fee-caps.md)")
	}
	switch args[0] {
	case "sign":
		return sign(args[1:])
	case "show", "apply", "metrics":
		return withStores(args[0], args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func sign(args []string) error { return signTo(args, os.Stdout, os.Stderr, time.Now) }

// signTo is `sign`. What it is about to sign goes to stderr in plain words; the signature file goes to -out or stdout.
func signTo(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	actor := fs.String("actor", "", "approver name in the zone config")
	keyFile := fs.String("key", "", "file with the approver's Ed25519 private key, hex")
	chainName := fs.String("chain", "", "the Bitcoin chain's name")
	tx := fs.Uint64("max-tx-fee-sats", 0, "the new max_tx_fee_sats")
	rate := fs.Uint64("max-fee-rate", 0, "the new max_fee_rate, sat/vB")
	seq := fs.Int64("seq", 0, "sequence number: the current one from `qv-fee-caps show`, plus one")
	signedAt := fs.Int64("signed-at", 0, "signing time, unix seconds (default now). Every approver of one change signs the same time: pass the first approver's, or use -like")
	like := fs.String("like", "", "the signature file of the first approver: sign the same change (chain, caps, sequence and time are copied from it; a flag that disagrees with it is refused)")
	out := fs.String("out", "", "write the signature file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *actor == "" || *keyFile == "" {
		return fmt.Errorf("-actor and -key are required")
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	chain, caps, sq, at := *chainName, btc.FeeCaps{MaxTxFeeSats: *tx, MaxFeeRate: *rate}, *seq, *signedAt
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
			{"chain", chain != first.Chain, fmt.Sprintf("chain %q, the file has %q", chain, first.Chain)},
			{"max-tx-fee-sats", caps.MaxTxFeeSats != first.Caps.MaxTxFeeSats, fmt.Sprintf("max_tx_fee_sats %d, the file has %d", caps.MaxTxFeeSats, first.Caps.MaxTxFeeSats)},
			{"max-fee-rate", caps.MaxFeeRate != first.Caps.MaxFeeRate, fmt.Sprintf("max_fee_rate %d, the file has %d", caps.MaxFeeRate, first.Caps.MaxFeeRate)},
			{"seq", sq != first.Seq, fmt.Sprintf("sequence %d, the file has %d", sq, first.Seq)},
			{"signed-at", at != first.SignedAt, fmt.Sprintf("signed-at %d, the file has %d", at, first.SignedAt)},
		} {
			if set[d.flag] && d.diff {
				return fmt.Errorf("-%s disagrees with %s: %s; not signing", d.flag, *like, d.text)
			}
		}
		chain, caps, sq, at = first.Chain, first.Caps, first.Seq, first.SignedAt
	} else {
		if chain == "" || caps.MaxTxFeeSats == 0 || caps.MaxFeeRate == 0 || sq < 1 {
			return fmt.Errorf("-chain, -max-tx-fee-sats, -max-fee-rate and -seq are required (or -like FILE)")
		}
		if at == 0 {
			at = now().Unix()
		}
	}
	priv, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	when := time.Unix(at, 0).UTC()
	fmt.Fprintf(stderr, "signing as %s: set the fee caps of chain %s to max_tx_fee_sats %d and max_fee_rate %d sat/vB, sequence %d, signing time %s (unix %d, %s ago).\n"+
		"Check these against what you agreed; the change must be applied within max_change_age of that time.\n",
		*actor, chain, caps.MaxTxFeeSats, caps.MaxFeeRate, sq, when.Format(time.RFC3339), at, now().Sub(when).Round(time.Second))
	c := btc.SignFeeCaps(priv, *actor, chain, caps, sq, when)
	j, _ := json.MarshalIndent(c, "", "  ")
	if *out == "" {
		fmt.Fprintln(stdout, string(j))
		return nil
	}
	return os.WriteFile(*out, j, 0o600)
}

// readChange reads a signature file and checks its shape: a chain, positive caps, a sequence number, a time, and at least one well-formed signature.
// It cannot check the signatures themselves (the tool has no approver keys); apply does.
func readChange(path string) (btc.FeeCapsChange, error) {
	var c btc.FeeCapsChange
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.Chain == "" || c.Caps.MaxTxFeeSats == 0 || c.Caps.MaxFeeRate == 0 || c.Seq < 1 || c.SignedAt <= 0 || len(c.Signatures) == 0 {
		return c, fmt.Errorf("%s is not a signed fee-cap change (chain, caps, seq, signed_at and a signature are needed)", path)
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

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// store is one database that holds the record: a zone guard (gateway or cosigner) or the core.
type store struct {
	name string
	core bool
	pool *pgxpool.Pool
}

func withStores(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "signing-zone config file")
	chainName := fs.String("chain", "", "the Bitcoin chain's name (show and metrics; apply takes it from the change)")
	coreDSN := fs.String("core-dsn", os.Getenv("QV_CORE_DSN"), "the core's database (env QV_CORE_DSN)")
	outFile := fs.String("out", "", "metrics: the file to write")
	var guards listFlag
	fs.Var(&guards, "guard-dsn", "a zone guard database as name=DSN, e.g. gateway=postgres://... (repeat for each cosigner)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || (len(guards) == 0 && *coreDSN == "") {
		return fmt.Errorf("-config and at least one -guard-dsn or -core-dsn are required")
	}
	cfg, err := gateway.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var stores []store
	for _, g := range guards {
		name, dsn, ok := strings.Cut(g, "=")
		if !ok || name == "" || name == "core" || dsn == "" {
			return fmt.Errorf("-guard-dsn %q: want name=DSN (the name is not \"core\")", g)
		}
		pool, err := db.NewPool(ctx, dsn, nil, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		defer pool.Close()
		stores = append(stores, store{name: name, pool: pool})
	}
	if *coreDSN != "" {
		pool, err := db.NewPool(ctx, *coreDSN, nil, nil)
		if err != nil {
			return fmt.Errorf("core: %w", err)
		}
		defer pool.Close()
		stores = append(stores, store{name: "core", core: true, pool: pool})
	}
	switch cmd {
	case "apply":
		var parts []btc.FeeCapsChange
		for _, f := range fs.Args() {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			var c btc.FeeCapsChange
			if err := json.Unmarshal(b, &c); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			parts = append(parts, c)
		}
		c, err := btc.MergeFeeCaps(parts...)
		if err != nil {
			return err
		}
		return apply(ctx, cfg, stores, c)
	}
	if *chainName == "" {
		return fmt.Errorf("-chain is required")
	}
	rules := cfg.FeeCapsRules(*chainName)
	if rules == nil {
		return fmt.Errorf("chain %q is not a Bitcoin chain with a fee_caps_change section", *chainName)
	}
	static := cfg.FeeCapsStatic(*chainName)
	var out bytes.Buffer
	var seqs []int64
	if cmd == "metrics" {
		fmt.Fprintln(&out, "# HELP qv_btc_fee_cap_max_tx_fee_sats The max_tx_fee_sats in force, by the database that holds the record.")
		fmt.Fprintln(&out, "# TYPE qv_btc_fee_cap_max_tx_fee_sats gauge")
	}
	type row struct {
		name string
		cur  btc.FeeCapsRecord
		skip int
	}
	var rows []row
	for _, s := range stores {
		var cur btc.FeeCapsRecord
		var skipped int
		var err error
		if s.core {
			// The core judges the record by its own approver list, which is the zone config's (same names and keys).
			cur, skipped, err = btc.CurrentFeeCaps(ctx, s.pool, *rules, static)
		} else {
			// The zone judges it by its effective approver set (the config's with the signed enrolments and revocations), like the gateway does.
			var g *gateway.Guard
			if g, err = gateway.OpenGuard(ctx, s.pool); err == nil {
				cur, skipped, err = g.CurrentFeeCaps(ctx, cfg, *chainName)
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		rows = append(rows, row{s.name, cur, skipped})
		seqs = append(seqs, cur.Seq)
	}
	same := true
	for _, q := range seqs {
		same = same && q == seqs[0]
	}
	if cmd == "show" {
		for _, r := range rows {
			fmt.Printf("%-12s max_tx_fee_sats %d, max_fee_rate %d sat/vB, sequence %d (next change uses sequence %d)\n", r.name, r.cur.MaxTxFeeSats, r.cur.MaxFeeRate, r.cur.Seq, r.cur.Seq+1)
			if r.skip > 0 {
				fmt.Printf("WARNING: %s: %d newer rows carry no valid approver signatures and are ignored\n", r.name, r.skip)
			}
		}
		if !same {
			fmt.Println("WARNING: the databases are on different sequence numbers: the core and the zone refuse each other until the same change is applied to all (run apply again)")
		}
		return nil
	}
	for _, m := range []struct{ name, help string }{{"qv_btc_fee_cap_max_tx_fee_sats", ""}, {"qv_btc_fee_cap_max_fee_rate_sat_vb", "The max_fee_rate in force, by the database that holds the record."},
		{"qv_btc_fee_caps_seq", "The sequence number of the fee-cap change in force (0: the configuration), by the database that holds the record."},
		{"qv_btc_fee_caps_ignored_rows", "Rows of the fee-cap table without valid approver signatures, which are ignored."}} {
		if m.help != "" {
			fmt.Fprintf(&out, "# HELP %s %s\n# TYPE %s gauge\n", m.name, m.help, m.name)
		}
		for _, r := range rows {
			v := map[string]int64{"qv_btc_fee_cap_max_tx_fee_sats": int64(r.cur.MaxTxFeeSats), "qv_btc_fee_cap_max_fee_rate_sat_vb": int64(r.cur.MaxFeeRate),
				"qv_btc_fee_caps_seq": r.cur.Seq, "qv_btc_fee_caps_ignored_rows": int64(r.skip)}[m.name]
			fmt.Fprintf(&out, "%s{chain=%q,store=%q} %d\n", m.name, *chainName, r.name, v)
		}
	}
	fmt.Fprintf(&out, "# HELP qv_btc_fee_caps_diverged 1 when the databases are on different sequence numbers (the core and the zone refuse each other).\n# TYPE qv_btc_fee_caps_diverged gauge\nqv_btc_fee_caps_diverged{chain=%q} %d\n", *chainName, map[bool]int{true: 0, false: 1}[same])
	if *outFile == "" {
		fmt.Print(out.String())
		return nil
	}
	tmp := *outFile + ".tmp"
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, *outFile)
}

// apply puts the change into every database. The zone's rules (approvers, bounds, age, the start-up rule) are checked first, once, so a refused
// change touches nothing; after that each database checks it again. A database that fails is reported and the others stay applied: run apply again
// with the same files to finish, it skips the ones that have the change.
func apply(ctx context.Context, cfg *gateway.Config, stores []store, c btc.FeeCapsChange) error {
	rules := cfg.FeeCapsRules(c.Chain)
	if rules == nil {
		return fmt.Errorf("chain %q is not a Bitcoin chain with a fee_caps_change section", c.Chain)
	}
	if _, err := rules.Verify(c); err != nil {
		return fmt.Errorf("change refused: %w", err)
	}
	// Each zone database judges the change by its own effective approver set (an approver revoked with operator signatures no longer counts there). Check
	// that first, for every one of them, so a change the zone would refuse is not applied to the core alone: the core only knows the configured list.
	for _, s := range stores {
		if s.core {
			continue
		}
		g, err := gateway.OpenGuard(ctx, s.pool)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		set, err := g.EffectiveApprovers(ctx, cfg)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		if _, err := cfg.FeeCapsRulesFor(c.Chain, set.Approvers).Verify(c); err != nil {
			return fmt.Errorf("change refused by %s, nothing was applied: %w", s.name, err)
		}
	}
	static := cfg.FeeCapsStatic(c.Chain)
	// The core goes first: a send already queued for the zone was built under the old change and the zone, still on it, signs it; only sends built
	// after the core's change wait for the zone's, and the window ends when the last database has it.
	sort.SliceStable(stores, func(i, j int) bool { return stores[i].core && !stores[j].core })
	var failed []string
	for _, s := range stores {
		var err error
		if s.core {
			err = btc.ApplyFeeCaps(ctx, s.pool, *rules, static, c, time.Now(), "core")
		} else {
			var g *gateway.Guard
			if g, err = gateway.OpenGuard(ctx, s.pool); err == nil {
				err = g.ApplyFeeCaps(ctx, cfg, c, time.Now(), s.name)
			}
		}
		if err != nil {
			fmt.Printf("%-12s FAILED: %v\n", s.name, err)
			failed = append(failed, s.name)
			continue
		}
		fmt.Printf("%-12s applied: max_tx_fee_sats %d, max_fee_rate %d sat/vB, sequence %d; the next build uses it\n", s.name, c.Caps.MaxTxFeeSats, c.Caps.MaxFeeRate, c.Seq)
	}
	if len(failed) > 0 {
		return fmt.Errorf("not applied to %s: the core and the zone refuse each other until it is applied to all; fix the cause and run apply again", strings.Join(failed, ", "))
	}
	return nil
}
