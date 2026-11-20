// Command qv-keysets changes the keyset states of the signing zone's EVM hot shards with operator signatures (internal/gateway/keysets.go).
//
//	qv-keysets show  -config C -guard-dsn gateway=D [-guard-dsn cosigner-b=D ...]
//	qv-keysets sign  -operator NAME -key FILE -seq N -shard S -generation G -action register-candidate -address 0x...
//	                 | -action activate | retire
//	                 | -action start-draining -successor H -cap ASSET=BASE_UNITS [-cap ...]
//	                 | -action mark-compromised [-successor H -cap ASSET=BASE_UNITS ...]
//	                 | -action set-drain-caps -cap ASSET=BASE_UNITS [-cap ...]     (the new total each named asset's drains may move)
//	                 register-candidate also takes -key-ref REF -public-key HEX (how the zone signs from the new key)
//	                 The deposit key tree of a Bitcoin or Solana chain is the shard entity/chain/deposit-tree/0: its register-candidate carries -key-ref (the
//	                 2-party HD keyset ID) and -public-key (the account xpub, or <node key hex>:<chain code hex>) and no -address; its start-draining takes
//	                 -window SECONDS (how long its addresses stay swept before it may retire) and, on Bitcoin, -cap BTC=SATS (the hot shards' drain)
//	                 [-signed-at UNIX] [-out F]       (on the operator's machine; no database)
//	qv-keysets sign  -operator NAME -key FILE -join F [-out F]    add this operator's signature to a change file another operator wrote
//	qv-keysets apply -config C -guard-dsn ... F...    join the signature files of one change and apply it to every guard database
//	qv-keysets party-auth -key FILE -op dkg|refresh|unfreeze -keyset ID [-out F]   an operator's admin authorisation for the MPC parties (valid for minutes;
//	                 qv-rekey dkg takes the file)
//
// The keyset state of a hot shard decides what the zone signs for it, drains included. Only operators (a key set of their own in the zone config's
// "operators" section, never the approvers) change it: min_operators distinct operators per change. A change goes into the guard database of the gateway
// and of every cosigner, each of which checks the signatures and the state machine again on every read, so the writer is not trusted. -config is the
// signing-zone config (its operators and chains). The key file holds the operator's Ed25519 private key as hex (the 32-byte seed or the 64-byte key).
// See docs/runbooks/key-replacement.md.
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

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qv-keysets:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qv-keysets show|sign|apply (see the runbook docs/runbooks/key-replacement.md)")
	}
	switch args[0] {
	case "sign":
		return sign(args[1:])
	case "party-auth":
		return partyAuth(args[1:])
	case "show", "apply":
		return withGuards(args[0], args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
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

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	operator := fs.String("operator", "", "operator name in the zone config")
	keyFile := fs.String("key", "", "file with the operator's Ed25519 private key, hex")
	action := fs.String("action", "", "register-candidate, activate, start-draining, retire, mark-compromised or set-drain-caps")
	shard := fs.String("shard", "", "the shard ID, entity/chain/pool/number (not a partition ID)")
	gen := fs.Int("generation", 0, "the generation the action is about")
	address := fs.String("address", "", "register-candidate: the new generation's address")
	keyRef := fs.String("key-ref", "", "register-candidate: the key's reference in the zone's signer (MPC keyset ID, or HSM CKA_ID in hex)")
	publicKey := fs.String("public-key", "", "register-candidate: the key's 65-byte uncompressed secp256k1 public key, hex (must hash to -address)")
	successor := fs.Int("successor", 0, "start-draining, mark-compromised: the generation a drain pays")
	var caps listFlag
	fs.Var(&caps, "cap", "start-draining, mark-compromised with a successor: ASSET=BASE_UNITS, the most all drains of that asset from this generation may move (repeat)")
	window := fs.Int64("window", 0, "start-draining of a deposit tree: seconds its deposit addresses stay swept before the generation may retire")
	seq := fs.Int64("seq", 0, "sequence number: the current one from `qv-keysets show`, plus one")
	signedAt := fs.Int64("signed-at", 0, "signing time, unix seconds (default now). Every operator of one change signs the same time: pass the first operator's, or use -join")
	join := fs.String("join", "", "a change file of another operator: add this operator's signature to it")
	out := fs.String("out", "", "write the change file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operator == "" || *keyFile == "" {
		return fmt.Errorf("-operator and -key are required")
	}
	priv, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	var c gateway.KeysetChange
	if *join != "" {
		b, err := os.ReadFile(*join)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("%s: %w", *join, err)
		}
		fmt.Fprintf(os.Stderr, "signing: %s\n", describe(c))
	} else {
		if *action == "" || *shard == "" || *gen < 1 || *seq < 1 {
			return fmt.Errorf("-action, -shard, -generation and -seq are required")
		}
		c = gateway.KeysetChange{Action: *action, Shard: *shard, Generation: *gen, Address: *address, KeyRef: *keyRef, PublicKey: *publicKey, Successor: *successor, Window: *window, Seq: *seq, SignedAt: *signedAt}
		if c.SignedAt == 0 {
			c.SignedAt = time.Now().Unix()
		}
		for _, kv := range caps {
			a, v, ok := strings.Cut(kv, "=")
			if !ok || a == "" || v == "" {
				return fmt.Errorf("-cap %q: want ASSET=BASE_UNITS", kv)
			}
			if c.Caps == nil {
				c.Caps = map[string]string{}
			}
			c.Caps[a] = v
		}
	}
	prior := c.Signatures // signatures of the operators who signed before (-join)
	c = gateway.SignKeysetChange(priv, *operator, c)
	c.Signatures = append(prior, c.Signatures...)
	j, _ := json.MarshalIndent(c, "", "  ")
	if *out == "" {
		fmt.Println(string(j))
		return nil
	}
	return os.WriteFile(*out, j, 0o600)
}

func describe(c gateway.KeysetChange) string {
	s := fmt.Sprintf("%s generation %d of %s (sequence %d)", c.Action, c.Generation, c.Shard, c.Seq)
	if c.Address != "" {
		s += ", address " + c.Address
	}
	if c.KeyRef != "" {
		s += ", key " + c.KeyRef
	}
	if c.Window > 0 {
		s += fmt.Sprintf(", window %ds", c.Window)
	}
	if c.Successor > 0 {
		s += fmt.Sprintf(", successor generation %d, caps %v", c.Successor, c.Caps)
	} else if len(c.Caps) > 0 {
		s += fmt.Sprintf(", caps %v", c.Caps)
	}
	return s
}

type store struct {
	name  string
	guard *gateway.Guard
}

func withGuards(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "signing-zone config file")
	var guards listFlag
	fs.Var(&guards, "guard-dsn", "a zone guard database as name=DSN, e.g. gateway=postgres://... (repeat for each cosigner)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || len(guards) == 0 {
		return fmt.Errorf("-config and at least one -guard-dsn are required")
	}
	cfg, err := gateway.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Operators == nil {
		return fmt.Errorf("the config has no operators section: signed keyset changes are off")
	}
	ctx := context.Background()
	var stores []store
	for _, g := range guards {
		name, dsn, ok := strings.Cut(g, "=")
		if !ok || name == "" || dsn == "" {
			return fmt.Errorf("-guard-dsn %q: want name=DSN", g)
		}
		pool, err := db.NewPool(ctx, dsn, nil, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		defer pool.Close()
		guard, err := gateway.OpenGuard(ctx, pool)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		stores = append(stores, store{name, guard})
	}
	if cmd == "apply" {
		var parts []gateway.KeysetChange
		for _, f := range fs.Args() {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			var c gateway.KeysetChange
			if err := json.Unmarshal(b, &c); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			parts = append(parts, c)
		}
		c, err := gateway.MergeKeysetChanges(parts...)
		if err != nil {
			return err
		}
		return apply(ctx, cfg, stores, c)
	}
	return show(ctx, cfg, stores)
}

func show(ctx context.Context, cfg *gateway.Config, stores []store) error {
	same := true
	var first int64
	for i, s := range stores {
		v, err := s.guard.EffectiveKeysets(ctx, cfg)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		if i == 0 {
			first = v.Seq
		}
		same = same && v.Seq == first
		fmt.Printf("%-12s sequence %d (next change uses sequence %d)\n", s.name, v.Seq, v.Seq+1)
		for _, shard := range v.Shards() {
			for _, e := range v.Generations(shard) {
				what := e.Address
				if what == "" && e.PublicKey != "" { // a deposit tree: its identity (xpub, node)
					what = "key " + e.PublicKey
				}
				line := fmt.Sprintf("%-12s %s generation %d  %-11s %s", "", shard, e.Generation, e.State, what)
				if e.KeyRef != "" {
					line += "  key " + e.KeyRef
				}
				if e.Successor > 0 {
					line += fmt.Sprintf("  drains into generation %d", e.Successor)
					for a, c := range e.Caps {
						line += fmt.Sprintf("  cap %s=%s", a, c)
					}
				}
				fmt.Println(line)
			}
		}
		if v.Ignored > 0 {
			fmt.Printf("WARNING: %s: %d rows of the log carry no valid operator signatures (or do not fit) and are ignored\n", s.name, v.Ignored)
		}
	}
	if !same {
		fmt.Println("WARNING: the databases are on different sequence numbers: a drain waits until the same change is applied to all (run apply again)")
	}
	return nil
}

// apply puts the change into every guard database. Each database checks it again (operators, order, state machine), so one that refuses leaves the others
// applied: fix the cause and run apply again with the same files; databases that have the change skip it.
func apply(ctx context.Context, cfg *gateway.Config, stores []store, c gateway.KeysetChange) error {
	var failed []string
	for _, s := range stores {
		if err := s.guard.ApplyKeysetChange(ctx, cfg, c, time.Now(), s.name); err != nil {
			fmt.Printf("%-12s FAILED: %v\n", s.name, err)
			failed = append(failed, s.name)
			continue
		}
		fmt.Printf("%-12s applied: %s; the next decision uses it\n", s.name, describe(c))
	}
	if len(failed) > 0 {
		return fmt.Errorf("not applied to %s: until it is applied to all, a drain waits; fix the cause and run apply again", strings.Join(failed, ", "))
	}
	return nil
}

// partyAuth writes an operator's authorisation for one admin call on the MPC parties (api/admin: an Ed25519 signature over operation, keyset and time). The
// parties accept it for a few minutes and once: make it right before qv-rekey dkg needs it.
func partyAuth(args []string) error {
	fs := flag.NewFlagSet("party-auth", flag.ContinueOnError)
	keyFile := fs.String("key", "", "file with the operator's Ed25519 private key, hex")
	op := fs.String("op", "dkg", "dkg, refresh or unfreeze")
	keyset := fs.String("keyset", "", "the keyset ID")
	out := fs.String("out", "", "write the file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *keyset == "" {
		return fmt.Errorf("-key and -keyset are required")
	}
	priv, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	a := admin.Sign(priv, *op, *keyset, time.Now())
	j, _ := json.MarshalIndent(map[string]any{"op": *op, "keyset": *keyset, "unix_seconds": a.UnixSeconds,
		"public_key": hex.EncodeToString(a.PublicKey), "signature": hex.EncodeToString(a.Signature)}, "", "  ")
	if *out == "" {
		fmt.Println(string(j))
		return nil
	}
	return os.WriteFile(*out, j, 0o600)
}
