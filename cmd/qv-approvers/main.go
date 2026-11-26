// Command qv-approvers enrols, disables, enables and revokes approvers of the signing zone with operator signatures (internal/gateway/approvers.go).
//
//	qv-approvers show  -config C -guard-dsn gateway=D [-guard-dsn cosigner-b=D ...]
//	qv-approvers sign  -operator NAME -key FILE -seq N (-action enrol -name N (-approver-file F | -public-key HEX [-identity I]) | -action disable|enable|revoke -name N)
//	                   [-signed-at UNIX] [-out F]       (on the operator's machine; no database)
//	qv-approvers sign  -operator NAME -key FILE -join F [-out F]    add this operator's signature to a change file another operator wrote
//	qv-approvers apply -config C -guard-dsn ... F...    join the signature files of one change and apply it to every guard database
//	qv-approvers gate-sign  -operator NAME -key FILE (-setting F -version N [-signed-at UNIX] | -join F) [-out F]
//	qv-approvers gate-apply -config C -guard-dsn ... F...    the Gate setting (internal/gateway/gate.go), signed and applied the same way
//	qv-approvers gate-show  -config C -guard-dsn ...
//
// An approver is the person whose signature releases money; operators are a different, small key set in the zone config's "operators" section. A change
// needs min_operators distinct operators. It goes into the guard database of the gateway and of every cosigner, each of which checks the signatures
// again on every read, so the writer is not trusted. -config is the signing-zone config (its operators and approvers). The key file holds the operator's
// Ed25519 private key as hex (the 32-byte seed or the 64-byte key).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qv-approvers:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qv-approvers show|sign|apply|gate-show|gate-sign|gate-apply (see docs/runbooks/approvers.md and docs/runbooks/gate-setting.md)")
	}
	switch args[0] {
	case "sign":
		return sign(args[1:])
	case "show", "apply", "gate-show", "gate-apply":
		return withGuards(args[0], args[1:])
	case "gate-sign":
		return gateSign(args[1:])
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

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	operator := fs.String("operator", "", "operator name in the zone config")
	keyFile := fs.String("key", "", "file with the operator's Ed25519 private key, hex")
	action := fs.String("action", "", "enrol, disable, enable or revoke")
	name := fs.String("name", "", "the approver's name")
	seq := fs.Int64("seq", 0, "sequence number: the current one from `qv-approvers show`, plus one")
	signedAt := fs.Int64("signed-at", 0, "signing time, unix seconds (default now). Every operator of one change signs the same time: pass the first operator's, or use -join")
	entryFile := fs.String("approver-file", "", "enrol: a JSON file with the approver entry (scheme, public_key, identity, and for webauthn alg, credential_id, rp_id, origins)")
	pub := fs.String("public-key", "", "enrol an Ed25519 approver: its public key, 64 hex chars")
	identity := fs.String("identity", "", "enrol: the person behind the key (default: the name)")
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
	var c gateway.ApproverChange
	if *join != "" {
		b, err := os.ReadFile(*join)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("%s: %w", *join, err)
		}
		fmt.Fprintf(os.Stderr, "signing: %s %s (sequence %d)%s\n", c.Action, c.Name, c.Seq, describe(c))
	} else {
		if *action == "" || *name == "" || *seq < 1 {
			return fmt.Errorf("-action, -name and -seq are required")
		}
		c = gateway.ApproverChange{Action: *action, Name: *name, Seq: *seq, SignedAt: *signedAt}
		if c.SignedAt == 0 {
			c.SignedAt = time.Now().Unix()
		}
		if *action == gateway.ActionEnrol {
			switch {
			case *entryFile != "":
				b, err := os.ReadFile(*entryFile)
				if err != nil {
					return err
				}
				dec := json.NewDecoder(strings.NewReader(string(b)))
				dec.DisallowUnknownFields()
				var e gateway.ApproverFile
				if err := dec.Decode(&e); err != nil {
					return fmt.Errorf("%s: %w", *entryFile, err)
				}
				c.Approver = &e
			case *pub != "":
				c.Approver = &gateway.ApproverFile{PublicKey: *pub, Identity: *identity}
			default:
				return fmt.Errorf("an enrolment needs -approver-file or -public-key")
			}
			c.Approver.Enabled = true
		}
	}
	prior := c.Signatures // signatures of the operators who signed before (-join)
	c = gateway.SignApproverChange(priv, *operator, c)
	c.Signatures = append(prior, c.Signatures...)
	j, _ := json.MarshalIndent(c, "", "  ")
	if *out == "" {
		fmt.Println(string(j))
		return nil
	}
	return os.WriteFile(*out, j, 0o600)
}

func describe(c gateway.ApproverChange) string {
	if c.Approver == nil {
		return ""
	}
	return fmt.Sprintf(": identity %q, scheme %q, key %s", c.Approver.Identity, c.Approver.Scheme, c.Approver.PublicKey)
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

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
		return fmt.Errorf("the config has no operators section: signed approver changes and the gate setting are off")
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
	switch cmd {
	case "gate-apply":
		return gateApply(ctx, cfg, stores, fs.Args())
	case "gate-show":
		return gateShow(ctx, cfg, stores)
	}
	if cmd == "apply" {
		var parts []gateway.ApproverChange
		for _, f := range fs.Args() {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			var c gateway.ApproverChange
			if err := json.Unmarshal(b, &c); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			parts = append(parts, c)
		}
		c, err := gateway.MergeApproverChanges(parts...)
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
		set, err := s.guard.EffectiveApprovers(ctx, cfg)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		if i == 0 {
			first = set.Seq
		}
		same = same && set.Seq == first
		var off, revoked []string
		for n, a := range set.Approvers {
			if !a.Enabled {
				off = append(off, n)
			}
		}
		for n := range set.Revoked {
			revoked = append(revoked, n)
		}
		sort.Strings(off)
		sort.Strings(revoked)
		fmt.Printf("%-12s sequence %d (next change uses sequence %d); enabled: %s\n", s.name, set.Seq, set.Seq+1, strings.Join(set.Enabled(), ", "))
		if len(off) > 0 {
			fmt.Printf("%-12s disabled: %s\n", "", strings.Join(off, ", "))
		}
		if len(revoked) > 0 {
			fmt.Printf("%-12s revoked: %s\n", "", strings.Join(revoked, ", "))
		}
		if set.Ignored > 0 {
			fmt.Printf("WARNING: %s: %d rows of the log carry no valid operator signatures (or do not fit) and are ignored\n", s.name, set.Ignored)
		}
	}
	if !same {
		fmt.Println("WARNING: the databases are on different sequence numbers: jobs that name a newer approver wait until the same change is applied to all (run apply again)")
	}
	return nil
}

// apply puts the change into every guard database. Each database checks it again (operators, order, content, the minimum of enabled approvers), so one
// that refuses leaves the others applied: fix the cause and run apply again with the same files; databases that have the change skip it.
func apply(ctx context.Context, cfg *gateway.Config, stores []store, c gateway.ApproverChange) error {
	var failed []string
	for _, s := range stores {
		if err := s.guard.ApplyApproverChange(ctx, cfg, c, time.Now(), s.name); err != nil {
			fmt.Printf("%-12s FAILED: %v\n", s.name, err)
			failed = append(failed, s.name)
			continue
		}
		fmt.Printf("%-12s applied: %s %s, sequence %d; the next decision uses it\n", s.name, c.Action, c.Name, c.Seq)
	}
	if len(failed) > 0 {
		return fmt.Errorf("not applied to %s: until it is applied to all, a job that names a newer approver waits; fix the cause and run apply again", strings.Join(failed, ", "))
	}
	return nil
}
