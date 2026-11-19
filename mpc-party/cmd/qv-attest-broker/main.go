// Command qv-attest-broker is the attestation release broker: it gives a party's data keys only to an enclave whose evidence verifies and
// matches the signed measurement allowlist. See docs/runbooks/tee-broker.md.
//
//	qv-attest-broker serve -config broker.json
//	qv-attest-broker allowlist keygen -key operator.key -pub operator.pub
//	qv-attest-broker allowlist new -seq N -out list.json -entry PARTY,PCR0HEX,NOT_BEFORE,NOT_AFTER [-entry ...]
//	qv-attest-broker allowlist sign -in list.json -key operator.key -operator NAME [-out list.json]
//	qv-attest-broker allowlist show -in list.json -operators broker.json
//	qv-attest-broker audit verify -file audit.log
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/broker"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	var err error
	switch {
	case len(args) >= 1 && args[0] == "serve":
		err = serve(args[1:])
	case len(args) >= 2 && args[0] == "allowlist":
		err = allowlist(args[1], args[2:], out)
	case len(args) >= 2 && args[0] == "audit" && args[1] == "verify":
		err = auditVerify(args[2:], out)
	default:
		fmt.Fprintln(errw, "usage: qv-attest-broker serve | allowlist keygen|new|sign|show | audit verify  (see the file header)")
		return 2
	}
	if err != nil {
		fmt.Fprintln(errw, "qv-attest-broker:", err)
		return 1
	}
	return 0
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "broker config (JSON)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := broker.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	srv, err := broker.Open(cfg, broker.Options{})
	if err != nil {
		return err
	}
	defer srv.Close()
	if broker.Simulation {
		fmt.Fprintln(os.Stderr, "qv-attest-broker: SIMULATION BUILD (-tags teesim): test roots and debug evidence are possible. Never run this in production.")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				_ = srv.Reload()
			}
		}
	}()
	go srv.Watch(ctx)
	return srv.Serve(ctx)
}

type entryFlags []string

func (e *entryFlags) String() string     { return strings.Join(*e, ";") }
func (e *entryFlags) Set(v string) error { *e = append(*e, v); return nil }

func allowlist(sub string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("allowlist "+sub, flag.ContinueOnError)
	in := fs.String("in", "", "allowlist file")
	outPath := fs.String("out", "", "output file")
	keyPath := fs.String("key", "", "operator private key file (hex Ed25519 seed, mode 0600)")
	pubPath := fs.String("pub", "", "keygen: where to write the public key (hex)")
	operator := fs.String("operator", "", "operator name as in the broker config")
	opsPath := fs.String("operators", "", "broker config holding the operators section (for show)")
	seq := fs.Int64("seq", 0, "new: sequence number (higher than the list in force)")
	var entries entryFlags
	fs.Var(&entries, "entry", "new: PARTY,PCR0HEX,NOT_BEFORE,NOT_AFTER (RFC 3339); repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch sub {
	case "keygen":
		return keygen(*keyPath, *pubPath, out)
	case "new":
		return newList(*seq, entries, *outPath, out)
	case "sign":
		return signList(*in, *keyPath, *operator, *outPath, out)
	case "show":
		return showList(*in, *opsPath, out)
	}
	return fmt.Errorf("allowlist: unknown command %q", sub)
}

func keygen(keyPath, pubPath string, out io.Writer) error {
	if keyPath == "" {
		return errors.New("keygen: -key is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // never overwrites a key
	if err != nil {
		return err
	}
	_, err = f.WriteString(hex.EncodeToString(priv.Seed()) + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if pubPath != "" {
		if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "public key:", hex.EncodeToString(pub))
	return nil
}

func newList(seq int64, entries entryFlags, outPath string, out io.Writer) error {
	if seq < 1 || outPath == "" || len(entries) == 0 {
		return errors.New("new: -seq (at least 1), -out and at least one -entry are required")
	}
	l := attest.SignedAllowlist{Seq: seq, SignedAt: time.Now().Unix()}
	for _, e := range entries {
		p := strings.Split(e, ",")
		if len(p) != 4 {
			return fmt.Errorf("entry %q: want PARTY,PCR0HEX,NOT_BEFORE,NOT_AFTER", e)
		}
		nb, err1 := time.Parse(time.RFC3339, p[2])
		na, err2 := time.Parse(time.RFC3339, p[3])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("entry %q: times must be RFC 3339", e)
		}
		l.Entries = append(l.Entries, attest.AllowEntry{Party: p[0], Measurement: strings.ToLower(p[1]), NotBefore: nb, NotAfter: na})
	}
	if err := attest.ValidEntries(l.Entries); err != nil {
		return err
	}
	return writeList(outPath, l, out)
}

func writeList(path string, l attest.SignedAllowlist, out io.Writer) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s: sequence %d, %d entries, %d signatures\n", path, l.Seq, len(l.Entries), len(l.Signatures))
	return nil
}

// signList adds this operator's signature. It prints what it signs first, so the operator reads before it signs.
func signList(in, keyPath, operator, outPath string, out io.Writer) error {
	if in == "" || keyPath == "" || operator == "" {
		return errors.New("sign: -in, -key and -operator are required")
	}
	if outPath == "" {
		outPath = in
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("key file %s has mode %v: group and others must have no access (chmod 0600)", keyPath, fi.Mode().Perm())
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	priv, err := attest.ParseOperatorKey(string(kb))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	l, err := attest.ParseSignedAllowlist(data)
	if err != nil {
		return err
	}
	if err := attest.ValidEntries(l.Entries); err != nil || l.Seq < 1 {
		return fmt.Errorf("the list is not valid: %v", err)
	}
	printEntries(out, l)
	return writeList(outPath, attest.SignAllowlist(priv, operator, l), out)
}

func printEntries(out io.Writer, l attest.SignedAllowlist) {
	fmt.Fprintf(out, "sequence %d, signed_at %s\n", l.Seq, time.Unix(l.SignedAt, 0).UTC().Format(time.RFC3339))
	for _, e := range l.Entries {
		fmt.Fprintf(out, "  party %-12s measurement %s  %s\n", e.Party, e.Measurement, e.Window())
	}
}

func showList(in, opsPath string, out io.Writer) error {
	if in == "" {
		return errors.New("show: -in is required")
	}
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	l, err := attest.ParseSignedAllowlist(data)
	if err != nil {
		return err
	}
	printEntries(out, l)
	fmt.Fprintf(out, "signatures: %d\n", len(l.Signatures))
	if opsPath == "" {
		fmt.Fprintln(out, "not verified (give -operators broker.json to verify)")
		return nil
	}
	cfg, err := broker.LoadConfig(opsPath)
	if err != nil {
		return err
	}
	ops, err := cfg.Operators.Build()
	if err != nil {
		return err
	}
	signed, err := ops.Verify(l)
	if err != nil {
		return fmt.Errorf("NOT VALID: %w", err)
	}
	fmt.Fprintf(out, "valid: signed by %s (%d needed)\n", strings.Join(signed, ", "), ops.Min)
	return nil
}

func auditVerify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	file := fs.String("file", "", "audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	n, err := broker.VerifyAudit(*file)
	if err != nil {
		return fmt.Errorf("audit log %s is not intact: %w", *file, err)
	}
	fmt.Fprintf(out, "audit log %s: %d records, chain intact\n", *file, n)
	return nil
}
