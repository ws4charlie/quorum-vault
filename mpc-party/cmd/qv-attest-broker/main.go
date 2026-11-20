// Command qv-attest-broker is the attestation release broker: it gives a party's data keys only to an enclave whose evidence verifies and
// matches the signed measurement allowlist. See docs/runbooks/tee-broker.md.
//
//	qv-attest-broker serve -config broker.json
//	qv-attest-broker allowlist keygen -key operator.key -pub operator.pub
//	qv-attest-broker allowlist new -seq N -out list.json -entry PARTY,PCR0HEX,NOT_BEFORE,NOT_AFTER[,VERSION[,STATUS]] [-entry ...]
//	qv-attest-broker allowlist add -in current.json -out next.json -party P -measurement HEX -version V -not-before T [-not-after T]
//	qv-attest-broker allowlist expire -in current.json -out next.json -party P -measurement HEX -not-after T
//	qv-attest-broker allowlist revoke -in current.json -out next.json -party P -measurement HEX
//	qv-attest-broker allowlist sign -in list.json -key operator.key -operator NAME [-out list.json] [-against current.json]
//	qv-attest-broker allowlist show -in list.json -operators broker.json [-against current.json]
//
// add, expire and revoke copy the list in -in, raise the sequence by one, drop every signature and write -out: every change is a new list that the
// operators then read (sign prints it, and with -against the difference to the list in force) and sign. NOT_AFTER may be empty: no end.
//
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
		fmt.Fprintln(errw, "usage: qv-attest-broker serve | allowlist keygen|new|add|expire|revoke|sign|show | audit verify  (see the file header)")
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
	against := fs.String("against", "", "sign, show: the list in force, to print what changes")
	party := fs.String("party", "", "add, expire, revoke: party role")
	meas := fs.String("measurement", "", "add, expire, revoke: PCR0 (hex)")
	version := fs.String("version", "", "add: release version, e.g. v1.4.0")
	notBefore := fs.String("not-before", "", "add: RFC 3339 (default now)")
	notAfter := fs.String("not-after", "", "add, expire: RFC 3339 (add: default no end)")
	var entries entryFlags
	fs.Var(&entries, "entry", "new: PARTY,PCR0HEX,NOT_BEFORE,NOT_AFTER[,VERSION[,STATUS]] (RFC 3339, NOT_AFTER may be empty); repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch sub {
	case "keygen":
		return keygen(*keyPath, *pubPath, out)
	case "new":
		return newList(*seq, entries, *outPath, out)
	case "sign":
		return signList(*in, *keyPath, *operator, *outPath, *against, out)
	case "show":
		return showList(*in, *opsPath, *against, out)
	case "add", "expire", "revoke":
		return editList(sub, *in, *outPath, *party, *meas, *version, *notBefore, *notAfter, out)
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
		if len(p) < 4 || len(p) > 6 {
			return fmt.Errorf("entry %q: want PARTY,PCR0HEX,NOT_BEFORE,NOT_AFTER[,VERSION[,STATUS]]", e)
		}
		nb, err1 := time.Parse(time.RFC3339, p[2])
		var na time.Time
		var err2 error
		if p[3] != "" {
			na, err2 = time.Parse(time.RFC3339, p[3])
		}
		if err1 != nil || err2 != nil {
			return fmt.Errorf("entry %q: times must be RFC 3339 (NOT_AFTER may be empty)", e)
		}
		en := attest.AllowEntry{Party: p[0], Measurement: strings.ToLower(p[1]), NotBefore: nb, NotAfter: na}
		if len(p) > 4 {
			en.Version = p[4]
		}
		if len(p) > 5 {
			en.Status = p[5]
		}
		l.Entries = append(l.Entries, en)
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
func signList(in, keyPath, operator, outPath, against string, out io.Writer) error {
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
	if err := printDiff(out, against, l); err != nil {
		return err
	}
	return writeList(outPath, attest.SignAllowlist(priv, operator, l), out)
}

func printEntries(out io.Writer, l attest.SignedAllowlist) {
	fmt.Fprintf(out, "sequence %d, signed_at %s\n", l.Seq, time.Unix(l.SignedAt, 0).UTC().Format(time.RFC3339))
	for _, e := range l.Entries {
		st := e.Status
		if st == "" {
			st = attest.StatusActive
		}
		fmt.Fprintf(out, "  party %-12s measurement %s  %s  version %q  %s\n", e.Party, e.Measurement, e.Window(), e.Version, st)
	}
}

func entryKey(e attest.AllowEntry) string {
	return e.Party + "/" + strings.ToLower(e.Measurement) + "/" + e.Status
}

// printDiff says what the list l changes against the list in force (no-op without a path): the thing an operator must read before signing.
func printDiff(out io.Writer, againstPath string, l attest.SignedAllowlist) error {
	if againstPath == "" {
		return nil
	}
	data, err := os.ReadFile(againstPath)
	if err != nil {
		return err
	}
	cur, err := attest.ParseSignedAllowlist(data)
	if err != nil {
		return err
	}
	if l.Seq <= cur.Seq {
		fmt.Fprintf(out, "WARNING: sequence %d is not higher than %d of the list given with -against: a broker refuses it\n", l.Seq, cur.Seq)
	}
	was := map[string]attest.AllowEntry{}
	for _, e := range cur.Entries {
		was[entryKey(e)] = e
	}
	fmt.Fprintf(out, "against sequence %d:\n", cur.Seq)
	n := 0
	for _, e := range l.Entries {
		old, ok := was[entryKey(e)]
		delete(was, entryKey(e))
		switch {
		case !ok:
			fmt.Fprintf(out, "  + %s %s %s version %q %s\n", e.Party, e.Measurement, e.Window(), e.Version, orActive(e.Status))
			n++
		case old.NotBefore != e.NotBefore || !old.NotAfter.Equal(e.NotAfter) || old.Version != e.Version:
			fmt.Fprintf(out, "  ~ %s %s window %s -> %s\n", e.Party, e.Measurement, old.Window(), e.Window())
			n++
		}
	}
	for _, e := range was {
		fmt.Fprintf(out, "  - %s %s (left out: that measurement is no longer allowed unless another entry lists it)\n", e.Party, e.Measurement)
		n++
	}
	if n == 0 {
		fmt.Fprintln(out, "  no change")
	}
	return nil
}

func orActive(s string) string {
	if s == "" {
		return attest.StatusActive
	}
	return s
}

// editList is add, expire and revoke: a copy of the list in -in with one change and the next sequence number, without signatures.
func editList(sub, in, outPath, party, meas, version, notBefore, notAfter string, out io.Writer) error {
	if in == "" || outPath == "" || party == "" || meas == "" {
		return fmt.Errorf("%s: -in, -out, -party and -measurement are required", sub)
	}
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	l, err := attest.ParseSignedAllowlist(data)
	if err != nil {
		return err
	}
	meas = strings.ToLower(meas)
	parse := func(name, v string) (time.Time, error) {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return t, fmt.Errorf("%s must be RFC 3339", name)
		}
		return t, nil
	}
	l.Seq++
	l.SignedAt = time.Now().Unix()
	l.Signatures = nil
	var found bool
	switch sub {
	case "add":
		nb := time.Now().UTC().Truncate(time.Second)
		if notBefore != "" {
			if nb, err = parse("-not-before", notBefore); err != nil {
				return err
			}
		}
		e := attest.AllowEntry{Party: party, Measurement: meas, NotBefore: nb, Version: version}
		if notAfter != "" {
			if e.NotAfter, err = parse("-not-after", notAfter); err != nil {
				return err
			}
		}
		for _, o := range l.Entries {
			if o.Party == party && strings.EqualFold(o.Measurement, meas) && !o.Revoked() {
				return fmt.Errorf("add: party %s already has an entry for %s: use expire, or revoke it first", party, meas)
			}
		}
		l.Entries = append(l.Entries, e)
	case "expire":
		if notAfter == "" {
			return errors.New("expire: -not-after is required")
		}
		na, err := parse("-not-after", notAfter)
		if err != nil {
			return err
		}
		for i, e := range l.Entries {
			if e.Party == party && strings.EqualFold(e.Measurement, meas) && !e.Revoked() {
				l.Entries[i].NotAfter, found = na, true
			}
		}
		if !found {
			return fmt.Errorf("expire: no entry of party %s with measurement %s", party, meas)
		}
	case "revoke":
		var version string
		for _, e := range l.Entries {
			if e.Party == party && strings.EqualFold(e.Measurement, meas) {
				version = e.Version
				if e.Revoked() {
					return fmt.Errorf("revoke: %s %s is already revoked", party, meas)
				}
			}
		}
		// keep the entry's own record (a revoked entry stays in the list as the proof) and let the revocation win over any overlap
		l.Entries = append(l.Entries, attest.AllowEntry{Party: party, Measurement: meas, NotBefore: time.Now().UTC().Truncate(time.Second), Version: version, Status: attest.StatusRevoked})
	}
	if err := attest.ValidEntries(l.Entries); err != nil {
		return err
	}
	return writeList(outPath, l, out)
}

func showList(in, opsPath, against string, out io.Writer) error {
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
	if err := printDiff(out, against, l); err != nil {
		return err
	}
	a, o, r := l.Counts(time.Now())
	fmt.Fprintf(out, "now: %d allowing, %d outside their window, %d revoked\n", a, o, r)
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
