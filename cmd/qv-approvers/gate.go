package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

// The Gate setting: which wallets pay only with a Gate credential, Gate's keys, the audience, the clock limits and the fast-lane limits. One version
// is the whole setting; operators sign it like an approver change, and apply puts it into the guard database of the gateway and of every cosigner.

func gateSign(args []string) error {
	fs := flag.NewFlagSet("gate-sign", flag.ContinueOnError)
	operator := fs.String("operator", "", "operator name in the zone config")
	keyFile := fs.String("key", "", "file with the operator's Ed25519 private key, hex")
	settingFile := fs.String("setting", "", "a JSON file with the whole setting: audience, keys, retired, skew_seconds, max_ttl_seconds, wallets")
	version := fs.Int64("version", 0, "version: the current one from `qv-approvers gate-show`, plus one")
	signedAt := fs.Int64("signed-at", 0, "signing time, unix seconds (default now); every operator of one version signs the same time (or use -join)")
	join := fs.String("join", "", "a version file of another operator: add this operator's signature to it")
	out := fs.String("out", "", "write the version file here (default stdout)")
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
	var c gateway.GateChange
	if *join != "" {
		b, err := os.ReadFile(*join)
		if err != nil {
			return err
		}
		if err := strictJSON(b, &c); err != nil {
			return fmt.Errorf("%s: %w", *join, err)
		}
	} else {
		if *settingFile == "" || *version < 1 {
			return fmt.Errorf("-setting and -version are required")
		}
		b, err := os.ReadFile(*settingFile)
		if err != nil {
			return err
		}
		if err := strictJSON(b, &c.Setting); err != nil {
			return fmt.Errorf("%s: %w", *settingFile, err)
		}
		c.Version, c.SignedAt = *version, *signedAt
		if c.SignedAt == 0 {
			c.SignedAt = time.Now().Unix()
		}
	}
	s, _ := json.MarshalIndent(c.Setting, "", "  ")
	fmt.Fprintf(os.Stderr, "signing gate setting version %d:\n%s\n", c.Version, s)
	prior := c.Signatures
	c = gateway.SignGateChange(priv, *operator, c)
	c.Signatures = append(prior, c.Signatures...)
	j, _ := json.MarshalIndent(c, "", "  ")
	if *out == "" {
		fmt.Println(string(j))
		return nil
	}
	return os.WriteFile(*out, j, 0o600)
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func gateApply(ctx context.Context, cfg *gateway.Config, stores []store, files []string) error {
	var parts []gateway.GateChange
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var c gateway.GateChange
		if err := strictJSON(b, &c); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		parts = append(parts, c)
	}
	c, err := gateway.MergeGateChanges(parts...)
	if err != nil {
		return err
	}
	var failed []string
	for _, s := range stores {
		if err := s.guard.ApplyGateChange(ctx, cfg, c, time.Now(), s.name); err != nil {
			fmt.Printf("%-12s FAILED: %v\n", s.name, err)
			failed = append(failed, s.name)
			continue
		}
		fmt.Printf("%-12s applied: gate setting version %d; the next decision uses it\n", s.name, c.Version)
	}
	if len(failed) > 0 {
		return fmt.Errorf("not applied to %s: until every checker has the same version they may disagree (a payment is signed only when all accept); fix the cause and run gate-apply again", strings.Join(failed, ", "))
	}
	return nil
}

func gateShow(ctx context.Context, cfg *gateway.Config, stores []store) error {
	same := true
	var first int64
	for i, s := range stores {
		set, err := s.guard.EffectiveGate(ctx, cfg)
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		if i == 0 {
			first = set.Version
		}
		same = same && set.Version == first
		fmt.Printf("%-12s %s (next version %d)\n", s.name, set.Describe(), set.Version+1)
		if set.Ignored > 0 {
			fmt.Printf("WARNING: %s: %d rows of the log carry no valid operator signatures (or do not fit) and are ignored\n", s.name, set.Ignored)
		}
	}
	if !same {
		fmt.Println("WARNING: the databases are on different versions: run gate-apply again so every checker has the same setting before Gate uses a wallet")
	}
	return nil
}
