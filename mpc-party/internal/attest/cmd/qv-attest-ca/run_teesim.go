//go:build teesim

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

func run(args []string) int {
	if len(args) > 0 && args[0] == "measure" {
		return measure(args[1:])
	}
	pkiDir := os.Getenv("QV_PKI_DIR")
	if pkiDir == "" {
		pkiDir = "data/pki"
	}
	fs := flag.NewFlagSet("qv-attest-ca", flag.ContinueOnError)
	dir := fs.String("dir", filepath.Join(pkiDir, "tee"), "directory for root.crt, intermediate.crt, intermediate.key")
	ttl := fs.Duration("ttl", 90*24*time.Hour, "lifetime of the new CA")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	now := time.Now()
	if ca, err := attest.LoadMockCA(*dir); err == nil && ca.Root.NotAfter.After(now.Add(24*time.Hour)) && ca.Intermediate.NotAfter.After(now.Add(24*time.Hour)) {
		fmt.Println("qv-attest-ca: keeping the CA in", *dir)
		return 0
	}
	ca, err := attest.NewMockCA(now, *ttl)
	if err == nil {
		err = ca.Write(*dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "qv-attest-ca:", err)
		return 1
	}
	fmt.Println("qv-attest-ca: test CA written to", *dir)
	return 0
}

// measure prints the mock PCR0 (hex) of a party image: SHA-384 over the binary and the config file (attest.MeasureFiles). The operator
// who signs an allowlist entry runs it on the files the party will run, the same way a real build publishes its measurement.
//
//	qv-attest-ca measure -binary mpc-party -config party-A.json
func measure(args []string) int {
	fs := flag.NewFlagSet("qv-attest-ca measure", flag.ContinueOnError)
	bin := fs.String("binary", "", "the party binary")
	cfg := fs.String("config", "", "the config file the party starts with")
	if err := fs.Parse(args); err != nil || *bin == "" || *cfg == "" {
		fmt.Fprintln(os.Stderr, "usage: qv-attest-ca measure -binary FILE -config FILE")
		return 2
	}
	m, err := attest.MeasureFiles(*bin, *cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "qv-attest-ca:", err)
		return 1
	}
	fmt.Println(hex.EncodeToString(m))
	return 0
}
