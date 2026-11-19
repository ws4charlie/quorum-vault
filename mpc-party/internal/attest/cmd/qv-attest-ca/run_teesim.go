//go:build teesim

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

func run(args []string) int {
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
