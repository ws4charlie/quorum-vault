// Command kindcert makes the certificate the expiry case needs: a leaf of the lane's business authority for the core, valid for an hour, issued three days ago, so it expired two days ago.
// The lane's authority key is in the gitignored work dir; the output goes there too (a directory with tls.crt, tls.key, ca.crt).
//
//	kindcert expired -ca-crt FILE -ca-key FILE -out DIR
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "expired" {
		fmt.Fprintln(os.Stderr, "usage: kindcert expired -ca-crt FILE -ca-key FILE -out DIR")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("expired", flag.ExitOnError)
	crt, key, out := fs.String("ca-crt", "", "authority certificate"), fs.String("ca-key", "", "authority key"), fs.String("out", "", "output directory")
	fs.Parse(os.Args[2:])
	if err := run(*crt, *key, *out); err != nil {
		fmt.Fprintln(os.Stderr, "kindcert:", err)
		os.Exit(1)
	}
}

func run(crt, key, out string) error {
	// LoadCA reads <dir>/<zone>/ca.crt and ca.key: lay the two files out that way in a private temporary directory
	tmp, err := os.MkdirTemp("", "kindcert")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := os.Mkdir(filepath.Join(tmp, pki.ZoneBusiness), 0o700); err != nil {
		return err
	}
	for src, dst := range map[string]string{crt: "ca.crt", key: "ca.key"} {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tmp, pki.ZoneBusiness, dst), b, 0o600); err != nil {
			return err
		}
	}
	ca, err := pki.LoadCA(tmp, pki.ZoneBusiness)
	if err != nil {
		return err
	}
	leaf, err := ca.Issue(pki.IssueRequest{Service: "core", DNS: []string{"qv-core.qv.svc"}, Usage: pki.Server | pki.Client, TTL: time.Hour, Now: time.Now().Add(-72 * time.Hour)})
	if err != nil {
		return err
	}
	return pki.WriteLeaf(out, leaf, ca)
}
