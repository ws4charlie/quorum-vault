// Command qv-pki makes the development certificate authorities and certificates: one private CA per trust zone (business, signing) and a
// short-lived certificate for every service, with SPIFFE-shaped names (spiffe://quorumvault/<zone>/<service>). Everything goes under one
// root (default data/pki, gitignored); no key or certificate is in the repository. Production gets its own from the operator's PKI.
//
//	qv-pki init   [-root data/pki] [-ca-ttl 2160h]            make the two CAs (an existing CA is kept)
//	qv-pki issue  [-root data/pki] [-ttl 72h]                  issue every service certificate (run it again to rotate)
//	qv-pki renew  [-root data/pki] [-ttl 72h] [-every 24h]     issue again every interval, until stopped (development rotation)
//	qv-pki check  -cert tls.crt [-min 1h]                      exit non-zero when the certificate expires within -min
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qv-pki:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qv-pki init|issue|renew|check [flags]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	root := fs.String("root", envOr("QV_PKI_DIR", "data/pki"), "directory of the authorities and certificates (env QV_PKI_DIR)")
	caTTL := fs.Duration("ca-ttl", 90*24*time.Hour, "init: lifetime of each CA")
	ttl := fs.Duration("ttl", envDur("QV_PKI_LEAF_TTL", 72*time.Hour), "issue, renew: lifetime of each certificate; at most 720h (env QV_PKI_LEAF_TTL)")
	every := fs.Duration("every", 24*time.Hour, "renew: how often to issue again; must be shorter than -ttl")
	cert := fs.String("cert", "", "check: certificate file")
	min := fs.Duration("min", time.Hour, "check: fail when less than this is left")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "init":
		return pki.Init(*root, *caTTL, time.Now())
	case "issue":
		return pki.IssueAll(*root, *ttl, time.Now())
	case "renew":
		if *every >= *ttl {
			return fmt.Errorf("-every %s must be shorter than -ttl %s, or a certificate expires before its replacement", *every, *ttl)
		}
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		for {
			if err := pki.IssueAll(*root, *ttl, time.Now()); err != nil {
				return err
			}
			fmt.Println("qv-pki: issued certificates valid for", *ttl)
			select {
			case <-stop:
				return nil
			case <-time.After(*every):
			}
		}
	case "check":
		b, err := os.ReadFile(*cert)
		if err != nil {
			return err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return fmt.Errorf("%s: no certificate", *cert)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return err
		}
		left := time.Until(c.NotAfter)
		fmt.Printf("%s expires %s (%s left)\n", *cert, c.NotAfter.UTC().Format(time.RFC3339), left.Round(time.Second))
		if left < *min {
			return fmt.Errorf("%s expires in %s, less than %s", *cert, left.Round(time.Second), *min)
		}
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envDur(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if x, err := time.ParseDuration(v); err == nil {
			return x
		}
	}
	return d
}
