// Command qv-btc-xpub prints the Bitcoin account xpub of a keyset held by mpc-party, and optionally the hot shard addresses derived
// from it, so an operator can paste them into the config of the core, the gateway and the cosigner.
//
// It connects to party A's caller port the way the gateway's signer does (mutual TLS, party A's certificate pinned by hash), asks for
// the public account node m/84'/coin'/0', and prints public values only. It never reads or prints a share, a PIN or a private key.
//
// Output, one value per line, in a fixed order, on standard output only when everything succeeded:
//
//	account_xpub=<xpub>
//	hot_shard.<i>=<address>     for each i below -shards, the account's key at 1/i
//
// Any failure prints one line on standard error and exits non-zero, with nothing on standard output.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
)

func main() {
	var out bytes.Buffer
	if err := run(os.Args[1:], &out, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "qv-btc-xpub:", err)
		os.Exit(1)
	}
	os.Stdout.Write(out.Bytes())
}

func run(args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("qv-btc-xpub", flag.ContinueOnError)
	fs.SetOutput(errw)
	addr := fs.String("party", "", "party A's caller address, host:port")
	certFile := fs.String("cert", "", "client certificate file (PEM) party A accepts")
	keyFile := fs.String("key", "", "client certificate key file (PEM)")
	pin := fs.String("server-pin", "", "sha256 of party A's certificate, 64 hex characters")
	keyset := fs.String("keyset", "", "keyset id")
	network := fs.String("network", "", "mainnet, testnet3, signet or regtest")
	shards := fs.Int("shards", 0, "also print this many hot shard addresses (1/0 ... 1/N-1)")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait for party A")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" || *certFile == "" || *keyFile == "" || *pin == "" || *keyset == "" || *network == "" {
		return fmt.Errorf("-party, -cert, -key, -server-pin, -keyset and -network are required")
	}
	if _, err := btc.Params(*network); err != nil {
		return err
	}
	if *shards < 0 {
		return fmt.Errorf("-shards must not be negative")
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
	d, err := mpcsigner.NewDeriving(mpcsigner.DerivingConfig{KeysetID: *keyset, HardenedPath: btc.AccountPath(*network),
		Config: mpcsigner.Config{PartitionID: "xpub", Address: *addr, ClientCert: cert, ServerPin: *pin, Timeout: *timeout}})
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	xpub, err := d.AccountXpub(ctx, *network)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "account_xpub=%s\n", xpub)
	for i := 0; i < *shards; i++ {
		a, err := btc.DeriveHotAddress(*network, xpub, uint32(i))
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "hot_shard.%d=%s\n", i, a)
	}
	return nil
}
