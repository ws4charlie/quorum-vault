// Command gen writes deploy/helm/qv-certs/catalog.json, the list of identities the chart renders, from internal/pki/catalog.go. The chart cannot drift from the
// catalog: a test (internal/pki/catalog_chart_test.go) fails when the committed file differs from what this program writes, and ci/helm checks the chart
// against the file. Run it with: go generate ./internal/pki
//
//	go run ./internal/pki/gen [-o file]   (no -o: standard output)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

func main() {
	out := flag.String("o", "", "write here instead of standard output")
	flag.Parse()
	b, err := pki.ChartCatalogJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	if *out == "" {
		os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}
