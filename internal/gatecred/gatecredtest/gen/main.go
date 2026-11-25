// Command gen writes testdata/gate-credential/vectors.json.
//
//	go run ./internal/gatecred/gatecredtest/gen > testdata/gate-credential/vectors.json
//
// The output is deterministic; a test fails when the committed file differs.
package main

import (
	"fmt"
	"os"

	"github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
)

func main() {
	b, err := gatecredtest.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}
