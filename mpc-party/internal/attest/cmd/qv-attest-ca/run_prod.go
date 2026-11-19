//go:build !teesim

package main

import (
	"fmt"
	"os"
)

func run([]string) int {
	fmt.Fprintln(os.Stderr, "qv-attest-ca: built without -tags teesim; the test CA does not exist in this build")
	return 1
}
