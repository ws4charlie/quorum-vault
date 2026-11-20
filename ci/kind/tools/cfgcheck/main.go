// Command cfgcheck parses a signing config the way qv-gateway and qv-cosigner do and prints the error, if any. The kind lane runs it on the config it generates, before it is put into a ConfigMap.
package main

import (
	"fmt"
	"os"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err == nil {
		_, err = gateway.ParseConfig(b)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cfgcheck:", err)
		os.Exit(1)
	}
	fmt.Println("cfgcheck: ok")
}
