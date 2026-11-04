//go:build devauth

package server

import "os"

// failpoint kills the process (exit code 86, no cleanup, like a crash) when QV_FAILPOINT names this point. Only in
// binaries built with -tags devauth; the crash matrix tests set it in the environment of one party.
func failpoint(name string) {
	if os.Getenv("QV_FAILPOINT") == name {
		os.Exit(86)
	}
}
