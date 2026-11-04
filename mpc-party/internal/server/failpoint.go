//go:build !devauth

package server

// failpoint is a no-op in production builds: crash testing hooks exist only in binaries built with -tags devauth.
func failpoint(name string) {}
