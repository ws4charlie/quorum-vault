// Command qv-approve is an approver's command-line client for a FIDO2 security key: show a withdrawal, approve it, or enrol the key.
// See docs/runbooks/webauthn-approver.md and internal/approvecli.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/ws4charlie/quorum-vault/internal/approvecli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := approvecli.Run(ctx, os.Args[1:], approvecli.Env{})
	stop()
	os.Exit(code)
}
