package workflow

import (
	"log/slog"
	"os"
)

// Failpoints let crash tests kill the worker at a named boundary. With
// QV_FAILPOINT="<kind>.<name>" in the environment, the process exits (like
// SIGKILL: no deferred calls, no flushed buffers) the first time that point is
// reached; the test then restarts the worker without the variable. In
// production the variable is unset and Hit is a map-free string compare.
//
// Boundaries, for kind "withdrawal" (sweeps have the same):
//
//	after_build   the sign job and nonce are committed, the activity has not returned
//	after_job     the gateway signed the job, the worker has not acted on it
//	after_broadcast  the transaction was sent, the worker has not recorded it
//	after_confirm the transaction is final, the worker has not settled the ledger
//	after_settle  the ledger is settled and committed, the activity has not returned
const failpointEnv = "QV_FAILPOINT"

// FailHook, when set (in-process tests), is called instead of exiting.
var FailHook func(point string)

// Hit exits the process if the failpoint "<kind>.<name>" is armed.
func Hit(kind, name string) {
	want := os.Getenv(failpointEnv)
	if want == "" || want != kind+"."+name {
		return
	}
	if FailHook != nil {
		FailHook(want)
		return
	}
	slog.Error("failpoint reached: killing the process", "failpoint", want)
	os.Exit(137)
}
