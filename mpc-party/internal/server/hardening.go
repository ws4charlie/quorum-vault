package server

import (
	"log/slog"
	"syscall"
)

// Harden applies process-level protections for secrets in memory. Results are logged, never silently ignored.
//
//	RLIMIT_CORE = 0                core dumps would write key shares to disk
//	PR_SET_DUMPABLE = 0 (Linux)    no ptrace/core by other processes of the same user
//	mlockall (Linux)               keep pages out of swap; failure is logged (needs RLIMIT_MEMLOCK or CAP_IPC_LOCK)
func Harden(log *slog.Logger) {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Error("hardening: cannot disable core dumps", "err", err.Error())
	} else {
		log.Info("hardening: core dumps disabled (RLIMIT_CORE=0)")
	}
	hardenPlatform(log)
}
