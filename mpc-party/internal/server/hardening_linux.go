//go:build linux

package server

import (
	"log/slog"
	"syscall"
)

const prSetDumpable = 4

func hardenPlatform(log *slog.Logger) {
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); e != 0 {
		log.Error("hardening: PR_SET_DUMPABLE=0 failed", "err", e.Error())
	} else {
		log.Info("hardening: PR_SET_DUMPABLE=0")
	}
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		log.Warn("hardening: mlockall failed; secrets may be swapped (raise RLIMIT_MEMLOCK or grant CAP_IPC_LOCK)", "err", err.Error())
	} else {
		log.Info("hardening: mlockall(MCL_CURRENT|MCL_FUTURE) ok")
	}
}
