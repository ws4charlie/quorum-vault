//go:build !linux

package server

import "log/slog"

func hardenPlatform(log *slog.Logger) {
	log.Warn("hardening: PR_SET_DUMPABLE and mlockall are Linux-only; this platform is for development")
}
