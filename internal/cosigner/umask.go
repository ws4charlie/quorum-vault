package cosigner

import "syscall"

func umask(m int) int { return syscall.Umask(m) }
