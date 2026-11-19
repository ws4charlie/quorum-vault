package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// dataLockName is the lock file inside data_dir.
const dataLockName = ".lock"

// dataLock is the exclusive OS lock on a party's data directory: the files in it (sealed shares, freeze records, generations,
// stored signatures) are written by one process, with no coordination between writers. Two processes on one directory (two pods
// that mount the same volume during a rolling update, a restart that overlaps its predecessor) would interleave writes and could
// corrupt or fork the state, so the second one must not start.
//
// It is an flock(2) on the open file, so the kernel drops it when the process exits for any reason, a crash and kill -9 included:
// there is no stale lock to clean up and no timeout to wait out. It is held for the life of the process.
type dataLock struct{ f *os.File }

// acquireDataLock creates dir if needed and takes the lock without waiting. If another process holds it, the error says so.
func acquireDataLock(dir string) (*dataLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("data_dir: %w", err)
	}
	path := filepath.Join(dir, dataLockName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("data_dir lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("data_dir %s is in use by another mpc-party process (the lock %s is held): exactly one party process may use a data directory; refusing to start", dir, path)
		}
		return nil, fmt.Errorf("data_dir lock %s: %w (the volume must support flock)", path, err)
	}
	// for the operator who finds the lock held: who has it. Best effort; the lock, not the content, is what counts.
	f.Truncate(0)
	fmt.Fprintf(f, "%d\n", os.Getpid())
	return &dataLock{f: f}, nil
}

// release drops the lock (the process ending does the same). Safe to call twice and on nil.
func (l *dataLock) release() {
	if l == nil || l.f == nil {
		return
	}
	syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
	l.f = nil
}
