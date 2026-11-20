//go:build unix

package server

import (
	"fmt"
	"sync"
	"syscall"
)

// secretBuf holds a secret (a data key) in memory that is locked in RAM (mlock): never swapped out, and not part of the Go heap, so the garbage
// collector never copies it. Slots come from page-sized anonymous mappings that are shared by all keys (a 4 KiB page holds 128 keys), so a
// small RLIMIT_MEMLOCK (the usual container default is 64 KiB) is enough. wipe zeroes the slot and gives it back; an arena page whose slots are
// all free stays mapped (it is never copied or written anywhere).
type secretBuf struct {
	b     []byte
	arena *keyArena
}

const secretSlot = 64 // bytes per slot (a 32-byte key)

type keyArena struct {
	mu    sync.Mutex
	pages [][]byte
	free  [][]byte
}

var arena = &keyArena{}

func newSecretBuf(n int) (*secretBuf, error) {
	if n > secretSlot {
		return nil, fmt.Errorf("sealer attested: secret of %d bytes does not fit a slot", n)
	}
	arena.mu.Lock()
	defer arena.mu.Unlock()
	if len(arena.free) == 0 {
		page := syscall.Getpagesize()
		m, err := syscall.Mmap(-1, 0, page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if err != nil {
			return nil, fmt.Errorf("sealer attested: mmap for data keys: %w", err)
		}
		if err := syscall.Mlock(m); err != nil {
			syscall.Munmap(m)
			return nil, fmt.Errorf("sealer attested: mlock of the data key memory failed (raise RLIMIT_MEMLOCK / `ulimit -l`, or grant CAP_IPC_LOCK): %w", err)
		}
		arena.pages = append(arena.pages, m)
		for off := 0; off+secretSlot <= len(m); off += secretSlot {
			arena.free = append(arena.free, m[off:off+secretSlot:off+secretSlot])
		}
	}
	b := arena.free[len(arena.free)-1][:n]
	arena.free = arena.free[:len(arena.free)-1]
	return &secretBuf{b: b, arena: arena}, nil
}

func (s *secretBuf) bytes() []byte { return s.b }

func (s *secretBuf) wipe() {
	if s == nil || s.b == nil {
		return
	}
	full := s.b[:cap(s.b)]
	for i := range full {
		full[i] = 0
	}
	s.arena.mu.Lock()
	s.arena.free = append(s.arena.free, s.b[:cap(s.b)])
	s.arena.mu.Unlock()
	s.b = nil
}
