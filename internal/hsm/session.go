// Package hsm talks to a PKCS#11 token (SoftHSM2 in dev) over raw PKCS#11.
//
// Object model: a Lib is one loaded PKCS#11 module (.so); it exposes slots;
// a slot holds a token; work happens in sessions on that token; logging in as
// CKU_USER on any one session logs the whole application in on that slot,
// and the login lasts until the last session on the slot is closed.
//
// Session strategy: each Token keeps a small pool (a buffered channel) of
// read-write sessions, created lazily up to poolSize. WithSession borrows
// one, runs fn, and returns it. The first session (opened by OpenToken to log
// in) stays in the pool until Token.Close, so the login never lapses while the
// Token is open. A session that fails with a "session is gone" error is
// discarded instead of returned.
package hsm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// ErrTokenNotFound is returned (wrapped, with the label) by OpenToken when no
// initialised token carries the requested label.
var ErrTokenNotFound = errors.New("hsm: token not found")

// ErrClosed is returned when using a Token or Lib after Close.
var ErrClosed = errors.New("hsm: closed")

const poolSize = 4

var (
	libsMu sync.Mutex
	libs   = map[string]*Lib{}
)

// Lib is one loaded PKCS#11 module. LoadLib returns the same *Lib for the same
// path; it is reference counted and finalized when the last user closes it.
type Lib struct {
	path string
	ctx  *pkcs11.Ctx
	refs int
}

// DefaultLibPath returns QV_PKCS11_LIB if set, else the first existing
// well-known SoftHSM2 path for this OS (or the primary one if none exists).
func DefaultLibPath() string {
	if p := os.Getenv("QV_PKCS11_LIB"); p != "" {
		return p
	}
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{"/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	default:
		candidates = []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return candidates[0]
}

// RepoSoftHSMConf returns the absolute path of the repo-local SoftHSM config
// (<repo root>/data/softhsm/softhsm2.conf, written by scripts/setup-softhsm.sh)
// if it exists, else "". The repo root is the nearest ancestor of the working
// directory containing go.mod.
func RepoSoftHSMConf() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			conf := filepath.Join(dir, "data", "softhsm", "softhsm2.conf")
			if _, err := os.Stat(conf); err == nil {
				return conf
			}
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// LoadLib loads and initialises the PKCS#11 module at path, or returns the
// already loaded one. If SOFTHSM2_CONF is unset it is pointed at the
// repo-local config first, so every worktree uses its own token directory.
func LoadLib(path string) (*Lib, error) {
	libsMu.Lock()
	defer libsMu.Unlock()
	if l, ok := libs[path]; ok {
		l.refs++
		return l, nil
	}
	if os.Getenv("SOFTHSM2_CONF") == "" {
		if conf := RepoSoftHSMConf(); conf != "" {
			os.Setenv("SOFTHSM2_CONF", conf)
		}
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("hsm: pkcs11 library %s: %w", path, err)
	}
	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, fmt.Errorf("hsm: cannot load pkcs11 library %s", path)
	}
	if err := ctx.Initialize(); err != nil && !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: C_Initialize: %w", err)
	}
	l := &Lib{path: path, ctx: ctx, refs: 1}
	libs[path] = l
	return l, nil
}

// Close drops one reference; the last one finalizes and unloads the module.
func (l *Lib) Close() error {
	libsMu.Lock()
	defer libsMu.Unlock()
	if l.refs <= 0 {
		return nil
	}
	l.refs--
	if l.refs > 0 {
		return nil
	}
	delete(libs, l.path)
	err := l.ctx.Finalize()
	l.ctx.Destroy()
	if err != nil && !isCKR(err, pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED) {
		return fmt.Errorf("hsm: C_Finalize: %w", err)
	}
	return nil
}

// OpenToken finds the slot whose token label equals label (slot IDs are not
// stable: SoftHSM reassigns them when tokens are initialised), opens a RW
// session and logs in as CKU_USER.
func (l *Lib) OpenToken(label, pin string) (*Token, error) {
	slot, err := l.findSlot(label)
	if err != nil {
		return nil, err
	}
	s, err := l.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("hsm: C_OpenSession on %q: %w", label, err)
	}
	if err := l.ctx.Login(s, pkcs11.CKU_USER, pin); err != nil && !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		l.ctx.CloseSession(s)
		return nil, fmt.Errorf("hsm: C_Login on %q: %w", label, err)
	}
	t := &Token{lib: l, label: label, slot: slot, idle: make(chan pkcs11.SessionHandle, poolSize), open: 1}
	t.idle <- s
	return t, nil
}

func (l *Lib) findSlot(label string) (uint, error) {
	slots, err := l.ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("hsm: C_GetSlotList: %w", err)
	}
	for _, slot := range slots {
		info, err := l.ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimRight(info.Label, " \x00") == label {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("%w: label %q", ErrTokenNotFound, label)
}

// Token is a logged-in handle on one token, safe for concurrent use.
type Token struct {
	lib   *Lib
	label string
	slot  uint

	mu     sync.Mutex
	idle   chan pkcs11.SessionHandle
	open   int // sessions created and not yet closed
	closed bool
}

func (t *Token) Label() string { return t.label }

// WithSession runs fn with a logged-in RW session from the pool. fn must
// finish (or cancel) any multi-part operation it starts, because the session
// is reused afterwards. The session must not be retained after fn returns.
func (t *Token) WithSession(ctx context.Context, fn func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error) error {
	s, err := t.acquire(ctx)
	if err != nil {
		return err
	}
	ferr := fn(t.lib.ctx, s)
	t.release(s, isSessionGone(ferr))
	return ferr
}

func (t *Token) acquire(ctx context.Context) (pkcs11.SessionHandle, error) {
	for {
		select {
		case s := <-t.idle:
			return s, nil
		default:
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return 0, ErrClosed
		}
		if t.open < poolSize {
			t.open++
			t.mu.Unlock()
			s, err := t.lib.ctx.OpenSession(t.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
			if err != nil {
				t.mu.Lock()
				t.open--
				t.mu.Unlock()
				return 0, fmt.Errorf("hsm: C_OpenSession on %q: %w", t.label, err)
			}
			return s, nil
		}
		t.mu.Unlock()
		select {
		case s := <-t.idle:
			return s, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (t *Token) release(s pkcs11.SessionHandle, discard bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || discard {
		t.lib.ctx.CloseSession(s)
		t.open--
		return
	}
	t.idle <- s // cannot block: at most poolSize sessions exist
}

// Close closes the Token's idle sessions; sessions still borrowed are closed
// when returned. When the last session on the slot closes, the token logs out.
func (t *Token) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	for {
		select {
		case s := <-t.idle:
			t.lib.ctx.CloseSession(s)
			t.open--
		default:
			return nil
		}
	}
}

func isCKR(err error, code uint) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && uint(e) == code
}

func isSessionGone(err error) bool {
	return isCKR(err, pkcs11.CKR_SESSION_HANDLE_INVALID) || isCKR(err, pkcs11.CKR_SESSION_CLOSED) ||
		isCKR(err, pkcs11.CKR_DEVICE_REMOVED) || isCKR(err, pkcs11.CKR_TOKEN_NOT_PRESENT)
}
