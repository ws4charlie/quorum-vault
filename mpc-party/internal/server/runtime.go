package server

import (
	"context"
	cryptoRand "crypto/rand"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// Codes carried in Fin.code / Fail.CB so the initiator can react to a follower's UNAVAILABLE without matching text.
const (
	CodeUnresolved  uint32 = 0xff0c0001 // the keyset has not been reconciled with the peer since this process started
	CodeGenMismatch uint32 = 0xff0c0002 // the two parties are on different generations right now
)

// ksRT is the in-memory runtime state of one keyset.
type ksRT struct {
	// gate: sessions that use the keyset hold RLock; the commit window of a refresh and reconciliation hold Lock, so no
	// session ever runs while the parties switch generation.
	gate     sync.RWMutex
	mu       sync.Mutex
	busy     string // "dkg", "refresh" or "reconcile" while one is running
	resolved bool   // reconciled with the peer (and proven by a SelfTest) since this process started, or created here
	partial  bool   // 2-of-3: resolved with ONE other member only because the third was unreachable (treconcile.go)
}

func (s *Server) rt(id string) *ksRT {
	s.rtMu.Lock()
	defer s.rtMu.Unlock()
	r := s.rts[id]
	if r == nil {
		r = &ksRT{}
		s.rts[id] = r
	}
	return r
}

// tryBusy claims the keyset for kind. It returns the kind that holds it if it is taken.
func (r *ksRT) tryBusy(kind string) (holder string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy != "" {
		return r.busy, false
	}
	r.busy = kind
	return "", true
}

func (r *ksRT) done() { r.mu.Lock(); r.busy = ""; r.mu.Unlock() }

// busyFail: a DKG/Refresh already running is a refusal (LIMIT); a reconciliation in progress is a short outage (retry).
func busyFail(op, id, holder string) *Fail {
	if holder == "reconcile" {
		return unresolvedFail(op, id)
	}
	return limitFail(op, "a %s of keyset %q is already running", holder, id)
}

func (r *ksRT) isResolved() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.resolved }

func (r *ksRT) setResolved(v bool) { r.mu.Lock(); r.resolved = v; r.mu.Unlock() }

// unresolve marks the keyset unresolved and wakes the reconcile loop (party A).
func (s *Server) unresolve(id string) {
	s.rt(id).setResolved(false)
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func unresolvedFail(op, id string) *Fail {
	f := failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, op, "keyset %q is not reconciled with the peer yet (after a restart or restore); retry shortly", id)
	f.CB = CodeUnresolved
	return f
}

func genMismatchFail(op, id string, want, have uint64) *Fail {
	f := failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, op, "keyset %q: the parties are on different generations right now (%d vs %d); retry shortly", id, want, have)
	f.CB = CodeGenMismatch
	return f
}

// keyset returns the current generation's keyset (cached, unsealed in C memory). wantGen != 0 requires that generation.
// Errors: not found, an HSM problem (UNAVAILABLE), a generation mismatch (UNAVAILABLE).
func (s *Server) keyset(ctx context.Context, id string, wantGen uint64) (*cbmpc.Keyset, uint64, error) {
	if !validID(id) {
		return nil, 0, invalid("keyset", "invalid keyset id")
	}
	return s.cache.get(ctx, s, id, wantGen)
}

type cacheEntry struct {
	gen uint64
	ks  *cbmpc.Keyset
}

// keyCache keeps unsealed keysets (secrets in C memory) so a session does not unseal and parse on every call.
type keyCache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

func newKeyCache() *keyCache { return &keyCache{m: map[string]cacheEntry{}} }

func (c *keyCache) get(ctx context.Context, s *Server, id string, wantGen uint64) (*cbmpc.Keyset, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := s.store.State(ctx, id)
	if errors.Is(err, ErrNotFound) || (err == nil && st.Current == 0) {
		return nil, 0, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.NotFound, "keyset", "keyset %q not found", id)
	}
	if err != nil {
		return nil, 0, fromWrapper("keyset", err)
	}
	if st.Scheme != 0 {
		return nil, 0, invalid("keyset", "keyset %q is a 2-of-3 keyset: this call is for 2-party HD keysets", id)
	}
	if wantGen != 0 && st.Current != wantGen {
		return nil, 0, genMismatchFail("keyset", id, wantGen, st.Current)
	}
	if e, ok := c.m[id]; ok && e.gen == st.Current {
		return e.ks, e.gen, nil
	}
	ks, err := s.store.GetKeyset(ctx, id, st.Current)
	if err != nil {
		var ue *UnavailableError
		if errors.As(err, &ue) {
			return nil, 0, failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, "keyset", "the HSM is unavailable: %v", err)
		}
		return nil, 0, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, "keyset", "cannot open keyset %q: %v", id, err)
	}
	if old, ok := c.m[id]; ok {
		go old.ks.Wipe()
	}
	c.m[id] = cacheEntry{gen: st.Current, ks: ks}
	return ks, st.Current, nil
}

func (c *keyCache) drop(id string) {
	c.mu.Lock()
	old, ok := c.m[id]
	delete(c.m, id)
	c.mu.Unlock()
	if ok {
		go old.ks.Wipe() // waits for sessions still using it
	}
}

func (c *keyCache) wipeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.m {
		e.ks.Wipe()
		delete(c.m, id)
	}
}

// candidate is a DKG or Refresh result waiting for the two-phase commit.
type candidate struct {
	id  string
	gen uint64
	ks  *cbmpc.Keyset
}

func (c *candidate) String() string { return fmt.Sprintf("%s@%d", c.id, c.gen) }

func randRead(b []byte) { _, _ = cryptoRand.Read(b) }
