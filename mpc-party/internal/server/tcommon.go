package server

// 2-of-3 threshold keysets (E23-2): shared pieces. The protocol is cb-mpc's ecdsa_mp through cbmpc.TKey (see
// internal/cbmpc/threshold.go and docs/spikes/e23-threshold.md). Members are A=0, B=1, C=2.
//
// Links. One peer link per pair, each side pinning the other's certificate: A dials B and C, B dials C. Every protocol
// session between two members is one gRPC stream (the same frames as the 2-party path). A session among three members
// (DKG, Refresh, Reconcile) is three streams: A opens one to B and one to C, B then opens a LINK stream to C with the
// same group id, and C starts when both arrived (groupTable). The protocol data of the A-B, A-C and B-C pairs flow on
// their own stream; every control message (ACK, results, commit steps) goes between A and each follower.

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// Codes added for 2-of-3 so the initiator can react without matching text.
const (
	CodeLinkDown uint32 = 0xff0c0003 // a link the operation needs could not be established
	// CodeSigningStarted marks a 2-of-3 Sign failure that happened AFTER signing messages may have been exchanged. The gateway
	// moves to its next coordinator only on TRANSPORT / UNAVAILABLE failures WITHOUT this code (E23-3).
	CodeSigningStarted        = pb.CodeSigningStarted
	CodePlan           uint32 = 0xff0c0004 // reconciliation found a member that is stale or has lost its state: operator action needed
)

func isT(open *pb.Open) bool { return open.GetScheme() == pb.Scheme_SCHEME_ECDSA_2OF3 }

// memberRole maps a role letter to the wrapper's member number.
func roleMember(r string) cbmpc.Member { return memberOf(r) }

// ---- key cache for threshold shares ----

type tcacheEntry struct {
	gen uint64
	k   *cbmpc.TKey
}

type tkeyCache struct {
	mu sync.Mutex
	m  map[string]tcacheEntry
}

func newTKeyCache() *tkeyCache { return &tkeyCache{m: map[string]tcacheEntry{}} }

func (c *tkeyCache) get(ctx context.Context, s *Server, id string, wantGen uint64) (*cbmpc.TKey, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := s.store.State(ctx, id)
	if errors.Is(err, ErrNotFound) || (err == nil && st.Current == 0) {
		return nil, 0, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.NotFound, "keyset", "keyset %q not found", id)
	}
	if err != nil {
		return nil, 0, fromWrapper("keyset", err)
	}
	if st.Scheme != int32(pb.Scheme_SCHEME_ECDSA_2OF3) {
		return nil, 0, invalid("keyset", "keyset %q is not a 2-of-3 keyset", id)
	}
	if wantGen != 0 && st.Current != wantGen {
		return nil, 0, genMismatchFail("keyset", id, wantGen, st.Current)
	}
	if e, ok := c.m[id]; ok && e.gen == st.Current {
		return e.k, e.gen, nil
	}
	k, err := s.store.GetTKey(ctx, id, st.Current)
	if err != nil {
		var ue *UnavailableError
		if errors.As(err, &ue) {
			return nil, 0, failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, "keyset", "the HSM is unavailable: %v", err)
		}
		return nil, 0, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, "keyset", "cannot open keyset %q: %v", id, err)
	}
	if old, ok := c.m[id]; ok {
		go old.k.Wipe()
	}
	c.m[id] = tcacheEntry{gen: st.Current, k: k}
	return k, st.Current, nil
}

func (c *tkeyCache) drop(id string) {
	c.mu.Lock()
	old, ok := c.m[id]
	delete(c.m, id)
	c.mu.Unlock()
	if ok {
		go old.k.Wipe() // waits for sessions still using it
	}
}

func (c *tkeyCache) wipeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.m {
		e.k.Wipe()
		delete(c.m, id)
	}
}

// tkey returns the current generation's share (cached). wantGen != 0 requires that generation.
func (s *Server) tkey(ctx context.Context, id string, wantGen uint64) (*cbmpc.TKey, uint64, error) {
	if !validID(id) {
		return nil, 0, invalid("keyset", "invalid keyset id")
	}
	return s.tcache.get(ctx, s, id, wantGen)
}

// dropKey forgets cached shares of a keyset, whatever its scheme.
func (s *Server) dropKey(id string) {
	s.cache.drop(id)
	s.tcache.drop(id)
}

// candidateT is a DKG or Refresh result of a threshold keyset waiting for the two-phase commit.
type candidateT struct {
	id  string
	gen uint64
	k   *cbmpc.TKey
}

// ---- who is calling (party C and B learn it from the pinned certificate) ----

func (s *Server) callerRole(ctx context.Context) string {
	switch s.cfg.Role {
	case "B":
		return "A" // B's peer listener pins A only
	case "C":
		p, ok := peer.FromContext(ctx)
		if !ok {
			return ""
		}
		ti, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(ti.State.PeerCertificates) == 0 {
			return ""
		}
		pin := PinOf(ti.State.PeerCertificates[0].Raw)
		switch {
		case s.peerA[pin]:
			return "A"
		case s.peerB[pin]:
			return "B"
		}
	}
	return ""
}

// ---- rendezvous of the streams of a three-party session at party C ----

type groupRV struct {
	mu       sync.Mutex
	open     *pb.Open
	fromA    *sessTransport
	fromB    *sessTransport
	ready    chan struct{} // closed when both streams are in
	done     chan struct{} // closed by the runner when it has finished (the link handler may then return)
	closedRd bool
}

type groupTable struct {
	mu sync.Mutex
	m  map[string]*groupRV
}

func (g *groupTable) join(id string) *groupRV {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil {
		g.m = map[string]*groupRV{}
	}
	rv := g.m[id]
	if rv == nil {
		rv = &groupRV{ready: make(chan struct{}), done: make(chan struct{})}
		g.m[id] = rv
	}
	return rv
}

func (g *groupTable) forget(id string) {
	g.mu.Lock()
	delete(g.m, id)
	g.mu.Unlock()
}

// set registers one stream; it reports false if that side already registered (a replayed group id).
func (rv *groupRV) set(from string, tr *sessTransport, open *pb.Open) bool {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	switch from {
	case "A":
		if rv.fromA != nil {
			return false
		}
		rv.fromA = tr
		rv.open = open
	case "B":
		if rv.fromB != nil {
			return false
		}
		rv.fromB = tr
	}
	if rv.fromA != nil && rv.fromB != nil && !rv.closedRd {
		rv.closedRd = true
		close(rv.ready)
	}
	return true
}

// ---- helpers shared by the T paths ----

// tOpenCtx returns the ctx of one session, with the session timeout.
func (s *Server) sessionCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
}

// meshOf builds the wrapper's Mesh from the session streams to the other members.
func meshOf(self string, links map[string]*sessTransport) *cbmpc.LinkMesh {
	m := map[cbmpc.Member]cbmpc.Transport{}
	for role, tr := range links {
		m[roleMember(role)] = tr
	}
	return cbmpc.NewLinkMesh(roleMember(self), m)
}

// selfTestLabel binds a self-test to a keyset and generation.
func selfTestLabel(id string, gen uint64) []byte {
	return []byte("qv-mpc|tecdsa-selftest|" + id + "|" + itoa(gen))
}

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

var _ = time.Second
