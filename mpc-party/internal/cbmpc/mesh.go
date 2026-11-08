package cbmpc

import (
	"context"
	"fmt"
)

// Member is one of the three parties of a 2-of-3 threshold keyset: 0, 1 or 2 (the service names them A, B and C).
type Member int

const (
	NumMembers = 3
	Threshold  = 2
)

func (m Member) valid() bool { return m >= 0 && m < NumMembers }
func (m Member) String() string {
	if m.valid() {
		return fmt.Sprintf("m%d", int(m))
	}
	return fmt.Sprintf("member(%d)", int(m))
}

// Mesh is what a threshold protocol call talks over: one ordered, whole-message, exactly-once link to EACH of the
// other members, addressed by member number. A Transport (transport.go) is a single link; a Mesh is up to two of them
// side by side. Everything the Transport contract says holds per link: Send and Recv block and must return promptly
// when ctx is done or the link fails; authentication and encryption of every link (mTLS) is the link's job: cb-mpc
// does not authenticate peers, and it attributes a message to a party ONLY by the link it came in on.
//
// One Mesh serves one protocol call at a time. Messages for different peers may be sent and received in any order and
// concurrently; cb-mpc sends to all peers of a round before it reads from them, so a link with buffering of at least one
// round of messages (about 100 KB) cannot deadlock.
type Mesh interface {
	Send(ctx context.Context, to Member, msg []byte) error
	Recv(ctx context.Context, from Member) ([]byte, error)
}

// LinkMesh builds a Mesh from one Transport per peer. In-process parties use NewMemMesh; processes use a
// ConnTransport (or the service's stream) per peer.
type LinkMesh struct {
	self  Member
	links map[Member]Transport
}

// NewLinkMesh wraps pairwise links. links must hold one Transport for every member other than self (a signing call
// that involves two members needs only the link to its peer).
func NewLinkMesh(self Member, links map[Member]Transport) *LinkMesh {
	m := &LinkMesh{self: self, links: map[Member]Transport{}}
	for p, l := range links {
		m.links[p] = l
	}
	return m
}

func (m *LinkMesh) Self() Member { return m.self }

// Link returns the Transport to peer (nil if there is none).
func (m *LinkMesh) Link(peer Member) Transport { return m.links[peer] }

func (m *LinkMesh) link(p Member) (Transport, error) {
	l := m.links[p]
	if l == nil || p == m.self {
		return nil, fmt.Errorf("no link from %s to %s", m.self, p)
	}
	return l, nil
}

func (m *LinkMesh) Send(ctx context.Context, to Member, msg []byte) error {
	l, err := m.link(to)
	if err != nil {
		return err
	}
	return l.Send(ctx, msg)
}

func (m *LinkMesh) Recv(ctx context.Context, from Member) ([]byte, error) {
	l, err := m.link(from)
	if err != nil {
		return nil, err
	}
	return l.Recv(ctx)
}

// Close closes every link that has a Close method; used by tests and by callers that abort a session.
func (m *LinkMesh) Close() {
	for _, l := range m.links {
		if c, ok := l.(interface{ Close() }); ok {
			c.Close()
		}
		if c, ok := l.(interface{ Close() error }); ok {
			c.Close()
		}
	}
}

var _ Mesh = (*LinkMesh)(nil)

// NewMemMesh returns the three members' meshes over in-memory pairwise links (0-1, 0-2, 1-2), for tests and
// in-process parties. Link(peer).(*MemTransport) gives access to Tap and Close.
func NewMemMesh() [NumMembers]*LinkMesh {
	var out [NumMembers]*LinkMesh
	for i := range out {
		out[i] = &LinkMesh{self: Member(i), links: map[Member]Transport{}}
	}
	for a := 0; a < NumMembers; a++ {
		for b := a + 1; b < NumMembers; b++ {
			x, y := NewMemPair()
			out[a].links[Member(b)] = x
			out[b].links[Member(a)] = y
		}
	}
	return out
}
