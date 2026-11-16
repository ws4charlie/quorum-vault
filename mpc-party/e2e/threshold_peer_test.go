package e2e

import (
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The wanted peer of a 2-of-3 Sign (SignRequest.peer): the gateway's route says which pair signs, the coordinator honours it or fails. It
// never swaps the peer by itself, and it never lets a pair skip a cosigner check.

func (cl *cluster3) signPeer(via, id, job string, seed int, peer string) (*pb.SignResponse, error) {
	c, cancel := context5(60 * time.Second)
	defer cancel()
	return cl.client[via].Sign(c, &pb.SignRequest{KeyId: id, Algorithm: cl.algorithm(), Digest: cl.msg(seed), JobId: job, IntentPackage: []byte("intent"), Peer: peer})
}

func (cl *cluster3) mustSignPeer(t *testing.T, via, id, job string, seed int, peer string, pub []byte) *pb.SignResponse {
	t.Helper()
	var r *pb.SignResponse
	retryUnavailable(t, 40*time.Second, func() (err error) { r, err = cl.signPeer(via, id, job, seed, peer); return })
	cl.verify(t, pub, cl.msg(seed), r.Signature)
	return r
}

func TestThresholdWantedPeerIsHonoured(t *testing.T) {
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, nil)
		pub := cl.dkg(t, "k")
		b0, c0 := cl.procs["B"].followedSign(), cl.procs["C"].followedSign()

		// A asked for C signs with C and not with B, although B is up and first in A's own order
		r := cl.mustSignPeer(t, "A", "k", "j-ac", 1, "C", pub)
		if r.SignedWith != "C" || cl.procs["C"].followedSign() != c0+1 || cl.procs["B"].followedSign() != b0 {
			t.Fatalf("A+C: signed_with %q, C served %d (was %d), B served %d (was %d)", r.SignedWith, cl.procs["C"].followedSign(), c0, cl.procs["B"].followedSign(), b0)
		}
		r = cl.mustSignPeer(t, "A", "k", "j-ab", 2, "B", pub)
		if r.SignedWith != "B" || cl.procs["B"].followedSign() != b0+1 {
			t.Fatalf("A+B: signed_with %q, B served %d (was %d)", r.SignedWith, cl.procs["B"].followedSign(), b0)
		}
		r = cl.mustSignPeer(t, "B", "k", "j-bc", 3, "C", pub)
		if r.SignedWith != "C" {
			t.Fatalf("B+C: signed_with %q", r.SignedWith)
		}
		// no wanted peer: the party's own order, and it names who signed
		r = cl.mustSignPeer(t, "A", "k", "j-own", 4, "", pub)
		if r.SignedWith != "B" {
			t.Fatalf("A's own order signed with %q, want B", r.SignedWith)
		}
		// a replay returns the stored signature whatever pair is asked for now
		r2, err := cl.signPeer("A", "k", "j-ac", 1, "B")
		must(t, err)
		if !r2.Replayed || r2.SignedWith != "" || string(r2.Signature) != string(cl.mustSignPeer(t, "A", "k", "j-ac", 1, "C", pub).Signature) {
			t.Fatalf("replay: %+v", r2)
		}
	})
}

// A request that names a peer the party cannot sign with is refused outright.
func TestThresholdWantedPeerMustBeLegal(t *testing.T) {
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, nil)
		cl.dkg(t, "k")
		for i, c := range []struct{ via, peer string }{{"A", "A"}, {"A", "X"}, {"B", "B"}, {"B", "A"}, {"B", "X"}} {
			if _, err := cl.signPeer(c.via, "k", "bad-"+string(rune('a'+i)), 10+i, c.peer); err == nil {
				t.Fatalf("%s asked for peer %q: signed", c.via, c.peer)
			}
		}
		if cl.procs["A"].followedSign()+cl.procs["B"].followedSign()+cl.procs["C"].followedSign() != 0 {
			t.Fatal("a session was opened for an illegal pair")
		}
	})
}

// No silent swap: with the wanted peer down, the coordinator fails as unavailable, before any signing message, and does not try the other peer.
func TestThresholdWantedPeerDownIsNotSwapped(t *testing.T) {
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, nil)
		pub := cl.dkg(t, "k")
		cl.stop("B")
		c0 := cl.procs["C"].followedSign()
		_, err := cl.signPeer("A", "k", "j-down-b", 20, "B")
		if err == nil {
			t.Fatal("A+B signed with B down")
		}
		if k, ok := kindOf(err); !ok || (k != pb.ErrorKind_ERROR_KIND_TRANSPORT && k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE) {
			t.Fatalf("kind %v: %v", k, err)
		}
		if cl.procs["C"].followedSign() != c0 {
			t.Fatal("A swapped to C although B was asked for")
		}
		// and the pair that does not need B keeps working
		cl.mustSignPeer(t, "A", "k", "j-down-c", 21, "C", pub)
	})
}

// A pair never skips a cosigner check: when the cosigner of C refuses, A+C is REFUSED (final), and A does not move on to B; the same pair
// with B asked for signs if B's own cosigner agrees.
func TestThresholdWantedPeerStillMeetsTheCosigner(t *testing.T) {
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, func(role string, c *server.Config) {
			if role == "C" {
				c.Authorizer = server.AuthorizerConfig{Type: "deny-all"}
			}
		})
		pub := cl.dkg(t, "k")
		b0 := cl.procs["B"].followedSign()
		_, err := cl.signPeer("A", "k", "j-refused", 30, "C")
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		if cl.procs["B"].followedSign() != b0 {
			t.Fatal("A moved on to B after C's cosigner refused")
		}
		_, err = cl.signPeer("B", "k", "j-refused-bc", 31, "C")
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		cl.mustSignPeer(t, "A", "k", "j-ok", 32, "B", pub)
	})
}
