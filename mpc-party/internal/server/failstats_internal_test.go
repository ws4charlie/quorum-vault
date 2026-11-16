package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func failServer(role string) *Server {
	return &Server{cfg: &Config{Role: role}, fails: newFailStats(role)}
}

var allKinds = []pb.ErrorKind{
	pb.ErrorKind_ERROR_KIND_TRANSPORT, pb.ErrorKind_ERROR_KIND_UNAVAILABLE, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC,
	pb.ErrorKind_ERROR_KIND_REFUSED, pb.ErrorKind_ERROR_KIND_LIMIT, pb.ErrorKind_ERROR_KIND_INTERNAL, pb.ErrorKind_ERROR_KIND_FROZEN,
}

// Every kind lands on its own series, with the peer that was named, for A, B and C as coordinator, and nothing else moves.
func TestFailCountCoordinatorKindsAndPeers(t *testing.T) {
	ops := map[pb.Op]string{pb.Op_OP_SIGN: "sign", pb.Op_OP_DKG: "dkg", pb.Op_OP_REFRESH: "refresh", pb.Op_OP_RECONCILE: "reconcile",
		pb.Op_OP_DERIVE: "other", pb.Op_OP_UNFREEZE: "other"}
	for _, role := range []string{"A", "B", "C"} {
		for _, peer := range []string{"A", "B", "C"} {
			if peer == role {
				continue
			}
			for _, k := range allKinds {
				for op, label := range ops {
					s := failServer(role)
					s.noteFail(sideCoordinator, op, peer, failf(k, 0, "x", "boom"))
					kl := kindLabel(k)
					if got := s.FailureCount("coordinator", label, peer, kl); got != 1 {
						t.Fatalf("%s %s %s %s: count %d, want 1", role, op, peer, kl, got)
					}
					if total := s.FailureCountTotal("", "", "", ""); total != 1 {
						t.Fatalf("%s %s %s %s: total %d, want exactly 1 series moved", role, op, peer, kl, total)
					}
				}
			}
		}
	}
}

func TestFailCountPeerLabelIsFixed(t *testing.T) {
	s := failServer("A")
	for _, bad := range []string{"", "A", "X", "BC", "b", "job-123"} { // self, unknown, or anything that could grow the label set
		s.noteFail(sideCoordinator, pb.Op_OP_SIGN, bad, failf(pb.ErrorKind_ERROR_KIND_LIMIT, 0, "x", "y"))
	}
	if got := s.FailureCount("coordinator", "sign", "none", "LIMIT"); got != 6 {
		t.Fatalf("peer none: %d, want 6", got)
	}
	var b strings.Builder
	s.WriteMetrics(&b)
	if strings.Contains(b.String(), `peer="job-123"`) || strings.Contains(b.String(), `peer="X"`) {
		t.Fatal("a caller-controlled value reached a label")
	}
}

func TestFailCountClassifiesPlainErrors(t *testing.T) {
	s := failServer("B")
	s.noteFail(sideCoordinator, pb.Op_OP_SIGN, "C", &transportErr{errors.New("connection reset")})
	s.noteFail(sideCoordinator, pb.Op_OP_SIGN, "C", context.DeadlineExceeded)
	s.noteFail(sideCoordinator, pb.Op_OP_SIGN, "C", errors.New("something else"))
	s.noteFail(sideCoordinator, pb.Op_OP_SIGN, "C", nil)
	if s.FailureCount("coordinator", "sign", "C", "TRANSPORT") != 2 || s.FailureCount("coordinator", "sign", "C", "INTERNAL") != 1 {
		t.Fatalf("classification wrong: total %d", s.FailureCountTotal("", "", "", ""))
	}
}

// All series exist at zero from the start, so a first failure is an increase for Prometheus.
func TestFailMetricsStartAtZero(t *testing.T) {
	for _, role := range []string{"A", "B", "C"} {
		s := failServer(role)
		var b strings.Builder
		s.WriteMetrics(&b)
		out := b.String()
		for _, peer := range []string{"A", "B", "C"} {
			want := fmt.Sprintf(`qv_mpc_party_session_failures_total{party=%q,side="coordinator",op="sign",peer=%q,kind="CRYPTOGRAPHIC"} 0`, role, peer)
			if peer == role {
				if strings.Contains(out, want) {
					t.Fatalf("%s has a series for itself", role)
				}
				continue
			}
			if !strings.Contains(out, want) {
				t.Fatalf("%s: missing zero series %s", role, want)
			}
		}
		if !strings.Contains(out, "SUSPECT") || !strings.Contains(out, "not proven guilty") {
			t.Fatal("help text must say the peer is a suspect, not proven")
		}
		if n := strings.Count(out, "\nqv_mpc_party_session_failures_total{"); n != 2*5*3*7 {
			t.Fatalf("%s: %d series, want %d (sides x ops x peers x kinds)", role, n, 2*5*3*7)
		}
	}
}

// A fake incoming stream: followWatch sees every FIN in both directions and counts the session once, on its worst failure.
type fakeIn struct {
	pb.Peer_SessionServer
	in []*pb.Frame
}

func (f *fakeIn) Context() context.Context { return context.Background() }
func (f *fakeIn) Send(*pb.Frame) error     { return nil }
func (f *fakeIn) Recv() (*pb.Frame, error) {
	if len(f.in) == 0 {
		return nil, errors.New("eof")
	}
	fr := f.in[0]
	f.in = f.in[1:]
	return fr, nil
}

func finFrame(ok bool, k pb.ErrorKind) *pb.Frame {
	b, _ := proto.Marshal(&pb.Fin{Ok: ok, Kind: k})
	return &pb.Frame{Kind: pb.FrameKind_FRAME_KIND_FIN, Payload: b}
}

func TestFailCountFollowerKindsAndDirections(t *testing.T) {
	for _, k := range allKinds {
		// sent by the follower (its own finding or a rejection)
		s := failServer("B") // B's only caller is A
		w := &followWatch{Peer_SessionServer: &fakeIn{}}
		w.setOp(pb.Op_OP_SIGN)
		w.Send(finFrame(false, k))
		s.finishFollow(w)
		if got := s.FailureCount("follower", "sign", "A", kindLabel(k)); got != 1 || s.FailureCountTotal("", "", "", "") != 1 {
			t.Fatalf("sent %s: count %d", k, got)
		}
		// received from the coordinator
		s = failServer("B")
		w = &followWatch{Peer_SessionServer: &fakeIn{in: []*pb.Frame{finFrame(false, k)}}}
		w.setOp(pb.Op_OP_REFRESH)
		w.Recv()
		s.finishFollow(w)
		if got := s.FailureCount("follower", "refresh", "A", kindLabel(k)); got != 1 || s.FailureCountTotal("", "", "", "") != 1 {
			t.Fatalf("received %s: count %d", k, got)
		}
	}
}

func TestFailCountFollowerCountsASessionOnceAtItsWorstKind(t *testing.T) {
	s := failServer("B")
	w := &followWatch{Peer_SessionServer: &fakeIn{in: []*pb.Frame{finFrame(false, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC)}}}
	w.setOp(pb.Op_OP_SIGN)
	w.Send(finFrame(false, pb.ErrorKind_ERROR_KIND_TRANSPORT))
	w.Recv()
	w.Send(finFrame(false, pb.ErrorKind_ERROR_KIND_TRANSPORT))
	s.finishFollow(w)
	if s.FailureCountTotal("", "", "", "") != 1 || s.FailureCount("follower", "sign", "A", "CRYPTOGRAPHIC") != 1 {
		t.Fatal("one session must count once, at its worst kind")
	}
}

func TestFailCountFollowerIgnoresSuccessAndOtherFrames(t *testing.T) {
	s := failServer("B")
	w := &followWatch{Peer_SessionServer: &fakeIn{in: []*pb.Frame{finFrame(true, 0), {Kind: pb.FrameKind_FRAME_KIND_DATA, Payload: []byte("x")}, {Kind: pb.FrameKind_FRAME_KIND_FIN, Payload: []byte{0xff, 0xff}}}}}
	w.setOp(pb.Op_OP_SIGN)
	w.Send(finFrame(true, 0))
	for i := 0; i < 3; i++ {
		w.Recv()
	}
	s.finishFollow(w)
	if s.FailureCountTotal("", "", "", "") != 0 {
		t.Fatal("a successful session was counted as a failure")
	}
}
