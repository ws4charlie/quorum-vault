package server

import (
	"context"
	"errors"
	"testing"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"google.golang.org/grpc/codes"
)

// A peer that refuses a session answers the OPEN with a failing FIN. The pump queues that FIN and then fails the session, so
// waitAck can find the FIN and the session error ready at the same time. The refusal must win every time: its kind is the
// cause (frozen, refused, unavailable) and the bare session error would map to a transport failure, which counts against the
// peer and is retried.
func TestWaitAckPrefersTheRefusalOverTheSessionError(t *testing.T) {
	for _, k := range []struct {
		kind pb.ErrorKind
		code codes.Code
	}{
		{pb.ErrorKind_ERROR_KIND_FROZEN, codes.FailedPrecondition},
		{pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied},
		{pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable},
	} {
		for i := 0; i < 200; i++ { // select picks at random between ready cases: repeat so a regression cannot pass by luck
			tr := newSessTransport("s", nil, 1<<20, &frameStats{})
			// exactly what pump does for a failing FIN
			fin := &pb.Fin{Ok: false, Kind: k.kind, Message: "keyset is frozen: because"}
			tr.fins <- fin
			tr.fail(errors.Join(ErrPeerFailed))
			err := tr.waitAck(context.Background())
			var f *Fail
			if !errors.As(err, &f) || f.Kind != k.kind || f.Code != k.code || !f.Peer {
				t.Fatalf("%v: waitAck = %#v, want the peer's refusal (kind %v, code %v)", k.kind, err, k.kind, k.code)
			}
		}
	}
}
