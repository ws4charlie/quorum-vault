package server

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// ackFail keeps the kind and code a member answered with (so a refusal stays a refusal and an unavailable member stays
// retryable), names the member, and turns only a missing answer into a transport failure.
func TestAckFailKeepsTheMembersKind(t *testing.T) {
	for _, k := range []pb.ErrorKind{pb.ErrorKind_ERROR_KIND_REFUSED, pb.ErrorKind_ERROR_KIND_UNAVAILABLE, pb.ErrorKind_ERROR_KIND_FROZEN,
		pb.ErrorKind_ERROR_KIND_LIMIT, pb.ErrorKind_ERROR_KIND_INTERNAL, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC} {
		in := peerFail("session", &pb.Fin{Kind: k, Message: "why"})
		got := ackFail("dkg", "C", in)
		if got.Kind != k || got.Code != in.Code || !got.Peer || got.Msg != "party C: why" {
			t.Fatalf("%v: got %+v", k, got)
		}
	}
	for _, e := range []error{context.DeadlineExceeded, ErrPeerGone, errors.New("stream broke")} {
		got := ackFail("dkg", "B", e)
		if got.Kind != pb.ErrorKind_ERROR_KIND_TRANSPORT || (got.Code != codes.Unavailable && got.Code != codes.DeadlineExceeded) {
			t.Fatalf("%v: got %+v", e, got)
		}
	}
}
