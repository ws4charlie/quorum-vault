package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// coordinate runs one protocol session as party A: open on B, wait for B's ACK, run our side, compare results with B,
// and for DKG/Refresh commit on B first and on ourselves second. It never returns a result unless both parties agree.
func (s *Server) coordinate(ctx context.Context, name string, open *pb.Open, rateKey string) (res *opResult, err error) {
	if s.peerClient == nil {
		return nil, invalid(name, "this party has no peer connection")
	}
	if !s.rl.allow(rateKey) {
		return nil, limitFail(name, "rate limit of %.0f sessions/s exceeded for %q", s.cfg.Limits.SessionsPerSecKey, rateKey)
	}
	if !s.slots.acquire() {
		return nil, limitFail(name, "too many concurrent sessions (max %d)", s.cfg.Limits.MaxPeerSessions)
	}
	defer s.slots.release()
	s.wg.Add(1)
	defer s.wg.Done()

	var sidRaw [16]byte
	if _, err := rand.Read(sidRaw[:]); err != nil {
		return nil, err
	}
	sid := hex.EncodeToString(sidRaw[:])
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()

	stream, err := s.peerClient.Session(ctx)
	if err != nil {
		return nil, fromWrapper(name, &transportErr{err})
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	defer stream.CloseSend()

	fail := func(mine error) error {
		f := fromWrapper(name, mine)
		tr.abortPeer(f.Msg)
		// The peer may have named the real cause (e.g. it detected tampering first): the worse kind wins.
		wait, c2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer c2()
		if fin, err := tr.waitFin(wait); err == nil && !fin.GetOk() {
			if pf := peerFail(name, fin); severity(pf.Kind) > severity(f.Kind) {
				return pf
			}
		}
		return f
	}

	b, _ := proto.Marshal(open)
	if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		return nil, fromWrapper(name, &transportErr{err})
	}
	ackCtx, c3 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	err = tr.waitAck(ackCtx)
	c3()
	if err != nil {
		var f *Fail
		if errors.As(err, &f) { // refused / limit / failed by the peer before any protocol message
			return nil, f
		}
		return nil, fromWrapper(name, &transportErr{err})
	}

	res, err = s.execOp(ctx, open, tr)
	if err != nil {
		return nil, fail(err)
	}
	defer func() {
		if res != nil && res.cleanup != nil {
			res.cleanup()
		}
	}()

	finCtx, c4 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	bfin, err := tr.waitFin(finCtx)
	c4()
	if err != nil {
		return nil, fail(&transportErr{err})
	}
	if !bfin.GetOk() {
		return nil, peerFail(name, bfin)
	}
	if string(bfin.Result) != string(res.compare) {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "parties computed different results"})
		return nil, failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, name, "the two parties computed different results")
	}
	commit := res.apply != nil
	if err := tr.sendFin(&pb.Fin{Ok: true, Commit: commit}); err != nil {
		return nil, fromWrapper(name, &transportErr{err})
	}
	if commit {
		// B stores first and tells us; only then do we store. A crash between the two is a mismatch that P5b-4's durable
		// two-phase commit closes; until then the operator re-runs the operation.
		cctx, c5 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		ack, err := tr.waitFin(cctx)
		c5()
		if err != nil {
			return nil, fromWrapper(name, &transportErr{err})
		}
		if !ack.GetOk() {
			return nil, peerFail(name, ack)
		}
		if err := res.apply(ctx); err != nil {
			return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, name, "peer committed but local commit failed: %v", err)
		}
	}
	return res, nil
}

// transportErr marks an error that is a plain link failure.
type transportErr struct{ error }

func (t *transportErr) Unwrap() error { return t.error }

var _ = grpc.WaitForReady
