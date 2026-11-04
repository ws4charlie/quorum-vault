package server

import (
	"context"
	"errors"
	"regexp"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

var sidRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Session is party B's side of the peer protocol (the Peer service). One stream is one protocol session started by A.
//
//	A: OPEN               B: checks (id, replay, limits, keyset, authorizer) -> ACK, or FIN{ok=false} and nothing runs
//	A <-> B: DATA frames (cb-mpc messages)
//	B: FIN{ok, result}    A compares B's result with its own
//	A: FIN{ok, commit}    commit only after A's SelfTest passed (DKG, Refresh)
//	B: FIN{ok}            B has stored the new shares (commit ops only); then A stores its own
func (s *Server) Session(stream pb.Peer_SessionServer) error {
	s.wg.Add(1)
	defer s.wg.Done()
	start := time.Now()
	ctx, cancel := context.WithTimeout(stream.Context(), s.cfg.Limits.SessionTimeout())
	defer cancel()

	// First frame, with a timeout: a peer that connects and says nothing must not hold a stream.
	type first struct {
		f   *pb.Frame
		err error
	}
	ch := make(chan first, 1)
	go func() { f, err := stream.Recv(); ch <- first{f, err} }()
	var fr *pb.Frame
	select {
	case r := <-ch:
		if r.err != nil {
			return nil
		}
		fr = r.f
	case <-time.After(s.cfg.Limits.RecvTimeout()):
		return nil
	case <-ctx.Done():
		return nil
	}
	sid := fr.GetSessionId()
	reject := func(kind pb.ErrorKind, msg string) error {
		b, _ := proto.Marshal(&pb.Fin{Ok: false, Kind: kind, Message: msg})
		stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_FIN, Payload: b})
		s.log.Warn("session rejected", "role", "B", "session", sid, "kind", kind.String(), "reason", msg)
		return nil
	}
	if fr.GetKind() != pb.FrameKind_FRAME_KIND_OPEN || !sidRe.MatchString(sid) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "first frame must be OPEN with a 32-hex session id")
	}
	if !s.replay.add(sid) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "session id already used (replayed OPEN)")
	}
	var open pb.Open
	if err := proto.Unmarshal(fr.Payload, &open); err != nil {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "malformed OPEN")
	}
	if len(open.IntentPackage) > s.cfg.Limits.MaxIntentBytes {
		return reject(pb.ErrorKind_ERROR_KIND_LIMIT, "intent package too large")
	}
	if !s.slots.acquire() {
		return reject(pb.ErrorKind_ERROR_KIND_LIMIT, "too many concurrent sessions")
	}
	defer s.slots.release()
	rateKey := open.KeysetId
	if open.KeyId != "" {
		rateKey = open.KeyId
	}
	if !s.rl.allow(rateKey) {
		return reject(pb.ErrorKind_ERROR_KIND_LIMIT, "session rate limit exceeded for this key")
	}

	// Pre-checks that decide whether anything may start.
	switch open.Op {
	case pb.Op_OP_DKG:
		if !validID(open.KeysetId) {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "invalid keyset id")
		}
		if _, err := s.store.GetKeyset(ctx, open.KeysetId); err == nil {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "keyset already exists on B")
		} else if !errors.Is(err, ErrNotFound) {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "keyset store error")
		}
	case pb.Op_OP_REFRESH, pb.Op_OP_NODE, pb.Op_OP_DERIVE, pb.Op_OP_SIGN:
		if _, err := s.cache.get(ctx, s.store, open.KeysetId); err != nil {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown keyset on B")
		}
	default:
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown op")
	}
	if open.Op == pb.Op_OP_SIGN {
		// B re-verifies what it is asked to sign BEFORE it joins the protocol: without this, compromising A alone would
		// be enough to make B sign anything.
		if err := s.authz.Authorize(ctx, AuthRequest{Role: "B", JobID: open.JobId, KeyID: open.KeyId, KeysetID: open.KeysetId,
			Algorithm: open.Algorithm, Digest: open.Digest, IntentPackage: open.IntentPackage, PublicKey: open.ExpectedPublicKey}); err != nil {
			return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "authorizer on B refused: "+err.Error())
		}
	}

	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	if err := tr.sendFrame(pb.FrameKind_FRAME_KIND_ACK, nil); err != nil {
		return nil
	}
	go tr.pump()

	opName := open.Op.String()
	outcome := "ok"
	var ferr *Fail
	defer func() {
		s.log.Info("session", "role", "B", "op", opName, "session", sid, "job_id", open.JobId, "key_id", open.KeyId,
			"keyset_id", open.KeysetId, "duration_ms", time.Since(start).Milliseconds(), "outcome", outcome,
			"kind", func() string {
				if ferr != nil {
					return ferr.Kind.String()
				}
				return ""
			}())
	}()
	failOut := func(f *Fail) error {
		ferr = f
		outcome = "failed"
		tr.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		return nil
	}

	res, err := s.execOp(ctx, &open, tr)
	if err != nil {
		return failOut(fromWrapper(opName, err))
	}
	if res.cleanup != nil {
		defer res.cleanup()
	}
	if err := tr.sendFin(&pb.Fin{Ok: true, Result: res.compare}); err != nil {
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	// A decides. Wait for its FIN within the receive timeout (A answers right after comparing).
	wctx, c2 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	afin, err := tr.waitFin(wctx)
	c2()
	if err != nil {
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	if !afin.GetOk() {
		outcome = "peer-rejected"
		ferr = peerFail(opName, afin)
		return nil
	}
	if afin.GetCommit() {
		if res.apply == nil {
			return failOut(failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, opName, "A asked to commit an operation that has nothing to commit"))
		}
		if err := res.apply(ctx); err != nil {
			return failOut(failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, opName, "commit failed on B: %v", err))
		}
		tr.sendFin(&pb.Fin{Ok: true})
	}
	return nil
}
