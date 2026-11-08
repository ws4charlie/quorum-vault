package server

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// sessionT is the follower side for 2-of-3 keysets (parties B and C), called from Session once the generic checks (session id,
// replay, size, slots, rate) passed. Party C serves nothing else: it holds no 2-party keyset.
func (s *Server) sessionT(ctx context.Context, stream pb.Peer_SessionServer, sid string, open *pb.Open, start time.Time,
	rejectCode func(pb.ErrorKind, uint32, string) error) error {
	reject := func(kind pb.ErrorKind, msg string) error { return rejectCode(kind, 0, msg) }
	if s.cfg.Role == "A" {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "party A never follows a session: it coordinates")
	}
	if !isT(open) {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "this party holds 2-of-3 keysets only")
	}
	from := s.callerRole(stream.Context())
	if from == "" {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "the caller's certificate is not one of the pinned parties")
	}
	switch open.Op {
	case pb.Op_OP_SIGN:
		return s.signFollowT(ctx, stream, sid, open, from, reject, rejectCode, start)
	case pb.Op_OP_FREEZE_NOTICE:
		return s.freezeNoticeFollow(stream, sid, open, from, reject)
	case pb.Op_OP_UNFREEZE:
		return s.unfreezeFollow(ctx, stream, sid, open, from, reject)
	case pb.Op_OP_DKG, pb.Op_OP_REFRESH, pb.Op_OP_RECONCILE:
		return s.groupFollow(ctx, stream, sid, open, from, reject, rejectCode, start)
	}
	return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown op")
}

// dialLink (party B) opens the link stream to C for a three-party operation and waits for C's ACK.
func (s *Server) dialLink(ctx context.Context, open *pb.Open) (*sessTransport, pb.Peer_SessionClient, *Fail) {
	if s.peerCClient == nil {
		return nil, nil, failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, 0, open.Op.String(), "party B has no link to party C configured")
	}
	sid := newSID()
	stream, err := s.peerCClient.Session(ctx)
	if err != nil {
		f := fromWrapper(open.Op.String(), &transportErr{err})
		f.Kind, f.CB, f.Msg = pb.ErrorKind_ERROR_KIND_UNAVAILABLE, CodeLinkDown, "party C is not reachable from B: "+f.Msg
		return nil, nil, f
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	lo := proto.Clone(open).(*pb.Open)
	lo.Link, lo.Admin, lo.Initiator = true, nil, "A" // C already checks the operator signature on A's own stream
	b, _ := proto.Marshal(lo)
	if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		stream.CloseSend()
		return nil, nil, fromWrapper(open.Op.String(), &transportErr{err})
	}
	c, cancel := context.WithTimeout(ctx, 2*s.cfg.Limits.RecvTimeout())
	defer cancel()
	if err := tr.waitAck(c); err != nil {
		stream.CloseSend()
		var f *Fail
		if errors.As(err, &f) {
			return nil, nil, f
		}
		return nil, nil, fromWrapper(open.Op.String(), &transportErr{err})
	}
	return tr, stream, nil
}

// groupFollow handles a member's side of DKG, Refresh and Reconcile.
func (s *Server) groupFollow(ctx context.Context, stream pb.Peer_SessionServer, sid string, open *pb.Open, from string,
	reject func(pb.ErrorKind, string) error, rejectCode func(pb.ErrorKind, uint32, string) error, start time.Time) error {
	me := s.cfg.Role
	if open.Op == pb.Op_OP_RECONCILE && open.Reason == "pair" && open.Group == "" {
		// A reconciles with this member alone (the third is unreachable)
		if from != "A" || open.Initiator != "A" || !validID(open.KeysetId) {
			return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "pair reconciliation only from party A")
		}
		tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
		if err := tr.sendFrame(pb.FrameKind_FRAME_KIND_ACK, nil); err != nil {
			return nil
		}
		go tr.pump()
		return s.reconcilePairFollow(ctx, open, me, tr, sid)
	}
	if !sidRe.MatchString(open.Group) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "a three-party session needs a 32-hex group id")
	}
	if open.Link {
		if me != "C" || from != "B" || open.Initiator != "A" {
			return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "link streams go from B to C only")
		}
		return s.linkHandler(ctx, stream, sid, open, reject)
	}
	if from != "A" || open.Initiator != "A" {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "three-party sessions are started by party A")
	}
	if !validID(open.KeysetId) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "invalid keyset id")
	}
	if open.Op == pb.Op_OP_RECONCILE {
		// reconcile has its own checks (it is exactly for keysets that are not resolved)
	} else if kind, msg, ok := s.groupPrecheck(ctx, open); !ok {
		return reject(kind, msg)
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	links := map[string]*sessTransport{"A": tr}
	var closeLink func()
	switch me {
	case "B":
		ltr, lstream, f := s.dialLink(ctx, open)
		if f != nil {
			return rejectCode(f.Kind, f.CB, f.Msg)
		}
		closeLink = func() {
			lstream.CloseSend()
			select {
			case <-ltr.done:
			case <-time.After(s.cfg.Limits.RecvTimeout()):
			}
		}
		links["C"] = ltr
	case "C":
		rv := s.groups.join(open.Group)
		defer s.groups.forget(open.Group)
		defer func() { // the link handler may return now
			select {
			case <-rv.done:
			default:
				close(rv.done)
			}
		}()
		if !rv.set("A", tr, open) {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "group id already used")
		}
		select {
		case <-rv.ready:
		case <-time.After(2 * s.cfg.Limits.RecvTimeout()):
			return rejectCode(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, CodeLinkDown, "the link from party B did not arrive")
		case <-ctx.Done():
			return nil
		}
		rv.mu.Lock()
		lb := rv.fromB
		rv.mu.Unlock()
		if err := lb.sendFrame(pb.FrameKind_FRAME_KIND_ACK, nil); err != nil {
			return nil
		}
		go lb.pump()
		links["B"] = lb
	}
	if err := tr.sendFrame(pb.FrameKind_FRAME_KIND_ACK, nil); err != nil {
		if closeLink != nil {
			closeLink()
		}
		return nil
	}
	go tr.pump()
	if closeLink != nil {
		defer closeLink()
	}
	if open.Op == pb.Op_OP_RECONCILE {
		return s.reconcileFollowT(ctx, open, me, tr, links, sid, start)
	}
	return s.runGroupFollower(ctx, open, me, tr, links, sid, start)
}

// linkHandler (party C) holds B's link stream until the A stream's handler (the runner) has finished.
func (s *Server) linkHandler(ctx context.Context, stream pb.Peer_SessionServer, sid string, open *pb.Open, reject func(pb.ErrorKind, string) error) error {
	rv := s.groups.join(open.Group)
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	if !rv.set("B", tr, nil) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "link already registered for this group")
	}
	select {
	case <-rv.done:
	case <-ctx.Done():
	case <-time.After(6 * s.cfg.Limits.SessionTimeout()):
	}
	return nil
}
