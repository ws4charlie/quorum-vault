package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Freeze for 2-of-3 keysets. A cryptographic failure in a session freezes the keyset durably on both members of the session
// (the follower freezes on its own finding or on the coordinator's FIN, the coordinator on its own finding or the
// follower's FIN). The coordinator then tells the third member with a FREEZE_NOTICE, if it has a link to it (A: B and C;
// B: C; C dials nobody). A member that was not told learns it the next time it is contacted: a frozen member refuses every
// session for the keyset with kind FROZEN, and a coordinator that hears FROZEN from a peer freezes too and passes it on.
// Reconciliation also carries the frozen flag. Unfreezing needs an operator signature accepted by all three.

// maybeFreezeT freezes after a cryptographic failure, or after a peer reported the keyset frozen. peer is the other member of
// the session; it already knows, so it is not told again.
func (s *Server) maybeFreezeT(open *pb.Open, f *Fail, peer string) {
	if f == nil || open.KeysetId == "" || open.Op == pb.Op_OP_DKG || open.Op == pb.Op_OP_FREEZE_NOTICE || open.Op == pb.Op_OP_UNFREEZE {
		return
	}
	var reason string
	switch {
	case f.Kind == pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC:
		reason = f.Msg
	case f.Kind == pb.ErrorKind_ERROR_KIND_FROZEN && f.Peer:
		reason = "party " + peer + " reported the keyset frozen: " + f.Msg
	default:
		return
	}
	s.freezeT(open.KeysetId, reason, peer, open.Op.String(), open.JobId, f.Peer)
}

func (s *Server) freezeT(id, reason, except, op, job string, peerReported bool) {
	already, _ := s.freeze.Frozen(id)
	if err := s.freeze.Freeze(id, reason); err != nil {
		s.log.Error("ALERT cannot persist keyset freeze", "role", s.cfg.Role, "keyset_id", id, "err", err.Error())
		return
	}
	if already {
		return
	}
	s.log.Error("ALERT keyset frozen after a cryptographic failure", "role", s.cfg.Role, "keyset_id", id, "scheme", s.schemeLog(id), "op", op,
		"job_id", job, "session_peer", except, "peer_reported", peerReported, "message", reason,
		"note", "the protocol aborts without blame: the session peer is where the failed message came in, not proven guilty")
	go s.notifyFreeze(id, reason, except)
}

// notifyFreeze tells every member this party has a link to, except `except`, that the keyset is frozen. Best effort.
func (s *Server) notifyFreeze(id, reason, except string) {
	for _, role := range []string{"A", "B", "C"} {
		if role == s.cfg.Role || role == except || s.link(role) == nil {
			continue
		}
		if err := s.sendFreezeNotice(role, id, reason); err != nil {
			s.log.Warn("freeze notice not delivered: that member learns it at its next contact", "keyset_id", id, "to", role, "error", err.Error())
		}
	}
}

func (s *Server) sendFreezeNotice(role, id, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Limits.SessionTimeout())
	defer cancel()
	var sidRaw [16]byte
	rand.Read(sidRaw[:])
	sid := hex.EncodeToString(sidRaw[:])
	stream, err := s.link(role).Session(ctx)
	if err != nil {
		return err
	}
	defer stream.CloseSend()
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	b, _ := proto.Marshal(&pb.Open{Op: pb.Op_OP_FREEZE_NOTICE, KeysetId: id, Scheme: s.keysetScheme(id), Initiator: s.cfg.Role, Reason: reason})
	if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		return err
	}
	wctx, c := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	defer c()
	fin, err := tr.waitFin(wctx)
	if err != nil {
		return err
	}
	if !fin.GetOk() {
		return peerFail("freeze-notice", fin)
	}
	return nil
}

// freezeNoticeFollow handles a FREEZE_NOTICE from a member: freeze durably and answer.
func (s *Server) freezeNoticeFollow(stream pb.Peer_SessionServer, sid string, open *pb.Open, from string, reject func(pb.ErrorKind, string) error) error {
	if from != "A" && from != "B" || open.Initiator != from || !validID(open.KeysetId) {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "freeze notice from an unexpected sender")
	}
	if st, err := s.store.State(context.Background(), open.KeysetId); err != nil || !isTScheme(st.Scheme) || st.Scheme != int32(open.Scheme) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown 2-of-3 keyset on this party")
	}
	reason := open.Reason
	if len(reason) > 512 {
		reason = reason[:512]
	}
	reason = "party " + from + " reported: " + reason
	already, _ := s.freeze.Frozen(open.KeysetId)
	if err := s.freeze.Freeze(open.KeysetId, reason); err != nil {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "cannot persist the freeze: "+err.Error())
	}
	if !already {
		s.log.Error("ALERT keyset frozen on notice from another member", "role", s.cfg.Role, "keyset_id", open.KeysetId, "from", from, "message", reason)
		// pass it on to the members this party can reach, except the sender
		go s.notifyFreeze(open.KeysetId, reason, from)
	}
	b, _ := proto.Marshal(&pb.Fin{Ok: true})
	stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_FIN, Payload: b})
	return nil
}

var _ = time.Second

// watchLink logs, per transition (not per job), that a link this party dials went down and that it came back. Operators alert on
// the log line `ALERT mpc party link down`; Health of every party shows the same (peers[].reachable). The first connection after
// start is not a transition.
func (s *Server) watchLink(ctx context.Context, conn interface {
	GetState() connectivity.State
	WaitForStateChange(context.Context, connectivity.State) bool
}, name string) {
	up := false
	state := conn.GetState()
	for {
		ready := state == connectivity.Ready
		switch {
		case ready && !up:
			if s.linkEverUp(name) {
				s.log.Info("mpc party link restored", "role", s.cfg.Role, "peer", name)
			}
			s.markLinkUp(name)
			up = true
		case !ready && up:
			s.log.Error("ALERT mpc party link down: signing continues with the other two parties", "role", s.cfg.Role, "peer", name)
			up = false
		}
		if !conn.WaitForStateChange(ctx, state) {
			return
		}
		state = conn.GetState()
	}
}

func (s *Server) linkEverUp(name string) bool {
	s.rtMu.Lock()
	defer s.rtMu.Unlock()
	return s.linksUp[s.cfg.Role+">"+name+"@"+s.cfg.Role]
}

func (s *Server) markLinkUp(name string) {
	s.rtMu.Lock()
	defer s.rtMu.Unlock()
	if s.linksUp == nil {
		s.linksUp = map[string]bool{}
	}
	s.linksUp[s.cfg.Role+">"+name+"@"+s.cfg.Role] = true
}
