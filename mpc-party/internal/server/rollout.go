package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Changes of the admin set and of the recovery-key registry reach every member through party A, which is only the courier: each member verifies the
// signatures against its OWN state and applies the change itself, so a compromised A can delay a change but cannot forge one. The answer lists what
// every member did (applied now, already had it, refused and why, unreachable); a member that did not take it stays on its old state, which Health
// shows, and the same change sent again finishes it (a member that already has it answers "already", without a signature check).
//
//	A:  apply locally   ->   OPEN(op) to B   ->   OPEN(op) to C        (one stream each, one FIN back: no protocol data)
//	B, C: verify against their own state, apply, FIN{ok, result = RecordMember}

// AdminSet changes the admin set (party A). See adminset.go.
func (s *Server) AdminSet(ctx context.Context, r *pb.AdminSetRequest) (_ *pb.AdminSetResponse, err error) {
	start := time.Now()
	defer func() {
		s.logOp("admin-set", start, err, "version", r.GetSetVersion())
		err = toStatus("admin-set", err)
	}()
	ms, err := s.rollRecord(ctx, admin.OpAdminSet, admin.OpenOf(r))
	if err != nil {
		return nil, err
	}
	return &pb.AdminSetResponse{Members: ms}, nil
}

// RecoveryKey changes the recovery-key registry (party A). See recoveryreg.go.
func (s *Server) RecoveryKey(ctx context.Context, r *pb.RecoveryKeyRequest) (_ *pb.RecoveryKeyResponse, err error) {
	start := time.Now()
	defer func() {
		s.logOp("recovery-key", start, err, "version", r.GetRkVersion())
		err = toStatus("recovery-key", err)
	}()
	ms, err := s.rollRecord(ctx, admin.OpRecoveryKey, admin.OpenOf(r))
	if err != nil {
		return nil, err
	}
	return &pb.RecoveryKeyResponse{Members: ms}, nil
}

// applyRecord applies a change of the named record on this party (the body is rebuilt from the Open, as a follower does for every admin operation).
func (s *Server) applyRecord(name string, open *pb.Open) (pb.RecordOutcome, uint64, []byte, error) {
	body, err := admin.BodyFromOpen(name, open)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: %v", errAdmin, err)
	}
	switch x := body.(type) {
	case *pb.AdminSetRequest:
		out, sn, err := s.admin.applySet(x, open.Admin)
		return out, sn.version, sn.hash[:], err
	case *pb.RecoveryKeyRequest:
		out, reg, err := s.recovery.apply(x, func() ([][]byte, error) { return s.admin.authorizeRecord(name, x, open.Admin) }, s.log)
		h := reg.Hash()
		return out, reg.Version, h[:], err
	}
	return 0, 0, nil, fmt.Errorf("%w: %s is not a versioned record", errAdmin, name)
}

func (s *Server) rollRecord(ctx context.Context, name string, open *pb.Open) ([]*pb.RecordMember, error) {
	if s.cfg.Role != "A" {
		return nil, invalid(name, "only party A takes this request")
	}
	if err := s.sealerReady(); err != nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, name, "%v", err)
	}
	if !s.slots.acquire() {
		return nil, limitFail(name, "too many concurrent sessions (max %d)", s.cfg.Limits.MaxPeerSessions)
	}
	defer s.slots.release()
	s.wg.Add(1)
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()
	out, ver, hash, aerr := s.applyRecord(name, open)
	me := &pb.RecordMember{Name: "A", Outcome: out, Version: ver, Hash: hash}
	if aerr != nil {
		me.Outcome, me.Detail = pb.RecordOutcome_RECORD_OUTCOME_REFUSED, aerr.Error()
		s.log.Warn("admin record change refused", "role", "A", "op", name, "err", aerr.Error())
	}
	members := []*pb.RecordMember{me}
	// A refusal about the version (stale, a gap, another predecessor) says nothing against the request itself: it may be right for a member that is
	// behind, so it goes on. Any other refusal is the request's own fault, and the members are not bothered with it.
	forward := aerr == nil || errors.Is(aerr, errSetStep)
	for _, role := range []string{"B", "C"} {
		if s.link(role) == nil {
			continue
		}
		if !forward {
			members = append(members, &pb.RecordMember{Name: role, Outcome: pb.RecordOutcome_RECORD_OUTCOME_REFUSED, Detail: "not sent: party A refused the request itself (" + me.Detail + ")"})
			continue
		}
		members = append(members, s.forwardRecord(ctx, role, name, open))
	}
	return members, nil
}

// forwardRecord sends the change to one member and reads its answer.
func (s *Server) forwardRecord(ctx context.Context, role, name string, open *pb.Open) *pb.RecordMember {
	m := &pb.RecordMember{Name: role}
	unreachable := func(err error) *pb.RecordMember {
		m.Outcome, m.Detail = pb.RecordOutcome_RECORD_OUTCOME_UNREACHABLE, err.Error()
		return m
	}
	sid := newSID()
	stream, err := s.link(role).Session(ctx)
	if err != nil {
		return unreachable(err)
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	defer stream.CloseSend()
	open.Initiator = "A"
	b, _ := proto.Marshal(open)
	if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		return unreachable(err)
	}
	wctx, c := context.WithTimeout(ctx, 2*s.cfg.Limits.RecvTimeout())
	defer c()
	fin, err := tr.waitFin(wctx)
	if err != nil {
		return unreachable(err)
	}
	var res pb.RecordMember
	if len(fin.Result) > 0 {
		_ = proto.Unmarshal(fin.Result, &res)
	}
	if !fin.GetOk() {
		m.Outcome, m.Detail = pb.RecordOutcome_RECORD_OUTCOME_REFUSED, fin.GetMessage()
		if fin.GetKind() == pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
			m.Outcome = pb.RecordOutcome_RECORD_OUTCOME_UNREACHABLE
		}
		m.Version, m.Hash = res.Version, res.Hash
		return m
	}
	m.Outcome, m.Version, m.Hash = res.Outcome, res.Version, res.Hash
	return m
}

// followRecord is a member's side: verify against its own state, apply, answer. It runs for B and for C.
func (s *Server) followRecord(stream pb.Peer_SessionServer, sid string, open *pb.Open, reject func(pb.ErrorKind, string) error) error {
	name := admin.OpAdminSet
	if open.Op == pb.Op_OP_RECOVERY_KEY {
		name = admin.OpRecoveryKey
	}
	out, ver, hash, err := s.applyRecord(name, open)
	if err != nil {
		s.log.Warn("admin record change refused", "role", s.cfg.Role, "op", name, "session", sid, "err", err.Error())
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, err.Error())
	}
	res, _ := proto.Marshal(&pb.RecordMember{Name: s.cfg.Role, Outcome: out, Version: ver, Hash: hash})
	b, _ := proto.Marshal(&pb.Fin{Ok: true, Result: res})
	stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_FIN, Payload: b})
	return nil
}
