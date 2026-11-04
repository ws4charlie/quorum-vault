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
	defer func() {
		var f *Fail
		if err != nil && errors.As(err, &f) {
			s.maybeFreeze(open, f)
			if f.Peer && (f.CB == CodeUnresolved || f.CB == CodeGenMismatch) && open.KeysetId != "" && open.Op != pb.Op_OP_DKG {
				s.unresolve(open.KeysetId) // the peer restarted or is on another generation: reconcile before more work
			}
		}
	}()
	if s.peerClient == nil {
		return nil, invalid(name, "this party has no peer connection")
	}
	// Per-keyset gating: refuse work on a keyset that has not been reconciled since the restart; one DKG/Refresh at a time;
	// sessions that use the keyset hold the gate shared so that the commit window of a refresh runs alone.
	var rt *ksRT
	if open.KeysetId != "" {
		rt = s.rt(open.KeysetId)
		switch open.Op {
		case pb.Op_OP_DKG, pb.Op_OP_REFRESH:
			if holder, ok := rt.tryBusy(name); !ok {
				return nil, busyFail(name, open.KeysetId, holder)
			}
			defer rt.done()
			if open.Op == pb.Op_OP_REFRESH && !rt.isResolved() {
				return nil, unresolvedFail(name, open.KeysetId)
			}
		default:
			if !rt.isResolved() {
				return nil, unresolvedFail(name, open.KeysetId)
			}
		}
		if open.Op != pb.Op_OP_DKG {
			if open.Op != pb.Op_OP_REFRESH {
				rt.gate.RLock()
				defer rt.gate.RUnlock()
			}
			_, g, err := s.keyset(ctx, open.KeysetId, 0)
			if err != nil {
				return nil, err
			}
			open.Generation = g
		}
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
	// Hold our slot until B has finished with the session too (its handler returning ends the stream). Otherwise A could
	// start a new session while B still counts the old one, and B would refuse it as over the limit.
	defer func() {
		select {
		case <-tr.done:
		case <-time.After(s.cfg.Limits.RecvTimeout()):
		}
	}()

	fail := func(mine error) error {
		f := fromWrapper(name, mine)
		if f.Kind == pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC {
			// Tell B in a FIN, not just an abort, so that B freezes its side too.
			tr.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		} else {
			tr.abortPeer(f.Msg)
		}
		// The peer may have named the real cause (e.g. it detected tampering first): the worse kind wins.
		wait, c2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer c2()
		if pf := tr.peerFin.Load(); pf != nil {
			if cand := peerFail(name, pf); severity(cand.Kind) > severity(f.Kind) {
				return cand
			}
		} else if fin, err := tr.waitFin(wait); err == nil && !fin.GetOk() {
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
	if res.cand == nil {
		if err := tr.sendFin(&pb.Fin{Ok: true}); err != nil {
			return nil, fromWrapper(name, &transportErr{err})
		}
		return res, nil
	}
	if err := s.commitA(ctx, name, open, tr, bfin, res.cand, rt); err != nil {
		return nil, err
	}
	return res, nil
}

// commitA is party A's half of the durable two-phase commit of a DKG or Refresh (B's half is in peer.go).
//
//	B stored the candidate (prepared)        A stores the candidate
//	A records its DECISION durably           A tells B to commit
//	B switches, tells A (switched)           A switches, tells B (confirm)
//	both delete the old generation
//
// A crash anywhere is repaired by reconciliation (reconcile.go): before A's decision is durable the candidate is dropped,
// after it the commit is completed. Old shares exist until both parties confirmed.
func (s *Server) commitA(ctx context.Context, name string, open *pb.Open, tr *sessTransport, bfin *pb.Fin, c *candidate, rt *ksRT) (err error) {
	if !bfin.GetPrepared() {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "peer did not store the candidate"})
		return failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, name, "party B did not durably store the new generation")
	}
	decided := false
	defer func() {
		if err == nil {
			return
		}
		if !decided {
			s.store.DropCandidate(context.Background(), c.id) // nothing was decided: forget the candidate
			return
		}
		// A decided to commit but could not finish: the outcome is settled by reconciliation, not by this call.
		s.unresolve(c.id)
	}()
	if e := s.store.PutCandidate(ctx, c.id, c.gen, c.ks); e != nil {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_INTERNAL, Message: "A could not store the candidate"})
		return failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, name, "cannot store the new generation: %v", e)
	}
	failpoint("a_after_candidate_stored")

	rt.gate.Lock() // from the decision until A switched, no session of this keyset runs on either party
	defer rt.gate.Unlock()
	if e := s.store.RecordDecision(ctx, c.id, c.gen); e != nil {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_INTERNAL, Message: "A could not record its decision"})
		return failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, name, "cannot record the commit decision: %v", e)
	}
	decided = true
	failpoint("a_after_decision")
	if e := tr.sendFin(&pb.Fin{Ok: true, Commit: true}); e != nil {
		return failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, name, "commit decided but party B was unreachable; reconciliation will finish it: %v", e)
	}
	wctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	sw, e := tr.waitFin(wctx)
	cancel()
	if e != nil {
		return failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, name, "commit decided but party B did not answer; reconciliation will finish it: %v", e)
	}
	if !sw.GetOk() || !sw.GetSwitched() {
		return failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, name, "commit decided but party B failed to switch (%s); reconciliation will finish it", sw.GetMessage())
	}
	failpoint("a_after_switched_recv")
	if e := s.store.Promote(ctx, c.id, c.gen); e != nil {
		return failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, name, "cannot switch to the new generation: %v", e)
	}
	s.cache.drop(c.id)
	failpoint("a_after_promote")
	tr.sendFin(&pb.Fin{Ok: true, Confirm: true}) // best effort: if lost, reconciliation confirms
	s.store.DeleteGenerationsBelow(ctx, c.id, c.gen)
	failpoint("a_after_delete_old")
	s.rt(c.id).setResolved(true)
	s.log.Warn("keyset moved to a new generation: existing backups are STALE, export new backups", "role", "A", "keyset_id", c.id, "generation", c.gen)
	return nil
}

// transportErr marks an error that is a plain link failure.
type transportErr struct{ error }

func (t *transportErr) Unwrap() error { return t.error }

var _ = grpc.WaitForReady

// unfreeze asks B to lift the freeze (B verifies the operator signature itself), then lifts ours.
func (s *Server) unfreezeSession(ctx context.Context, keysetID string, admin *pb.AdminAuth) error {
	if s.peerClient == nil {
		return invalid("unfreeze", "this party has no peer connection")
	}
	var sidRaw [16]byte
	if _, err := rand.Read(sidRaw[:]); err != nil {
		return err
	}
	sid := hex.EncodeToString(sidRaw[:])
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()
	stream, err := s.peerClient.Session(ctx)
	if err != nil {
		return fromWrapper("unfreeze", &transportErr{err})
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	defer stream.CloseSend()
	b, _ := proto.Marshal(&pb.Open{Op: pb.Op_OP_UNFREEZE, KeysetId: keysetID, Admin: admin})
	if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		return fromWrapper("unfreeze", &transportErr{err})
	}
	wctx, c := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	defer c()
	fin, err := tr.waitFin(wctx)
	if err != nil {
		var f *Fail
		if errors.As(err, &f) {
			return f
		}
		return fromWrapper("unfreeze", &transportErr{err})
	}
	if !fin.GetOk() {
		return peerFail("unfreeze", fin)
	}
	return nil
}
