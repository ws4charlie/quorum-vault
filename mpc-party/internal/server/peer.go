package server

import (
	"context"
	"errors"
	"regexp"
	"strings"
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
	var rejectCode func(kind pb.ErrorKind, code uint32, msg string) error
	reject := func(kind pb.ErrorKind, msg string) error { return rejectCode(kind, 0, msg) }
	rejectCode = func(kind pb.ErrorKind, code uint32, msg string) error {
		b, _ := proto.Marshal(&pb.Fin{Ok: false, Kind: kind, Code: code, Message: msg})
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

	// Pre-checks that decide whether anything may start. B trusts nothing A says: admin operations need an operator
	// signature that B verifies against its own keys, a frozen keyset refuses work, and a Sign must name the key it will
	// use.
	switch open.Op {
	case pb.Op_OP_DKG:
		if !validID(open.KeysetId) {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "invalid keyset id")
		}
		if _, err := s.admin.check("dkg", open.KeysetId, open.Admin); err != nil {
			return reject(pb.ErrorKind_ERROR_KIND_REFUSED, err.Error())
		}
		if st, err := s.store.State(ctx, open.KeysetId); err == nil && st.Current != 0 {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "keyset already exists on B")
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "keyset store error")
		}
	case pb.Op_OP_RECONCILE:
		if !validID(open.KeysetId) {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "invalid keyset id")
		}
		return s.reconcileB(ctx, stream, sid, &open, reject)
	case pb.Op_OP_REFRESH, pb.Op_OP_NODE, pb.Op_OP_DERIVE, pb.Op_OP_SIGN, pb.Op_OP_UNFREEZE:
		if !validID(open.KeysetId) {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "invalid keyset id")
		}
		if _, _, err := s.keyset(ctx, open.KeysetId, 0); err != nil {
			var f *Fail
			if errors.As(err, &f) && f.Kind == pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
				return reject(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, f.Msg)
			}
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown keyset on B")
		}
		if open.Op != pb.Op_OP_UNFREEZE && !s.rt(open.KeysetId).isResolved() {
			return rejectCode(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, CodeUnresolved, "keyset is not reconciled with the peer yet (after a restart or restore)")
		}
		frozen, why := s.freeze.Frozen(open.KeysetId)
		switch open.Op {
		case pb.Op_OP_REFRESH:
			if _, err := s.admin.check("refresh", open.KeysetId, open.Admin); err != nil {
				return reject(pb.ErrorKind_ERROR_KIND_REFUSED, err.Error())
			}
			if frozen {
				return reject(pb.ErrorKind_ERROR_KIND_FROZEN, "keyset is frozen: "+why)
			}
		case pb.Op_OP_DERIVE, pb.Op_OP_SIGN:
			if frozen {
				return reject(pb.ErrorKind_ERROR_KIND_FROZEN, "keyset is frozen: "+why)
			}
		case pb.Op_OP_UNFREEZE:
			key, err := s.admin.check("unfreeze", open.KeysetId, open.Admin)
			if err != nil {
				return reject(pb.ErrorKind_ERROR_KIND_REFUSED, err.Error())
			}
			if err := s.freeze.Unfreeze(open.KeysetId); err != nil {
				return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "cannot unfreeze: "+err.Error())
			}
			s.log.Warn("AUDIT keyset unfrozen", "role", "B", "keyset_id", open.KeysetId, "admin_key", key, "session", sid)
			b, _ := proto.Marshal(&pb.Fin{Ok: true})
			stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_FIN, Payload: b})
			return nil
		}
	default:
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown op")
	}
	if open.Op == pb.Op_OP_SIGN {
		if len(open.ExpectedPublicKey) == 0 {
			return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "sign without an expected public key: B cannot tell which key it would sign with")
		}
		// B re-verifies what it is asked to sign BEFORE it joins the protocol: without this, compromising A alone would
		// be enough to make B sign anything.
		if err := s.authz.Authorize(ctx, AuthRequest{Role: "B", JobID: open.JobId, KeyID: open.KeyId, KeysetID: open.KeysetId,
			Algorithm: open.Algorithm, Digest: open.Digest, IntentPackage: open.IntentPackage, PublicKey: open.ExpectedPublicKey}); err != nil {
			var ue *UnavailableError
			if errors.As(err, &ue) {
				return reject(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, "authorizer on B unavailable: "+err.Error())
			}
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
		if pf := tr.peerFin.Load(); pf != nil { // the peer named a cause: the worse kind wins
			if cand := peerFail(opName, pf); severity(cand.Kind) > severity(f.Kind) {
				f = cand
			}
		}
		ferr = f
		outcome = "failed"
		s.maybeFreeze(&open, f)
		tr.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		return nil
	}

	// Sessions that use the keyset hold the gate shared, so a generation switch never happens under them.
	var rt *ksRT
	if open.KeysetId != "" {
		rt = s.rt(open.KeysetId)
		switch open.Op {
		case pb.Op_OP_DKG, pb.Op_OP_REFRESH:
			if holder, ok := rt.tryBusy(strings.ToLower(strings.TrimPrefix(opName, "OP_"))); !ok {
				return failOut(busyFail(opName, open.KeysetId, holder))
			}
			defer rt.done()
		default:
			rt.gate.RLock()
			defer rt.gate.RUnlock()
		}
	}

	res, err := s.execOp(ctx, &open, tr)
	if err != nil {
		return failOut(fromWrapper(opName, err))
	}
	if res.cleanup != nil {
		defer res.cleanup()
	}
	if res.cand != nil {
		// Phase 1 on B: the candidate generation is durable BEFORE B says it is prepared.
		if err := s.store.PutCandidate(ctx, res.cand.id, res.cand.gen, res.cand.ks); err != nil {
			return failOut(failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, opName, "B cannot store the new generation: %v", err))
		}
		failpoint("b_after_candidate_stored")
	}
	if err := tr.sendFin(&pb.Fin{Ok: true, Result: res.compare, Prepared: res.cand != nil}); err != nil {
		if res.cand != nil {
			s.store.DropCandidate(context.Background(), res.cand.id)
		}
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	// A decides. Wait for its FIN within the receive timeout (A answers right after comparing).
	wctx, c2 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	afin, err := tr.waitFin(wctx)
	c2()
	if err != nil {
		// A candidate stays on disk if A may have decided: reconciliation (A's decision is durable before it asks us to
		// commit) settles it. Without a decision A drops its side and tells us to drop ours.
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	if !afin.GetOk() {
		if res.cand != nil {
			s.store.DropCandidate(context.Background(), res.cand.id)
		}
		outcome = "peer-rejected"
		ferr = peerFail(opName, afin)
		s.maybeFreeze(&open, ferr)
		return nil
	}
	if afin.GetCommit() {
		if res.cand == nil {
			return failOut(failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, opName, "A asked to commit an operation that has nothing to commit"))
		}
		failpoint("b_after_commit_received")
		// Phase 2 on B: switch. B's own sessions on this keyset are none (only A starts them, and A holds its gate); Lock
		// waits for any that is still finishing.
		rt.setResolved(false) // until A confirmed that both are on the new generation
		rt.gate.Lock()
		perr := s.store.Promote(ctx, res.cand.id, res.cand.gen)
		s.cache.drop(res.cand.id)
		rt.gate.Unlock()
		if perr != nil {
			return failOut(failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, opName, "B cannot switch to the new generation: %v", perr))
		}
		failpoint("b_after_promote")
		if err := tr.sendFin(&pb.Fin{Ok: true, Switched: true}); err != nil {
			return failOut(fromWrapper(opName, &transportErr{err}))
		}
		cctx, c3 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		cfin, err := tr.waitFin(cctx)
		c3()
		if err != nil || !cfin.GetOk() || !cfin.GetConfirm() {
			// A's confirmation is missing: stay unresolved; A's reconciliation confirms (or finishes) it.
			outcome = "switched-unconfirmed"
			return nil
		}
		failpoint("b_after_confirm_recv")
		s.store.DeleteGenerationsBelow(ctx, res.cand.id, res.cand.gen)
		rt.setResolved(true)
		s.log.Warn("keyset moved to a new generation: existing backups are STALE, export new backups", "role", "B", "keyset_id", res.cand.id, "generation", res.cand.gen)
	}
	return nil
}

// maybeFreeze freezes the keyset after a cryptographic failure (either party's finding). Durable; unfreezing needs an
// operator signature. DKG has no keyset yet.
func (s *Server) maybeFreeze(open *pb.Open, f *Fail) {
	if f == nil || f.Kind != pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC || open.KeysetId == "" || open.Op == pb.Op_OP_DKG {
		return
	}
	if err := s.freeze.Freeze(open.KeysetId, f.Msg); err != nil {
		s.log.Error("ALERT cannot persist keyset freeze", "role", s.cfg.Role, "keyset_id", open.KeysetId, "err", err.Error())
		return
	}
	s.log.Error("ALERT keyset frozen after a cryptographic failure", "role", s.cfg.Role, "keyset_id", open.KeysetId, "op", open.Op.String(),
		"job_id", open.JobId, "peer_reported", f.Peer, "message", f.Msg)
}
