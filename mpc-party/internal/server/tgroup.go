package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// Three-party operations of 2-of-3 keysets: DKG, Refresh (this file), Reconcile (treconcile.go), Unfreeze (below).
//
//	A  ---OPEN(group g)--->  B  ---OPEN(link, g)--->  C       (A also opens a stream to C with group g)
//	A  <--------ACK--------  B  <--------ACK---------  C      (C ACKs when both its streams arrived and passed its checks)
//	protocol data between every pair on their own stream; SelfTest = every pair signs
//	B, C --> A: FIN{ok, result = group public key, prepared}  (candidate generation durable)
//	A: stores its candidate, records its DECISION, FIN{commit} to B and C
//	B, C --> A: FIN{switched}      A switches, FIN{confirm}; everybody deletes the old generation
//
// Reconciliation (treconcile.go) repairs a crash at any step, as for two parties: before A's decision is durable the
// candidate is dropped on all three, after it the commit is completed on all three.

func newSID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// groupSess is A's stream to one follower.
type groupSess struct {
	role   string
	stream pb.Peer_SessionClient
	tr     *sessTransport
}

func (g *groupSess) close(wait time.Duration) {
	g.stream.CloseSend()
	select {
	case <-g.tr.done:
	case <-time.After(wait):
	}
}

// openGroup opens a stream to B and to C with the same group id and waits for both ACKs. group.link tells C to expect B's link
// stream (DKG, Refresh, Reconcile); Unfreeze needs no data between B and C.
func (s *Server) openGroup(ctx context.Context, name string, open *pb.Open, withLink bool) (map[string]*groupSess, *Fail) {
	if s.cfg.Role != "A" || s.peerClient == nil || s.peerCClient == nil {
		return nil, invalid(name, "a 2-of-3 operation needs party A with the links to B and C configured")
	}
	if withLink {
		open.Group = newSID()
	}
	open.Scheme, open.Initiator = pb.Scheme_SCHEME_ECDSA_2OF3, "A"
	out := map[string]*groupSess{}
	abort := func(why string) {
		for _, g := range out {
			g.tr.abortPeer(why)
			g.stream.CloseSend()
		}
	}
	for _, role := range []string{"B", "C"} {
		sid := newSID()
		stream, err := s.link(role).Session(ctx)
		if err != nil {
			abort("link failed")
			f := fromWrapper(name, &transportErr{err})
			f.Msg = "party " + role + " is not reachable: " + f.Msg
			f.CB = CodeLinkDown
			return nil, f
		}
		tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
		go tr.pump()
		out[role] = &groupSess{role: role, stream: stream, tr: tr}
		b, _ := proto.Marshal(open)
		if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
			abort("send failed")
			return nil, fromWrapper(name, &transportErr{err})
		}
	}
	for _, role := range []string{"B", "C"} {
		c, cancel := context.WithTimeout(ctx, 2*s.cfg.Limits.RecvTimeout())
		err := out[role].tr.waitAck(c)
		cancel()
		if err != nil {
			abort("a member did not accept the session")
			var f *Fail
			if errors.As(err, &f) {
				return nil, f
			}
			return nil, fromWrapper(name, &transportErr{err})
		}
	}
	return out, nil
}

// coordinateGroup runs DKG or Refresh of a 2-of-3 keyset as party A.
func (s *Server) coordinateGroup(ctx context.Context, name string, open *pb.Open) (res *opResult, err error) {
	id := open.KeysetId
	rt := s.rt(id)
	if holder, ok := rt.tryBusy(name); !ok {
		return nil, busyFail(name, id, holder)
	}
	defer rt.done()
	if open.Op == pb.Op_OP_REFRESH {
		if !rt.isResolved() {
			return nil, unresolvedFail(name, id)
		}
		old, g, e := s.tkey(ctx, id, 0)
		if e != nil {
			return nil, e
		}
		_ = old
		open.Generation = g
	}
	if !s.rl.allow(id) {
		return nil, limitFail(name, "rate limit of %.0f sessions/s exceeded for %q", s.cfg.Limits.SessionsPerSecKey, id)
	}
	if !s.slots.acquire() {
		return nil, limitFail(name, "too many concurrent sessions (max %d)", s.cfg.Limits.MaxPeerSessions)
	}
	defer s.slots.release()
	s.wg.Add(1)
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()

	sess, f := s.openGroup(ctx, name, open, true)
	if f != nil {
		return nil, f
	}
	defer func() {
		for _, g := range sess {
			g.close(s.cfg.Limits.RecvTimeout())
		}
	}()
	abortAll := func(f *Fail) {
		for _, g := range sess {
			if f.Kind == pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC {
				g.tr.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
			} else {
				g.tr.abortPeer(f.Msg)
			}
		}
	}
	fail := func(mine error) error {
		f := fromWrapper(name, mine)
		abortAll(f)
		wait, c2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer c2()
		for _, g := range sess { // a member may have named the real cause: the worse kind wins
			if pf := g.tr.peerFin.Load(); pf != nil {
				if cand := peerFail(name, pf); severity(cand.Kind) > severity(f.Kind) {
					f = cand
				}
			} else if fin, e := g.tr.waitFin(wait); e == nil && !fin.GetOk() {
				if cand := peerFail(name, fin); severity(cand.Kind) > severity(f.Kind) {
					f = cand
				}
			}
		}
		s.maybeFreezeT(open, f, "")
		return f
	}

	mesh := meshOf("A", map[string]*sessTransport{"B": sess["B"].tr, "C": sess["C"].tr})
	cand, pub, err := s.execGroup(ctx, open, "A", mesh)
	if err != nil {
		return nil, fail(err)
	}
	defer cand.k.Wipe()

	// Both followers report their result; every public key must be the one we computed.
	var prepared int
	for _, role := range []string{"B", "C"} {
		fc, c4 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		fin, e := sess[role].tr.waitFin(fc)
		c4()
		if e != nil {
			return nil, fail(&transportErr{e})
		}
		if !fin.GetOk() {
			abortAll(peerFail(name, fin))
			return nil, peerFail(name, fin)
		}
		if string(fin.Result) != string(pub) {
			f := failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, name, "the three parties computed different public keys")
			abortAll(f)
			return nil, f
		}
		if fin.GetPrepared() {
			prepared++
		}
	}
	if prepared != 2 {
		f := failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, name, "a member did not durably store the new generation")
		abortAll(f)
		return nil, f
	}
	if err := s.commitAT(ctx, name, open, sess, cand); err != nil {
		return nil, err
	}
	return &opResult{public: pub, compare: pub}, nil
}

// execGroup runs one member's side of DKG or Refresh over mesh, including the mandatory three-way SelfTest.
func (s *Server) execGroup(ctx context.Context, open *pb.Open, me string, mesh cbmpc.Mesh) (*candidateT, []byte, error) {
	id := open.KeysetId
	self := roleMember(me)
	var k *cbmpc.TKey
	var gen uint64
	var opn string
	switch open.Op {
	case pb.Op_OP_DKG:
		opn, gen = "dkg", 1
		var err error
		k, err = cbmpc.TDKG(ctx, mesh, self, s.keygenOpts()...)
		if err != nil {
			return nil, nil, fromWrapper("dkg", err)
		}
	case pb.Op_OP_REFRESH:
		opn = "refresh"
		old, g, err := s.tkey(ctx, id, open.Generation)
		if err != nil {
			return nil, nil, err
		}
		gen = g + 1
		k, err = old.Refresh(ctx, mesh, s.keygenOpts()...)
		if err != nil {
			return nil, nil, fromWrapper("refresh", err)
		}
	default:
		return nil, nil, invalid("session", "unknown op %v", open.Op)
	}
	// Mandatory: the three-way SelfTest proves that every pair signs with the new shares. Refresh and DKG can report
	// success on every member and still leave shares that do not sign together.
	if err := k.SelfTest(ctx, mesh, selfTestLabel(id, gen), s.opts()...); err != nil {
		k.Wipe() // the old shares stay in force
		return nil, nil, fromWrapper(opn+".selftest", err)
	}
	if fi := s.fi; fi != nil && fi.FailSelfTest != nil && fi.FailSelfTest(opn, me) {
		k.Wipe()
		return nil, nil, &cbmpc.Error{Kind: cbmpc.KindCryptographic, Op: "tecdsa.selftest", Msg: "injected self-test failure"}
	}
	failpoint("after_selftest")
	return &candidateT{id: id, gen: gen, k: k}, k.PublicKey(), nil
}

// commitAT is party A's half of the durable two-phase commit of a 2-of-3 DKG or Refresh (see the diagram at the top).
func (s *Server) commitAT(ctx context.Context, name string, open *pb.Open, sess map[string]*groupSess, c *candidateT) (err error) {
	rt := s.rt(c.id)
	roles := []string{"B", "C"}
	decided := false
	defer func() {
		if err == nil {
			return
		}
		if !decided {
			s.store.DropCandidate(context.Background(), c.id)
			for _, g := range sess {
				g.tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_INTERNAL, Message: "commit not decided"})
			}
			return
		}
		s.unresolve(c.id) // decided but not finished: reconciliation completes it
	}()
	if e := s.store.PutTCandidate(ctx, c.id, c.gen, c.k); e != nil {
		return failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, name, "cannot store the new generation: %v", e)
	}
	failpoint("a_after_candidate_stored")

	rt.gate.Lock() // from the decision until A switched, no session of this keyset runs on any member
	defer rt.gate.Unlock()
	if e := s.store.RecordDecision(ctx, c.id, c.gen); e != nil {
		return failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, name, "cannot record the commit decision: %v", e)
	}
	decided = true
	failpoint("a_after_decision")
	for _, r := range roles {
		if e := sess[r].tr.sendFin(&pb.Fin{Ok: true, Commit: true}); e != nil {
			return failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, name, "commit decided but party %s was unreachable; reconciliation will finish it: %v", r, e)
		}
	}
	for _, r := range roles {
		wctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		sw, e := sess[r].tr.waitFin(wctx)
		cancel()
		if e != nil {
			return failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, name, "commit decided but party %s did not answer; reconciliation will finish it: %v", r, e)
		}
		if !sw.GetOk() || !sw.GetSwitched() {
			return failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, name, "commit decided but party %s failed to switch (%s); reconciliation will finish it", r, sw.GetMessage())
		}
	}
	failpoint("a_after_switched_recv")
	if e := s.store.Promote(ctx, c.id, c.gen); e != nil {
		return failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, name, "cannot switch to the new generation: %v", e)
	}
	s.dropKey(c.id)
	failpoint("a_after_promote")
	for _, r := range roles {
		sess[r].tr.sendFin(&pb.Fin{Ok: true, Confirm: true}) // best effort: if lost, reconciliation confirms
	}
	s.store.DeleteGenerationsBelow(ctx, c.id, c.gen)
	failpoint("a_after_delete_old")
	rt.setResolved(true)
	s.log.Warn("keyset moved to a new generation: existing backups are STALE, export new backups", "role", "A", "scheme", "ecdsa-2of3", "keyset_id", c.id, "generation", c.gen)
	// Keep the gate until both followers took the confirmation (their handlers returning end the streams).
	for _, r := range roles {
		select {
		case <-sess[r].tr.done:
		case <-ctx.Done():
		case <-time.After(s.cfg.Limits.RecvTimeout()):
		}
	}
	return nil
}

// ---- followers (B and C) ----

// groupPrecheck is what a member checks before it takes part in a three-party DKG or Refresh. It returns a rejection or nil.
func (s *Server) groupPrecheck(ctx context.Context, open *pb.Open) (kind pb.ErrorKind, msg string, ok bool) {
	id := open.KeysetId
	if !validID(id) {
		return pb.ErrorKind_ERROR_KIND_INTERNAL, "invalid keyset id", false
	}
	switch open.Op {
	case pb.Op_OP_DKG:
		if _, err := s.admin.check("dkg", id, open.Admin); err != nil {
			return pb.ErrorKind_ERROR_KIND_REFUSED, err.Error(), false
		}
		if st, err := s.store.State(ctx, id); err == nil && st.Current != 0 {
			return pb.ErrorKind_ERROR_KIND_INTERNAL, "keyset already exists on this party", false
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return pb.ErrorKind_ERROR_KIND_INTERNAL, "keyset store error", false
		}
	case pb.Op_OP_REFRESH:
		if _, _, err := s.tkey(ctx, id, 0); err != nil {
			var f *Fail
			if errors.As(err, &f) && f.Kind == pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
				return pb.ErrorKind_ERROR_KIND_UNAVAILABLE, f.Msg, false
			}
			return pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown 2-of-3 keyset on this party", false
		}
		if !s.rt(id).isResolved() {
			return pb.ErrorKind_ERROR_KIND_UNAVAILABLE, "keyset is not reconciled with the peers yet (after a restart or restore)", false
		}
		if frozen, why := s.freeze.Frozen(id); frozen {
			return pb.ErrorKind_ERROR_KIND_FROZEN, "keyset is frozen: " + why, false
		}
		if _, err := s.admin.check("refresh", id, open.Admin); err != nil {
			return pb.ErrorKind_ERROR_KIND_REFUSED, err.Error(), false
		}
	default:
		return pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown op", false
	}
	return 0, "", true
}

// runGroupFollower is one follower's (B or C) part of a DKG or Refresh after the session is ACKed: run the protocol over the
// mesh, store the candidate, and take the two-phase commit from A over the control stream.
func (s *Server) runGroupFollower(ctx context.Context, open *pb.Open, me string, control *sessTransport, links map[string]*sessTransport, sid string, start time.Time) error {
	opName := open.Op.String()
	outcome := "ok"
	var ferr *Fail
	defer func() {
		s.log.Info("session", "role", me, "op", opName, "scheme", "ecdsa-2of3", "session", sid, "keyset_id", open.KeysetId,
			"duration_ms", time.Since(start).Milliseconds(), "outcome", outcome,
			"kind", func() string {
				if ferr != nil {
					return ferr.Kind.String()
				}
				return ""
			}())
	}()
	failOut := func(f *Fail) error {
		if pf := control.peerFin.Load(); pf != nil {
			if cand := peerFail(opName, pf); severity(cand.Kind) > severity(f.Kind) {
				f = cand
			}
		}
		ferr, outcome = f, "failed"
		s.maybeFreezeT(open, f, "A")
		control.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		for role, tr := range links {
			if tr != control {
				_ = role
				tr.abortPeer(f.Msg) // the other follower is waiting for our messages
			}
		}
		return nil
	}
	rt := s.rt(open.KeysetId)
	if holder, ok := rt.tryBusy(strings.ToLower(strings.TrimPrefix(opName, "OP_"))); !ok {
		return failOut(busyFail(opName, open.KeysetId, holder))
	}
	defer rt.done()

	mesh := meshOf(me, links)
	cand, pub, err := s.execGroup(ctx, open, me, mesh)
	if err != nil {
		return failOut(fromWrapper(opName, err))
	}
	defer cand.k.Wipe()
	// Phase 1: the candidate generation is durable BEFORE this member says it is prepared.
	if err := s.store.PutTCandidate(ctx, cand.id, cand.gen, cand.k); err != nil {
		return failOut(failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, opName, "%s cannot store the new generation: %v", me, err))
	}
	failpoint(strings.ToLower(me) + "_after_candidate_stored")
	if err := control.sendFin(&pb.Fin{Ok: true, Result: pub, Prepared: true}); err != nil {
		s.store.DropCandidate(context.Background(), cand.id)
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	wctx, c2 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	afin, err := control.waitFin(wctx)
	c2()
	if err != nil {
		// A candidate stays on disk if A may have decided: reconciliation settles it.
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	if !afin.GetOk() {
		s.store.DropCandidate(context.Background(), cand.id)
		outcome = "peer-rejected"
		ferr = peerFail(opName, afin)
		s.maybeFreezeT(open, ferr, "A")
		return nil
	}
	if !afin.GetCommit() {
		return nil
	}
	failpoint(strings.ToLower(me) + "_after_commit_received")
	rt.setResolved(false) // until A confirmed that all three are on the new generation
	rt.gate.Lock()
	perr := s.store.Promote(ctx, cand.id, cand.gen)
	s.dropKey(cand.id)
	rt.gate.Unlock()
	if perr != nil {
		return failOut(failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, opName, "%s cannot switch to the new generation: %v", me, perr))
	}
	failpoint(strings.ToLower(me) + "_after_promote")
	if err := control.sendFin(&pb.Fin{Ok: true, Switched: true}); err != nil {
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	cctx, c3 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	cfin, err := control.waitFin(cctx)
	c3()
	if err != nil || !cfin.GetOk() || !cfin.GetConfirm() {
		outcome = "switched-unconfirmed" // stay unresolved; A's reconciliation confirms (or finishes) it
		return nil
	}
	failpoint(strings.ToLower(me) + "_after_confirm_recv")
	s.store.DeleteGenerationsBelow(ctx, cand.id, cand.gen)
	rt.setResolved(true)
	s.log.Warn("keyset moved to a new generation: existing backups are STALE, export new backups", "role", me, "scheme", "ecdsa-2of3", "keyset_id", cand.id, "generation", cand.gen)
	return nil
}

// ---- Unfreeze ----

// unfreezeGroup (party A): every member verifies the operator signature itself and must be reachable; nothing is lifted
// unless all three accepted.
func (s *Server) unfreezeGroup(ctx context.Context, keysetID string, admin *pb.AdminAuth) error {
	const name = "unfreeze"
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()
	open := &pb.Open{Op: pb.Op_OP_UNFREEZE, KeysetId: keysetID, Admin: admin}
	sess, f := s.openGroup(ctx, name, open, false)
	if f != nil {
		return f // includes "party X is not reachable": nothing was lifted anywhere
	}
	defer func() {
		for _, g := range sess {
			g.close(s.cfg.Limits.RecvTimeout())
		}
	}()
	// Both ACKed: both verified the signature and are ready. Now commit on both, then on A.
	for _, g := range sess {
		if err := g.tr.sendFin(&pb.Fin{Ok: true, Commit: true}); err != nil {
			return fromWrapper(name, &transportErr{err})
		}
	}
	for _, g := range sess {
		c, cc := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		fin, err := g.tr.waitFin(c)
		cc()
		if err != nil {
			return fromWrapper(name, &transportErr{err})
		}
		if !fin.GetOk() {
			return peerFail(name, fin)
		}
	}
	return nil
}

// unfreezeFollow is a member's side: verify the signature, ACK, lift on A's commit.
func (s *Server) unfreezeFollow(ctx context.Context, stream pb.Peer_SessionServer, sid string, open *pb.Open, from string, reject func(pb.ErrorKind, string) error) error {
	if from != "A" || open.Initiator != "A" || !validID(open.KeysetId) {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "unfreeze only from party A")
	}
	if st, err := s.store.State(ctx, open.KeysetId); err != nil || st.Scheme != int32(pb.Scheme_SCHEME_ECDSA_2OF3) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown 2-of-3 keyset on this party")
	}
	key, err := s.admin.check("unfreeze", open.KeysetId, open.Admin)
	if err != nil {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, err.Error())
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	if err := tr.sendFrame(pb.FrameKind_FRAME_KIND_ACK, nil); err != nil {
		return nil
	}
	go tr.pump()
	wctx, c := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	fin, err := tr.waitFin(wctx)
	c()
	if err != nil || !fin.GetOk() || !fin.GetCommit() {
		s.log.Warn("unfreeze not committed by party A: nothing lifted", "role", s.cfg.Role, "keyset_id", open.KeysetId)
		return nil
	}
	if err := s.freeze.Unfreeze(open.KeysetId); err != nil {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_INTERNAL, Message: "cannot unfreeze: " + err.Error()})
		return nil
	}
	s.log.Warn("AUDIT keyset unfrozen", "role", s.cfg.Role, "scheme", "ecdsa-2of3", "keyset_id", open.KeysetId, "admin_key", key, "session", sid)
	tr.sendFin(&pb.Fin{Ok: true})
	return nil
}
