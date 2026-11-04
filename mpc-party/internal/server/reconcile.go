package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Reconciliation brings the two parties to ONE generation that works, after a restart, a crash during a refresh, or a
// restore. Party A drives it; both parties hold their keyset gate exclusively, so no session runs meanwhile. Until it has
// succeeded for a keyset, that keyset answers UNAVAILABLE on both parties.
//
// Rules (a = party A's durable state, b = party B's):
//   - A recorded a commit decision for generation g: finish the commit. g is the target: A and B each make g current if it
//     is still their candidate. (A's decision is durable before B is ever told to commit, and B stores the candidate
//     before A decides, so both have g.)
//   - no decision: nothing was committed anywhere. The target is the current generation; both drop any candidate. (B only
//     switches on A's commit message, which follows A's durable decision.) If the two current generations differ, one
//     party is on an older generation than the other (a stale restore): refuse, say which one.
//   - an aborted DKG (no current generation anywhere): both remove the keyset.
// Then both run SelfTest on the target generation. Only after it passed are older generations deleted.

// peerKS is a party's state as reported to the reconciler.
type peerKS struct {
	Exists    bool   `json:"exists"`
	Current   uint64 `json:"current"`
	Candidate uint64 `json:"candidate"`
}

// plan is party A's decision, sent to B.
type plan struct {
	Target   uint64 `json:"target"` // generation both must end on; 0 = the keyset must not exist
	PromoteA bool   `json:"promote_a"`
	PromoteB bool   `json:"promote_b"`
	DropA    bool   `json:"drop_a"`
	DropB    bool   `json:"drop_b"`
	Err      string `json:"err,omitempty"`
}

func stateOf(st KeysetState, ex bool) peerKS {
	if !ex {
		return peerKS{}
	}
	return peerKS{Exists: true, Current: st.Current, Candidate: st.Candidate}
}

// planReconcile decides, from A's full state and B's report, how to converge. It is pure so that every case is unit-tested.
func planReconcile(a KeysetState, aEx bool, b peerKS) plan {
	switch {
	case !aEx && !b.Exists:
		return plan{}
	case !aEx && b.Exists:
		if b.Current == 0 { // B holds only a DKG candidate that A never stored
			return plan{DropB: true}
		}
		return plan{Err: fmt.Sprintf("party A has no state for this keyset but party B is on generation %d: restore party A from a backup of generation %d or newer", b.Current, b.Current)}
	case aEx && !b.Exists:
		if a.Current == 0 { // A holds only a DKG candidate
			return plan{DropA: true}
		}
		return plan{Err: fmt.Sprintf("party B has no state for this keyset but party A is on generation %d: restore party B from a backup of generation %d", a.Current, a.Current)}
	}
	if a.Decision != 0 {
		g := a.Decision
		p := plan{Target: g}
		switch {
		case a.Candidate == g:
			p.PromoteA = true
		case a.Current == g:
		default:
			return plan{Err: fmt.Sprintf("party A decided generation %d but holds neither it as candidate nor as current (current %d, candidate %d)", g, a.Current, a.Candidate)}
		}
		switch {
		case b.Current == g:
		case b.Candidate == g:
			p.PromoteB = true
		default:
			return plan{Err: fmt.Sprintf("party A decided generation %d but party B holds neither it as candidate nor as current (current %d, candidate %d): restore party B from a backup of generation %d or %d", g, b.Current, b.Candidate, g-1, g)}
		}
		return p
	}
	// no decision: nothing committed anywhere
	switch {
	case b.Current > a.Current:
		return plan{Err: fmt.Sprintf("party A is on generation %d but party B is on %d: party A's state is older (a stale restore?): restore party A from a backup of generation %d", a.Current, b.Current, b.Current)}
	case b.Current < a.Current:
		return plan{Err: fmt.Sprintf("party B is on generation %d but party A is on %d: party B's state is older (a stale restore?): restore party B from a backup of generation %d", b.Current, a.Current, a.Current)}
	}
	p := plan{Target: a.Current, DropA: a.Candidate != 0, DropB: b.Candidate != 0}
	return p
}

func (s *Server) applyPlanA(ctx context.Context, id string, p plan, isA bool) error {
	promote, drop := p.PromoteA, p.DropA
	if !isA {
		promote, drop = p.PromoteB, p.DropB
	}
	switch {
	case p.Target == 0:
		return s.store.RemoveKeyset(ctx, id)
	case promote:
		if err := s.store.Promote(ctx, id, p.Target); err != nil {
			return err
		}
	case drop:
		if err := s.store.DropCandidate(ctx, id); err != nil {
			return err
		}
	}
	s.cache.drop(id)
	return nil
}

// reconcileA runs one reconciliation of keyset id with party B. It returns nil when the keyset is resolved.
func (s *Server) reconcileA(ctx context.Context, id string) (err error) {
	rt := s.rt(id)
	if holder, ok := rt.tryBusy("reconcile"); !ok {
		return fmt.Errorf("a %s of this keyset is running", holder)
	}
	defer rt.done()
	rt.gate.Lock()
	defer rt.gate.Unlock()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()

	var sidRaw [16]byte
	randRead(sidRaw[:])
	sid := fmt.Sprintf("%x", sidRaw)
	stream, err := s.peerClient.Session(ctx)
	if err != nil {
		return err
	}
	defer stream.CloseSend()
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	b, _ := proto.Marshal(&pb.Open{Op: pb.Op_OP_RECONCILE, KeysetId: id})
	if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		return err
	}
	step := func() (*pb.Fin, error) {
		c, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		defer cancel()
		f, err := tr.waitFin(c)
		if err != nil {
			return nil, err
		}
		if !f.GetOk() {
			return nil, peerFail("reconcile", f)
		}
		return f, nil
	}
	ackCtx, c0 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	if err := tr.waitAck(ackCtx); err != nil {
		c0()
		return err
	}
	c0()
	f1, err := step()
	if err != nil {
		return err
	}
	var bs peerKS
	if err := json.Unmarshal(f1.Result, &bs); err != nil {
		return fmt.Errorf("bad state from party B: %w", err)
	}
	as, aerr := s.store.State(ctx, id)
	aEx := aerr == nil
	if aerr != nil && !errors.Is(aerr, ErrNotFound) {
		return aerr
	}
	p := planReconcile(as, aEx, bs)
	pb64, _ := json.Marshal(p)
	if p.Err != "" {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_INTERNAL, Message: p.Err})
		s.log.Error("ALERT keyset cannot be reconciled with the peer: operator action needed", "role", "A", "keyset_id", id, "reason", p.Err)
		return errors.New(p.Err)
	}
	if err := tr.sendFin(&pb.Fin{Ok: true, Result: pb64}); err != nil {
		return err
	}
	if _, err := step(); err != nil { // B applied its part
		return err
	}
	if aEx {
		if err := s.applyPlanA(ctx, id, p, true); err != nil {
			return err
		}
	}
	if p.Target == 0 {
		s.log.Warn("reconciled: an unfinished DKG was aborted on both parties", "role", "A", "keyset_id", id)
		rt.setResolved(true)
		return nil
	}
	ks, _, err := s.keyset(ctx, id, p.Target)
	if err != nil {
		return err
	}
	pub, err := ks.SelfTest(ctx, tr, s.opts()...)
	if err != nil {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "self-test after reconciliation failed"})
		s.log.Error("ALERT self-test after reconciliation failed", "role", "A", "keyset_id", id, "generation", p.Target, "error", err.Error())
		return err
	}
	f3, err := step()
	if err != nil {
		return err
	}
	if string(f3.Result) != string(pub) {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "self-test results differ"})
		return errors.New("self-test results differ after reconciliation")
	}
	failpoint("reconcile_a_before_confirm")
	tr.sendFin(&pb.Fin{Ok: true, Confirm: true})
	// Wait for B to finish (its handler returning ends the stream) before this call returns and cancels the stream: B must
	// have read the confirmation.
	select {
	case <-tr.done:
	case <-time.After(s.cfg.Limits.RecvTimeout()):
	}
	s.store.DeleteGenerationsBelow(ctx, id, p.Target)
	rt.setResolved(true)
	s.log.Info("keyset reconciled and proven", "role", "A", "keyset_id", id, "generation", p.Target)
	return nil
}

// reconcileB is the follower side. open arrived on a fresh peer stream.
func (s *Server) reconcileB(ctx context.Context, stream pb.Peer_SessionServer, sid string, open *pb.Open, reject func(pb.ErrorKind, string) error) error {
	id := open.KeysetId
	rt := s.rt(id)
	if holder, ok := rt.tryBusy("reconcile"); !ok {
		return reject(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, "a "+holder+" of this keyset is running")
	}
	defer rt.done()
	rt.gate.Lock()
	defer rt.gate.Unlock()

	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	if err := tr.sendFrame(pb.FrameKind_FRAME_KIND_ACK, nil); err != nil {
		return nil
	}
	go tr.pump()
	bail := func(f *Fail) error {
		tr.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		s.log.Warn("reconciliation failed on B", "keyset_id", id, "error", f.Error())
		return nil
	}
	st, err := s.store.State(ctx, id)
	ex := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return bail(fromWrapper("reconcile", err))
	}
	rb, _ := json.Marshal(stateOf(st, ex))
	if err := tr.sendFin(&pb.Fin{Ok: true, Result: rb}); err != nil {
		return nil
	}
	wait := func() (*pb.Fin, error) {
		c, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		defer cancel()
		return tr.waitFin(c)
	}
	pf, err := wait()
	if err != nil || !pf.GetOk() {
		return nil
	}
	var p plan
	if json.Unmarshal(pf.Result, &p) != nil {
		return bail(invalid("reconcile", "bad plan"))
	}
	if ex {
		if err := s.applyPlanA(ctx, id, p, false); err != nil {
			return bail(fromWrapper("reconcile", err))
		}
	}
	if err := tr.sendFin(&pb.Fin{Ok: true}); err != nil {
		return nil
	}
	if p.Target == 0 {
		rt.setResolved(true)
		return nil
	}
	ks, _, err := s.keyset(ctx, id, p.Target)
	if err != nil {
		return bail(fromWrapper("reconcile", err))
	}
	pub, err := ks.SelfTest(ctx, tr, s.opts()...)
	if err != nil {
		return bail(fromWrapper("reconcile.selftest", err))
	}
	if err := tr.sendFin(&pb.Fin{Ok: true, Result: pub}); err != nil {
		return nil
	}
	cf, err := wait()
	if err != nil || !cf.GetOk() || !cf.GetConfirm() {
		return nil
	}
	s.store.DeleteGenerationsBelow(ctx, id, p.Target)
	rt.setResolved(true)
	s.log.Info("keyset reconciled and proven", "role", "B", "keyset_id", id, "generation", p.Target)
	return nil
}

// reconcileLoop (party A) reconciles every unresolved keyset as soon as party B is reachable, and keeps trying.
func (s *Server) reconcileLoop(ctx context.Context) {
	last := map[string]time.Time{}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		// Keep the connection to B alive (a gRPC channel goes idle after a drop). A NEW connection is noticed by watchPeer, not
		// here: this loop only reconciles what is unresolved.
		s.peerConn.Connect()
		ids, err := s.store.List(ctx)
		if err != nil {
			continue
		}
		for _, id := range ids {
			if s.rt(id).isResolved() || time.Since(last[id]) < time.Second {
				continue
			}
			last[id] = time.Now()
			t0 := time.Now()
			if err := s.reconcileA(ctx, id); err != nil {
				s.log.Warn("reconciliation pending", "keyset_id", id, "error", err.Error())
			} else {
				s.log.Info("reconciliation finished", "keyset_id", id, "duration_ms", time.Since(t0).Milliseconds())
			}
		}
	}
}

var _ = codes.OK

// watchPeer notices, the moment it happens, that the connection to party B was lost and came back. B may have restarted or been
// restored in between, so every keyset is marked unresolved and reconciled again before it serves. The first connection after
// start is not a reconnection (every keyset starts unresolved). Because this reacts to the state change itself and not to a
// timer, a keyset that is committed AFTER the new connection was established is never marked unresolved by it: the mark
// always comes before any work on the new connection.
func (s *Server) watchPeer(ctx context.Context) {
	everReady, wasReady := false, false
	state := s.peerConn.GetState()
	for {
		ready := state == connectivity.Ready
		if ready && !wasReady && everReady {
			ids, _ := s.store.List(ctx)
			for _, id := range ids {
				s.rt(id).setResolved(false)
			}
			s.log.Info("connection to party B re-established: keysets are reconciled again before they serve", "keysets", len(ids))
			select {
			case s.kick <- struct{}{}:
			default:
			}
		}
		wasReady = ready
		everReady = everReady || ready
		if !s.peerConn.WaitForStateChange(ctx, state) {
			return
		}
		state = s.peerConn.GetState()
	}
}
