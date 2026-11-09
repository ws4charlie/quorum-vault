package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// Reconciliation of a 2-of-3 keyset: party A drives it with B and C (all three must be reachable), exactly the rules of the
// 2-party reconciliation (reconcile.go) over three states:
//   - A recorded a commit decision for generation g: finish the commit; every member makes g current if it is still its
//     candidate (each stored it before A decided). A member that has neither is an error that needs an operator.
//   - no decision: nothing was committed anywhere. Target is the current generation; candidates are dropped. Members on
//     different generations, or a member without state, mean a stale restore: refuse, say which member.
//   - no member has a current generation: an aborted DKG, the keyset is removed everywhere.
//   - any member frozen: all freeze.
// Then all three run the three-way SelfTest on the target generation. Older generations are deleted only after it passed.

type planT struct {
	Target  uint64  `json:"target"`
	Promote [3]bool `json:"promote"`
	Drop    [3]bool `json:"drop"`
	Freeze  string  `json:"freeze,omitempty"`
	Err     string  `json:"err,omitempty"`
}

var memberNames = [3]string{"A", "B", "C"}

// planReconcileT decides from the three reports (index = member). decision is party A's durable decision. Pure, unit-tested.
func planReconcileT(st [3]peerKS, decision uint64) planT {
	any := false
	for _, s := range st {
		any = any || s.Exists
	}
	if !any {
		return planT{}
	}
	if decision != 0 {
		g := decision
		p := planT{Target: g}
		for i, s := range st {
			switch {
			case !s.Exists:
				return planT{Err: fmt.Sprintf("party A decided generation %d but party %s has no state for this keyset: restore party %s from a backup of generation %d or %d", g, memberNames[i], memberNames[i], g-1, g)}
			case s.Current == g:
			case s.Candidate == g:
				p.Promote[i] = true
			default:
				return planT{Err: fmt.Sprintf("party A decided generation %d but party %s holds neither it as candidate nor as current (current %d, candidate %d): restore party %s from a backup of generation %d or %d", g, memberNames[i], s.Current, s.Candidate, memberNames[i], g-1, g)}
			}
		}
		return p
	}
	var max uint64
	for _, s := range st {
		if s.Current > max {
			max = s.Current
		}
	}
	if max == 0 { // an unfinished DKG that nobody decided: nothing of the keyset remains
		return planT{}
	}
	for i, s := range st {
		switch {
		case !s.Exists:
			return planT{Err: fmt.Sprintf("party %s has no state for this keyset but another party is on generation %d: restore party %s from a backup of generation %d", memberNames[i], max, memberNames[i], max)}
		case s.Current < max:
			return planT{Err: fmt.Sprintf("party %s is on generation %d but another party is on %d: party %s's state is older (a stale restore?): restore it from a backup of generation %d", memberNames[i], s.Current, max, memberNames[i], max)}
		}
	}
	p := planT{Target: max}
	for i, s := range st {
		p.Drop[i] = s.Candidate != 0
	}
	return p
}

type stateT struct {
	peerKS
	Frozen string `json:"frozen,omitempty"`
}

func (s *Server) applyPlanT(ctx context.Context, id string, p planT, idx int, exists bool) error {
	if !exists {
		return nil
	}
	switch {
	case p.Target == 0:
		if err := s.store.RemoveKeyset(ctx, id); err != nil {
			return err
		}
	case p.Promote[idx]:
		if err := s.store.Promote(ctx, id, p.Target); err != nil {
			return err
		}
	case p.Drop[idx]:
		if err := s.store.DropCandidate(ctx, id); err != nil {
			return err
		}
	}
	s.dropKey(id)
	return nil
}

func (s *Server) localStateT(ctx context.Context, id string) (KeysetState, bool, string, error) {
	st, err := s.store.State(ctx, id)
	ex := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return st, false, "", err
	}
	fz, why := s.freeze.Frozen(id)
	if !fz {
		why = ""
	} else if why == "" {
		why = "frozen"
	}
	return st, ex, why, nil
}

// reconcileAT (party A) reconciles one 2-of-3 keyset with B and C. It returns nil when the keyset is resolved.
func (s *Server) reconcileAT(ctx context.Context, id string) (err error) {
	const name = "reconcile"
	rt := s.rt(id)
	if holder, ok := rt.tryBusy("reconcile"); !ok {
		return fmt.Errorf("a %s of this keyset is running", holder)
	}
	defer rt.done()
	rt.gate.Lock()
	defer rt.gate.Unlock()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()

	open := &pb.Open{Op: pb.Op_OP_RECONCILE, KeysetId: id}
	sess, f := s.openGroup(ctx, name, open, true)
	if f != nil {
		return f
	}
	defer func() {
		for _, g := range sess {
			g.close(s.cfg.Limits.RecvTimeout())
		}
	}()
	step := func(role string) (*pb.Fin, error) {
		c, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		defer cancel()
		fin, err := sess[role].tr.waitFin(c)
		if err != nil {
			return nil, err
		}
		if !fin.GetOk() {
			return nil, peerFail(name, fin)
		}
		return fin, nil
	}
	sendAll := func(f *pb.Fin) error {
		for _, g := range sess {
			if err := g.tr.sendFin(f); err != nil {
				return err
			}
		}
		return nil
	}
	var rep [3]stateT
	for _, role := range []string{"B", "C"} {
		fin, err := step(role)
		if err != nil {
			return err
		}
		var sb stateT
		if err := json.Unmarshal(fin.Result, &sb); err != nil {
			return fmt.Errorf("bad state from party %s: %w", role, err)
		}
		rep[memberOf(role)] = sb
	}
	as, aEx, afz, aerr := s.localStateT(ctx, id)
	if aerr != nil {
		return aerr
	}
	rep[0] = stateT{peerKS: stateOf(as, aEx), Frozen: afz}
	var states [3]peerKS
	frozenBy := ""
	for i := range rep {
		states[i] = rep[i].peerKS
		if rep[i].Frozen != "" && frozenBy == "" {
			frozenBy = fmt.Sprintf("party %s holds the keyset frozen: %s", memberNames[i], rep[i].Frozen)
		}
	}
	p := planReconcileT(states, as.Decision)
	p.Freeze = frozenBy
	pj, _ := json.Marshal(p)
	if p.Err != "" {
		sendAll(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_INTERNAL, Message: p.Err})
		s.log.Error("ALERT keyset cannot be reconciled with the peers: operator action needed", "role", "A", "scheme", s.schemeLog(id), "keyset_id", id, "reason", p.Err)
		pf := failf(pb.ErrorKind_ERROR_KIND_INTERNAL, 0, name, "%s", p.Err)
		pf.CB = CodePlan
		return pf
	}
	if err := sendAll(&pb.Fin{Ok: true, Result: pj}); err != nil {
		return err
	}
	for _, role := range []string{"B", "C"} { // each applied its part
		if _, err := step(role); err != nil {
			return err
		}
	}
	if err := s.applyPlanT(ctx, id, p, 0, aEx); err != nil {
		return err
	}
	if p.Freeze != "" {
		if fz, _ := s.freeze.Frozen(id); !fz {
			s.freeze.Freeze(id, p.Freeze)
			s.log.Error("ALERT keyset frozen: another member holds it frozen", "role", "A", "keyset_id", id, "message", p.Freeze)
		}
	}
	if p.Target == 0 {
		s.log.Warn("reconciled: an unfinished DKG was aborted on all three parties", "role", "A", "keyset_id", id)
		rt.setResolved(true)
		rt.setPartial(false)
		return nil
	}
	tk, _, err := s.tkey(ctx, id, p.Target)
	if err != nil {
		return err
	}
	mesh := meshOf("A", map[string]*sessTransport{"B": sess["B"].tr, "C": sess["C"].tr})
	if err := tk.SelfTest(ctx, mesh, selfTestLabel(tk.Alg(), id, p.Target), s.opts()...); err != nil {
		sendAll(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "self-test after reconciliation failed"})
		s.log.Error("ALERT self-test after reconciliation failed", "role", "A", "scheme", s.schemeLog(id), "keyset_id", id, "generation", p.Target, "error", err.Error())
		return err
	}
	pub := tk.PublicKey()
	for _, role := range []string{"B", "C"} {
		fin, err := step(role)
		if err != nil {
			return err
		}
		if string(fin.Result) != string(pub) {
			sendAll(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "self-test results differ"})
			return errors.New("public keys differ after reconciliation")
		}
	}
	failpoint("reconcile_a_before_confirm")
	sendAll(&pb.Fin{Ok: true, Confirm: true})
	for _, g := range sess {
		select {
		case <-g.tr.done:
		case <-time.After(s.cfg.Limits.RecvTimeout()):
		}
	}
	s.store.DeleteGenerationsBelow(ctx, id, p.Target)
	rt.setResolved(true)
	rt.setPartial(false)
	s.log.Info("keyset reconciled and proven", "role", "A", "scheme", s.schemeLog(id), "keyset_id", id, "generation", p.Target)
	return nil
}

// reconcileFollowT is a member's (B or C) side. Its streams are already ACKed.
func (s *Server) reconcileFollowT(ctx context.Context, open *pb.Open, me string, control *sessTransport, links map[string]*sessTransport, sid string, start time.Time) error {
	id := open.KeysetId
	rt := s.rt(id)
	bail := func(f *Fail) error {
		control.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		for _, tr := range links {
			if tr != control {
				tr.abortPeer(f.Msg)
			}
		}
		s.log.Warn("reconciliation failed", "role", me, "keyset_id", id, "error", f.Error())
		return nil
	}
	if holder, ok := rt.tryBusy("reconcile"); !ok {
		return bail(failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, 0, "reconcile", "a %s of this keyset is running", holder))
	}
	defer rt.done()
	rt.gate.Lock()
	defer rt.gate.Unlock()

	idx := int(memberOf(me))
	st, ex, fz, err := s.localStateT(ctx, id)
	if err != nil {
		return bail(fromWrapper("reconcile", err))
	}
	if ex && st.Scheme != int32(open.Scheme) {
		return bail(failf(pb.ErrorKind_ERROR_KIND_REFUSED, 0, "reconcile", "keyset %q is %s here, the request names %s", id, schemeName(pb.Scheme(st.Scheme)), schemeName(open.Scheme)))
	}
	rb, _ := json.Marshal(stateT{peerKS: stateOf(st, ex), Frozen: fz})
	if err := control.sendFin(&pb.Fin{Ok: true, Result: rb}); err != nil {
		return nil
	}
	wait := func() (*pb.Fin, error) {
		c, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		defer cancel()
		return control.waitFin(c)
	}
	pf, err := wait()
	if err != nil || !pf.GetOk() {
		return nil
	}
	var p planT
	if json.Unmarshal(pf.Result, &p) != nil {
		return bail(invalid("reconcile", "bad plan"))
	}
	if err := s.applyPlanT(ctx, id, p, idx, ex); err != nil {
		return bail(fromWrapper("reconcile", err))
	}
	if p.Freeze != "" {
		if fz, _ := s.freeze.Frozen(id); !fz {
			s.freeze.Freeze(id, p.Freeze)
			s.log.Error("ALERT keyset frozen: another member holds it frozen", "role", me, "keyset_id", id, "message", p.Freeze)
		}
	}
	if err := control.sendFin(&pb.Fin{Ok: true}); err != nil {
		return nil
	}
	if p.Target == 0 {
		rt.setResolved(true)
		return nil
	}
	tk, _, err := s.tkey(ctx, id, p.Target)
	if err != nil {
		return bail(fromWrapper("reconcile", err))
	}
	mesh := meshOf(me, links)
	if err := tk.SelfTest(ctx, mesh, selfTestLabel(tk.Alg(), id, p.Target), s.opts()...); err != nil {
		return bail(fromWrapper("reconcile.selftest", err))
	}
	if err := control.sendFin(&pb.Fin{Ok: true, Result: tk.PublicKey()}); err != nil {
		return nil
	}
	cf, err := wait()
	if err != nil || !cf.GetOk() || !cf.GetConfirm() {
		return nil
	}
	s.store.DeleteGenerationsBelow(ctx, id, p.Target)
	rt.setResolved(true)
	rt.setPartial(false)
	s.log.Info("keyset reconciled and proven", "role", me, "scheme", s.schemeLog(id), "keyset_id", id, "generation", p.Target)
	return nil
}

var _ = proto.Marshal

// ---- pairwise reconciliation: A and ONE reachable member when the third is down ----
//
// After a restart A cannot reconcile across all three while one member is down, and without it the keyset would stay
// UNAVAILABLE for as long as that member is away: the availability 2-of-3 exists for. When the three-way reconciliation cannot be
// done because a member is unreachable, A reconciles with each reachable member separately, but ONLY when it is safe to do so
// without the third: both hold the same current generation, neither has a candidate, and A has recorded no commit decision (so
// nothing can be half-done that the missing member would have to finish). Both then prove the keyset with a signature between
// the two of them and serve; signing among that pair compares generations in every OPEN anyway. The keyset is marked partial: the
// moment the missing member's link is up again, A reconciles all three (and the returning member, which has not been reconciled,
// stays UNAVAILABLE until then).

func isLinkDown(err error) bool {
	var f *Fail
	return errors.As(err, &f) && f.CB == CodeLinkDown
}

func isPlanErr(err error) bool {
	var f *Fail
	return errors.As(err, &f) && f.CB == CodePlan
}

func (r *ksRT) setPartial(v bool) { r.mu.Lock(); r.partial = v; r.mu.Unlock() }
func (r *ksRT) isPartial() bool   { r.mu.Lock(); defer r.mu.Unlock(); return r.partial }

func (s *Server) reconcileTWithFallback(ctx context.Context, id string) error {
	err := s.reconcileAT(ctx, id)
	// A member that is away, stale, or has lost its state must not stop the other two: they reconcile with each other when it is
	// safe (the stale member is flagged with an ALERT and stays out until an operator restores it).
	if err == nil || !(isLinkDown(err) || isPlanErr(err)) {
		return err
	}
	var last error = err
	for _, role := range []string{"B", "C"} {
		perr := s.reconcilePairWith(ctx, id, role)
		if perr == nil {
			return nil
		}
		last = perr
	}
	return last
}

func (s *Server) reconcilePairWith(ctx context.Context, id, role string) error {
	const name = "reconcile"
	if s.link(role) == nil {
		return errors.New("no link")
	}
	rt := s.rt(id)
	if holder, ok := rt.tryBusy("reconcile"); !ok {
		return fmt.Errorf("a %s of this keyset is running", holder)
	}
	defer rt.done()
	rt.gate.Lock()
	defer rt.gate.Unlock()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()
	sid := newSID()
	stream, err := s.link(role).Session(ctx)
	if err != nil {
		return fromWrapper(name, &transportErr{err})
	}
	defer stream.CloseSend()
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	open := &pb.Open{Op: pb.Op_OP_RECONCILE, KeysetId: id, Scheme: s.keysetScheme(id), Initiator: "A", Reason: "pair"}
	b, _ := proto.Marshal(open)
	if err := stream.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		return err
	}
	step := func() (*pb.Fin, error) {
		c, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		defer cancel()
		fin, err := tr.waitFin(c)
		if err != nil {
			return nil, err
		}
		if !fin.GetOk() {
			return nil, peerFail(name, fin)
		}
		return fin, nil
	}
	ac, c0 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	err = tr.waitAck(ac)
	c0()
	if err != nil {
		return err
	}
	f1, err := step()
	if err != nil {
		return err
	}
	var x stateT
	if err := json.Unmarshal(f1.Result, &x); err != nil {
		return fmt.Errorf("bad state from party %s: %w", role, err)
	}
	as, aEx, afz, aerr := s.localStateT(ctx, id)
	if aerr != nil {
		return aerr
	}
	refuse := func(why string) error {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_UNAVAILABLE, Message: why})
		return errors.New(why)
	}
	switch {
	case !aEx || !x.Exists || as.Current == 0 || as.Current != x.Current:
		return refuse(fmt.Sprintf("cannot reconcile A with %s alone: generations %d and %d (a full reconciliation with the third member is needed)", role, as.Current, x.Current))
	case as.Candidate != 0 || x.Candidate != 0 || as.Decision != 0:
		return refuse("cannot reconcile A with " + role + " alone: a commit may be unfinished (a full reconciliation with the third member is needed)")
	}
	freeze := ""
	if afz != "" {
		freeze = "party A holds the keyset frozen: " + afz
	} else if x.Frozen != "" {
		freeze = "party " + role + " holds the keyset frozen: " + x.Frozen
	}
	if freeze != "" {
		if fz, _ := s.freeze.Frozen(id); !fz {
			s.freeze.Freeze(id, freeze)
		}
	}
	pj, _ := json.Marshal(planT{Target: as.Current, Freeze: freeze})
	if err := tr.sendFin(&pb.Fin{Ok: true, Result: pj}); err != nil {
		return err
	}
	if _, err := step(); err != nil { // the member applied the freeze flag
		return err
	}
	tk, _, err := s.tkey(ctx, id, as.Current)
	if err != nil {
		return err
	}
	digest := cbmpc.SelfTestDigestAlg(tk.Alg(), tk.PublicKey(), append(selfTestLabel(tk.Alg(), id, as.Current), []byte("|pair")...), 0, roleMember(role))
	mesh := meshOf("A", map[string]*sessTransport{role: tr})
	if _, err := tk.Sign(ctx, mesh, roleMember(role), 0, digest, s.opts()...); err != nil {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "pair self-test after reconciliation failed"})
		s.log.Error("ALERT self-test after reconciliation failed", "role", "A", "scheme", s.schemeLog(id), "keyset_id", id, "generation", as.Current, "pair", "A+"+role, "error", err.Error())
		return err
	}
	fin, err := step()
	if err != nil {
		return err
	}
	if string(fin.Result) != string(tk.PublicKey()) {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "public keys differ"})
		return errors.New("public keys differ after pair reconciliation")
	}
	tr.sendFin(&pb.Fin{Ok: true, Confirm: true})
	select {
	case <-tr.done:
	case <-time.After(s.cfg.Limits.RecvTimeout()):
	}
	rt.setResolved(true)
	rt.setPartial(true)
	s.log.Warn("keyset reconciled with one member only: the third is unreachable; it is reconciled when it returns", "role", "A",
		"scheme", s.schemeLog(id), "keyset_id", id, "generation", as.Current, "with", role)
	return nil
}

// reconcilePairFollow is the member's side of a pairwise reconciliation with A.
func (s *Server) reconcilePairFollow(ctx context.Context, open *pb.Open, me string, control *sessTransport, sid string) error {
	id := open.KeysetId
	rt := s.rt(id)
	bail := func(f *Fail) error {
		control.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		s.log.Warn("pair reconciliation failed", "role", me, "keyset_id", id, "error", f.Error())
		return nil
	}
	if holder, ok := rt.tryBusy("reconcile"); !ok {
		return bail(failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, 0, "reconcile", "a %s of this keyset is running", holder))
	}
	defer rt.done()
	rt.gate.Lock()
	defer rt.gate.Unlock()
	st, ex, fz, err := s.localStateT(ctx, id)
	if err != nil {
		return bail(fromWrapper("reconcile", err))
	}
	if ex && st.Scheme != int32(open.Scheme) {
		return bail(failf(pb.ErrorKind_ERROR_KIND_REFUSED, 0, "reconcile", "keyset %q is %s here, the request names %s", id, schemeName(pb.Scheme(st.Scheme)), schemeName(open.Scheme)))
	}
	rb, _ := json.Marshal(stateT{peerKS: stateOf(st, ex), Frozen: fz})
	if err := control.sendFin(&pb.Fin{Ok: true, Result: rb}); err != nil {
		return nil
	}
	wait := func() (*pb.Fin, error) {
		c, cancel := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
		defer cancel()
		return control.waitFin(c)
	}
	pf, err := wait()
	if err != nil || !pf.GetOk() {
		return nil
	}
	var p planT
	if json.Unmarshal(pf.Result, &p) != nil || p.Target == 0 || p.Target != st.Current {
		return bail(invalid("reconcile", "bad plan"))
	}
	if p.Freeze != "" {
		if fz, _ := s.freeze.Frozen(id); !fz {
			s.freeze.Freeze(id, p.Freeze)
			s.log.Error("ALERT keyset frozen: another member holds it frozen", "role", me, "keyset_id", id, "message", p.Freeze)
		}
	}
	if err := control.sendFin(&pb.Fin{Ok: true}); err != nil {
		return nil
	}
	tk, _, err := s.tkey(ctx, id, p.Target)
	if err != nil {
		return bail(fromWrapper("reconcile", err))
	}
	mesh := meshOf(me, map[string]*sessTransport{"A": control})
	if _, err := tk.Sign(ctx, mesh, 0, 0, cbmpc.SelfTestDigestAlg(tk.Alg(), tk.PublicKey(), append(selfTestLabel(tk.Alg(), id, p.Target), []byte("|pair")...), 0, roleMember(me)), s.opts()...); err != nil {
		return bail(fromWrapper("reconcile.selftest", err))
	}
	if err := control.sendFin(&pb.Fin{Ok: true, Result: tk.PublicKey()}); err != nil {
		return nil
	}
	cf, err := wait()
	if err != nil || !cf.GetOk() || !cf.GetConfirm() {
		return nil
	}
	rt.setResolved(true)
	rt.setPartial(true)
	s.log.Info("keyset reconciled with party A alone (the third member is unreachable)", "role", me, "scheme", s.schemeLog(id), "keyset_id", id, "generation", p.Target)
	return nil
}
