package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// Signing a 2-of-3 keyset. The coordinator is A or B (the party the gateway called); the signer pair is the coordinator and
// the first peer in its fixed order that answers: A tries B, then C; B uses C. A coordinator moves to the next peer ONLY when
// the failure is an availability one (TRANSPORT or UNAVAILABLE) and happened before any signing message was exchanged
// (connect, OPEN, ACK). It never moves on after REFUSED, CRYPTOGRAPHIC, FROZEN, LIMIT, or a failure after the ACK.

func signOrder(role string) []string {
	switch role {
	case "A":
		return []string{"B", "C"}
	case "B":
		return []string{"C"}
	}
	return nil
}

// link returns the client of the peer link to the member with the given role, nil if this party does not dial it.
func (s *Server) link(role string) pbPeerClient {
	switch {
	case s.cfg.Role == "A" && role == "B":
		return s.peerClient
	case (s.cfg.Role == "A" || s.cfg.Role == "B") && role == "C":
		return s.peerCClient
	}
	return nil
}

type pbPeerClient = pb.PeerClient

func (s *Server) signCtxErr(err error) *Fail { return fromWrapper("sign", &transportErr{err}) }

// coordinateSignT runs one signature of a 2-of-3 keyset as coordinator (A or B).
func (s *Server) coordinateSignT(ctx context.Context, open *pb.Open, rateKey string) (res *opResult, err error) {
	id := open.KeysetId
	rt := s.rt(id)
	var unres bool
	defer func() {
		if unres {
			s.unresolve(id) // a peer is unresolved or on another generation: reconcile before more work
		}
	}()
	if !rt.isResolved() {
		return nil, unresolvedFail("sign", id)
	}
	rt.gate.RLock()
	defer rt.gate.RUnlock()
	tk, gen, err := s.tkey(ctx, id, 0)
	if err != nil {
		return nil, err
	}
	open.Generation, open.Scheme, open.Initiator = gen, algScheme(tk.Alg()), s.cfg.Role
	open.ExpectedPublicKey = tk.PublicKey()
	if !s.rl.allow(rateKey) {
		return nil, limitFail("sign", "rate limit of %.0f sessions/s exceeded for %q", s.cfg.Limits.SessionsPerSecKey, rateKey)
	}
	var last error
	for _, peer := range signOrder(s.cfg.Role) {
		if s.link(peer) == nil {
			continue
		}
		var started bool
		res, started, err = s.signViaPeer(ctx, open, tk, peer)
		if err == nil {
			return res, nil
		}
		last = err
		var f *Fail
		if errors.As(err, &f) && f.Peer && (f.CB == CodeUnresolved || f.CB == CodeGenMismatch) {
			unres = true
		}
		if !started && errors.As(err, &f) && (f.Kind == pb.ErrorKind_ERROR_KIND_TRANSPORT || f.Kind == pb.ErrorKind_ERROR_KIND_UNAVAILABLE) {
			s.log.Warn("sign: peer not available before any signing message, trying the next one", "role", s.cfg.Role, "peer", peer,
				"keyset_id", id, "job_id", open.JobId, "kind", f.Kind.String(), "message", f.Msg)
			continue
		}
		return nil, err
	}
	if last == nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, "sign", "this party has no peer link for 2-of-3 signing")
	}
	return nil, last
}

// signViaPeer is one signing attempt with one peer. started reports whether the signing protocol had begun (the peer's ACK arrived).
func (s *Server) signViaPeer(ctx context.Context, open *pb.Open, tk *cbmpc.TKey, peer string) (res *opResult, started bool, err error) {
	const name = "sign"
	defer func() {
		var f *Fail
		if err != nil && errors.As(err, &f) {
			s.maybeFreezeT(open, f, peer)
			if started && f.CB == 0 {
				f.CB = CodeSigningStarted // the caller must not treat this as "nothing was exchanged"
			}
		}
	}()
	if !s.slots.acquire() {
		return nil, false, limitFail(name, "too many concurrent sessions (max %d)", s.cfg.Limits.MaxPeerSessions)
	}
	defer s.slots.release()
	s.wg.Add(1)
	defer s.wg.Done()
	var sidRaw [16]byte
	if _, err := rand.Read(sidRaw[:]); err != nil {
		return nil, false, err
	}
	sid := hex.EncodeToString(sidRaw[:])
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.SessionTimeout())
	defer cancel()
	stream, err := s.link(peer).Session(ctx)
	if err != nil {
		return nil, false, fromWrapper(name, &transportErr{err})
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	go tr.pump()
	defer stream.CloseSend()
	defer func() { // hold the slot until the peer has finished with the session too (nothing to wait for if it never ACKed)
		if !started {
			return
		}
		select {
		case <-tr.done:
		case <-time.After(s.cfg.Limits.RecvTimeout()):
		}
	}()
	fail := func(mine error) error {
		f := fromWrapper(name, mine)
		if f.Kind == pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC {
			tr.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		} else {
			tr.abortPeer(f.Msg)
		}
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
		return nil, false, fromWrapper(name, &transportErr{err})
	}
	ackCtx, c3 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	err = tr.waitAck(ackCtx)
	c3()
	if err != nil {
		var f *Fail
		if errors.As(err, &f) { // refused / limit / unavailable / frozen by the peer before any protocol message
			return nil, false, f
		}
		return nil, false, fromWrapper(name, &transportErr{err})
	}
	started = true

	if fi := s.fi; fi != nil && fi.BeforeSign != nil {
		fi.BeforeSign(s.cfg.Role)
	}
	mesh := meshOf(s.cfg.Role, map[string]*sessTransport{peer: tr})
	sig, err := tk.Sign(ctx, mesh, roleMember(peer), roleMember(s.cfg.Role), open.Digest, s.opts()...)
	if err != nil {
		return nil, started, fail(err)
	}
	pub := tk.PublicKey()
	if err := verifySignature(tk.Alg(), pub, open.Digest, sig); err != nil {
		return nil, started, fail(failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, name, "signature failed local verification: %v", err))
	}
	finCtx, c4 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	pfin, err := tr.waitFin(finCtx)
	c4()
	if err != nil {
		return nil, started, fail(&transportErr{err})
	}
	if !pfin.GetOk() {
		return nil, started, peerFail(name, pfin)
	}
	if string(pfin.Result) != string(pub) {
		tr.sendFin(&pb.Fin{Ok: false, Kind: pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, Message: "parties computed different results"})
		return nil, started, failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, name, "the two parties hold different public keys")
	}
	if err := tr.sendFin(&pb.Fin{Ok: true}); err != nil {
		return nil, started, fromWrapper(name, &transportErr{err})
	}
	return &opResult{public: sig, signature: sig, compare: pub}, started, nil
}

// signFollowT is the follower's side of a 2-of-3 signing session (party B or C). Everything that can refuse happens BEFORE the
// ACK, so that the coordinator can tell "peer unavailable before signing" from "failed during signing".
func (s *Server) signFollowT(ctx context.Context, stream pb.Peer_SessionServer, sid string, open *pb.Open, from string,
	reject func(pb.ErrorKind, string) error, rejectCode func(pb.ErrorKind, uint32, string) error, start time.Time) error {
	opName := "OP_SIGN"
	if from != "A" && from != "B" || from == s.cfg.Role || open.Initiator != from {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "this party does not follow 2-of-3 signing sessions of that party")
	}
	if s.cfg.Role == "B" && from != "A" {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "party B follows only party A")
	}
	id := open.KeysetId
	if !validID(id) {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "invalid keyset id")
	}
	rt := s.rt(id)
	rt.gate.RLock()
	defer rt.gate.RUnlock()
	tk, _, err := s.tkey(ctx, id, 0)
	if err != nil {
		var f *Fail
		if errors.As(err, &f) && f.Kind == pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
			return reject(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, f.Msg)
		}
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "unknown 2-of-3 keyset on this party")
	}
	if frozen, why := s.freeze.Frozen(id); frozen {
		return reject(pb.ErrorKind_ERROR_KIND_FROZEN, "keyset is frozen: "+why)
	}
	if !rt.isResolved() {
		return rejectCode(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, CodeUnresolved, "keyset is not reconciled with the peers yet (after a restart or restore)")
	}
	if _, _, err := s.tkey(ctx, id, open.Generation); err != nil {
		var f *Fail
		if errors.As(err, &f) && f.Kind == pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
			return rejectCode(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, f.CB, f.Msg)
		}
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "generation check failed")
	}
	pub := tk.PublicKey()
	if len(open.ExpectedPublicKey) == 0 {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "sign without an expected public key: this party cannot tell which key it would sign with")
	}
	if open.Scheme != algScheme(tk.Alg()) {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "the request is for "+schemeName(open.Scheme)+", this keyset is "+schemeName(algScheme(tk.Alg())))
	}
	if tk.Alg() == cbmpc.Ed25519 {
		if open.Algorithm != pb.Algorithm_ALGORITHM_ED25519 || len(open.Digest) == 0 || len(open.Digest) > cbmpc.MaxEdMessage {
			return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "a 2-of-3 Ed25519 keyset signs a whole message of 1 to 65536 bytes")
		}
	} else if open.Algorithm != pb.Algorithm_ALGORITHM_ECDSA_SECP256K1 || len(open.Digest) != 32 {
		return reject(pb.ErrorKind_ERROR_KIND_INTERNAL, "a 2-of-3 keyset signs 32-byte ECDSA digests")
	}
	// The party re-verifies what it is asked to sign BEFORE it joins: its own cosigner, in every role. The cosigner judges the key the
	// OPEN names (its transaction must come from that key); only then is that key required to be this keyset's key, so the cosigner's
	// own key check is still exercised exactly as for a 2-party key.
	if err := s.authz.Authorize(ctx, AuthRequest{Role: s.cfg.Role, JobID: open.JobId, KeyID: open.KeyId, KeysetID: id,
		Algorithm: open.Algorithm, Digest: open.Digest, IntentPackage: open.IntentPackage, PublicKey: open.ExpectedPublicKey}); err != nil {
		var ue *UnavailableError
		if errors.As(err, &ue) {
			return reject(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, "authorizer on "+s.cfg.Role+" unavailable: "+err.Error())
		}
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "authorizer on "+s.cfg.Role+" refused: "+err.Error())
	}
	if string(open.ExpectedPublicKey) != string(pub) {
		return reject(pb.ErrorKind_ERROR_KIND_REFUSED, "the expected public key is not the key of this keyset")
	}
	tr := newSessTransport(sid, stream, s.cfg.Limits.MaxFrameBytes, &s.stats)
	if err := tr.sendFrame(pb.FrameKind_FRAME_KIND_ACK, nil); err != nil {
		return nil
	}
	go tr.pump()

	outcome := "ok"
	var ferr *Fail
	defer func() {
		s.log.Info("session", "role", s.cfg.Role, "op", opName, "scheme", s.schemeLog(id), "from", from, "session", sid, "job_id", open.JobId,
			"keyset_id", id, "duration_ms", time.Since(start).Milliseconds(), "outcome", outcome,
			"kind", func() string {
				if ferr != nil {
					return ferr.Kind.String()
				}
				return ""
			}())
	}()
	failOut := func(f *Fail) error {
		if pf := tr.peerFin.Load(); pf != nil {
			if cand := peerFail(opName, pf); severity(cand.Kind) > severity(f.Kind) {
				f = cand
			}
		}
		ferr, outcome = f, "failed"
		s.maybeFreezeT(open, f, from)
		tr.sendFin(&pb.Fin{Ok: false, Kind: f.Kind, Code: f.CB, Message: f.Msg})
		return nil
	}
	if fi := s.fi; fi != nil && fi.BeforeSign != nil {
		fi.BeforeSign(s.cfg.Role)
	}
	mesh := meshOf(s.cfg.Role, map[string]*sessTransport{from: tr})
	if _, err := tk.Sign(ctx, mesh, roleMember(from), roleMember(from), open.Digest, s.opts()...); err != nil {
		return failOut(fromWrapper("sign", err))
	}
	if err := tr.sendFin(&pb.Fin{Ok: true, Result: pub}); err != nil {
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	// The coordinator compares and answers; its FIN is the last frame.
	wctx, c2 := context.WithTimeout(ctx, s.cfg.Limits.RecvTimeout())
	afin, err := tr.waitFin(wctx)
	c2()
	if err != nil {
		return failOut(fromWrapper(opName, &transportErr{err}))
	}
	if !afin.GetOk() {
		outcome = "peer-rejected"
		ferr = peerFail(opName, afin)
		s.maybeFreezeT(open, ferr, from)
	}
	return nil
}
