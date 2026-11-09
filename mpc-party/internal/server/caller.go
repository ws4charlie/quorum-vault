package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

const maxPath = 16

func checkPath(op string, hardened, path []uint32, needHardened bool) *Fail {
	if needHardened && len(hardened) == 0 || len(hardened) > maxPath || len(path) > maxPath {
		return invalid(op, "hardened_path must have 1..%d entries and path at most %d", maxPath, maxPath)
	}
	for _, i := range path {
		if i >= 0x80000000 {
			return invalid(op, "path index %d must be below 2^31 (non-hardened)", i)
		}
	}
	return nil
}

func (s *Server) logOp(op string, start time.Time, err error, kv ...any) {
	outcome, kind := "ok", ""
	if err != nil {
		outcome = "failed"
		var f *Fail
		if errors.As(err, &f) {
			kind = f.Kind.String()
		}
	}
	s.log.Info("op", append([]any{"role", s.cfg.Role, "op", op, "duration_ms", time.Since(start).Milliseconds(), "outcome", outcome, "kind", kind}, kv...)...)
}

func (s *Server) DKG(ctx context.Context, r *pb.DKGRequest) (_ *pb.DKGResponse, err error) {
	start := time.Now()
	defer func() { s.logOp("dkg", start, err, "keyset_id", r.GetKeysetId()); err = toStatus("dkg", err) }()
	if !validID(r.KeysetId) {
		return nil, invalid("dkg", "keyset_id must match [A-Za-z0-9._-]{1,64}")
	}
	threshold := isTScheme(int32(r.Scheme))
	tcurve := pb.Curve_CURVE_SECP256K1
	if r.Scheme == pb.Scheme_SCHEME_ED25519_2OF3 {
		tcurve = pb.Curve_CURVE_ED25519
	}
	if threshold {
		if r.Curve != pb.Curve_CURVE_UNSPECIFIED && r.Curve != tcurve {
			return nil, invalid("dkg", "%s is a %s keyset: the curve does not match", schemeName(r.Scheme), tcurve)
		}
	} else if r.Scheme != pb.Scheme_SCHEME_UNSPECIFIED {
		return nil, invalid("dkg", "unknown scheme %v", r.Scheme)
	} else if _, e := algForCurve(r.Curve); e != nil {
		return nil, invalid("dkg", "%v", e)
	}
	if s.cfg.Role != "A" {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Unimplemented, "dkg", "DKG is served by party A")
	}
	if st, e := s.store.State(ctx, r.KeysetId); e == nil && st.Current != 0 {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.AlreadyExists, "dkg", "keyset %q already exists", r.KeysetId)
	} else if e == nil && !s.rt(r.KeysetId).isResolved() {
		// An unfinished DKG (a candidate, maybe with a commit decision) must be reconciled first: starting over now could
		// leave a stale decision beside a new candidate.
		s.unresolve(r.KeysetId)
		return nil, unresolvedFail("dkg", r.KeysetId)
	} else if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, fromWrapper("dkg", e)
	}
	if _, e := s.admin.check("dkg", r.KeysetId, r.Admin); e != nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied, "dkg", "%v", e)
	}
	if threshold {
		res, err := s.coordinateGroup(ctx, "dkg", &pb.Open{Op: pb.Op_OP_DKG, KeysetId: r.KeysetId, Curve: tcurve, Scheme: r.Scheme, Admin: r.Admin})
		if err != nil {
			return nil, err
		}
		return &pb.DKGResponse{RootPublicKey: res.public}, nil
	}
	res, err := s.coordinate(ctx, "dkg", &pb.Open{Op: pb.Op_OP_DKG, KeysetId: r.KeysetId, Curve: r.Curve, Admin: r.Admin}, r.KeysetId)
	if err != nil {
		return nil, err
	}
	return &pb.DKGResponse{RootPublicKey: res.public}, nil
}

func (s *Server) Refresh(ctx context.Context, r *pb.RefreshRequest) (_ *pb.RefreshResponse, err error) {
	start := time.Now()
	defer func() { s.logOp("refresh", start, err, "keyset_id", r.GetKeysetId()); err = toStatus("refresh", err) }()
	if st, e := s.store.State(ctx, r.KeysetId); e == nil && isTScheme(st.Scheme) {
		if _, _, e := s.tkey(ctx, r.KeysetId, 0); e != nil {
			return nil, e
		}
		if frozen, why := s.freeze.Frozen(r.KeysetId); frozen {
			return nil, frozenFail("refresh", r.KeysetId, why)
		}
		if _, e := s.admin.check("refresh", r.KeysetId, r.Admin); e != nil {
			return nil, failf(pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied, "refresh", "%v", e)
		}
		res, err := s.coordinateGroup(ctx, "refresh", &pb.Open{Op: pb.Op_OP_REFRESH, KeysetId: r.KeysetId, Scheme: pb.Scheme(st.Scheme), Admin: r.Admin})
		if err != nil {
			return nil, err
		}
		return &pb.RefreshResponse{RootPublicKey: res.public}, nil
	}
	if _, _, e := s.keyset(ctx, r.KeysetId, 0); e != nil {
		return nil, e
	}
	if frozen, why := s.freeze.Frozen(r.KeysetId); frozen {
		return nil, frozenFail("refresh", r.KeysetId, why)
	}
	if _, e := s.admin.check("refresh", r.KeysetId, r.Admin); e != nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied, "refresh", "%v", e)
	}
	res, err := s.coordinate(ctx, "refresh", &pb.Open{Op: pb.Op_OP_REFRESH, KeysetId: r.KeysetId, Admin: r.Admin}, r.KeysetId)
	if err != nil {
		return nil, err
	}
	return &pb.RefreshResponse{RootPublicKey: res.public}, nil
}

func (s *Server) Node(ctx context.Context, r *pb.NodeRequest) (_ *pb.NodeResponse, err error) {
	start := time.Now()
	defer func() { s.logOp("node", start, err, "keyset_id", r.GetKeysetId()); err = toStatus("node", err) }()
	if f := checkPath("node", r.HardenedPath, nil, true); f != nil {
		return nil, f
	}
	ks, _, err := s.keyset(ctx, r.KeysetId, 0)
	if err != nil {
		return nil, err
	}
	res, err := s.coordinate(ctx, "node", &pb.Open{Op: pb.Op_OP_NODE, KeysetId: r.KeysetId, HardenedPath: r.HardenedPath}, r.KeysetId)
	if err != nil {
		return nil, err
	}
	n := len(res.public) - 32
	if n != 33 && n != 32 || (ks.Alg() == cbmpc.Ed25519) != (n == 32) {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, "node", "unexpected node size")
	}
	return &pb.NodeResponse{PublicKey: res.public[:n], ChainCode: res.public[n:]}, nil
}

func keyIDOf(keyset string, hardened, path []uint32) string {
	h := sha256.New()
	h.Write([]byte("qv-mpc-key|v1|" + keyset))
	for _, p := range [][]uint32{hardened, path} {
		h.Write([]byte{0xff, byte(len(p))})
		for _, i := range p {
			h.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (s *Server) Derive(ctx context.Context, r *pb.DeriveRequest) (_ *pb.DeriveResponse, err error) {
	start := time.Now()
	defer func() { s.logOp("derive", start, err, "keyset_id", r.GetKeysetId()); err = toStatus("derive", err) }()
	if f := checkPath("derive", r.HardenedPath, r.Path, true); f != nil {
		return nil, f
	}
	ks, _, err := s.keyset(ctx, r.KeysetId, 0)
	if err != nil {
		return nil, err
	}
	if frozen, why := s.freeze.Frozen(r.KeysetId); frozen {
		return nil, frozenFail("derive", r.KeysetId, why)
	}
	keyID := keyIDOf(r.KeysetId, r.HardenedPath, r.Path)
	res, err := s.coordinate(ctx, "derive", &pb.Open{Op: pb.Op_OP_DERIVE, KeysetId: r.KeysetId, HardenedPath: r.HardenedPath, Path: r.Path}, keyID)
	if err != nil {
		return nil, err
	}
	if err := s.store.PutKey(ctx, KeyMeta{KeyID: keyID, KeysetID: r.KeysetId, Alg: ks.Alg(), HardenedPath: r.HardenedPath,
		Path: r.Path, PublicKey: hex.EncodeToString(res.public), CreatedAt: time.Now().UTC()}); err != nil {
		return nil, fromWrapper("derive", err)
	}
	return &pb.DeriveResponse{KeyId: keyID, PublicKey: res.public}, nil
}

func (s *Server) Health(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	h := &pb.HealthResponse{Role: s.cfg.Role, PeerReachable: s.peerReachable(), ActiveSessions: int32(s.slots.active()),
		Version: Version, CbmpcCommit: cbmpc.PinnedCommit}
	if s.peerConn != nil {
		h.Peers = append(h.Peers, &pb.PeerStatus{Name: "B", Reachable: s.peerConn.GetState() == connectivity.Ready})
	}
	if s.peerCConn != nil {
		h.Peers = append(h.Peers, &pb.PeerStatus{Name: "C", Reachable: s.peerCConn.GetState() == connectivity.Ready})
	}
	ids, _ := s.store.List(ctx)
	for _, id := range ids {
		st, err := s.store.State(ctx, id)
		if err != nil {
			continue
		}
		bk := ReadBackup(s.cfg.DataDir, id)
		frozen, _ := s.freeze.Frozen(id)
		ks := &pb.KeysetStatus{KeysetId: id, Generation: st.Current, Resolved: s.rt(id).isResolved(),
			BackupGeneration: bk.Generation, BackupStale: st.Current != 0 && bk.Generation < st.Current, Frozen: frozen,
			Scheme: pb.Scheme(st.Scheme)}
		if isTScheme(st.Scheme) && st.PubKey != "" {
			ks.PublicKey, _ = hex.DecodeString(st.PubKey)
		}
		h.Keysets = append(h.Keysets, ks)
	}
	return h, nil
}

func (s *Server) Sign(ctx context.Context, r *pb.SignRequest) (resp *pb.SignResponse, err error) {
	start := time.Now()
	defer func() {
		s.logOp("sign", start, err, "job_id", r.GetJobId(), "key_id", r.GetKeyId())
		err = toStatus("sign", err)
	}()
	if r.JobId == "" || len(r.JobId) > 128 {
		return nil, invalid("sign", "job_id is required (at most 128 bytes)")
	}
	if len(r.Digest) == 0 || len(r.Digest) > 1<<20 {
		return nil, invalid("sign", "digest size out of range")
	}
	if len(r.IntentPackage) > s.cfg.Limits.MaxIntentBytes {
		return nil, limitFail("sign", "intent package above %d bytes", s.cfg.Limits.MaxIntentBytes)
	}
	alg, e := algForAlgorithm(r.Algorithm)
	if e != nil {
		return nil, invalid("sign", "%v", e)
	}
	if alg == cbmpc.ECDSA && len(r.Digest) != 32 {
		return nil, invalid("sign", "an ECDSA digest must be 32 bytes")
	}
	var meta KeyMeta
	var e2 error
	tkeyset := false
	if validID(r.KeyId) {
		// A 2-of-3 keyset IS the key: Sign names the keyset as key_id.
		if st, e := s.store.State(ctx, r.KeyId); e == nil && isTScheme(st.Scheme) && st.Current != 0 {
			tkeyset = true
			meta = KeyMeta{KeyID: r.KeyId, KeysetID: r.KeyId, Alg: schemeAlg(pb.Scheme(st.Scheme)), PublicKey: st.PubKey}
			if meta.Alg != alg { // an ECDSA keyset asked for an Ed25519 signature or the reverse
				return nil, invalid("sign", "keyset %q is %s but the request asks for a %s signature", r.KeyId, schemeName(pb.Scheme(st.Scheme)), r.Algorithm)
			}
			if alg == cbmpc.Ed25519 && len(r.Digest) > cbmpc.MaxEdMessage {
				return nil, invalid("sign", "a 2-of-3 Ed25519 message is at most %d bytes", cbmpc.MaxEdMessage)
			}
		}
	}
	if !tkeyset {
		if s.cfg.Role != "A" {
			return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Unimplemented, "sign", "2-of-3 keyset %q not found on this party (party %s signs 2-of-3 keysets only)", r.KeyId, s.cfg.Role)
		}
		meta, e2 = s.store.GetKey(ctx, r.KeyId)
		if errors.Is(e2, ErrNotFound) {
			return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.NotFound, "sign", "key %q not found (call Derive first)", r.KeyId)
		} else if e2 != nil {
			return nil, fromWrapper("sign", e2)
		}
	}
	if meta.Alg != alg {
		return nil, invalid("sign", "algorithm does not match the key")
	}
	pub, _ := hex.DecodeString(meta.PublicKey)
	if len(pub) == 0 {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, "sign", "key %q has no recorded public key", r.KeyId)
	}
	if frozen, why := s.freeze.Frozen(meta.KeysetID); frozen {
		return nil, frozenFail("sign", meta.KeysetID, why)
	}

	// Party A's own check, before anything else happens (B repeats it on its side).
	if e := s.authz.Authorize(ctx, AuthRequest{Role: s.cfg.Role, JobID: r.JobId, KeyID: r.KeyId, KeysetID: meta.KeysetID,
		Algorithm: r.Algorithm, Digest: r.Digest, IntentPackage: r.IntentPackage, PublicKey: pub}); e != nil {
		var ue *UnavailableError
		if errors.As(e, &ue) {
			return nil, failf(pb.ErrorKind_ERROR_KIND_UNAVAILABLE, codes.Unavailable, "sign", "authorizer on %s unavailable: %v", s.cfg.Role, e)
		}
		return nil, failf(pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied, "sign", "refused by the authorizer on %s: %v", s.cfg.Role, e)
	}

	digestHex := hex.EncodeToString(r.Digest)
	for {
		// Idempotency: the first signature for a job id is final.
		if rec, e := s.store.GetJob(ctx, r.JobId); e == nil {
			if rec.Digest != digestHex || rec.KeyID != r.KeyId || rec.Algorithm != int32(r.Algorithm) {
				return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.FailedPrecondition, "sign",
					"job_id %q was already used for a different request (digest, key or algorithm differ)", r.JobId)
			}
			sig, _ := hex.DecodeString(rec.Signature)
			return &pb.SignResponse{Signature: sig, Replayed: true}, nil
		} else if !errors.Is(e, ErrNotFound) {
			return nil, fromWrapper("sign", e)
		}
		// Only one protocol run per job id at a time; followers wait and then read the stored result.
		s.jobMu.Lock()
		if f, busy := s.inflight[r.JobId]; busy {
			s.jobMu.Unlock()
			select {
			case <-f.done:
				continue
			case <-ctx.Done():
				return nil, fromWrapper("sign", &transportErr{ctx.Err()})
			}
		}
		f := &flight{done: make(chan struct{})}
		s.inflight[r.JobId] = f
		s.jobMu.Unlock()
		resp, err = s.signLeader(ctx, r, meta, pub, digestHex, tkeyset)
		s.jobMu.Lock()
		delete(s.inflight, r.JobId)
		s.jobMu.Unlock()
		close(f.done)
		return resp, err
	}
}

func (s *Server) signLeader(ctx context.Context, r *pb.SignRequest, meta KeyMeta, pub []byte, digestHex string, tkeyset bool) (*pb.SignResponse, error) {
	open := &pb.Open{Op: pb.Op_OP_SIGN, KeysetId: meta.KeysetID, HardenedPath: meta.HardenedPath, Path: meta.Path, KeyId: r.KeyId,
		Algorithm: r.Algorithm, Digest: r.Digest, JobId: r.JobId, IntentPackage: r.IntentPackage, ExpectedPublicKey: pub}
	var res *opResult
	var err error
	if tkeyset {
		res, err = s.coordinateSignT(ctx, open, r.KeyId)
	} else {
		res, err = s.coordinate(ctx, "sign", open, r.KeyId)
	}
	if err != nil {
		return nil, err
	}
	rec := JobRecord{JobID: r.JobId, KeyID: r.KeyId, Algorithm: int32(r.Algorithm), Digest: digestHex,
		Signature: hex.EncodeToString(res.signature), At: time.Now().UTC()}
	if err := s.store.PutJob(ctx, rec); err != nil && !errors.Is(err, ErrExists) {
		// The signature exists but could not be stored: do not hand it out (a retry would sign again and the first one
		// would be lost). The caller sees an internal error.
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, "sign", "cannot store the signature durably: %v", err)
	}
	return &pb.SignResponse{Signature: res.signature}, nil
}

func (s *Server) Unfreeze(ctx context.Context, r *pb.UnfreezeRequest) (_ *pb.UnfreezeResponse, err error) {
	start := time.Now()
	defer func() { s.logOp("unfreeze", start, err, "keyset_id", r.GetKeysetId()); err = toStatus("unfreeze", err) }()
	if !validID(r.KeysetId) {
		return nil, invalid("unfreeze", "invalid keyset id")
	}
	key, e := s.admin.check("unfreeze", r.KeysetId, r.Admin)
	if e != nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied, "unfreeze", "%v", e)
	}
	if st, e := s.store.State(ctx, r.KeysetId); e == nil && isTScheme(st.Scheme) {
		// all three accept the operator signature or nothing is lifted
		if e := s.unfreezeGroup(ctx, r.KeysetId, r.Admin); e != nil {
			return nil, e
		}
	} else if e := s.unfreezeSession(ctx, r.KeysetId, r.Admin); e != nil {
		return nil, e
	}
	if e := s.freeze.Unfreeze(r.KeysetId); e != nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, "unfreeze", "B unfroze but A could not: %v", e)
	}
	s.log.Warn("AUDIT keyset unfrozen", "role", "A", "keyset_id", r.KeysetId, "admin_key", key)
	return &pb.UnfreezeResponse{}, nil
}
