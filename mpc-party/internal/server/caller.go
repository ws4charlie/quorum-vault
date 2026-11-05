package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/grpc/codes"

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
	s.log.Info("op", append([]any{"role", "A", "op", op, "duration_ms", time.Since(start).Milliseconds(), "outcome", outcome, "kind", kind}, kv...)...)
}

func (s *Server) DKG(ctx context.Context, r *pb.DKGRequest) (_ *pb.DKGResponse, err error) {
	start := time.Now()
	defer func() { s.logOp("dkg", start, err, "keyset_id", r.GetKeysetId()); err = toStatus("dkg", err) }()
	if !validID(r.KeysetId) {
		return nil, invalid("dkg", "keyset_id must match [A-Za-z0-9._-]{1,64}")
	}
	if _, e := algForCurve(r.Curve); e != nil {
		return nil, invalid("dkg", "%v", e)
	}
	if _, e := s.store.GetKeyset(ctx, r.KeysetId); e == nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.AlreadyExists, "dkg", "keyset %q already exists", r.KeysetId)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, fromWrapper("dkg", e)
	}
	res, err := s.coordinate(ctx, "dkg", &pb.Open{Op: pb.Op_OP_DKG, KeysetId: r.KeysetId, Curve: r.Curve}, r.KeysetId)
	if err != nil {
		return nil, err
	}
	return &pb.DKGResponse{RootPublicKey: res.public}, nil
}

func (s *Server) Refresh(ctx context.Context, r *pb.RefreshRequest) (_ *pb.RefreshResponse, err error) {
	start := time.Now()
	defer func() { s.logOp("refresh", start, err, "keyset_id", r.GetKeysetId()); err = toStatus("refresh", err) }()
	if _, e := s.cache.get(ctx, s.store, r.KeysetId); e != nil {
		return nil, e
	}
	res, err := s.coordinate(ctx, "refresh", &pb.Open{Op: pb.Op_OP_REFRESH, KeysetId: r.KeysetId}, r.KeysetId)
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
	ks, err := s.cache.get(ctx, s.store, r.KeysetId)
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
	ks, err := s.cache.get(ctx, s.store, r.KeysetId)
	if err != nil {
		return nil, err
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

func (s *Server) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Role: s.cfg.Role, PeerReachable: s.peerReachable(), ActiveSessions: int32(s.slots.active()),
		Version: Version, CbmpcCommit: cbmpc.PinnedCommit}, nil
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
	meta, e := s.store.GetKey(ctx, r.KeyId)
	if errors.Is(e, ErrNotFound) {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.NotFound, "sign", "key %q not found (call Derive first)", r.KeyId)
	} else if e != nil {
		return nil, fromWrapper("sign", e)
	}
	if meta.Alg != alg {
		return nil, invalid("sign", "algorithm does not match the key")
	}
	pub, _ := hex.DecodeString(meta.PublicKey)

	// Party A's own check, before anything else happens (B repeats it on its side).
	if e := s.authz.Authorize(ctx, AuthRequest{Role: "A", JobID: r.JobId, KeyID: r.KeyId, KeysetID: meta.KeysetID,
		Algorithm: r.Algorithm, Digest: r.Digest, IntentPackage: r.IntentPackage, PublicKey: pub}); e != nil {
		return nil, failf(pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied, "sign", "refused by the authorizer on A: %v", e)
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
		resp, err = s.signLeader(ctx, r, meta, pub, digestHex)
		s.jobMu.Lock()
		delete(s.inflight, r.JobId)
		s.jobMu.Unlock()
		close(f.done)
		return resp, err
	}
}

func (s *Server) signLeader(ctx context.Context, r *pb.SignRequest, meta KeyMeta, pub []byte, digestHex string) (*pb.SignResponse, error) {
	open := &pb.Open{Op: pb.Op_OP_SIGN, KeysetId: meta.KeysetID, HardenedPath: meta.HardenedPath, Path: meta.Path, KeyId: r.KeyId,
		Algorithm: r.Algorithm, Digest: r.Digest, JobId: r.JobId, IntentPackage: r.IntentPackage, ExpectedPublicKey: pub}
	res, err := s.coordinate(ctx, "sign", open, r.KeyId)
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
