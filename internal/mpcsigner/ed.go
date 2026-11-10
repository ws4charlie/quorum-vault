package mpcsigner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Ed25519 signers (Solana). They sign the whole message, so they implement signer.MessageSigner next to the ECDSA signers, which are unchanged.

// EdThresholdSigner is a signer.MessageSigner over a 2-of-3 Ed25519 keyset on parties A, B and C (P8-2). It shares everything with the ECDSA
// ThresholdSigner except the request and the signature: the same coordinators, the same fallback rule (to the next coordinator only on an
// availability failure before any signing message), the same retry composition and the same alerts.
//
// The second-signature case. cb-mpc's Ed25519 signatures are randomized, so a job that fails on coordinator A after signing began and is
// then signed through B yields a second, different, valid signature over the same message. The fallback rule never lets that happen
// once a signing message was exchanged (such a failure pins the job to its coordinator). If A failed without a trace and B signs, only B's
// signature exists. And if both did exist, the network runs only one transaction per message: see the experiment in e2e/mpcsign
// (TestSecondSignatureOfOneMessageDoesNotLand) and docs/learn/solana.md.
type EdThresholdSigner struct {
	*thresholdCore
	pub []byte
}

// NewEdThreshold builds the signer; cfg.PublicKey is the keyset's 32-byte Ed25519 public key.
func NewEdThreshold(cfg ThresholdConfig) (*EdThresholdSigner, error) {
	if len(cfg.PublicKey) != 32 {
		return nil, errors.New("an Ed25519 keyset's public key is 32 bytes")
	}
	core, err := newThresholdCore(cfg)
	if err != nil {
		return nil, err
	}
	return &EdThresholdSigner{thresholdCore: core, pub: append([]byte(nil), cfg.PublicKey...)}, nil
}

func (t *EdThresholdSigner) Backend() domain.Backend { return domain.BackendMPC }
func (t *EdThresholdSigner) PublicKey() []byte       { return append([]byte(nil), t.pub...) }

// RetryOnTimeout: a sign_timeout means "try again later", never "failed" (as for ECDSA).
func (t *EdThresholdSigner) RetryOnTimeout() bool { return true }

// SignMessage implements signer.MessageSigner.
func (t *EdThresholdSigner) SignMessage(ctx context.Context, msg []byte, opts signer.SignOptions) (signer.MessageResult, error) {
	if opts.JobID == "" || len(opts.IntentPackage) == 0 {
		return signer.MessageResult{}, &Error{Kind: KindInternal, Message: "job id and intent package are required"}
	}
	ctx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	defer cancel()
	req := &pb.SignRequest{KeyId: t.cfg.KeysetID, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: msg, JobId: opts.JobID, IntentPackage: opts.IntentPackage}
	start := time.Now()
	resp, i, calls, err := t.call(ctx, req)
	if err != nil {
		return signer.MessageResult{}, err
	}
	if len(resp.Signature) != 64 {
		return signer.MessageResult{}, &Error{Kind: KindCryptographic, Message: fmt.Sprintf("party %s returned a signature of %d bytes", t.cfg.Coordinators[i].Name, len(resp.Signature))}
	}
	t.note(i)
	return signer.MessageResult{Signature: resp.Signature, Participants: []string{"mpc-" + strings.ToLower(t.cfg.Coordinators[i].Name), "mpc-2of3"},
		Meta: map[string]any{"duration_ms": time.Since(start).Milliseconds(), "calls": calls, "coordinator": t.cfg.Coordinators[i].Name, "replayed": resp.Replayed}}, nil
}

var _ signer.MessageSigner = (*EdThresholdSigner)(nil)

// ---- the 2-party HD Ed25519 keyset (deposit keys) ----

// EdDerivingConfig is the config of a deriving Ed25519 signer through party A.
type EdDerivingConfig struct {
	PartitionID  string
	Address      string // party A's caller port
	ClientCert   tls.Certificate
	ServerPin    string
	KeysetID     string
	HardenedPath []uint32
	MaxRetries   int           // default 3
	Timeout      time.Duration // bounds one SignMessage including retries; default 30s
	Dial         func(addr string, creds credentials.TransportCredentials) (*grpc.ClientConn, error)
}

// EdDeriving signs with the keys of an Ed25519 HD keyset: At derives the key at a path below HardenedPath (party A's Derive is idempotent) and
// returns its signer. It is how a deposit key signs as the owner of a deposit address.
type EdDeriving struct {
	cfg  EdDerivingConfig
	conn *grpc.ClientConn
	cl   pb.MpcPartyClient
	mu   sync.Mutex
	by   map[string]*edSigner
}

// NewEdDeriving connects to party A.
func NewEdDeriving(cfg EdDerivingConfig) (*EdDeriving, error) {
	if cfg.KeysetID == "" || len(cfg.HardenedPath) == 0 || cfg.Address == "" {
		return nil, errors.New("address, keyset id and hardened path are required")
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	creds, err := pinnedCreds(cfg.ClientCert, cfg.ServerPin)
	if err != nil {
		return nil, err
	}
	dial := cfg.Dial
	if dial == nil {
		dial = func(addr string, c credentials.TransportCredentials) (*grpc.ClientConn, error) {
			return grpc.NewClient(addr, grpc.WithTransportCredentials(c))
		}
	}
	conn, err := dial(cfg.Address, creds)
	if err != nil {
		return nil, err
	}
	return &EdDeriving{cfg: cfg, conn: conn, cl: pb.NewMpcPartyClient(conn), by: map[string]*edSigner{}}, nil
}

func (d *EdDeriving) Close()                  { d.conn.Close() }
func (d *EdDeriving) Backend() domain.Backend { return domain.BackendMPC }
func (d *EdDeriving) PublicKey() []byte       { return nil }
func (d *EdDeriving) RetryOnTimeout() bool    { return true }
func (d *EdDeriving) SignMessage(context.Context, []byte, signer.SignOptions) (signer.MessageResult, error) {
	return signer.MessageResult{}, &Error{Kind: KindInternal, Message: "a deriving signer signs through At(path)"}
}

// At implements signer.MessageDeriver.
func (d *EdDeriving) At(ctx context.Context, path []uint32) (signer.MessageSigner, error) {
	key := fmt.Sprint(path)
	d.mu.Lock()
	defer d.mu.Unlock()
	if s := d.by[key]; s != nil {
		return s, nil
	}
	x, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
	defer cancel()
	r, err := d.cl.Derive(x, &pb.DeriveRequest{KeysetId: d.cfg.KeysetID, HardenedPath: d.cfg.HardenedPath, Path: path})
	if err != nil {
		return nil, classify(err)
	}
	if len(r.PublicKey) != 32 {
		return nil, &Error{Kind: KindCryptographic, Message: fmt.Sprintf("party A returned a public key of %d bytes for an Ed25519 keyset", len(r.PublicKey))}
	}
	s := &edSigner{d: d, keyID: r.KeyId, pub: append([]byte(nil), r.PublicKey...)}
	d.by[key] = s
	return s, nil
}

type edSigner struct {
	d     *EdDeriving
	keyID string
	pub   []byte
}

func (s *edSigner) Backend() domain.Backend { return domain.BackendMPC }
func (s *edSigner) PublicKey() []byte       { return append([]byte(nil), s.pub...) }
func (s *edSigner) RetryOnTimeout() bool    { return true }

// SignMessage asks party A to sign msg with the derived key. TRANSPORT, LIMIT and UNAVAILABLE failures are retried with the same job id (a
// stored signature is returned, nothing is signed twice).
func (s *edSigner) SignMessage(ctx context.Context, msg []byte, opts signer.SignOptions) (signer.MessageResult, error) {
	if opts.JobID == "" || len(opts.IntentPackage) == 0 {
		return signer.MessageResult{}, &Error{Kind: KindInternal, Message: "job id and intent package are required"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.d.cfg.Timeout)
	defer cancel()
	req := &pb.SignRequest{KeyId: s.keyID, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: msg, JobId: opts.JobID, IntentPackage: opts.IntentPackage}
	start := time.Now()
	var last error
	for attempt := 0; attempt <= s.d.cfg.MaxRetries; attempt++ {
		resp, err := s.d.cl.Sign(ctx, req)
		if err == nil {
			if len(resp.Signature) != 64 {
				return signer.MessageResult{}, &Error{Kind: KindCryptographic, Message: fmt.Sprintf("party A returned a signature of %d bytes", len(resp.Signature))}
			}
			return signer.MessageResult{Signature: resp.Signature, Participants: []string{"mpc-a", "mpc-b"},
				Meta: map[string]any{"duration_ms": time.Since(start).Milliseconds(), "attempts": attempt + 1, "replayed": resp.Replayed}}, nil
		}
		last = classify(err)
		var e *Error
		if !errors.As(last, &e) || !e.SignerUnavailable() {
			return signer.MessageResult{}, last
		}
		select {
		case <-ctx.Done():
			return signer.MessageResult{}, last
		case <-time.After(time.Duration(100*(attempt+1)) * time.Millisecond):
		}
	}
	return signer.MessageResult{}, last
}

var _ signer.MessageDeriver = (*EdDeriving)(nil)
