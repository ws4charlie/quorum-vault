// Package mpcsigner implements signer.Signer on top of the cb-mpc service (party A's caller port, gRPC over mTLS). It
// links no C++ and no cb-mpc code: only the pure-Go generated API.
package mpcsigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Config of one partition's signer.
type Config struct {
	PartitionID string
	Address     string // party A's caller port
	KeyID       string // from Derive
	PublicKey   []byte // 65-byte uncompressed secp256k1 of the derived key
	ClientCert  tls.Certificate
	ServerPin   string        // sha256 hex of party A's certificate
	MaxRetries  int           // default 3
	Timeout     time.Duration // bounds one SignDigest including retries; default 30s
	// Dial overrides the connection (tests).
	Dial func(addr string, creds credentials.TransportCredentials) (*grpc.ClientConn, error)
}

// Signer is a signer.Signer backed by party A.
type Signer struct {
	cfg  Config
	pub  *ecdsa.PublicKey
	conn *grpc.ClientConn
	cl   pb.MpcPartyClient
}

// Kind of a failure reported by the service, as the gateway needs it.
type Kind int

const (
	KindTransport Kind = iota + 1
	KindLimit
	KindRefused
	KindCryptographic
	KindFrozen
	KindInternal
	KindUnavailable // a dependency of the service is down (party B's cosigner or its database); nothing was signed
)

// Error is returned by SignDigest on failure. The gateway maps it: Refused -> job rejected (the workflow cancels the
// nonce); Alert -> job failed with an ALERT log; the rest -> job failed.
type Error struct {
	Kind    Kind
	Message string
	Err     error
}

func (e *Error) Error() string { return fmt.Sprintf("mpc signer: %s", e.Message) }
func (e *Error) Unwrap() error { return e.Err }

// SignerRefusal implements the gateway's interface: reason text if the refusal is a policy refusal.
func (e *Error) SignerRefusal() (string, bool) { return e.Message, e.Kind == KindRefused }

// SignerUnavailable implements the gateway's interface: an availability failure (link, limit, or a dependency of
// the service is down). The gateway must not finish the job: nothing was signed or refused, so it is retried later.
func (e *Error) SignerUnavailable() bool {
	return e.Kind == KindTransport || e.Kind == KindLimit || e.Kind == KindUnavailable
}

// RetryOnTimeout implements the gateway's interface: when sign_timeout passes without an answer, the outcome is "try
// again later", never "failed": the same job id is idempotent at party A and the reservation allows signing the same
// digest again.
func (s *Signer) RetryOnTimeout() bool { return true }

// SignerAlert implements the gateway's interface: whether an operator must look at this.
func (e *Error) SignerAlert() bool {
	return e.Kind == KindCryptographic || e.Kind == KindInternal || e.Kind == KindFrozen
}

func New(cfg Config) (*Signer, error) {
	pub, err := signerParse(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	pin, err := hex.DecodeString(strings.ToLower(cfg.ServerPin))
	if err != nil || len(pin) != 32 {
		return nil, errors.New("server_pin must be 64 hex chars (sha256 of party A's certificate)")
	}
	if cfg.KeyID == "" || cfg.Address == "" {
		return nil, errors.New("key id and address are required")
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cfg.ClientCert},
		InsecureSkipVerify: true, //nolint:gosec // pinned below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			if sum := sha256.Sum256(raw[0]); string(sum[:]) != string(pin) {
				return errors.New("party A certificate is not the pinned one")
			}
			return nil
		},
	}
	creds := credentials.NewTLS(tc)
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
	return &Signer{cfg: cfg, pub: pub, conn: conn, cl: pb.NewMpcPartyClient(conn)}, nil
}

func (s *Signer) Close() { s.conn.Close() }

func (s *Signer) Backend() domain.Backend { return domain.BackendMPC }
func (s *Signer) Key() domain.Key {
	return domain.Key{ID: s.cfg.PartitionID, Backend: domain.BackendMPC, Curve: domain.CurveSecp256k1, MPCKeyRef: s.cfg.KeyID, PublicKey: s.cfg.PublicKey}
}
func (s *Signer) PublicKey() *ecdsa.PublicKey { return s.pub }

// SignDigest asks party A to sign digest. opts.JobID (the idempotency key) and opts.IntentPackage are required: they go
// to party B's cosigner, which refuses anything without them. TRANSPORT, LIMIT and UNAVAILABLE failures are retried with the same job
// id (safe: a stored signature is returned, nothing is signed twice) until MaxRetries or ctx ends.
func (s *Signer) SignDigest(ctx context.Context, digest [32]byte, opts signer.SignOptions) (signer.Result, error) {
	if opts.JobID == "" || len(opts.IntentPackage) == 0 {
		return signer.Result{}, &Error{Kind: KindInternal, Message: "job id and intent package are required"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	req := &pb.SignRequest{KeyId: s.cfg.KeyID, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: digest[:],
		JobId: opts.JobID, IntentPackage: opts.IntentPackage}
	start := time.Now()
	var last error
	for attempt := 0; attempt <= s.cfg.MaxRetries; attempt++ {
		resp, err := s.cl.Sign(ctx, req)
		if err == nil {
			sig, perr := parseDER(resp.Signature)
			if perr != nil {
				return signer.Result{}, &Error{Kind: KindCryptographic, Message: "bad signature from party A: " + perr.Error()}
			}
			return signer.Result{Sig: sig, Participants: []string{"mpc-a", "mpc-b"},
				Meta: map[string]any{"duration_ms": time.Since(start).Milliseconds(), "attempts": attempt + 1, "replayed": resp.Replayed}}, nil
		}
		last = classify(err)
		var e *Error
		if !errors.As(last, &e) || !e.SignerUnavailable() {
			return signer.Result{}, last
		}
		select {
		case <-ctx.Done():
			return signer.Result{}, last
		case <-time.After(time.Duration(100*(attempt+1)) * time.Millisecond):
		}
	}
	return signer.Result{}, last
}

// classify maps a gRPC error to *Error using the typed ErrorDetail.
func classify(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return &Error{Kind: KindTransport, Message: err.Error(), Err: err}
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*pb.ErrorDetail); ok {
			k := KindInternal
			switch ed.Kind {
			case pb.ErrorKind_ERROR_KIND_TRANSPORT:
				k = KindTransport
			case pb.ErrorKind_ERROR_KIND_LIMIT:
				k = KindLimit
			case pb.ErrorKind_ERROR_KIND_REFUSED:
				k = KindRefused
			case pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC:
				k = KindCryptographic
			case pb.ErrorKind_ERROR_KIND_FROZEN:
				k = KindFrozen
			case pb.ErrorKind_ERROR_KIND_UNAVAILABLE:
				k = KindUnavailable
			}
			return &Error{Kind: k, Message: ed.Message, Err: err}
		}
	}
	// No typed detail: a connection-level failure (certificate refused, server down) is a transport failure.
	switch st.Code().String() {
	case "Unavailable", "DeadlineExceeded", "Canceled":
		return &Error{Kind: KindTransport, Message: st.Message(), Err: err}
	}
	return &Error{Kind: KindInternal, Message: st.Message(), Err: err}
}

type derSig struct{ R, S *big.Int }

// parseDER converts a DER signature to (r, s), normalizes to low-S and asserts it.
func parseDER(der []byte) (signer.Signature, error) {
	var d derSig
	rest, err := asn1.Unmarshal(der, &d)
	if err != nil || len(rest) != 0 || d.R == nil || d.S == nil || d.R.Sign() <= 0 || d.S.Sign() <= 0 {
		return signer.Signature{}, errors.New("not a canonical DER signature")
	}
	sig := signer.NormalizeLowS(signer.Signature{R: d.R, S: d.S})
	if sig.S.Cmp(new(big.Int).Rsh(secpN(), 1)) > 0 {
		return signer.Signature{}, errors.New("S is not low after normalization")
	}
	return sig, nil
}

var _ signer.Signer = (*Signer)(nil)

// Deriving is the signer of a whole keyset's subtree: the key of any path below HardenedPath is made on demand by party A's Derive
// (which returns the same key id and public key every time) and signs through the same connection. It is how Bitcoin signs every input
// under its own key. It implements signer.Signer only so it can sit in the gateway's signer map: SignDigest on it is an error, a job
// has to name a path (At).
type Deriving struct {
	cfg DerivingConfig
	cl  pb.MpcPartyClient
	mu  sync.Mutex
	by  map[string]*Signer
	// base is the connection owner; children share its connection and do not close it.
	base *Signer
}

// DerivingConfig is Config without a key: the keyset and the hardened path stand in for KeyID and PublicKey.
type DerivingConfig struct {
	Config
	KeysetID     string
	HardenedPath []uint32
}

// NewDeriving connects to party A. Config.KeyID and PublicKey are ignored.
func NewDeriving(cfg DerivingConfig) (*Deriving, error) {
	if cfg.KeysetID == "" || len(cfg.HardenedPath) == 0 {
		return nil, errors.New("keyset id and hardened path are required")
	}
	// A throwaway valid key and id satisfy New's checks; the deriving signer never signs with them.
	cfg.Config.KeyID = "deriving"
	cfg.Config.PublicKey = crypto.FromECDSAPub(&ecdsa.PublicKey{Curve: crypto.S256(), X: crypto.S256().Params().Gx, Y: crypto.S256().Params().Gy})
	base, err := New(cfg.Config)
	if err != nil {
		return nil, err
	}
	return &Deriving{cfg: cfg, cl: pb.NewMpcPartyClient(base.conn), by: map[string]*Signer{}, base: base}, nil
}

func (d *Deriving) Close()                  { d.base.Close() }
func (d *Deriving) Backend() domain.Backend { return domain.BackendMPC }
func (d *Deriving) Key() domain.Key {
	return domain.Key{ID: d.cfg.PartitionID, Backend: domain.BackendMPC, Curve: domain.CurveSecp256k1}
}
func (d *Deriving) PublicKey() *ecdsa.PublicKey { return nil }
func (d *Deriving) RetryOnTimeout() bool        { return true }
func (d *Deriving) SignDigest(context.Context, [32]byte, signer.SignOptions) (signer.Result, error) {
	return signer.Result{}, &Error{Kind: KindInternal, Message: "a deriving signer signs through At(path)"}
}

// At derives the key at path (idempotent at party A) and returns its signer.
func (d *Deriving) At(ctx context.Context, path []uint32) (signer.Signer, error) {
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
	pk, err := crypto.DecompressPubkey(r.PublicKey)
	if err != nil {
		return nil, &Error{Kind: KindCryptographic, Message: "party A returned a bad public key: " + err.Error()}
	}
	child := *d.base
	child.cfg.KeyID = r.KeyId
	child.cfg.PublicKey = crypto.FromECDSAPub(pk)
	child.pub = pk
	s := &child
	d.by[key] = s
	return s, nil
}

var _ signer.Deriver = (*Deriving)(nil)
