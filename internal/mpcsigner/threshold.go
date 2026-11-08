package mpcsigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Coordinator is one party that can coordinate a 2-of-3 signature: A, then B. The gateway calls the first; it moves to the next only
// by the rule in ThresholdSigner.
type Coordinator struct {
	Name       string // "A" or "B": for logs and Participants
	Address    string // the party's caller port
	ClientCert tls.Certificate
	ServerPin  string // sha256 hex of that party's certificate
}

// ThresholdConfig is the signer of one EVM hot shard held as a 2-of-3 keyset on parties A, B and C (E23-3). The keyset IS the key:
// Sign names it as key_id; its public key is what the hot address is checked against at start.
type ThresholdConfig struct {
	PartitionID  string
	KeysetID     string
	PublicKey    []byte // 65-byte uncompressed secp256k1 (the keyset's public key)
	Coordinators []Coordinator
	MaxRetries   int           // rounds beyond the first; default 3
	Timeout      time.Duration // bounds one SignDigest including retries; default 30s
	Logger       *slog.Logger
	Dial         func(addr string, creds credentials.TransportCredentials) (*grpc.ClientConn, error) // tests
}

// ThresholdSigner is a signer.Signer over a 2-of-3 keyset.
//
// Fallback rule. A coordinator that answers with an AVAILABILITY failure (TRANSPORT or UNAVAILABLE, or no answer at all: the connection
// is refused) AND does not say that signing had started (ErrorDetail.code != CodeSigningStarted) failed before any signing message was
// exchanged: the next coordinator is tried at once, in the same round. Every other failure ends the round without trying anyone else:
// REFUSED (a cosigner said no), CRYPTOGRAPHIC and FROZEN (the keyset is suspect), LIMIT, INTERNAL, and an availability failure after
// signing started.
//
// Retry composition. MaxRetries counts ROUNDS, as for the 2-party signer. A round tries each coordinator at most once, in order. A
// job therefore makes at most (MaxRetries+1) x (number of coordinators) calls and cannot loop between coordinators. An availability
// failure after signing started pins the rest of the call to that coordinator (later rounds retry the same one, as the 2-party
// signer does; the service is idempotent per job id on each coordinator). A second signature over the same digest through the other
// coordinator is possible after an A failure that left no trace: harmless (same transaction, same nonce), and the gateway's guard
// still refuses a different digest under one job.
type ThresholdSigner struct {
	cfg   ThresholdConfig
	pub   *ecdsa.PublicKey
	log   *slog.Logger
	conns []*grpc.ClientConn
	cls   []pb.MpcPartyClient

	mu       sync.Mutex
	degraded bool
}

func pinnedCreds(cert tls.Certificate, pinHex string) (credentials.TransportCredentials, error) {
	pin, err := hex.DecodeString(strings.ToLower(pinHex))
	if err != nil || len(pin) != 32 {
		return nil, errors.New("server_pin must be 64 hex chars (sha256 of the party's certificate)")
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true, //nolint:gosec // pinned below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			if sum := sha256.Sum256(raw[0]); string(sum[:]) != string(pin) {
				return errors.New("the party's certificate is not the pinned one")
			}
			return nil
		},
	}), nil
}

func NewThreshold(cfg ThresholdConfig) (*ThresholdSigner, error) {
	pub, err := signerParse(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	if cfg.KeysetID == "" || len(cfg.Coordinators) == 0 {
		return nil, errors.New("keyset id and at least one coordinator are required")
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	t := &ThresholdSigner{cfg: cfg, pub: pub, log: lg}
	dial := cfg.Dial
	if dial == nil {
		dial = func(addr string, c credentials.TransportCredentials) (*grpc.ClientConn, error) {
			// A short reconnect backoff: the first coordinator must be noticed again within seconds of coming back (gRPC's default
			// backoff grows to two minutes).
			return grpc.NewClient(addr, grpc.WithTransportCredentials(c), grpc.WithConnectParams(grpc.ConnectParams{
				Backoff:           backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 2 * time.Second},
				MinConnectTimeout: 2 * time.Second}))
		}
	}
	for _, c := range cfg.Coordinators {
		if c.Address == "" || c.Name == "" {
			t.Close()
			return nil, errors.New("every coordinator needs a name and an address")
		}
		creds, err := pinnedCreds(c.ClientCert, c.ServerPin)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("coordinator %s: %w", c.Name, err)
		}
		conn, err := dial(c.Address, creds)
		if err != nil {
			t.Close()
			return nil, err
		}
		t.conns = append(t.conns, conn)
		t.cls = append(t.cls, pb.NewMpcPartyClient(conn))
	}
	return t, nil
}

func (t *ThresholdSigner) Close() {
	for _, c := range t.conns {
		c.Close()
	}
}

func (t *ThresholdSigner) Backend() domain.Backend { return domain.BackendMPC }
func (t *ThresholdSigner) Key() domain.Key {
	return domain.Key{ID: t.cfg.PartitionID, Backend: domain.BackendMPC, Curve: domain.CurveSecp256k1, MPCKeyRef: t.cfg.KeysetID, PublicKey: t.cfg.PublicKey}
}
func (t *ThresholdSigner) PublicKey() *ecdsa.PublicKey { return t.pub }

// RetryOnTimeout: as for the 2-party signer, a sign_timeout means "try again later", never "failed".
func (t *ThresholdSigner) RetryOnTimeout() bool { return true }

// fallbackOK is the rule above for one failure.
func fallbackOK(e *Error) bool {
	return (e.Kind == KindTransport || e.Kind == KindUnavailable) && !e.Started
}

func (t *ThresholdSigner) SignDigest(ctx context.Context, digest [32]byte, opts signer.SignOptions) (signer.Result, error) {
	if opts.JobID == "" || len(opts.IntentPackage) == 0 {
		return signer.Result{}, &Error{Kind: KindInternal, Message: "job id and intent package are required"}
	}
	ctx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	defer cancel()
	req := &pb.SignRequest{KeyId: t.cfg.KeysetID, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: digest[:],
		JobId: opts.JobID, IntentPackage: opts.IntentPackage}
	start := time.Now()
	var last error
	pinned := -1 // set after an availability failure that happened once signing had started
	calls := 0
	for round := 0; round <= t.cfg.MaxRetries; round++ {
		for i := range t.cls {
			if pinned >= 0 && i != pinned {
				continue
			}
			calls++
			resp, err := t.cls[i].Sign(ctx, req)
			if err == nil {
				sig, perr := parseDER(resp.Signature)
				if perr != nil {
					return signer.Result{}, &Error{Kind: KindCryptographic, Message: "bad signature from party " + t.cfg.Coordinators[i].Name + ": " + perr.Error()}
				}
				t.note(i)
				return signer.Result{Sig: sig, Participants: []string{"mpc-" + strings.ToLower(t.cfg.Coordinators[i].Name), "mpc-2of3"},
					Meta: map[string]any{"duration_ms": time.Since(start).Milliseconds(), "calls": calls, "coordinator": t.cfg.Coordinators[i].Name, "replayed": resp.Replayed}}, nil
			}
			last = classify(err)
			var e *Error
			if !errors.As(last, &e) || !e.SignerUnavailable() {
				return signer.Result{}, last // refused, cryptographic, frozen, internal: final, nobody else is asked
			}
			if fallbackOK(e) {
				if i+1 < len(t.cls) {
					continue // failed before any signing message: the next coordinator, same round
				}
				break
			}
			pinned = i // signing had started on this coordinator: only it is retried
			break
		}
		select {
		case <-ctx.Done():
			return signer.Result{}, last
		case <-time.After(time.Duration(100*(round+1)) * time.Millisecond):
		}
	}
	return signer.Result{}, last
}

// note records which coordinator signed and logs the transitions: one ALERT when the second coordinator starts being used, one INFO
// when the first is back. Per transition, not per job.
func (t *ThresholdSigner) note(i int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case i > 0 && !t.degraded:
		t.degraded = true
		t.log.Error("ALERT mpc signer degraded: the first coordinator does not answer, signing through the next",
			"partition", t.cfg.PartitionID, "keyset_id", t.cfg.KeysetID, "using", t.cfg.Coordinators[i].Name, "unavailable", t.cfg.Coordinators[0].Name)
	case i == 0 && t.degraded:
		t.degraded = false
		t.log.Info("mpc signer recovered: the first coordinator signs again",
			"partition", t.cfg.PartitionID, "keyset_id", t.cfg.KeysetID, "coordinator", t.cfg.Coordinators[0].Name)
	}
}

var _ signer.Signer = (*ThresholdSigner)(nil)
