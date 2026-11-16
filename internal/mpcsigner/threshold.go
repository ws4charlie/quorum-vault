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
	"google.golang.org/protobuf/proto"

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
	// Router, when set, chooses the pair of every job (operator's preferred pair, health fallback; see route.go) and the signer names the wanted
	// peer in every request. Nil: the legacy order, coordinators as listed, each choosing its own peer.
	Router     *Router
	MaxRetries int           // rounds beyond the first; default 3
	Timeout    time.Duration // bounds one SignDigest including retries; default 30s
	Logger     *slog.Logger
	Dial       func(addr string, creds credentials.TransportCredentials) (*grpc.ClientConn, error) // tests
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
	*thresholdCore
	pub *ecdsa.PublicKey
}

// thresholdCore is what every 2-of-3 signer shares, whatever the curve: the connections to the coordinators, the fallback rule, the retry
// composition and the degraded-state alerts. ECDSA (ThresholdSigner) and Ed25519 (EdThresholdSigner, ed.go) differ only in the request
// they send and the signature they parse.
type thresholdCore struct {
	cfg   ThresholdConfig
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
	core, err := newThresholdCore(cfg)
	if err != nil {
		return nil, err
	}
	return &ThresholdSigner{thresholdCore: core, pub: pub}, nil
}

func newThresholdCore(cfg ThresholdConfig) (*thresholdCore, error) {
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
	t := &thresholdCore{cfg: cfg, log: lg}
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

func (t *thresholdCore) Close() {
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
	resp, st, calls, err := t.call(ctx, req)
	if err != nil {
		return signer.Result{}, err
	}
	if e := checkPeer(st, resp); e != nil {
		return signer.Result{}, e
	}
	sig, perr := parseDER(resp.Signature)
	if perr != nil {
		return signer.Result{}, &Error{Kind: KindCryptographic, Message: "bad signature from party " + t.cfg.Coordinators[st.ci].Name + ": " + perr.Error()}
	}
	t.note(st)
	return signer.Result{Sig: sig, Participants: t.participants(st), Meta: t.meta(st, calls, start, resp)}, nil
}

// step is one attempt: the coordinator to call (an index into cfg.Coordinators) and the peer it must sign with ("" in the legacy order, where
// the coordinator chooses). pair is empty in the legacy order.
type step struct {
	ci   int
	peer string
	pair Pair
}

// steps is the order of attempts for one job. With a Router: the plan's pairs (the effective pair first), each as its coordinator and wanted
// peer; a pair whose coordinator is not configured is left out. Without: the coordinators as listed.
func (t *thresholdCore) steps(ctx context.Context) (steps []step, plan Plan) {
	if t.cfg.Router == nil {
		for i := range t.cls {
			steps = append(steps, step{ci: i})
		}
		return steps, Plan{}
	}
	plan = t.cfg.Router.Plan(ctx)
	for _, p := range plan.Steps {
		for i, c := range t.cfg.Coordinators {
			if c.Name == p.Coordinator() {
				steps = append(steps, step{ci: i, peer: p.Peer(), pair: p})
			}
		}
	}
	return steps, plan
}

// call runs req through the steps by the fallback rule and the retry composition above. It returns the first answer, the step that gave it and how
// many calls were made; on failure the last classified error. The caller bounds ctx. The plan is taken once, when the job starts: a job already
// signing finishes on its pair even if the operator or the health checks change the route meanwhile.
func (t *thresholdCore) call(ctx context.Context, req *pb.SignRequest) (resp *pb.SignResponse, from step, calls int, _ error) {
	steps, _ := t.steps(ctx)
	if len(steps) == 0 {
		return nil, step{}, 0, &Error{Kind: KindInternal, Message: "no configured coordinator can serve any pair of the route"}
	}
	var last error
	pinned := -1 // set after an availability failure that happened once signing had started
	for round := 0; round <= t.cfg.MaxRetries; round++ {
		down := map[int]bool{} // coordinators that did not answer at all this round: their other pairs are not tried
		for si, st := range steps {
			if pinned >= 0 && si != pinned || down[st.ci] {
				continue
			}
			calls++
			r := proto.Clone(req).(*pb.SignRequest) // the request differs only in the wanted peer
			r.Peer = st.peer
			rs, err := t.cls[st.ci].Sign(ctx, r)
			if err == nil {
				return rs, st, calls, nil
			}
			last = classify(err)
			var e *Error
			if !errors.As(last, &e) || !e.SignerUnavailable() {
				return nil, step{}, calls, last // refused, cryptographic, frozen, internal: final, nobody else is asked
			}
			if fallbackOK(e) {
				if e.Kind == KindTransport {
					down[st.ci] = true
				}
				if si+1 < len(steps) {
					continue // failed before any signing message: the next pair, same round
				}
				break
			}
			pinned = si // signing had started on this pair: only it is retried
			break
		}
		select {
		case <-ctx.Done():
			return nil, step{}, calls, last
		case <-time.After(time.Duration(100*(round+1)) * time.Millisecond):
		}
	}
	return nil, step{}, calls, last
}

// checkPeer is the "no silent swap" rule for the pair A+C: an old party that does not know the wanted peer would sign with B and say nothing.
// A response that names another peer than the one asked for, or none when the pair is A+C, is refused (the signature is not released).
func checkPeer(st step, r *pb.SignResponse) *Error {
	if st.peer == "" || r.Replayed { // a replay returns the stored signature, whichever pair made it
		return nil
	}
	if r.SignedWith == st.peer || r.SignedWith == "" && st.pair != PairAC {
		return nil
	}
	got := fmt.Sprintf("%q", r.SignedWith)
	if r.SignedWith == "" {
		got = "none named (the party may predate the wanted-peer field)"
	}
	return &Error{Kind: KindInternal, Message: fmt.Sprintf("party %s signed with peer %s although %q was asked for: not releasing the signature", st.pair.Coordinator(), got, st.peer)}
}

func (t *thresholdCore) participants(st step) []string {
	c := strings.ToLower(t.cfg.Coordinators[st.ci].Name)
	if st.pair == "" {
		return []string{"mpc-" + c, "mpc-2of3"}
	}
	return []string{"mpc-" + c, "mpc-" + strings.ToLower(st.peer), "mpc-2of3"}
}

func (t *thresholdCore) meta(st step, calls int, start time.Time, resp *pb.SignResponse) map[string]any {
	m := map[string]any{"duration_ms": time.Since(start).Milliseconds(), "calls": calls, "coordinator": t.cfg.Coordinators[st.ci].Name, "replayed": resp.Replayed}
	if st.pair != "" {
		m["pair"] = string(st.pair)
	}
	return m
}

// note records which coordinator signed and logs the transitions: one ALERT when the second coordinator starts being used, one INFO
// when the first is back. Per transition, not per job. With a Router the route logs its own transitions (route.go) and this does nothing.
func (t *thresholdCore) note(st step) {
	if t.cfg.Router != nil {
		return
	}
	i := st.ci
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
