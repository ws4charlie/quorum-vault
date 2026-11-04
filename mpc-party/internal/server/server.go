package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

const Version = "p5b-2"

// Options are the injected parts of a Server. Store is optional (built from the config when nil).
type Options struct {
	Config     *Config
	Authorizer Authorizer
	Store      interface {
		KeyStore
		JobStore
	}
	Logger         *slog.Logger
	FaultInjection *FaultInjection // tests only
}

type Server struct {
	cfg   *Config
	log   *slog.Logger
	authz Authorizer
	store interface {
		KeyStore
		JobStore
	}
	fi    *FaultInjection
	cert  tls.Certificate
	cache *keyCache
	stats frameStats

	rl      *rateLimiter
	slots   *slots // concurrent sessions: outgoing on A, incoming on B
	replay  *replayCache
	wg      sync.WaitGroup
	stopMu  sync.Mutex
	stopped bool

	callerLn, peerLn net.Listener
	callerSrv        *grpc.Server
	peerSrv          *grpc.Server
	peerConn         *grpc.ClientConn
	peerClient       pb.PeerClient

	jobMu    sync.Mutex
	inflight map[string]*flight

	pb.UnimplementedMpcPartyServer
	pb.UnimplementedPeerServer
}

type flight struct {
	done chan struct{}
}

func New(o Options) (*Server, error) {
	if o.Config == nil {
		return nil, errors.New("config is required")
	}
	if err := o.Config.Validate(); err != nil {
		return nil, err
	}
	if o.Authorizer == nil {
		return nil, ErrNoAuthorizer
	}
	c := o.Config
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls key pair: %w", err)
	}
	lg := o.Logger
	if lg == nil {
		lg = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	st := o.Store
	if st == nil {
		sealer, err := NewSealer(c.Sealer)
		if err != nil {
			return nil, err
		}
		fs, err := NewFileStore(c.DataDir, c.Role, sealer)
		if err != nil {
			return nil, err
		}
		st = fs
		if c.Sealer.Type == InsecureSealerType {
			lg.Warn("using the insecure test sealer: key shares are only as safe as the key file next to them")
		}
	}
	return &Server{cfg: c, log: lg, authz: o.Authorizer, store: st, fi: o.FaultInjection, cert: cert,
		cache: newKeyCache(), rl: newRateLimiter(c.Limits.SessionsPerSecKey), slots: newSlots(c.Limits.MaxPeerSessions),
		replay: newReplayCache(c.Limits.ReplayCacheSize), inflight: map[string]*flight{}}, nil
}

func (s *Server) CallerAddr() string {
	if s.callerLn == nil {
		return ""
	}
	return s.callerLn.Addr().String()
}

func (s *Server) PeerAddr() string {
	if s.peerLn == nil {
		return ""
	}
	return s.peerLn.Addr().String()
}

// MaxFrameSeen is the largest protocol message observed on peer sessions (to size max_frame_bytes).
func (s *Server) MaxFrameSeen() int { s.stats.mu.Lock(); defer s.stats.mu.Unlock(); return s.stats.Max }

func (s *Server) ActiveSessions() int { return s.slots.active() }

// Start opens the listeners and serves in the background.
func (s *Server) Start() error {
	c := s.cfg
	callerPins, err := parsePins(c.CallerPins)
	if err != nil {
		return err
	}
	peerPins, err := parsePins(c.PeerPins)
	if err != nil {
		return err
	}
	maxMsg := c.Limits.MaxFrameBytes + 64<<10
	common := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxMsg), grpc.MaxSendMsgSize(maxMsg),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
	}

	s.callerLn, err = net.Listen("tcp", c.CallerListen)
	if err != nil {
		return err
	}
	s.callerSrv = grpc.NewServer(append(common, grpc.Creds(credentials.NewTLS(ServerTLS(s.cert, callerPins))))...)
	if c.Role == "A" {
		pb.RegisterMpcPartyServer(s.callerSrv, s)
		// Party A dials B on the peer port.
		conn, err := grpc.NewClient(c.PeerAddress,
			grpc.WithTransportCredentials(credentials.NewTLS(ClientTLS(s.cert, peerPins))),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsg), grpc.MaxCallSendMsgSize(maxMsg)),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
			grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, MaxDelay: time.Second}, MinConnectTimeout: 2 * time.Second}))
		if err != nil {
			return err
		}
		s.peerConn = conn
		s.peerClient = pb.NewPeerClient(conn)
		conn.Connect()
	} else {
		pb.RegisterMpcPartyServer(s.callerSrv, healthOnly{s: s})
		s.peerLn, err = net.Listen("tcp", c.PeerListen)
		if err != nil {
			return err
		}
		s.peerSrv = grpc.NewServer(append(common, grpc.MaxConcurrentStreams(uint32(2*c.Limits.MaxPeerSessions)+4),
			grpc.Creds(credentials.NewTLS(ServerTLS(s.cert, peerPins))))...)
		pb.RegisterPeerServer(s.peerSrv, s)
		go s.peerSrv.Serve(s.peerLn)
	}
	go s.callerSrv.Serve(s.callerLn)
	s.log.Info("serving", "role", c.Role, "caller", s.CallerAddr(), "peer", s.PeerAddr(), "version", Version, "cbmpc_commit", cbmpc.PinnedCommit)
	return nil
}

// Shutdown stops accepting, waits for running sessions until ctx ends, then stops hard and wipes all keysets.
func (s *Server) Shutdown(ctx context.Context) {
	s.stopMu.Lock()
	if s.stopped {
		s.stopMu.Unlock()
		return
	}
	s.stopped = true
	s.stopMu.Unlock()
	done := make(chan struct{})
	go func() {
		for _, g := range []*grpc.Server{s.callerSrv, s.peerSrv} {
			if g != nil {
				g.GracefulStop()
			}
		}
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn("shutdown deadline reached, stopping running sessions")
		for _, g := range []*grpc.Server{s.callerSrv, s.peerSrv} {
			if g != nil {
				g.Stop()
			}
		}
		s.wg.Wait()
	}
	if s.peerConn != nil {
		s.peerConn.Close()
	}
	s.cache.wipeAll()
	s.log.Info("stopped, keysets wiped")
}

func (s *Server) peerReachable() bool {
	return s.peerConn != nil && s.peerConn.GetState() == connectivity.Ready
}

// healthOnly is what party B serves on its caller port: Health. Everything else is Unimplemented (Sign and key
// operations belong to party A).
type healthOnly struct {
	pb.UnimplementedMpcPartyServer
	s *Server
}

func (h healthOnly) Health(ctx context.Context, r *pb.HealthRequest) (*pb.HealthResponse, error) {
	return h.s.Health(ctx, r)
}

// keyCache keeps unsealed keysets (secrets in C memory) so a session does not unseal and parse on every call.
type keyCache struct {
	mu sync.Mutex
	m  map[string]*cbmpc.Keyset
}

func newKeyCache() *keyCache { return &keyCache{m: map[string]*cbmpc.Keyset{}} }

func (c *keyCache) get(ctx context.Context, st KeyStore, id string) (*cbmpc.Keyset, error) {
	if !validID(id) {
		return nil, invalid("keyset", "invalid keyset id")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ks, ok := c.m[id]; ok {
		return ks, nil
	}
	ks, err := st.GetKeyset(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, failf(pb.ErrorKind_ERROR_KIND_INTERNAL, codes.NotFound, "keyset", "keyset %q not found", id)
	}
	if err != nil {
		return nil, fromWrapper("keyset", err)
	}
	c.m[id] = ks
	return ks, nil
}

func (c *keyCache) drop(id string) {
	c.mu.Lock()
	old := c.m[id]
	delete(c.m, id)
	c.mu.Unlock()
	if old != nil {
		go old.Wipe() // waits for sessions still using it
	}
}

func (c *keyCache) wipeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ks := range c.m {
		ks.Wipe()
		delete(c.m, id)
	}
}
