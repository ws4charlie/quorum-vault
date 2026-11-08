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
	"google.golang.org/grpc/status"

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
	fi         *FaultInjection
	admin      *adminVerifier
	freeze     FreezeStore
	cert       tls.Certificate
	cache      *keyCache
	rtMu       sync.Mutex
	rts        map[string]*ksRT
	linksUp    map[string]bool
	kick       chan struct{}
	loopCancel context.CancelFunc
	stats      frameStats

	rl      *rateLimiter
	slots   *slots // concurrent sessions: outgoing on A, incoming on B
	replay  *replayCache
	wg      sync.WaitGroup
	stopMu  sync.Mutex
	stopped bool

	callerLn, peerLn net.Listener
	callerSrv        *grpc.Server
	peerSrv          *grpc.Server
	peerA, peerB     map[Pin]bool // party C: who may be calling, by certificate
	peerConn         *grpc.ClientConn
	peerClient       pb.PeerClient
	peerCConn        *grpc.ClientConn // A and B: the link to party C (2-of-3 keysets)
	peerCClient      pb.PeerClient
	tcache           *tkeyCache
	groups           groupTable

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
	adm, err := newAdminVerifier(c)
	if err != nil {
		return nil, err
	}
	fz, err := newFileFreeze(c.DataDir)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: c, log: lg, admin: adm, freeze: fz, authz: o.Authorizer, store: st, fi: o.FaultInjection, cert: cert,
		cache: newKeyCache(), tcache: newTKeyCache(), rts: map[string]*ksRT{}, kick: make(chan struct{}, 1), rl: newRateLimiter(c.Limits.SessionsPerSecKey), slots: newSlots(c.Limits.MaxPeerSessions),
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
	dial := func(addr string, pins map[Pin]bool) (*grpc.ClientConn, error) {
		return grpc.NewClient(addr,
			grpc.WithTransportCredentials(credentials.NewTLS(ClientTLS(s.cert, pins))),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsg), grpc.MaxCallSendMsgSize(maxMsg)),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
			grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, MaxDelay: time.Second}, MinConnectTimeout: 2 * time.Second}))
	}
	if c.PeerCAddress != "" { // A and B dial C
		cpins, err := parsePins(c.PeerCPins)
		if err != nil {
			return err
		}
		conn, err := dial(c.PeerCAddress, cpins)
		if err != nil {
			return err
		}
		s.peerCConn, s.peerCClient = conn, pb.NewPeerClient(conn)
		conn.Connect()
	}
	switch c.Role {
	case "A":
		pb.RegisterMpcPartyServer(s.callerSrv, s)
		// Party A dials B on the peer port.
		conn, err := dial(c.PeerAddress, peerPins)
		if err != nil {
			return err
		}
		s.peerConn = conn
		s.peerClient = pb.NewPeerClient(conn)
		conn.Connect()
		lctx, lcancel := context.WithCancel(context.Background())
		s.loopCancel = lcancel
		go s.reconcileLoop(lctx)
		go s.watchPeer(lctx, s.peerConn, "B", true)
		go s.watchLink(lctx, s.peerConn, "B")
		if s.peerCConn != nil {
			go s.watchPeer(lctx, s.peerCConn, "C", false)
			go s.watchLink(lctx, s.peerCConn, "C")
		}
	case "B":
		if s.peerCConn != nil {
			// keep the link to C alive: a gRPC channel goes idle after a drop and reconnects only when asked
			lctx, lcancel := context.WithCancel(context.Background())
			s.loopCancel = lcancel
			go s.watchLink(lctx, s.peerCConn, "C")
			go func() {
				t := time.NewTicker(500 * time.Millisecond)
				defer t.Stop()
				for {
					select {
					case <-lctx.Done():
						return
					case <-t.C:
						s.peerCConn.Connect()
					}
				}
			}()
		}
		pb.RegisterMpcPartyServer(s.callerSrv, bCaller{s: s})
		s.peerLn, err = net.Listen("tcp", c.PeerListen)
		if err != nil {
			return err
		}
		s.peerSrv = grpc.NewServer(append(common, grpc.MaxConcurrentStreams(uint32(2*c.Limits.MaxPeerSessions)+4),
			grpc.Creds(credentials.NewTLS(ServerTLS(s.cert, peerPins))))...)
		pb.RegisterPeerServer(s.peerSrv, s)
		go s.peerSrv.Serve(s.peerLn)
	case "C":
		pb.RegisterMpcPartyServer(s.callerSrv, healthOnly{s: s})
		apins, err := parsePins(c.PeerAPins)
		if err != nil {
			return err
		}
		bpins, err := parsePins(c.PeerBPins)
		if err != nil {
			return err
		}
		s.peerA, s.peerB = apins, bpins
		all := map[Pin]bool{}
		for p := range apins {
			all[p] = true
		}
		for p := range bpins {
			all[p] = true
		}
		s.peerLn, err = net.Listen("tcp", c.PeerListen)
		if err != nil {
			return err
		}
		s.peerSrv = grpc.NewServer(append(common, grpc.MaxConcurrentStreams(uint32(4*c.Limits.MaxPeerSessions)+8),
			grpc.Creds(credentials.NewTLS(ServerTLS(s.cert, all))))...)
		pb.RegisterPeerServer(s.peerSrv, s)
		go s.peerSrv.Serve(s.peerLn)
	}
	go s.callerSrv.Serve(s.callerLn)
	s.log.Info("serving", "role", c.Role, "caller", s.CallerAddr(), "peer", s.PeerAddr(), "version", Version, "cbmpc_commit", cbmpc.PinnedCommit)
	return nil
}

// Shutdown stops accepting, waits for running sessions until ctx ends, then stops hard and wipes all keysets.
func (s *Server) Shutdown(ctx context.Context) {
	if s.loopCancel != nil {
		s.loopCancel()
	}
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
	if s.peerCConn != nil {
		s.peerCConn.Close()
	}
	s.cache.wipeAll()
	s.tcache.wipeAll()
	s.log.Info("stopped, keysets wiped")
}

func (s *Server) peerReachable() bool {
	if s.cfg.Role == "B" {
		return s.peerCConn != nil && s.peerCConn.GetState() == connectivity.Ready
	}
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

// bCaller is what party B serves on its caller port: Health, and Sign for 2-of-3 keysets (B coordinates B+C signatures). Key
// operations and 2-party keysets belong to party A.
type bCaller struct {
	pb.UnimplementedMpcPartyServer
	s *Server
}

func (b bCaller) Health(ctx context.Context, r *pb.HealthRequest) (*pb.HealthResponse, error) {
	return b.s.Health(ctx, r)
}

func (b bCaller) Sign(ctx context.Context, r *pb.SignRequest) (*pb.SignResponse, error) {
	if validID(r.GetKeyId()) {
		if st, err := b.s.store.State(ctx, r.KeyId); err == nil && st.Scheme == int32(pb.Scheme_SCHEME_ECDSA_2OF3) && st.Current != 0 {
			return b.s.Sign(ctx, r)
		}
	}
	return nil, status.Error(codes.Unimplemented, "party B signs 2-of-3 keysets only; 2-party keys are signed through party A")
}
