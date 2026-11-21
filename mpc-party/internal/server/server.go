package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
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
	dataLock *dataLock // held until Shutdown (or the process ends)
	started  atomic.Bool
	cfg      *Config
	log      *slog.Logger
	authz    Authorizer
	store    interface {
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
	ident      *tlsHolder  // the sealed TLS identity (tls_sealed); nil when the key is a file
	gate       *sealerGate // attested sealer: the party is not ready until it holds its data keys (nil for the other sealers)
	gateCancel context.CancelFunc
	stats      frameStats
	fails      *failStats // failed sessions by side, op, suspected peer and kind (read-only metrics)
	metricsLn  net.Listener
	metricsSrv *http.Server

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
	lastA            atomic.Int64 // party B: when A last opened a session here (unix nanoseconds), for the pair reconcile with C
	pairMu           sync.Mutex
	pairBusy         map[string]bool
	pairLast         map[string]time.Time

	jobMu    sync.Mutex
	inflight map[string]*flight

	pb.UnimplementedMpcPartyServer
	pb.UnimplementedPeerServer
}

type flight struct {
	done chan struct{}
}

func New(o Options) (srv *Server, err error) {
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
	// One process per data directory, checked before anything is read or written (and before the HSM login): a second one refuses to start.
	lock, err := acquireDataLock(c.DataDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			lock.release()
		}
	}()
	var cert tls.Certificate
	var ident *tlsHolder
	if c.TLSSealed {
		ident = &tlsHolder{} // filled by the sealer gate once the data keys are released
	} else if cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
		return nil, fmt.Errorf("tls key pair: %w", err)
	}
	lg := o.Logger
	if lg == nil {
		lg = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	st := o.Store
	if st == nil {
		sealer, err := NewSealerForRole(c.Role, c.Sealer)
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
	adm.persistOn(st, c.DataDir)
	adm.log = lg
	if adm.allowV1 && c.AdminThreshold > 0 {
		lg.Warn("the v1 admin authorization is still accepted (admin_allow_v1): it covers no request field beyond the keyset and needs no quorum; switch it off after the roll-over", "admin_threshold", c.AdminThreshold)
	}
	var fz *fileFreeze
	if fs, ok := st.(*FileStore); ok {
		fz, err = newFileFreezeOn(fs)
	} else {
		fz, err = newFileFreeze(c.DataDir)
	}
	if err != nil {
		return nil, err
	}
	gate := newSealerGate(st, c.Role, lg)
	if ident != nil {
		if gate == nil {
			return nil, errors.New("tls_sealed needs the attested sealer")
		}
		fs := st.(*FileStore)
		gate.afterKeys = func(ctx context.Context) error {
			cert, err := fs.LoadTLSIdentity(ctx)
			if err != nil {
				return err
			}
			ident.p.Store(cert)
			return nil
		}
		if ia, ok := o.Authorizer.(IdentityAware); ok {
			ia.SetIdentity(ident.get)
		}
	}
	return &Server{gate: gate, ident: ident, dataLock: lock, cfg: c, log: lg, admin: adm, freeze: fz, authz: o.Authorizer, store: st, fi: o.FaultInjection, cert: cert,
		fails: newFailStats(c.Role), cache: newKeyCache(), tcache: newTKeyCache(), rts: map[string]*ksRT{}, kick: make(chan struct{}, 1), rl: newRateLimiter(c.Limits.SessionsPerSecKey), slots: newSlots(c.Limits.MaxPeerSessions),
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

	if err := s.startMetrics(); err != nil {
		return err
	}
	if s.gate != nil { // the attested sealer: fetch the data keys in the background; the party is not ready until they are here
		gctx, gcancel := context.WithCancel(context.Background())
		s.gateCancel = gcancel
		go s.gate.run(gctx)
	}
	s.callerLn, err = net.Listen("tcp", c.CallerListen)
	if err != nil {
		return err
	}
	s.callerSrv = grpc.NewServer(append(common, grpc.Creds(credentials.NewTLS(s.tlsServer(callerPins))))...)
	dial := func(addr string, pins map[Pin]bool) (*grpc.ClientConn, error) {
		return grpc.NewClient(addr,
			grpc.WithTransportCredentials(credentials.NewTLS(s.tlsClient(pins))),
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
			s.pairBusy, s.pairLast = map[string]bool{}, map[string]time.Time{}
			s.noteContactFromA() // A counts as silent from now on until it opens a session here
			go func() {
				t := time.NewTicker(500 * time.Millisecond)
				defer t.Stop()
				for {
					select {
					case <-lctx.Done():
						return
					case <-t.C:
						s.peerCConn.Connect()
						s.pairLoopStep(lctx)
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
			grpc.Creds(credentials.NewTLS(s.tlsServer(peerPins))))...)
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
			grpc.Creds(credentials.NewTLS(s.tlsServer(all))))...)
		pb.RegisterPeerServer(s.peerSrv, s)
		go s.peerSrv.Serve(s.peerLn)
	}
	go s.callerSrv.Serve(s.callerLn)
	s.started.Store(true)
	s.log.Info("serving", "role", c.Role, "caller", s.CallerAddr(), "peer", s.PeerAddr(), "version", Version, "cbmpc_commit", cbmpc.PinnedCommit)
	return nil
}

// Shutdown stops accepting, waits for running sessions until ctx ends, then stops hard and wipes all keysets.
func (s *Server) Shutdown(ctx context.Context) {
	if s.loopCancel != nil {
		s.loopCancel()
	}
	if s.gateCancel != nil {
		s.gateCancel()
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
	s.stopMetrics()
	s.cache.wipeAll()
	s.tcache.wipeAll()
	if s.gate != nil {
		s.gate.as.Close() // wipes every data key
	}
	s.dataLock.release() // last: nothing writes to the directory after this
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
		if st, err := b.s.store.State(ctx, r.KeyId); err == nil && isTScheme(st.Scheme) && st.Current != 0 {
			return b.s.Sign(ctx, r)
		}
	}
	return nil, status.Error(codes.Unimplemented, "party B signs 2-of-3 keysets only; 2-party keys are signed through party A")
}
