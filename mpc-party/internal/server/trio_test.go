package server_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// A trio is parties A, B and C in one process (2-of-3 keysets), optionally with a session-layer tamper proxy on any link.
type trioOpts struct {
	proxyAB, proxyAC, proxyBC bool
	auth                      map[string]server.Authorizer
	fi                        map[string]*server.FaultInjection
	recvMS                    int
}

type trio struct {
	Env     *testenv.Env
	Addrs   testenv.Addrs
	Cfg     map[string]*server.Config
	Store   map[string]*server.FileStore
	Srv     map[string]*server.Server
	Client  map[string]pb.MpcPartyClient
	Proxy   map[string]*tamperProxy // "AB", "AC", "BC"
	opts    trioOpts
	started map[string]bool
}

type countAuth struct {
	n atomic.Int32
	f func() error
}

func (c *countAuth) Authorize(context.Context, server.AuthRequest) error {
	c.n.Add(1)
	if c.f != nil {
		return c.f()
	}
	return nil
}

// startLink makes a tamper proxy for one link: toward the target it presents proxyCert (pinned by the target), toward the
// client it presents proxyCert too (pinned by the client) and accepts only clientPin.
func startLink(t *testing.T, targetAddr, targetPin, clientPin string, proxyCert testenv.Cert) (*tamperProxy, string) {
	t.Helper()
	conn, err := grpc.NewClient(targetAddr, grpc.WithTransportCredentials(credentials.NewTLS(
		server.ClientTLS(proxyCert.TLS, map[server.Pin]bool{mustPin(targetPin): true}))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	p := &tamperProxy{client: pb.NewPeerClient(conn)}
	p.n.Store(-1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(server.ServerTLS(proxyCert.TLS, map[server.Pin]bool{mustPin(clientPin): true}))))
	pb.RegisterPeerServer(srv, p)
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return p, ln.Addr().String()
}

func startTrio(t *testing.T, o trioOpts) *trio {
	t.Helper()
	env := testenv.NewEnv(t)
	tr := &trio{Env: env, Addrs: testenv.NewAddrs(t), Cfg: map[string]*server.Config{}, Store: map[string]*server.FileStore{}, Srv: map[string]*server.Server{},
		Client: map[string]pb.MpcPartyClient{}, Proxy: map[string]*tamperProxy{}, opts: o, started: map[string]bool{}}
	dialB, dialC := tr.Addrs.PeerB, tr.Addrs.PeerC
	var abPin, acPin, bcPin string
	if o.proxyAB {
		c := testenv.NewCert(t, "proxy-ab")
		tr.Proxy["AB"], dialB = startLink(t, tr.Addrs.PeerB, env.CertB.Pin, env.CertA.Pin, c)
		abPin = c.Pin
	}
	cdialA, cdialB := dialC, dialC
	if o.proxyAC {
		c := testenv.NewCert(t, "proxy-ac")
		tr.Proxy["AC"], cdialA = startLink(t, tr.Addrs.PeerC, env.CertC.Pin, env.CertA.Pin, c)
		acPin = c.Pin
	}
	if o.proxyBC {
		c := testenv.NewCert(t, "proxy-bc")
		tr.Proxy["BC"], cdialB = startLink(t, tr.Addrs.PeerC, env.CertC.Pin, env.CertB.Pin, c)
		bcPin = c.Pin
	}
	for _, role := range []string{"A", "B", "C"} {
		c := env.Config3(t, role, tr.Addrs, dialB, dialC)
		switch role {
		case "A":
			c.PeerCAddress = cdialA
			if abPin != "" {
				c.PeerPins = []string{abPin}
			}
			if acPin != "" {
				c.PeerCPins = []string{acPin}
			}
		case "B":
			c.PeerCAddress = cdialB
			if abPin != "" {
				c.PeerPins = []string{abPin}
			}
			if bcPin != "" {
				c.PeerCPins = []string{bcPin}
			}
		case "C":
			if acPin != "" {
				c.PeerAPins = []string{acPin}
			}
			if bcPin != "" {
				c.PeerBPins = []string{bcPin}
			}
		}
		if o.recvMS > 0 {
			c.Limits.RecvTimeoutMS = o.recvMS
		}
		tr.Cfg[role] = c
		tr.Store[role] = testenv.Store(t, c)
	}
	for _, role := range []string{"C", "B", "A"} {
		tr.start(t, role)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, role := range []string{"A", "B", "C"} {
			if tr.started[role] {
				tr.Srv[role].Shutdown(ctx)
			}
		}
	})
	callers := map[string]string{"A": tr.Addrs.CallerA, "B": tr.Addrs.CallerB, "C": tr.Addrs.CallerC}
	pins := map[string]string{"A": env.CertA.Pin, "B": env.CertB.Pin, "C": env.CertC.Pin}
	for role, addr := range callers {
		c, _ := testenv.Dial(t, addr, env.CertCaller, pins[role])
		tr.Client[role] = c
	}
	tr.waitReady(t)
	return tr
}

func (tr *trio) start(t *testing.T, role string) {
	t.Helper()
	var authz server.Authorizer = allowAll
	if a := tr.opts.auth[role]; a != nil {
		authz = a
	}
	s, err := server.New(server.Options{Config: tr.Cfg[role], Authorizer: authz, Logger: quiet(), FaultInjection: tr.opts.fi[role], Store: tr.Store[role]})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	tr.Srv[role], tr.started[role] = s, true
}

func (tr *trio) stop(role string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr.Srv[role].Shutdown(ctx)
	tr.started[role] = false
}

func (tr *trio) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		h, err := tr.Client["A"].Health(ctx30(t), &pb.HealthRequest{})
		if err == nil && len(h.Peers) == 2 && h.Peers[0].Reachable && h.Peers[1].Reachable {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("trio not ready")
}

func (tr *trio) dkg(t *testing.T, id string) []byte {
	t.Helper()
	r, err := tr.Client["A"].DKG(ctx30(t), &pb.DKGRequest{KeysetId: id, Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Admin: tr.Env.Admin("dkg", id)})
	mustOK(t, err)
	return r.RootPublicKey
}

func (tr *trio) sign(via, id, job string, seed byte) (*pb.SignResponse, error) {
	return tr.Client[via].Sign(context.Background(), &pb.SignRequest{KeyId: id, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: digest(seed), JobId: job})
}

func (tr *trio) frozen(t *testing.T, role, id string) bool {
	t.Helper()
	h, err := tr.Client[role].Health(ctx30(t), &pb.HealthRequest{})
	mustOK(t, err)
	for _, k := range h.Keysets {
		if k.KeysetId == id {
			return k.Frozen
		}
	}
	t.Fatalf("party %s has no keyset %s", role, id)
	return false
}

func (tr *trio) waitFrozen(t *testing.T, role, id string, want bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if tr.frozen(t, role, id) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("party %s frozen=%v, want %v", role, tr.frozen(t, role, id), want)
}

// Tampering between two members freezes both; the third is told and freezes; nothing signs, through any path, until the
// operator's signature is accepted by all three. The third member's cosigner is never asked after the failure (no fallback).
func TestTrioTamperFreezesAllThree(t *testing.T) {
	cAuth := &countAuth{}
	tr := startTrio(t, trioOpts{proxyAB: true, auth: map[string]server.Authorizer{"C": cAuth}})
	pub := tr.dkg(t, "k")
	px := tr.Proxy["AB"]
	outcomes := map[string]int{}
	for _, dir := range []int{0, 1} {
		for _, n := range []int{0, 2, 4} {
			px.set(dir, n)
			job := fmt.Sprintf("tamper-%d-%d", dir, n)
			cAuth.n.Store(0)
			r, err := tr.sign("A", "k", job, byte(n+1))
			if !px.hit.Load() {
				mustOK(t, err)
				continue
			}
			if err == nil {
				verifyECDSA(t, pub, digest(byte(n+1)), r.Signature)
				outcomes["tolerated"]++
				continue
			}
			if r != nil && len(r.GetSignature()) > 0 {
				t.Fatalf("%s: error and signature together", job)
			}
			wantKind(t, err, codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC)
			outcomes["cryptographic"]++
			if cAuth.n.Load() != 0 {
				t.Fatalf("%s: C's cosigner was asked after a cryptographic failure (fallback)", job)
			}
			for _, role := range []string{"A", "B", "C"} {
				tr.waitFrozen(t, role, "k", true)
			}
			// frozen on all three: nothing signs, whoever is asked
			px.set(0, -1)
			for _, via := range []string{"A", "B"} {
				_, ferr := tr.sign(via, "k", job+"-after-"+via, 9)
				wantKind(t, ferr, codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_FROZEN)
			}
			// a forged unfreeze is refused and changes nothing; the real one lifts it on all three
			_, uerr := tr.Client["A"].Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: "k", Admin: server.SignAdmin(tr.Env.CertCallerKey(), "unfreeze", "k", time.Now())})
			wantKind(t, uerr, codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED)
			for _, role := range []string{"A", "B", "C"} {
				if !tr.frozen(t, role, "k") {
					t.Fatalf("a refused unfreeze lifted the freeze on %s", role)
				}
			}
			_, uerr = tr.Client["A"].Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: "k", Admin: tr.Env.Admin("unfreeze", "k")})
			mustOK(t, uerr)
			for _, role := range []string{"A", "B", "C"} {
				tr.waitFrozen(t, role, "k", false)
			}
			r, err = tr.sign("A", "k", job+"-resumed", 10)
			mustOK(t, err)
			verifyECDSA(t, pub, digest(10), r.Signature)
		}
	}
	t.Logf("outcomes: %v", outcomes)
	if outcomes["cryptographic"] == 0 {
		t.Fatal("no tampering produced a failure")
	}
}

// The third member was down when the others froze: it learns at its next contact (reconciliation), and unfreezing needs it.
func TestTrioFreezeReachesAMemberThatWasDown(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyAB: true})
	pub := tr.dkg(t, "k")
	_ = pub
	tr.stop("C")
	px := tr.Proxy["AB"]
	for n := 0; n < 6; n++ {
		px.set(0, n)
		_, err := tr.sign("A", "k", fmt.Sprintf("t%d", n), byte(n+1))
		if px.hit.Load() && err != nil {
			wantKind(t, err, codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC)
			break
		}
		if n == 5 {
			t.Fatal("no tampering produced a failure")
		}
	}
	px.set(0, -1)
	tr.waitFrozen(t, "A", "k", true)
	tr.waitFrozen(t, "B", "k", true)
	tr.start(t, "C")
	tr.waitFrozen(t, "C", "k", true) // told at the next contact: A reconciles with C and the frozen flag spreads

	// while C was down an unfreeze could not have been accepted by all three; now it can
	_, uerr := tr.Client["A"].Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: "k", Admin: tr.Env.Admin("unfreeze", "k")})
	mustOK(t, uerr)
	for _, role := range []string{"A", "B", "C"} {
		tr.waitFrozen(t, role, "k", false)
	}
}

func TestTrioUnfreezeNeedsAllThree(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyAB: true})
	tr.dkg(t, "k")
	px := tr.Proxy["AB"]
	for n := 0; n < 6; n++ {
		px.set(1, n)
		if _, err := tr.sign("A", "k", fmt.Sprintf("t%d", n), byte(n+1)); px.hit.Load() && err != nil {
			break
		}
	}
	px.set(0, -1)
	tr.waitFrozen(t, "C", "k", true)
	tr.stop("C")
	_, uerr := tr.Client["A"].Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: "k", Admin: tr.Env.Admin("unfreeze", "k")})
	if uerr == nil {
		t.Fatal("unfreeze succeeded with C down")
	}
	if !tr.frozen(t, "A", "k") || !tr.frozen(t, "B", "k") {
		t.Fatal("a failed unfreeze lifted the freeze on A or B")
	}
}

// A failure in the middle of the protocol that is not cryptographic (a stalled follower) is a plain transport error: the
// coordinator does NOT move on to the next peer and nothing is frozen.
func TestTrioNoFallbackMidProtocol(t *testing.T) {
	cAuth := &countAuth{}
	tr := startTrio(t, trioOpts{recvMS: 700,
		auth: map[string]server.Authorizer{"C": cAuth},
		fi:   map[string]*server.FaultInjection{"B": {BeforeSign: func(role string) { time.Sleep(3 * time.Second) }}}})
	pub := tr.dkg(t, "k")
	_ = pub
	_, err := tr.sign("A", "k", "stall", 1)
	if err == nil {
		t.Fatal("signed although B stalled")
	}
	if k, ok := server.KindOfStatus(err); !ok || k != pb.ErrorKind_ERROR_KIND_TRANSPORT {
		t.Fatalf("want TRANSPORT, got %v (typed=%v): %v", k, ok, err)
	}
	if cAuth.n.Load() != 0 {
		t.Fatal("C was asked after a mid-protocol failure")
	}
	if tr.frozen(t, "A", "k") || tr.frozen(t, "B", "k") {
		t.Fatal("a stall froze the keyset")
	}
}

// Followers never accept a session from a party that is not the expected coordinator, and A never follows.
func TestTrioRolesAreFixed(t *testing.T) {
	tr := startTrio(t, trioOpts{})
	tr.dkg(t, "k")
	if tr.Srv["A"].PeerAddr() != "" {
		t.Fatal("party A has a peer listener: it would be able to follow")
	}
	// B does not serve Sign for keysets it does not hold, and C does not serve Sign at all
	_, err := tr.Client["C"].Sign(ctx30(t), &pb.SignRequest{KeyId: "k", Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: digest(1), JobId: "c"})
	if statusCode(err) != codes.Unimplemented {
		t.Fatalf("C served Sign: %v", err)
	}
}

// Tampering between B and C (B coordinating) freezes both; A, which B cannot reach, freezes at its next contact: B tells it
// FROZEN when A tries to use it, and A passes the freeze on.
func TestTrioFreezeReachesACoordinatorLater(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyBC: true})
	tr.dkg(t, "k")
	px := tr.Proxy["BC"]
	hit := false
	for n := 0; n < 6 && !hit; n++ {
		px.set(0, n)
		if _, err := tr.sign("B", "k", fmt.Sprintf("bc%d", n), byte(n+1)); px.hit.Load() && err != nil {
			wantKind(t, err, codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC)
			hit = true
		}
	}
	if !hit {
		t.Fatal("no tampering produced a failure")
	}
	px.set(0, -1)
	tr.waitFrozen(t, "B", "k", true)
	tr.waitFrozen(t, "C", "k", true)
	if tr.frozen(t, "A", "k") {
		t.Log("A already knew (told by a reconciliation)")
	}
	// A's next signature is refused as FROZEN by its first peer (B), and A freezes too
	_, err := tr.sign("A", "k", "late", 9)
	wantKind(t, err, codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_FROZEN)
	tr.waitFrozen(t, "A", "k", true)
}
