package server_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

type authFunc func(server.AuthRequest) error

func (f authFunc) Authorize(_ context.Context, r server.AuthRequest) error { return f(r) }

// allowAll exists only in this _test.go file: it cannot be compiled into the binary.
var allowAll = authFunc(func(server.AuthRequest) error { return nil })

type pairOpts struct {
	tweak     func(role string, c *server.Config)
	authA     server.Authorizer
	authB     server.Authorizer
	fiA, fiB  *server.FaultInjection
	aPeerAddr func(env *testenv.Env, bPeer string) string
	beforeA   func(env *testenv.Env)
}

type pair struct {
	Env    *testenv.Env
	A, B   *server.Server
	Client pb.MpcPartyClient // caller -> A
	BCall  pb.MpcPartyClient // caller -> B (health only)
	ConnA  *grpc.ClientConn
}

func quiet() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func startPair(t *testing.T, o pairOpts) *pair {
	t.Helper()
	env := testenv.NewEnv(t)
	if o.authA == nil {
		o.authA = allowAll
	}
	if o.authB == nil {
		o.authB = allowAll
	}
	cb := env.Config(t, "B", "", "127.0.0.1:0", "127.0.0.1:0")
	if o.tweak != nil {
		o.tweak("B", cb)
	}
	b, err := server.New(server.Options{Config: cb, Authorizer: o.authB, Logger: quiet(), FaultInjection: o.fiB})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	peer := b.PeerAddr()
	if o.aPeerAddr != nil {
		peer = o.aPeerAddr(env, peer)
	}
	ca := env.Config(t, "A", peer, "127.0.0.1:0", "")
	if o.tweak != nil {
		o.tweak("A", ca)
	}
	a, err := server.New(server.Options{Config: ca, Authorizer: o.authA, Logger: quiet(), FaultInjection: o.fiA})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a.Shutdown(ctx)
		b.Shutdown(ctx)
	})
	cl, conn := testenv.Dial(t, a.CallerAddr(), env.CertCaller, env.CertA.Pin)
	bc, _ := testenv.Dial(t, b.CallerAddr(), env.CertCaller, env.CertB.Pin)
	return &pair{Env: env, A: a, B: b, Client: cl, BCall: bc, ConnA: conn}
}

func ctx30(t testing.TB) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func mustOK(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// wantKind asserts that err is a gRPC error with the given code and typed kind.
func wantKind(t testing.TB, err error, code codes.Code, kind pb.ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %v/%v, got success", code, kind)
	}
	if got := grpcstatus.Code(err); got != code {
		t.Fatalf("want code %v, got %v: %v", code, got, err)
	}
	k, ok := server.KindOfStatus(err)
	if !ok || k != kind {
		t.Fatalf("want kind %v, got %v (typed=%v): %v", kind, k, ok, err)
	}
}

func (p *pair) dkg(t testing.TB, id string, c pb.Curve) []byte {
	t.Helper()
	r, err := p.Client.DKG(ctx30(t), &pb.DKGRequest{KeysetId: id, Curve: c, Admin: p.Env.Admin("dkg", id)})
	mustOK(t, err)
	return r.RootPublicKey
}

func (p *pair) derive(t testing.TB, id string, hard, path []uint32) *pb.DeriveResponse {
	t.Helper()
	r, err := p.Client.Derive(ctx30(t), &pb.DeriveRequest{KeysetId: id, HardenedPath: hard, Path: path})
	mustOK(t, err)
	return r
}

func edVerify(pub, msg, sig []byte) bool { return ed25519.Verify(pub, msg, sig) }

type errString string

func (e errString) Error() string { return string(e) }

func statusCode(err error) codes.Code { return grpcstatus.Code(err) }

func ctxTimeout(p context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(p, d)
}

func verifyECDSA(t testing.TB, pub, digest, der []byte) {
	t.Helper()
	pk, err := btcec.ParsePubKey(pub)
	mustOK(t, err)
	sig, err := btcecdsa.ParseDERSignature(der)
	mustOK(t, err)
	if !sig.Verify(digest, pk) {
		t.Fatal("ECDSA signature does not verify (btcec)")
	}
}
