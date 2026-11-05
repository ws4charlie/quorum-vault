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
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

type authFunc func(server.AuthRequest) error

func (f authFunc) Authorize(_ context.Context, r server.AuthRequest) error { return f(r) }

// allowAll exists only in this _test.go file: it cannot be compiled into the binary.
var allowAll = authFunc(func(server.AuthRequest) error { return nil })

type pairOpts struct {
	tweak            func(role string, c *server.Config)
	authA            server.Authorizer
	authB            server.Authorizer
	fiA, fiB         *server.FaultInjection
	aPeerAddr        func(env *testenv.Env, bPeer string) string
	beforeA          func(env *testenv.Env)
	sealerA, sealerB server.Sealer // override the test sealer
	logA, logB       io.Writer     // capture logs
}

type pair struct {
	storeA, storeB *server.FileStore
	Env            *testenv.Env
	A, B           *server.Server
	Client         pb.MpcPartyClient // caller -> A
	BCall          pb.MpcPartyClient // caller -> B (health only)
	ConnA          *grpc.ClientConn
}

func quiet() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func logTo(w io.Writer) *slog.Logger {
	if w == nil {
		return quiet()
	}
	return slog.New(slog.NewJSONHandler(w, nil))
}

func storeFor(t *testing.T, cfg *server.Config, sealer server.Sealer) *server.FileStore {
	if sealer == nil {
		return testenv.Store(t, cfg)
	}
	fs, err := server.NewFileStore(cfg.DataDir, cfg.Role, sealer)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

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
	storeB := storeFor(t, cb, o.sealerB)
	b, err := server.New(server.Options{Config: cb, Authorizer: o.authB, Logger: logTo(o.logB), FaultInjection: o.fiB, Store: storeB})
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
	storeA := storeFor(t, ca, o.sealerA)
	a, err := server.New(server.Options{Config: ca, Authorizer: o.authA, Logger: logTo(o.logA), FaultInjection: o.fiA, Store: storeA})
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
	return &pair{storeA: storeA, storeB: storeB, Env: env, A: a, B: b, Client: cl, BCall: bc, ConnA: conn}
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

// dkgPairForTest makes a throwaway ECDSA keyset pair with the wrapper over an in-memory link.
func dkgPairForTest(t testing.TB) (*cbmpc.Keyset, *cbmpc.Keyset) {
	t.Helper()
	a, b := cbmpc.NewMemPair()
	var k1, k2 *cbmpc.Keyset
	var e1, e2 error
	done := make(chan struct{})
	go func() { k2, e2 = cbmpc.DKG(context.Background(), b, cbmpc.P2, cbmpc.ECDSA); close(done) }()
	k1, e1 = cbmpc.DKG(context.Background(), a, cbmpc.P1, cbmpc.ECDSA)
	<-done
	if e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	return k1, k2
}

// PlainKeyset returns the plaintext keyset blob of the current generation of a party (test only: reads through the store).
func (p *pair) PlainKeyset(t *testing.T, role, id string) []byte {
	t.Helper()
	st := p.storeA
	if role == "B" {
		st = p.storeB
	}
	state, err := st.State(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := st.GetKeyset(context.Background(), id, state.Current)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Wipe()
	b, err := ks.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
