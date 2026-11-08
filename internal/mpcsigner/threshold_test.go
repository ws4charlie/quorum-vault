package mpcsigner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/ws4charlie/quorum-vault/internal/signer"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// fakeCoord is a coordinator that answers Sign from a script.
type fakeCoord struct {
	pb.UnimplementedMpcPartyServer
	calls atomic.Int32
	// script returns the error for call n (1-based); nil means success
	script func(n int) error
	der    []byte
	lis    net.Listener
	srv    *grpc.Server
}

func (f *fakeCoord) Sign(_ context.Context, r *pb.SignRequest) (*pb.SignResponse, error) {
	n := int(f.calls.Add(1))
	if f.script != nil {
		if err := f.script(n); err != nil {
			return nil, err
		}
	}
	return &pb.SignResponse{Signature: f.der}, nil
}

func (f *fakeCoord) start(t *testing.T) string {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.lis, f.srv = lis, grpc.NewServer()
	pb.RegisterMpcPartyServer(f.srv, f)
	go f.srv.Serve(lis)
	t.Cleanup(f.srv.Stop)
	return lis.Addr().String()
}

func typedCode(code codes.Code, kind pb.ErrorKind, rpcCode uint32, msg string) error {
	st, _ := status.New(code, msg).WithDetails(&pb.ErrorDetail{Kind: kind, Message: msg, Code: rpcCode})
	return st.Err()
}

var (
	errBefore  = func(kind pb.ErrorKind) error { return typedCode(codes.Unavailable, kind, 0, "before signing") }
	errStarted = func(kind pb.ErrorKind) error {
		return typedCode(codes.Unavailable, kind, pb.CodeSigningStarted, "mid protocol")
	}
)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) count(s string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.b.String(), s)
}

func newThreshold(t *testing.T, a, b *fakeCoord, retries int) (*ThresholdSigner, *logBuf) {
	t.Helper()
	key, _ := crypto.GenerateKey()
	n := crypto.S256().Params().N
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(77), new(big.Int).Sub(n, big.NewInt(9))})
	var coords []Coordinator
	for name, f := range map[string]*fakeCoord{"A": a, "B": b} {
		_ = name
		_ = f
	}
	for _, c := range []struct {
		name string
		f    *fakeCoord
	}{{"A", a}, {"B", b}} {
		c.f.der = der
		coords = append(coords, Coordinator{Name: c.name, Address: c.f.start(t), ClientCert: tls.Certificate{},
			ServerPin: "00000000000000000000000000000000000000000000000000000000000000aa"})
	}
	lb := &logBuf{}
	s, err := NewThreshold(ThresholdConfig{PartitionID: "p", KeysetID: "evm1", PublicKey: crypto.FromECDSAPub(&key.PublicKey), Coordinators: coords,
		MaxRetries: retries, Timeout: 10 * time.Second, Logger: slog.New(slog.NewTextHandler(lb, nil)),
		Dial: func(addr string, _ credentials.TransportCredentials) (*grpc.ClientConn, error) {
			return grpc.NewClient(addr, grpc.WithTransportCredentials(insecureCreds()))
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, lb
}

func sign(s *ThresholdSigner, job string) (signer.Result, error) {
	return s.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{JobID: job, IntentPackage: []byte("pkg")})
}

// The fallback rule, for every error kind, before and after signing started.
func TestThresholdFallbackRule(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		fallback  bool // B is tried
		retriesA  bool // A is called again in a later round
		wantError bool
	}{
		{"transport before signing", errBefore(pb.ErrorKind_ERROR_KIND_TRANSPORT), true, true, false},
		{"unavailable before signing", errBefore(pb.ErrorKind_ERROR_KIND_UNAVAILABLE), true, true, false},
		{"no typed detail (connect failed)", status.Error(codes.Unavailable, "connection refused"), true, true, false},
		{"transport after signing started", errStarted(pb.ErrorKind_ERROR_KIND_TRANSPORT), false, true, true},
		{"unavailable after signing started", errStarted(pb.ErrorKind_ERROR_KIND_UNAVAILABLE), false, true, true},
		{"refused", typedCode(codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED, 0, "no"), false, false, true},
		{"cryptographic", typedCode(codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, 0, "bad proof"), false, false, true},
		{"frozen", typedCode(codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_FROZEN, 0, "frozen"), false, false, true},
		{"limit", typedCode(codes.ResourceExhausted, pb.ErrorKind_ERROR_KIND_LIMIT, 0, "limit"), false, true, true},
		{"internal", typedCode(codes.Internal, pb.ErrorKind_ERROR_KIND_INTERNAL, 0, "bug"), false, false, true},
	}
	for _, c := range cases {
		a := &fakeCoord{script: func(int) error { return c.err }}
		b := &fakeCoord{}
		s, _ := newThreshold(t, a, b, 2)
		_, err := sign(s, "j1")
		if c.fallback {
			if err != nil || b.calls.Load() != 1 {
				t.Errorf("%s: want B to sign once, got err=%v B calls=%d", c.name, err, b.calls.Load())
			}
			continue
		}
		if err == nil || b.calls.Load() != 0 {
			t.Errorf("%s: B must not be tried; err=%v B calls=%d", c.name, err, b.calls.Load())
		}
		if c.retriesA != (a.calls.Load() > 1) {
			t.Errorf("%s: A called %d times (retries expected: %v)", c.name, a.calls.Load(), c.retriesA)
		}
		if a.calls.Load() > 3 {
			t.Errorf("%s: A called %d times with MaxRetries 2", c.name, a.calls.Load())
		}
	}
}

// A refusal by A is final even though B would sign; a refusal by B after A was unavailable is final too.
func TestThresholdRefusalsAreFinal(t *testing.T) {
	a := &fakeCoord{script: func(int) error { return errBefore(pb.ErrorKind_ERROR_KIND_UNAVAILABLE) }}
	b := &fakeCoord{script: func(int) error {
		return typedCode(codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED, 0, "policy says no")
	}}
	s, _ := newThreshold(t, a, b, 3)
	_, err := sign(s, "j")
	var e *Error
	if !errorsAs(err, &e) || e.Kind != KindRefused {
		t.Fatalf("want refused, got %v", err)
	}
	if a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Fatalf("a refusal must end the job at once: A %d B %d", a.calls.Load(), b.calls.Load())
	}
}

// Retry plus fallback never loops: both coordinators unavailable before signing: at most (MaxRetries+1) calls each; a mid-protocol failure on B
// pins the call to B.
func TestThresholdRetryAndFallbackDoNotLoop(t *testing.T) {
	a := &fakeCoord{script: func(int) error { return errBefore(pb.ErrorKind_ERROR_KIND_TRANSPORT) }}
	b := &fakeCoord{script: func(int) error { return errBefore(pb.ErrorKind_ERROR_KIND_UNAVAILABLE) }}
	s, _ := newThreshold(t, a, b, 2)
	if _, err := sign(s, "j"); err == nil {
		t.Fatal("signed with nobody available")
	}
	if a.calls.Load() != 3 || b.calls.Load() != 3 {
		t.Fatalf("calls A %d B %d, want 3 and 3 (MaxRetries 2 = 3 rounds)", a.calls.Load(), b.calls.Load())
	}
	// A unavailable at first, then B fails MID-protocol: the remaining rounds go to B only, never back to A
	a2 := &fakeCoord{script: func(int) error { return errBefore(pb.ErrorKind_ERROR_KIND_TRANSPORT) }}
	b2 := &fakeCoord{script: func(int) error { return errStarted(pb.ErrorKind_ERROR_KIND_TRANSPORT) }}
	s2, _ := newThreshold(t, a2, b2, 3)
	if _, err := sign(s2, "j"); err == nil {
		t.Fatal("signed")
	}
	if a2.calls.Load() != 1 || b2.calls.Load() != 4 {
		t.Fatalf("calls A %d B %d, want 1 and 4: after B's mid-protocol failure only B is retried", a2.calls.Load(), b2.calls.Load())
	}
	// A recovers on the second round after a transient pre-signing failure
	a3 := &fakeCoord{script: func(n int) error {
		if n <= 1 {
			return errBefore(pb.ErrorKind_ERROR_KIND_TRANSPORT)
		}
		return nil
	}}
	b3 := &fakeCoord{script: func(int) error { return errBefore(pb.ErrorKind_ERROR_KIND_TRANSPORT) }}
	s3, _ := newThreshold(t, a3, b3, 2)
	if _, err := sign(s3, "j"); err != nil {
		t.Fatal(err)
	}
	if a3.calls.Load() != 2 || b3.calls.Load() != 1 {
		t.Fatalf("calls A %d B %d", a3.calls.Load(), b3.calls.Load())
	}
}

// One ALERT when the second coordinator starts being used, one INFO when the first is back; not one per job.
func TestThresholdAlertsPerTransition(t *testing.T) {
	var aDown atomic.Bool
	aDown.Store(true)
	a := &fakeCoord{script: func(int) error {
		if aDown.Load() {
			return errBefore(pb.ErrorKind_ERROR_KIND_TRANSPORT)
		}
		return nil
	}}
	b := &fakeCoord{}
	s, lb := newThreshold(t, a, b, 1)
	for i := 0; i < 6; i++ {
		if _, err := sign(s, "job"); err != nil {
			t.Fatal(err)
		}
	}
	if lb.count("ALERT mpc signer degraded") != 1 || lb.count("recovered") != 0 {
		t.Fatalf("after 6 degraded signatures: alerts %d recoveries %d\n%s", lb.count("ALERT"), lb.count("recovered"), lb.b.String())
	}
	aDown.Store(false)
	for i := 0; i < 4; i++ {
		if _, err := sign(s, "job"); err != nil {
			t.Fatal(err)
		}
	}
	if lb.count("ALERT") != 1 || lb.count("recovered") != 1 {
		t.Fatalf("after recovery: alerts %d recoveries %d", lb.count("ALERT"), lb.count("recovered"))
	}
	aDown.Store(true) // a second degraded period alerts again
	if _, err := sign(s, "job"); err != nil {
		t.Fatal(err)
	}
	if lb.count("ALERT") != 2 {
		t.Fatalf("a new degraded period must alert once more: %d", lb.count("ALERT"))
	}
}

func TestThresholdRequiresJobAndPackage(t *testing.T) {
	s, _ := newThreshold(t, &fakeCoord{}, &fakeCoord{}, 1)
	if _, err := s.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{}); err == nil {
		t.Fatal("signed without job id and package")
	}
	if s.Key().MPCKeyRef != "evm1" || s.PublicKey() == nil {
		t.Fatal("the key is the keyset")
	}
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }
