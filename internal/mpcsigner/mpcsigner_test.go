package mpcsigner

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
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

func typed(code codes.Code, kind pb.ErrorKind, msg string) error {
	st, _ := status.New(code, msg).WithDetails(&pb.ErrorDetail{Kind: kind, Message: msg})
	return st.Err()
}

func TestClassifyMapsKinds(t *testing.T) {
	cases := []struct {
		err     error
		kind    Kind
		refusal bool
		alert   bool
	}{
		{typed(codes.Unavailable, pb.ErrorKind_ERROR_KIND_TRANSPORT, "x"), KindTransport, false, false},
		{typed(codes.ResourceExhausted, pb.ErrorKind_ERROR_KIND_LIMIT, "x"), KindLimit, false, false},
		{typed(codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED, "policy says no"), KindRefused, true, false},
		{typed(codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, "x"), KindCryptographic, false, true},
		{typed(codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_FROZEN, "x"), KindFrozen, false, true},
		{typed(codes.Internal, pb.ErrorKind_ERROR_KIND_INTERNAL, "x"), KindInternal, false, true},
		{typed(codes.Unavailable, pb.ErrorKind_ERROR_KIND_UNAVAILABLE, "cosigner down"), KindUnavailable, false, false},
		{status.Error(codes.Unavailable, "connection refused"), KindTransport, false, false}, // no detail: link failure
		{errors.New("plain"), KindTransport, false, false},
	}
	for i, c := range cases {
		var e *Error
		if !errors.As(classify(c.err), &e) {
			t.Fatalf("case %d: not *Error", i)
		}
		if e.Kind != c.kind {
			t.Errorf("case %d: kind %v want %v", i, e.Kind, c.kind)
		}
		if _, ok := e.SignerRefusal(); ok != c.refusal {
			t.Errorf("case %d: refusal %v", i, ok)
		}
		if e.SignerAlert() != c.alert {
			t.Errorf("case %d: alert %v", i, e.SignerAlert())
		}
		// availability failures never finish a job; nothing else is availability
		wantUnavail := c.kind == KindTransport || c.kind == KindLimit || c.kind == KindUnavailable
		if e.SignerUnavailable() != wantUnavail {
			t.Errorf("case %d: unavailable %v", i, e.SignerUnavailable())
		}
	}
}

func TestParseDERNormalizesLowS(t *testing.T) {
	n := crypto.S256().Params().N
	r := big.NewInt(12345)
	high := new(big.Int).Sub(n, big.NewInt(5)) // a high S
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{r, high})
	sig, err := parseDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if sig.S.Cmp(big.NewInt(5)) != 0 || sig.R.Cmp(r) != 0 {
		t.Fatalf("S not flipped: %v", sig.S)
	}
	for name, bad := range map[string][]byte{"empty": nil, "garbage": []byte{1, 2, 3}, "trailing": append(der, 0)} {
		if _, err := parseDER(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	zero, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(0), big.NewInt(1)})
	if _, err := parseDER(zero); err == nil {
		t.Error("r = 0 accepted")
	}
}

type fakeA struct {
	pb.UnimplementedMpcPartyServer
	calls    int
	failures int // first N calls fail with failKind
	failKind pb.ErrorKind
	last     *pb.SignRequest
	der      []byte
}

func (f *fakeA) Sign(_ context.Context, r *pb.SignRequest) (*pb.SignResponse, error) {
	f.calls++
	f.last = r
	if f.calls <= f.failures {
		return nil, typed(codes.Unavailable, f.failKind, "boom")
	}
	return &pb.SignResponse{Signature: f.der}, nil
}

func newTestSigner(t *testing.T, f *fakeA, retries int) *Signer {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterMpcPartyServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	key, _ := crypto.GenerateKey()
	s, err := New(Config{PartitionID: "p", Address: lis.Addr().String(), KeyID: "k1", PublicKey: crypto.FromECDSAPub(&key.PublicKey),
		ClientCert: tls.Certificate{}, ServerPin: "00000000000000000000000000000000000000000000000000000000000000aa", MaxRetries: retries,
		Timeout: 5 * time.Second,
		Dial: func(addr string, _ credentials.TransportCredentials) (*grpc.ClientConn, error) { // plaintext to the fake
			return grpc.NewClient(addr, grpc.WithTransportCredentials(insecureCreds()))
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestSignDigestRetriesTransportAndKeepsJobID(t *testing.T) {
	n := crypto.S256().Params().N
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(77), new(big.Int).Sub(n, big.NewInt(9))})
	f := &fakeA{failures: 2, failKind: pb.ErrorKind_ERROR_KIND_TRANSPORT, der: der}
	s := newTestSigner(t, f, 3)
	res, err := s.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{JobID: "job-9", IntentPackage: []byte("pkg")})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 3 || f.last.JobId != "job-9" || string(f.last.IntentPackage) != "pkg" || f.last.KeyId != "k1" {
		t.Fatalf("calls %d request %+v", f.calls, f.last)
	}
	if res.Sig.S.Cmp(big.NewInt(9)) != 0 {
		t.Fatal("signature was not normalized to low S")
	}
	// UNAVAILABLE is retried like transport, and never yields a signature
	fu := &fakeA{failures: 100, failKind: pb.ErrorKind_ERROR_KIND_UNAVAILABLE, der: der}
	su := newTestSigner(t, fu, 2)
	res2, err := su.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{JobID: "j", IntentPackage: []byte("p")})
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindUnavailable || !ue.SignerUnavailable() || res2.Sig.R != nil || fu.calls != 3 {
		t.Fatalf("unavailable: err %v calls %d sig %v", err, fu.calls, res2.Sig)
	}
	// refusals and cryptographic failures are not retried
	for _, k := range []pb.ErrorKind{pb.ErrorKind_ERROR_KIND_REFUSED, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC} {
		f2 := &fakeA{failures: 5, failKind: k, der: der}
		s2 := newTestSigner(t, f2, 3)
		if _, err := s2.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{JobID: "j", IntentPackage: []byte("p")}); err == nil || f2.calls != 1 {
			t.Fatalf("kind %v: err %v calls %d", k, err, f2.calls)
		}
	}
	// transport retries are bounded
	f3 := &fakeA{failures: 100, failKind: pb.ErrorKind_ERROR_KIND_TRANSPORT, der: der}
	s3 := newTestSigner(t, f3, 2)
	if _, err := s3.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{JobID: "j", IntentPackage: []byte("p")}); err == nil || f3.calls != 3 {
		t.Fatalf("err %v calls %d", err, f3.calls)
	}
	// job id and package are mandatory
	if _, err := s.SignDigest(context.Background(), [32]byte{1}, signer.SignOptions{}); err == nil {
		t.Fatal("signed without job id and package")
	}
}

// The root module must never link cb-mpc or any mpc-party internals: it talks to the service over gRPC with the pure-Go
// api module only (cb-mpc's libsecp256k1 collides with go-ethereum's, and the root build has no C++ toolchain).
func TestRootModuleIsFreeOfCbmpc(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-test", "./...")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "mpc-party/internal") || strings.Contains(l, "internal/cbmpc") || strings.Contains(l, "cb-mpc") {
			t.Fatalf("the root module depends on cb-mpc code: %s", l)
		}
	}
	mod, _ := os.ReadFile("../../go.mod")
	if !strings.Contains(string(mod), "mpc-party/api") {
		t.Fatal("expected the replace to mpc-party/api")
	}
}
