package server_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

func TestLimitConcurrentSessions(t *testing.T) {
	release := make(chan struct{})
	var holding atomic.Int32
	p := startPair(t, pairOpts{
		tweak: func(role string, c *server.Config) { c.Limits.MaxPeerSessions = 2 },
		fiA:   &server.FaultInjection{BeforeSign: func(string) { holding.Add(1); <-release }},
	})
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	d := p.derive(t, "ks", []uint32{1}, []uint32{0})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.Client.Sign(ctx30(t), &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: fmt.Sprintf("hold-%d", i)})
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	for holding.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	_, err := p.Client.Sign(ctx30(t), &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "third"})
	wantKind(t, err, codes.ResourceExhausted, pb.ErrorKind_ERROR_KIND_LIMIT)
	if time.Since(start) > time.Second {
		t.Fatalf("the limit answered after %v: it must not queue", time.Since(start))
	}
	close(release)
	wg.Wait()
	// Slots are free again.
	_, err = p.Client.Sign(ctx30(t), &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "after"})
	mustOK(t, err)
}

// Party B enforces its own limit on the peer port (a compromised A must not be able to exhaust it).
func TestLimitConcurrentSessionsOnB(t *testing.T) {
	p := startPair(t, pairOpts{tweak: func(role string, c *server.Config) {
		c.Limits.MaxPeerSessions = 2
		c.Limits.RecvTimeoutMS = 3000
	}})
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	conn, err := grpc.NewClient(p.B.PeerAddr(), grpc.WithTransportCredentials(credentials.NewTLS(
		server.ClientTLS(p.Env.CertA.TLS, map[server.Pin]bool{mustPin(p.Env.CertB.Pin): true}))))
	mustOK(t, err)
	defer conn.Close()
	cl := pb.NewPeerClient(conn)
	open := func(sid string) (pb.Peer_SessionClient, *pb.Frame) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		st, err := cl.Session(ctx)
		mustOK(t, err)
		b, _ := proto.Marshal(&pb.Open{Op: pb.Op_OP_NODE, KeysetId: "ks", HardenedPath: []uint32{1}})
		mustOK(t, st.Send(&pb.Frame{SessionId: sid, Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}))
		f, err := st.Recv()
		mustOK(t, err)
		return st, f
	}
	_, f1 := open("00000000000000000000000000000001")
	_, f2 := open("00000000000000000000000000000002")
	if f1.Kind != pb.FrameKind_FRAME_KIND_ACK || f2.Kind != pb.FrameKind_FRAME_KIND_ACK {
		t.Fatalf("first two sessions must be accepted: %v %v", f1.Kind, f2.Kind)
	}
	_, f3 := open("00000000000000000000000000000003")
	var fin pb.Fin
	mustOK(t, proto.Unmarshal(f3.Payload, &fin))
	if f3.Kind != pb.FrameKind_FRAME_KIND_FIN || fin.Ok || fin.Kind != pb.ErrorKind_ERROR_KIND_LIMIT {
		t.Fatalf("third session must be refused with LIMIT, got %v %+v", f3.Kind, &fin)
	}
	// A replayed OPEN for a session id B has already seen is refused.
	_, f4 := open("00000000000000000000000000000001")
	mustOK(t, proto.Unmarshal(f4.Payload, &fin))
	if f4.Kind != pb.FrameKind_FRAME_KIND_FIN || fin.Ok {
		t.Fatalf("replayed session id accepted: %v %+v", f4.Kind, &fin)
	}
	t.Logf("replay refusal: %s", fin.Message)
}

func mustPin(s string) server.Pin { p, _ := server.ParsePin(s); return p }

func TestLimitFrameSize(t *testing.T) {
	p := startPair(t, pairOpts{tweak: func(role string, c *server.Config) { c.Limits.MaxFrameBytes = 2000 }})
	start := time.Now()
	_, err := p.Client.DKG(ctx30(t), &pb.DKGRequest{KeysetId: "ks", Curve: pb.Curve_CURVE_SECP256K1})
	if err == nil {
		t.Fatal("DKG succeeded although its messages exceed the frame limit")
	}
	k, _ := server.KindOfStatus(err)
	if k != pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC && k != pb.ErrorKind_ERROR_KIND_LIMIT {
		t.Fatalf("want a cryptographic/limit kind for an oversize frame, got %v: %v", k, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	// And nothing was stored.
	if _, err := p.Client.Derive(ctx30(t), &pb.DeriveRequest{KeysetId: "ks", HardenedPath: []uint32{1}}); statusCode(err) != codes.NotFound {
		t.Fatalf("keyset exists: %v", err)
	}
}

func TestLimitSessionRate(t *testing.T) {
	p := startPair(t, pairOpts{tweak: func(role string, c *server.Config) { c.Limits.SessionsPerSecKey = 2 }})
	// DKG itself counts: wait for the bucket to refill between setup and the burst.
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	time.Sleep(1200 * time.Millisecond)
	var limited, ok int
	for i := 0; i < 6; i++ {
		_, err := p.Client.Node(ctx30(t), &pb.NodeRequest{KeysetId: "ks", HardenedPath: []uint32{1}})
		switch {
		case err == nil:
			ok++
		case statusCode(err) == codes.ResourceExhausted:
			k, _ := server.KindOfStatus(err)
			if k != pb.ErrorKind_ERROR_KIND_LIMIT {
				t.Fatalf("kind %v", k)
			}
			limited++
		default:
			t.Fatal(err)
		}
	}
	if limited == 0 || ok == 0 {
		t.Fatalf("rate limit: %d ok, %d limited (want both)", ok, limited)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := p.Client.Node(ctx30(t), &pb.NodeRequest{KeysetId: "ks", HardenedPath: []uint32{1}}); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}
