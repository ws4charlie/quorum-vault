package server_test

import (
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

// tamperProxy is a man in the middle at the session layer: it terminates mTLS from A with its own certificate (pinned by A),
// dials B with another (pinned by B), and forwards frames, flipping one byte in the payload of the n-th DATA frame going
// in direction dir (0: A to B, 1: B to A). n < 0: forward faithfully.
type tamperProxy struct {
	pb.UnimplementedPeerServer
	client pb.PeerClient
	dir    atomic.Int32
	n      atomic.Int32
	count  [2]atomic.Int32
	hit    atomic.Bool
}

func (p *tamperProxy) set(dir, n int) {
	p.count[0].Store(0)
	p.count[1].Store(0)
	p.hit.Store(false)
	p.dir.Store(int32(dir))
	p.n.Store(int32(n))
}

func (p *tamperProxy) mutate(dir int, f *pb.Frame) {
	if f.Kind != pb.FrameKind_FRAME_KIND_DATA || len(f.Payload) == 0 {
		return
	}
	idx := p.count[dir].Add(1) - 1
	if int(p.dir.Load()) == dir && idx == p.n.Load() {
		f.Payload = append([]byte(nil), f.Payload...)
		f.Payload[len(f.Payload)/2] ^= 0x01
		p.hit.Store(true)
	}
}

func (p *tamperProxy) Session(in pb.Peer_SessionServer) error {
	out, err := p.client.Session(in.Context())
	if err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() {
		for {
			f, err := in.Recv()
			if err != nil {
				out.CloseSend()
				break
			}
			p.mutate(0, f)
			if out.Send(f) != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		for {
			f, err := out.Recv()
			if err != nil {
				break
			}
			p.mutate(1, f)
			if in.Send(f) != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
	return nil
}

func startProxy(t *testing.T, env *testenv.Env, bPeer string, proxyCert testenv.Cert) (*tamperProxy, string) {
	t.Helper()
	// toward B: the proxy presents ITS certificate, which B pins as "party A"
	conn, err := grpc.NewClient(bPeer, grpc.WithTransportCredentials(credentials.NewTLS(
		server.ClientTLS(proxyCert.TLS, map[server.Pin]bool{mustPin(env.CertB.Pin): true}))))
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
	// toward A: the proxy presents the same certificate, which A pins as "party B"
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(server.ServerTLS(proxyCert.TLS, map[server.Pin]bool{mustPin(env.CertA.Pin): true}))))
	pb.RegisterPeerServer(srv, p)
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return p, ln.Addr().String()
}

// A peer that flips bytes in session frames: the honest party ends with a Cryptographic error, never a signature,
// never a crash, and the service keeps working afterwards.
func TestTamperingProxyYieldsCryptographicNoSignature(t *testing.T) {
	proxyCert := testenv.NewCert(t, "proxy")
	var proxy *tamperProxy
	p2 := startPair(t, pairOpts{
		// A believes the proxy is party B, and B believes the proxy is party A.
		tweak: func(role string, c *server.Config) { c.PeerPins = []string{proxyCert.Pin} },
		aPeerAddr: func(env *testenv.Env, bPeer string) string {
			var addr string
			proxy, addr = startProxy(t, env, bPeer, proxyCert)
			return addr
		},
	})
	p2.dkg(t, "ks-e", pb.Curve_CURVE_SECP256K1)
	d := p2.derive(t, "ks-e", []uint32{1, 2}, []uint32{5})
	p2.dkg(t, "ks-s", pb.Curve_CURVE_ED25519)
	ds := p2.derive(t, "ks-s", []uint32{1, 2}, []uint32{5})
	dg := digest(3)
	type tc struct {
		name string
		req  func(job string) *pb.SignRequest
		pub  []byte
		ver  func(sig []byte) bool
	}
	cases := []tc{
		{"ecdsa", func(j string) *pb.SignRequest {
			return &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: j}
		}, d.PublicKey, func(sig []byte) bool { verifyECDSA(t, d.PublicKey, dg, sig); return true }},
		{"ed25519", func(j string) *pb.SignRequest {
			return &pb.SignRequest{KeyId: ds.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("msg"), JobId: j}
		}, ds.PublicKey, func(sig []byte) bool { return edVerify(ds.PublicKey, []byte("msg"), sig) }},
	}
	outcomes := map[string]int{}
	for _, c := range cases {
		for dir := 0; dir < 2; dir++ {
			for n := 0; n < 5; n++ {
				proxy.set(dir, n)
				job := fmt.Sprintf("%s-%d-%d", c.name, dir, n)
				r, err := p2.Client.Sign(ctx30(t), c.req(job))
				if !proxy.hit.Load() {
					if err != nil {
						t.Fatalf("%s: no tampering happened but sign failed: %v", job, err)
					}
					continue
				}
				if err == nil {
					// the flipped byte was not used by the protocol: the signature must still verify
					if !c.ver(r.Signature) {
						t.Fatalf("%s: INVALID SIGNATURE RETURNED", job)
					}
					outcomes["tolerated"]++
					continue
				}
				if r != nil && len(r.GetSignature()) > 0 {
					t.Fatalf("%s: error and signature together", job)
				}
				k, typed := server.KindOfStatus(err)
				if !typed || k != pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC {
					t.Errorf("%s: want a typed CRYPTOGRAPHIC error, got kind %v typed=%v: %v", job, k, typed, err)
				}
				outcomes[k.String()]++
				// The keyset is frozen on both parties: any further work is refused as FROZEN until an operator unfreezes it.
				_, ferr := p2.Client.Sign(ctx30(t), c.req(job+"-after"))
				wantKind(t, ferr, codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_FROZEN)
				keyset := "ks-e"
				if c.name == "ed25519" {
					keyset = "ks-s"
				}
				// A forged or wrong-key unfreeze is refused; the real one works and signing resumes.
				_, uerr := p2.Client.Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: keyset, Admin: server.SignAdmin(p2.Env.CertCallerKey(), "unfreeze", keyset, time.Now())})
				wantKind(t, uerr, codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED)
				_, uerr = p2.Client.Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: keyset, Admin: p2.Env.Admin("unfreeze", keyset)})
				mustOK(t, uerr)
			}
		}
	}
	t.Logf("outcomes: %v", outcomes)
	// The service survived: an honest run through the same proxy works.
	proxy.set(0, -1)
	r, err := p2.Client.Sign(ctx30(t), cases[0].req("clean"))
	mustOK(t, err)
	verifyECDSA(t, d.PublicKey, dg, r.Signature)
}
