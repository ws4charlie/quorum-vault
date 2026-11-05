package server_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

func digest(seed byte) []byte {
	d := sha256.Sum256([]byte{seed})
	return d[:]
}

func TestEndToEndBothAlgorithms(t *testing.T) {
	p := startPair(t, pairOpts{})
	ctx := ctx30(t)

	h, err := p.Client.Health(ctx, &pb.HealthRequest{})
	mustOK(t, err)
	if h.Role != "A" {
		t.Fatalf("health: %v", h)
	}
	// Party B serves only Health on its caller port.
	hb, err := p.BCall.Health(ctx, &pb.HealthRequest{})
	mustOK(t, err)
	if hb.Role != "B" {
		t.Fatalf("B health: %v", hb)
	}
	if _, err := p.BCall.Sign(ctx, &pb.SignRequest{KeyId: "x", JobId: "j", Digest: digest(1)}); err == nil || statusCode(err) != codes.Unimplemented {
		t.Fatalf("B must not serve Sign: %v", err)
	}

	// ECDSA
	root := p.dkg(t, "ks-e", pb.Curve_CURVE_SECP256K1)
	if len(root) != 33 {
		t.Fatalf("root %x", root)
	}
	if _, err := p.Client.DKG(ctx, &pb.DKGRequest{KeysetId: "ks-e", Curve: pb.Curve_CURVE_SECP256K1}); statusCode(err) != codes.AlreadyExists {
		t.Fatalf("duplicate DKG: %v", err)
	}
	hard := []uint32{44, 60, 0}
	node, err := p.Client.Node(ctx, &pb.NodeRequest{KeysetId: "ks-e", HardenedPath: hard})
	mustOK(t, err)
	// BIP32 check through Node: child from the xpub (pub, chain code) equals the key Derive registers.
	xpub := hdkeychain.NewExtendedKey(chaincfg.MainNetParams.HDPublicKeyID[:], node.PublicKey, node.ChainCode, []byte{0, 0, 0, 0}, 3, 0, false)
	for _, idx := range []uint32{0, 7} {
		child, err := xpub.Derive(idx)
		mustOK(t, err)
		want, _ := child.ECPubKey()
		d := p.derive(t, "ks-e", hard, []uint32{idx})
		if !bytes.Equal(d.PublicKey, want.SerializeCompressed()) {
			t.Fatalf("index %d: service %x != BIP32 from Node %x", idx, d.PublicKey, want.SerializeCompressed())
		}
	}
	d := p.derive(t, "ks-e", hard, []uint32{0})
	dg := digest(2)
	s, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "job-e1", IntentPackage: []byte("intent")})
	mustOK(t, err)
	verifyECDSA(t, d.PublicKey, dg, s.Signature)

	// Refresh, then sign again with the same key id
	r2, err := p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: "ks-e"})
	mustOK(t, err)
	if !bytes.Equal(r2.RootPublicKey, root) {
		t.Fatal("refresh changed the root key")
	}
	s2, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "job-e2"})
	mustOK(t, err)
	verifyECDSA(t, d.PublicKey, dg, s2.Signature)
	t.Logf("largest protocol message seen: A %d B %d bytes", p.A.MaxFrameSeen(), p.B.MaxFrameSeen())

	// Ed25519
	p.dkg(t, "ks-s", pb.Curve_CURVE_ED25519)
	ds := p.derive(t, "ks-s", []uint32{44, 501, 0}, []uint32{3})
	msg := []byte("a solana transaction message")
	ss, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: ds.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: msg, JobId: "job-s1"})
	mustOK(t, err)
	if !edVerify(ds.PublicKey, msg, ss.Signature) {
		t.Fatal("ed25519 signature does not verify")
	}
	if _, err := p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: "ks-s"}); err != nil {
		t.Fatal(err)
	}
	ss2, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: ds.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: msg, JobId: "job-s2"})
	mustOK(t, err)
	if !edVerify(ds.PublicKey, msg, ss2.Signature) {
		t.Fatal("ed25519 signature after refresh does not verify")
	}
	// A wrong algorithm for the key is refused up front.
	if _, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: ds.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "job-bad"}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("algorithm mismatch: %v", err)
	}
}

func TestSignIsIdempotentPerJobID(t *testing.T) {
	var runsB atomic.Int32
	p := startPair(t, pairOpts{fiB: &server.FaultInjection{BeforeSign: func(string) { runsB.Add(1) }}})
	ctx := ctx30(t)
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	d := p.derive(t, "ks", []uint32{1}, []uint32{0})
	req := &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("message one"), JobId: "job-1"}
	a, err := p.Client.Sign(ctx, req)
	mustOK(t, err)
	b, err := p.Client.Sign(ctx, req)
	mustOK(t, err)
	if !bytes.Equal(a.Signature, b.Signature) || a.Replayed || !b.Replayed {
		t.Fatalf("retry must return the stored signature (replayed=%v/%v)", a.Replayed, b.Replayed)
	}
	if runsB.Load() != 1 {
		t.Fatalf("protocol ran %d times for one job id", runsB.Load())
	}
	// A different digest under the same job id is refused and runs nothing.
	bad := &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("message TWO"), JobId: "job-1"}
	_, err = p.Client.Sign(ctx, bad)
	wantKind(t, err, codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_INTERNAL)
	// Ed25519 signatures are randomized: a re-sign would differ. Fresh job id => new run, new signature.
	c, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("message one"), JobId: "job-2"})
	mustOK(t, err)
	if bytes.Equal(a.Signature, c.Signature) {
		t.Fatal("expected a fresh randomized signature for a new job id")
	}
	if runsB.Load() != 2 {
		t.Fatalf("runs %d", runsB.Load())
	}
	// Concurrent calls with one job id: one protocol run, identical results.
	var wg sync.WaitGroup
	sigs := make([][]byte, 6)
	for i := range sigs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("concurrent"), JobId: "job-conc"})
			if err != nil {
				t.Error(err)
				return
			}
			sigs[i] = r.Signature
		}(i)
	}
	wg.Wait()
	for _, s := range sigs {
		if !bytes.Equal(s, sigs[0]) || s == nil {
			t.Fatal("concurrent retries returned different signatures")
		}
	}
	if runsB.Load() != 3 {
		t.Fatalf("concurrent same-job calls ran the protocol %d times in total (want 3)", runsB.Load())
	}
}

func TestAuthorizerRefusal(t *testing.T) {
	var ranA, ranB atomic.Int32
	var authB atomic.Bool
	deny := authFunc(func(r server.AuthRequest) error {
		if authB.Load() {
			return errString("policy says no")
		}
		return nil
	})
	p := startPair(t, pairOpts{authB: deny,
		fiA: &server.FaultInjection{BeforeSign: func(string) { ranA.Add(1) }},
		fiB: &server.FaultInjection{BeforeSign: func(string) { ranB.Add(1) }}})
	ctx := ctx30(t)
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	d := p.derive(t, "ks", []uint32{1}, []uint32{0})
	authB.Store(true)
	_, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "refused-1"})
	wantKind(t, err, codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED)
	if ranA.Load() != 0 || ranB.Load() != 0 {
		t.Fatalf("a protocol run started despite B's refusal (A %d, B %d)", ranA.Load(), ranB.Load())
	}
	// A refusal is not remembered as a signed job.
	authB.Store(false)
	r, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "refused-1"})
	mustOK(t, err)
	if r.Replayed {
		t.Fatal("refused job was recorded")
	}
}

func TestAuthorizerRefusalOnA(t *testing.T) {
	var ranB atomic.Int32
	p := startPair(t, pairOpts{authA: authFunc(func(server.AuthRequest) error { return errString("no") }),
		fiB: &server.FaultInjection{BeforeSign: func(string) { ranB.Add(1) }}})
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	d := p.derive(t, "ks", []uint32{1}, []uint32{0})
	_, err := p.Client.Sign(ctx30(t), &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "j"})
	wantKind(t, err, codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED)
	if ranB.Load() != 0 {
		t.Fatal("B ran")
	}
}

// DKG and Refresh must pass SelfTest on both sides; a failure leaves the old state in force.
func TestSelfTestFailureKeepsOldState(t *testing.T) {
	var failRefresh, failDKG atomic.Bool
	fi := &server.FaultInjection{FailSelfTest: func(op, role string) bool {
		return role == "A" && (op == "refresh" && failRefresh.Load() || op == "dkg" && failDKG.Load())
	}}
	p := startPair(t, pairOpts{fiA: fi})
	ctx := ctx30(t)

	failDKG.Store(true)
	_, err := p.Client.DKG(ctx, &pb.DKGRequest{KeysetId: "ks", Curve: pb.Curve_CURVE_SECP256K1})
	wantKind(t, err, codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC)
	// Nothing was stored on either side: Derive finds no keyset, and the id is free again.
	if _, err := p.Client.Derive(ctx, &pb.DeriveRequest{KeysetId: "ks", HardenedPath: []uint32{1}}); statusCode(err) != codes.NotFound {
		t.Fatalf("keyset exists after a failed DKG: %v", err)
	}
	failDKG.Store(false)
	root := p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	d := p.derive(t, "ks", []uint32{1}, []uint32{0})
	dg := digest(9)
	before, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "before"})
	mustOK(t, err)
	verifyECDSA(t, d.PublicKey, dg, before.Signature)

	failRefresh.Store(true)
	_, err = p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: "ks"})
	wantKind(t, err, codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC)
	failRefresh.Store(false)
	// The old shares are still current on both sides: signing works and the key is unchanged.
	after, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "after"})
	mustOK(t, err)
	verifyECDSA(t, d.PublicKey, dg, after.Signature)
	r, err := p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: "ks"})
	mustOK(t, err)
	if !bytes.Equal(r.RootPublicKey, root) {
		t.Fatal("root key changed")
	}
}

func TestHealthAndConfig(t *testing.T) {
	p := startPair(t, pairOpts{})
	time.Sleep(200 * time.Millisecond)
	h, err := p.Client.Health(ctx30(t), &pb.HealthRequest{})
	mustOK(t, err)
	if !h.PeerReachable || h.CbmpcCommit == "" {
		t.Fatalf("%v", h)
	}
}

// ---- mTLS ----

func TestMutualTLSRefusals(t *testing.T) {
	p := startPair(t, pairOpts{})
	env := p.Env
	ctx := ctx30(t)

	try := func(name string, addr string, client *tls.Certificate, serverPin string, minV, maxV uint16) error {
		pins := map[server.Pin]bool{}
		pp, _ := server.ParsePin(serverPin)
		pins[pp] = true
		cfg := server.ClientTLS(env.CertCaller.TLS, pins)
		if client == nil {
			cfg.Certificates = nil
		} else {
			cfg.Certificates = []tls.Certificate{*client}
		}
		if minV != 0 {
			cfg.MinVersion, cfg.MaxVersion = minV, maxV
		}
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		c, cancel := ctxTimeout(ctx, 3*time.Second)
		defer cancel()
		_, err = pb.NewMpcPartyClient(conn).Health(c, &pb.HealthRequest{})
		if err == nil {
			t.Errorf("%s: connection was accepted", name)
		} else {
			t.Logf("%s: refused (%v)", name, statusCode(err))
		}
		return err
	}
	good := env.CertCaller.TLS
	stranger := env.Stranger.TLS
	try("unpinned client certificate on caller port", p.A.CallerAddr(), &stranger, env.CertA.Pin, 0, 0)
	try("missing client certificate on caller port", p.A.CallerAddr(), nil, env.CertA.Pin, 0, 0)
	try("client pins the wrong server certificate", p.A.CallerAddr(), &good, env.Stranger.Pin, 0, 0)
	try("TLS 1.2 client", p.A.CallerAddr(), &good, env.CertA.Pin, tls.VersionTLS12, tls.VersionTLS12)
	// A legitimate caller certificate must not open the peer port (it is pinned to party A only).
	try("caller certificate on the peer port", p.B.PeerAddr(), &good, env.CertB.Pin, 0, 0)
	try("stranger on the peer port", p.B.PeerAddr(), &stranger, env.CertB.Pin, 0, 0)
	// Party A's own certificate must not open the caller port of A (callers are pinned separately).
	a := env.CertA.TLS
	try("party certificate on a caller port", p.A.CallerAddr(), &a, env.CertA.Pin, 0, 0)
	// Sanity: the real caller works.
	if _, err := p.Client.Health(ctx, &pb.HealthRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	env := testenv.NewEnv(t)
	good := env.Config(t, "A", "127.0.0.1:1", "127.0.0.1:0", "")
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(c *server.Config){
		"bad role":           func(c *server.Config) { c.Role = "C" },
		"no pins":            func(c *server.Config) { c.PeerPins = nil },
		"bad pin":            func(c *server.Config) { c.CallerPins = []string{"zz"} },
		"no data dir":        func(c *server.Config) { c.DataDir = "" },
		"A with peer_listen": func(c *server.Config) { c.PeerListen = "127.0.0.1:1" },
		"no authorizer":      func(c *server.Config) { c.Authorizer.Type = "" },
		"same listener": func(c *server.Config) {
			c.Role = "B"
			c.PeerAddress = ""
			c.CallerListen = "127.0.0.1:7001"
			c.PeerListen = "127.0.0.1:7001"
		},
	} {
		c := *good
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	if _, err := server.LoadConfig("/nonexistent/config.json"); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := server.New(server.Options{Config: good}); err == nil {
		t.Error("server created without an authorizer")
	}
}
