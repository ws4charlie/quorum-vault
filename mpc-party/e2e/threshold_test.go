package e2e

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"os/exec"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// cluster3 is parties A, B and C as three real processes (2-of-3 keysets, E23-2). A dials B and C, B dials C.
type cluster3 struct {
	env    *testenv.Env
	addrs  testenv.Addrs
	cfgs   map[string]*server.Config
	paths  map[string]string
	procs  map[string]*proc
	client map[string]pb.MpcPartyClient
	bin    string
	scheme pb.Scheme // the scheme the helpers make and use keysets in (zero value: ECDSA)
}

// threshold schemes the 2-of-3 tests run for. The two share every code path of the service; the tests that exercise a path
// whose code does not look at the scheme run for ECDSA only (said in a comment at each).
var tSchemes = []pb.Scheme{pb.Scheme_SCHEME_ECDSA_2OF3, pb.Scheme_SCHEME_ED25519_2OF3}

func schemeName(sc pb.Scheme) string {
	if sc == pb.Scheme_SCHEME_ED25519_2OF3 {
		return "ed25519"
	}
	return "ecdsa"
}

// forSchemes runs f as a subtest for each threshold scheme.
func forSchemes(t *testing.T, f func(t *testing.T, sc pb.Scheme)) {
	for _, sc := range tSchemes {
		sc := sc
		t.Run(schemeName(sc), func(t *testing.T) { f(t, sc) })
	}
}

func (cl *cluster3) isEd() bool { return cl.scheme == pb.Scheme_SCHEME_ED25519_2OF3 }

func (cl *cluster3) algorithm() pb.Algorithm {
	if cl.isEd() {
		return pb.Algorithm_ALGORITHM_ED25519
	}
	return pb.Algorithm_ALGORITHM_ECDSA_SECP256K1
}

// msg is what a job signs: a 32-byte digest for ECDSA, a whole message (longer than a digest) for Ed25519.
func (cl *cluster3) msg(seed int) []byte {
	if cl.isEd() {
		return edMessage(seed)
	}
	return dgst(seed)
}

func edMessage(seed int) []byte {
	return append([]byte(fmt.Sprintf("solana-message-%d|", seed)), bytes.Repeat([]byte{byte(seed)}, 150)...)
}

func (cl *cluster3) verify(t testing.TB, pub, msg, sig []byte) {
	t.Helper()
	if cl.isEd() {
		verifyEd25519(t, pub, msg, sig)
		return
	}
	verifyECDSA(t, pub, msg, sig)
}

func newCluster3(t *testing.T, tweak func(role string, c *server.Config)) *cluster3 {
	return newCluster3S(t, pb.Scheme_SCHEME_ECDSA_2OF3, tweak)
}

func newCluster3S(t *testing.T, sc pb.Scheme, tweak func(role string, c *server.Config)) *cluster3 {
	t.Helper()
	env := testenv.NewEnv(t)
	cl := &cluster3{scheme: sc, env: env, addrs: testenv.NewAddrs(t), cfgs: map[string]*server.Config{}, paths: map[string]string{},
		procs: map[string]*proc{}, client: map[string]pb.MpcPartyClient{}, bin: binDev}
	for _, role := range []string{"A", "B", "C"} {
		c := env.Config3(t, role, cl.addrs, cl.addrs.PeerB, cl.addrs.PeerC)
		if tweak != nil {
			tweak(role, c)
		}
		cl.cfgs[role] = c
		cl.paths[role] = env.WriteConfig(t, c, strings.ToLower(role)+".json")
	}
	for _, role := range []string{"C", "B", "A"} {
		cl.start(t, role)
	}
	callers := map[string]string{"A": cl.addrs.CallerA, "B": cl.addrs.CallerB, "C": cl.addrs.CallerC}
	pins := map[string]string{"A": env.CertA.Pin, "B": env.CertB.Pin, "C": env.CertC.Pin}
	for role, addr := range callers {
		c, _ := testenv.Dial(t, addr, env.CertCaller, pins[role])
		cl.client[role] = c
	}
	cl.waitReady(t)
	return cl
}

func (cl *cluster3) start(t *testing.T, role string, env ...string) {
	t.Helper()
	cl.procs[role] = start(t, cl.bin, cl.paths[role], env...)
}

func (cl *cluster3) stop(role string) { cl.procs[role].kill() }

// restart kills and starts a party again.
func (cl *cluster3) restart(t *testing.T, role string, env ...string) {
	t.Helper()
	if !cl.procs[role].exited() {
		cl.procs[role].kill()
	}
	cl.start(t, role, env...)
}

func (cl *cluster3) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context5(2 * time.Second)
		h, err := cl.client["A"].Health(ctx, &pb.HealthRequest{})
		cancel()
		if err == nil && len(h.Peers) == 2 && h.Peers[0].Reachable && h.Peers[1].Reachable {
			hb, err := cl.client["B"].Health(ctx5(t, 2*time.Second), &pb.HealthRequest{})
			if err == nil && hb.PeerReachable {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("parties not ready.\nA: %s\nB: %s\nC: %s", cl.procs["A"].stderr, cl.procs["B"].stderr, cl.procs["C"].stderr)
}

func (cl *cluster3) sc() pb.Scheme {
	if cl.scheme == pb.Scheme_SCHEME_UNSPECIFIED {
		return pb.Scheme_SCHEME_ECDSA_2OF3
	}
	return cl.scheme
}

func (cl *cluster3) dkg(t *testing.T, id string) []byte {
	t.Helper()
	r, err := cl.client["A"].DKG(ctx(t, 60*time.Second), &pb.DKGRequest{KeysetId: id, Scheme: cl.sc(), Admin: cl.env.Admin("dkg", id)})
	must(t, err)
	return r.RootPublicKey
}

func (cl *cluster3) refresh(t *testing.T, id string) {
	t.Helper()
	_, err := cl.client["A"].Refresh(ctx(t, 60*time.Second), &pb.RefreshRequest{KeysetId: id, Admin: cl.env.Admin("refresh", id)})
	must(t, err)
}

// sign through coordinator `via` ("A" or "B") and verify the signature against pub.
func (cl *cluster3) sign(t *testing.T, via, id, job string, seed int, pub []byte) {
	t.Helper()
	dg := cl.msg(seed)
	r, err := cl.client[via].Sign(ctx(t, 60*time.Second), &pb.SignRequest{KeyId: id, Algorithm: cl.algorithm(),
		Digest: dg, JobId: job, IntentPackage: []byte("intent")})
	must(t, err)
	cl.verify(t, pub, dg, r.Signature)
}

// signs counts the signing sessions a process served or started (log lines "op":"OP_SIGN" of followers).
func (p *proc) followed(op string) int {
	return strings.Count(p.stderr.String(), `"op":"`+op+`"`)
}

func context5(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func ctx5(t testing.TB, d time.Duration) context.Context { return ctx(t, d) }

// ---- helpers ----

func (cl *cluster3) health(t *testing.T) (h map[string]*pb.HealthResponse) {
	t.Helper()
	h = map[string]*pb.HealthResponse{}
	for role, c := range cl.client {
		if cl.procs[role].exited() {
			continue
		}
		r, err := c.Health(ctx(t, 3*time.Second), &pb.HealthRequest{})
		if err == nil {
			h[role] = r
		}
	}
	return
}

func statusOf(h *pb.HealthResponse, id string) *pb.KeysetStatus { return status(h, id) }

// waitConverged3 waits until every running party reports the keyset resolved on the same generation (or, when !mustExist, on
// none of them). Returns the generation.
func (cl *cluster3) waitConverged3(t *testing.T, id string, mustExist bool) uint64 {
	t.Helper()
	return cl.waitConvergedOn(t, id, mustExist, "A", "B", "C")
}

// waitConvergedOn is waitConverged3 for the parties that hold the keyset (a 2-party keyset: A and B).
func (cl *cluster3) waitConvergedOn(t *testing.T, id string, mustExist bool, roles ...string) uint64 {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var h map[string]*pb.HealthResponse
	for time.Now().Before(deadline) {
		h = map[string]*pb.HealthResponse{}
		for role, hr := range cl.health(t) {
			for _, r := range roles {
				if r == role {
					h[role] = hr
				}
			}
		}
		var gen uint64
		ok, none := len(h) > 0, len(h) > 0
		for _, hr := range h {
			ks := statusOf(hr, id)
			if ks == nil {
				ok = false
				continue
			}
			none = false
			if !ks.Resolved || ks.Generation == 0 || (gen != 0 && ks.Generation != gen) {
				ok = false
			}
			gen = ks.Generation
		}
		if ok && gen > 0 {
			return gen
		}
		if !mustExist && none {
			return 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("parties did not converge on keyset %s\nhealth: %v\nA: %s\nB: %s\nC: %s", id, h, tail(cl.procs["A"].stderr.String()), tail(cl.procs["B"].stderr.String()), tail(cl.procs["C"].stderr.String()))
	return 0
}

func wantKind(t *testing.T, err error, want pb.ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", want)
	}
	if k, ok := kindOf(err); !ok || k != want {
		t.Fatalf("error kind %v (typed=%v), want %v: %v", k, ok, want, err)
	}
}

func (cl *cluster3) signRaw(via, id, job string, seed int) (*pb.SignResponse, error) {
	c, cancel := context5(60 * time.Second)
	defer cancel()
	return cl.client[via].Sign(c, &pb.SignRequest{KeyId: id, Algorithm: cl.algorithm(), Digest: cl.msg(seed), JobId: job, IntentPackage: []byte("intent")})
}

// followedSign counts the signing sessions a party served as follower.
func (p *proc) followedSign() int {
	return strings.Count(p.stderr.String(), `"op":"OP_SIGN","scheme":"`)
}

// signUntil retries a signature while the typed kind is UNAVAILABLE (a party is reconciling or coming back).
func (cl *cluster3) signUntil(t *testing.T, via, id, job string, seed int, pub []byte) {
	t.Helper()
	var r *pb.SignResponse
	retryUnavailable(t, 40*time.Second, func() (err error) { r, err = cl.signRaw(via, id, job, seed); return })
	cl.verify(t, pub, cl.msg(seed), r.Signature)
}

// signEveryPair signs with A+B, A+C (B down) and B+C (A down), restoring the parties after each.
func (cl *cluster3) signEveryPair(t *testing.T, id string, pub []byte, tag string) {
	t.Helper()
	cl.signUntil(t, "A", id, tag+"-ab", 11, pub)
	cl.stop("B")
	cl.signUntil(t, "A", id, tag+"-ac", 12, pub)
	cl.start(t, "B")
	cl.waitReady(t)
	cl.waitConverged3(t, id, true)
	cl.stop("A")
	cl.signUntil(t, "B", id, tag+"-bc", 13, pub)
	cl.start(t, "A")
	cl.waitReady(t)
	cl.waitConverged3(t, id, true)
}

// ---- tests ----

func TestThresholdDKGSignRefresh(t *testing.T) {
	// Runs for both schemes: the paths it covers are scheme-specific in what they sign and verify.
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, nil)
		pub := cl.dkg(t, "evm1")
		if len(pub) != map[bool]int{true: 32, false: 33}[sc == pb.Scheme_SCHEME_ED25519_2OF3] {
			t.Fatalf("public key %x", pub)
		}
		for role, h := range cl.health(t) {
			ks := statusOf(h, "evm1")
			if ks == nil || ks.Scheme != sc || !bytes.Equal(ks.PublicKey, pub) || !ks.Resolved || ks.Generation != 1 {
				t.Fatalf("party %s status %v", role, ks)
			}
		}
		cl.sign(t, "A", "evm1", "j1", 1, pub)
		if cl.procs["B"].followedSign() != 1 || cl.procs["C"].followedSign() != 0 {
			t.Fatalf("A's first choice is B: B served %d, C served %d", cl.procs["B"].followedSign(), cl.procs["C"].followedSign())
		}
		cl.sign(t, "B", "evm1", "j2", 2, pub)
		if cl.procs["C"].followedSign() != 1 {
			t.Fatalf("B signs with C: C served %d", cl.procs["C"].followedSign())
		}
		// idempotency: the same job id returns the stored signature
		r1, err := cl.signRaw("A", "evm1", "j1", 1)
		must(t, err)
		if !r1.Replayed {
			t.Fatal("a repeated job id did not return the stored signature")
		}
		cl.refresh(t, "evm1")
		if g := cl.waitConverged3(t, "evm1", true); g != 2 {
			t.Fatalf("generation %d after a refresh", g)
		}
		// every pair signs after the refresh (the three-way self-test already proved it before the commit)
		cl.signEveryPair(t, "evm1", pub, "after-refresh")
		// Node/Derive are 2-party HD calls
		_, err = cl.client["A"].Derive(ctx(t, 10*time.Second), &pb.DeriveRequest{KeysetId: "evm1", HardenedPath: []uint32{1}, Path: []uint32{0}})
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_INTERNAL)
		// a second DKG of the same id is refused
		_, err = cl.client["A"].DKG(ctx(t, 20*time.Second), &pb.DKGRequest{KeysetId: "evm1", Scheme: sc, Admin: cl.env.Admin("dkg", "evm1")})
		if err == nil {
			t.Fatal("DKG of an existing keyset succeeded")
		}
	})
}

// Fallback happens only before any signing message and only on availability failures.
func TestThresholdFallbackOrder(t *testing.T) {
	// Runs for both schemes: the paths it covers are scheme-specific in what they sign and verify.
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, nil)
		pub := cl.dkg(t, "k")
		cl.sign(t, "A", "k", "a1", 1, pub)

		// B down: A moves on to C
		cl.stop("B")
		start := time.Now()
		cl.signUntil(t, "A", "k", "a2", 2, pub)
		t.Logf("A with B down signed with C in %v", time.Since(start).Round(time.Millisecond))
		if cl.procs["C"].followedSign() < 1 {
			t.Fatal("C did not serve the fallback signature")
		}
		cl.start(t, "B")
		cl.waitReady(t)
		cl.waitConverged3(t, "k", true)
		n := cl.procs["B"].followedSign()
		cl.signUntil(t, "A", "k", "a3", 3, pub)
		if cl.procs["B"].followedSign() != n+1 {
			t.Fatal("with B back, A uses B again")
		}

		// A down: B signs with C
		cl.stop("A")
		cl.signUntil(t, "B", "k", "b1", 4, pub)
		// C down too: B has nobody
		cl.stop("C")
		_, err := cl.signRaw("B", "k", "b2", 5)
		if err == nil {
			t.Fatal("B signed without C")
		}
		if k, ok := kindOf(err); !ok || (k != pb.ErrorKind_ERROR_KIND_TRANSPORT && k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE) {
			t.Fatalf("B with C down: kind %v: %v", k, err)
		}
	})
}

// A refusal is final: no attempt with the next peer. Both B and C ask their own cosigner in every role.
func TestThresholdCosignersEveryRole(t *testing.T) {
	// Runs for both schemes: the paths it covers are scheme-specific in what they sign and verify.
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, func(role string, c *server.Config) {
			if role == "B" || role == "C" {
				c.Authorizer = server.AuthorizerConfig{Type: "deny-all"}
			}
		})
		// DKG needs no authorizer; signing needs both cosigners, B and C both refuse everything
		pub := cl.dkg(t, "k")
		// A -> B: B's cosigner (follower role) refuses; no attempt with C
		_, err := cl.signRaw("A", "k", "a1", 1)
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		if n := cl.procs["C"].followedSign(); n != 0 {
			t.Fatalf("C was contacted after B refused (%d sessions)", n)
		}
		if strings.Contains(cl.procs["C"].stderr.String(), `"op":"OP_SIGN"`) {
			t.Fatal("C saw a signing session after B refused")
		}
		// B as coordinator: B asks its own cosigner before it opens anything
		_, err = cl.signRaw("B", "k", "b1", 2)
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		if strings.Contains(cl.procs["C"].stderr.String(), `"op":"OP_SIGN"`) {
			t.Fatal("C saw a signing session although B's own cosigner refused")
		}
		_ = pub
	})
}

func TestThresholdCosignerOfC(t *testing.T) {
	// Runs for both schemes: the paths it covers are scheme-specific in what they sign and verify.
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		// only C refuses: A+B signs (the pair does not involve C); with B down A+C is refused by C; B+C is refused by C
		cl := newCluster3S(t, sc, func(role string, c *server.Config) {
			if role == "C" {
				c.Authorizer = server.AuthorizerConfig{Type: "deny-all"}
			}
		})
		pub := cl.dkg(t, "k")
		cl.sign(t, "A", "k", "a1", 1, pub)
		_, err := cl.signRaw("B", "k", "b1", 2)
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		cl.stop("B")
		_, err = cl.signRaw("A", "k", "a2", 3)
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
	})
}

func TestThresholdCosignerOfBOnlyBC(t *testing.T) {
	// Runs for both schemes: the paths it covers are scheme-specific in what they sign and verify.
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		// only B refuses: A is refused by B (no fallback), B+C is refused by B's own cosigner in the coordinator role
		cl := newCluster3S(t, sc, func(role string, c *server.Config) {
			if role == "B" {
				c.Authorizer = server.AuthorizerConfig{Type: "deny-all"}
			}
		})
		_ = cl.dkg(t, "k")
		_, err := cl.signRaw("A", "k", "a1", 1)
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		_, err = cl.signRaw("B", "k", "b1", 2)
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		if cl.procs["C"].followedSign() != 0 {
			t.Fatal("C was asked although B refused")
		}
	})
}

// A cosigner that is down is an outage, not a refusal: the coordinator moves on to the next peer.
func TestThresholdFallbackOnCosignerOutage(t *testing.T) {
	// Runs for both schemes: the paths it covers are scheme-specific in what they sign and verify.
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, func(role string, c *server.Config) {
			if role == "B" {
				c.Authorizer = server.AuthorizerConfig{Type: "cosigner", Socket: "/nonexistent/cosigner.sock", TimeoutMS: 500}
			}
		})
		pub := cl.dkg(t, "k")
		cl.signUntil(t, "A", "k", "a1", 1, pub)
		if cl.procs["C"].followedSign() != 1 {
			t.Fatalf("C should have signed after B's cosigner was unavailable (C served %d)", cl.procs["C"].followedSign())
		}
	})
}

func TestThresholdEveryMemberRestart(t *testing.T) {
	// Runs for both schemes: the paths it covers are scheme-specific in what they sign and verify.
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		cl := newCluster3S(t, sc, nil)
		pub := cl.dkg(t, "k")
		for i, role := range []string{"C", "B", "A", "C", "A"} {
			cl.restart(t, role)
			cl.waitReady(t)
			g := cl.waitConverged3(t, "k", true)
			if g != 1 {
				t.Fatalf("generation %d", g)
			}
			cl.signUntil(t, "A", "k", fmt.Sprintf("r%d", i), 20+i, pub)
			t.Logf("restart of %s: reconciled and signing", role)
		}
	})
}

// Pins per pair: a certificate is refused on every listener that does not pin it.
func TestThresholdPinsPerPair(t *testing.T) {
	cl := newCluster3(t, nil)
	e := cl.env
	certs := map[string]testenv.Cert{"A": e.CertA, "B": e.CertB, "C": e.CertC, "caller": e.CertCaller, "stranger": e.Stranger}
	try := func(addr, serverPin string, c testenv.Cert) bool {
		pins := map[server.Pin]bool{}
		p, _ := server.ParsePin(serverPin)
		pins[p] = true
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(server.ClientTLS(c.TLS, pins))))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		x, cancel := context5(4 * time.Second)
		defer cancel()
		_, err = pb.NewMpcPartyClient(conn).Health(x, &pb.HealthRequest{})
		if err == nil {
			return true
		}
		// on a peer port Health is Unimplemented: the TLS handshake still decides
		return grpcstatus.Code(err) == codes.Unimplemented
	}
	cases := []struct {
		port, addr, pin string
		allowed         map[string]bool
	}{
		{"A caller", cl.addrs.CallerA, e.CertA.Pin, map[string]bool{"caller": true}},
		{"B caller", cl.addrs.CallerB, e.CertB.Pin, map[string]bool{"caller": true}},
		{"C caller", cl.addrs.CallerC, e.CertC.Pin, map[string]bool{"caller": true}},
		{"B peer", cl.addrs.PeerB, e.CertB.Pin, map[string]bool{"A": true}},
		{"C peer", cl.addrs.PeerC, e.CertC.Pin, map[string]bool{"A": true, "B": true}},
	}
	for _, c := range cases {
		for name, cert := range certs {
			got := try(c.addr, c.pin, cert)
			if got != c.allowed[name] {
				t.Errorf("%s port: certificate of %s accepted=%v, want %v", c.port, name, got, c.allowed[name])
			}
		}
	}
	// a dialer that pins the wrong server certificate does not connect either
	if try(cl.addrs.PeerC, e.CertB.Pin, e.CertA) {
		t.Error("a client pinned to B's certificate talked to C")
	}
}

// C serves Health only on its caller port; B serves Health and Sign; DKG, Refresh, Unfreeze belong to A.
func TestThresholdCallerPorts(t *testing.T) {
	cl := newCluster3(t, nil)
	pub := cl.dkg(t, "k")
	x := ctx(t, 10*time.Second)
	for _, role := range []string{"B", "C"} {
		c := cl.client[role]
		if _, err := c.DKG(x, &pb.DKGRequest{KeysetId: "z", Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Admin: cl.env.Admin("dkg", "z")}); grpcstatus.Code(err) != codes.Unimplemented {
			t.Errorf("%s served DKG: %v", role, err)
		}
		if _, err := c.Refresh(x, &pb.RefreshRequest{KeysetId: "k", Admin: cl.env.Admin("refresh", "k")}); grpcstatus.Code(err) != codes.Unimplemented {
			t.Errorf("%s served Refresh: %v", role, err)
		}
		if _, err := c.Unfreeze(x, &pb.UnfreezeRequest{KeysetId: "k", Admin: cl.env.Admin("unfreeze", "k")}); grpcstatus.Code(err) != codes.Unimplemented {
			t.Errorf("%s served Unfreeze: %v", role, err)
		}
	}
	if _, err := cl.client["C"].Sign(x, &pb.SignRequest{KeyId: "k", JobId: "x", Digest: dgst(1), Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1}); grpcstatus.Code(err) != codes.Unimplemented {
		t.Errorf("C served Sign: %v", err)
	}
	cl.sign(t, "B", "k", "ok", 1, pub) // B does serve Sign for 2-of-3
	// B has no 2-party keys
	if _, err := cl.client["B"].Sign(x, &pb.SignRequest{KeyId: "nokey", JobId: "y", Digest: dgst(1), Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1}); grpcstatus.Code(err) != codes.Unimplemented {
		t.Errorf("B served an HD Sign: %v", err)
	}
}

// DKG and Refresh need all three online; an admin signature checked by all three; nothing is half-created.
func TestThresholdNeedsAllThree(t *testing.T) {
	cl := newCluster3(t, nil)
	pub := cl.dkg(t, "k")
	cl.stop("C")
	_, err := cl.client["A"].DKG(ctx(t, 30*time.Second), &pb.DKGRequest{KeysetId: "z", Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Admin: cl.env.Admin("dkg", "z")})
	if err == nil {
		t.Fatal("DKG with C down succeeded")
	}
	if k, ok := kindOf(err); !ok || (k != pb.ErrorKind_ERROR_KIND_TRANSPORT && k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE) {
		t.Fatalf("kind %v: %v", k, err)
	}
	_, err = cl.client["A"].Refresh(ctx(t, 30*time.Second), &pb.RefreshRequest{KeysetId: "k", Admin: cl.env.Admin("refresh", "k")})
	if err == nil {
		t.Fatal("Refresh with C down succeeded")
	}
	cl.signUntil(t, "A", "k", "still", 1, pub) // signing needs only two
	cl.start(t, "C")
	cl.waitReady(t)
	cl.waitConverged3(t, "k", true)
	// a wrong or missing admin signature is refused (checked by B and C themselves, not only by A)
	_, err = cl.client["A"].Refresh(ctx(t, 30*time.Second), &pb.RefreshRequest{KeysetId: "k"})
	wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
	cl.refresh(t, "k")
	if cl.waitConverged3(t, "k", true) != 2 {
		t.Fatal("refresh did not move to generation 2")
	}
}

// 2-party HD keysets run beside 2-of-3 keysets in the same processes, unchanged.
func TestThresholdBesideTwoPartyKeysets(t *testing.T) {
	cl := newCluster3(t, nil)
	x := ctx(t, 90*time.Second)
	tpub := cl.dkg(t, "evm-t")
	root, err := cl.client["A"].DKG(x, &pb.DKGRequest{KeysetId: "btc", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "btc")})
	must(t, err)
	d, err := cl.client["A"].Derive(x, &pb.DeriveRequest{KeysetId: "btc", HardenedPath: []uint32{84, 0, 0}, Path: []uint32{0, 5}})
	must(t, err)
	dg := dgst(31)
	r, err := cl.client["A"].Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "hd-1", IntentPackage: []byte("i")})
	must(t, err)
	verifyECDSA(t, d.PublicKey, dg, r.Signature)
	cl.sign(t, "A", "evm-t", "t-1", 32, tpub)
	_, err = cl.client["A"].Refresh(x, &pb.RefreshRequest{KeysetId: "btc", Admin: cl.env.Admin("refresh", "btc")})
	must(t, err)
	cl.refresh(t, "evm-t")
	r, err = cl.client["A"].Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "hd-2", IntentPackage: []byte("i")})
	must(t, err)
	verifyECDSA(t, d.PublicKey, dg, r.Signature)
	cl.sign(t, "A", "evm-t", "t-2", 33, tpub)
	// C holds only the 2-of-3 keyset
	hc := cl.health(t)["C"]
	if statusOf(hc, "btc") != nil || statusOf(hc, "evm-t") == nil {
		t.Fatalf("C's keysets: %v", hc.Keysets)
	}
	_ = root
	// the 2-party keyset still reconciles with B after B restarts, C running alongside
	cl.restart(t, "B")
	cl.waitReady(t)
	cl.waitConvergedOn(t, "btc", true, "A", "B")
	cl.waitConverged3(t, "evm-t", true)
}

// Mixed generations across three members never sign: a member restored to an older generation is refused (UNAVAILABLE,
// generation mismatch), never a signature, never a freeze.
func TestThresholdMixedGenerationsNeverSign(t *testing.T) {
	cl := newCluster3(t, nil)
	pub := cl.dkg(t, "k")
	cl.sign(t, "A", "k", "a1", 1, pub)
	// take C's data directory at generation 1, refresh, then put the old one back
	cl.stop("C")
	old := copyDir(t, cl.cfgs["C"].DataDir)
	cl.start(t, "C")
	cl.waitReady(t)
	cl.waitConverged3(t, "k", true)
	cl.refresh(t, "k")
	cl.waitConverged3(t, "k", true)
	cl.stop("C")
	replaceDir(t, cl.cfgs["C"].DataDir, old)
	cl.start(t, "C")
	cl.waitReady(t)
	// A reconciles: C is on an older generation: refused with an operator message; the keyset never serves a mix
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(cl.procs["A"].stderr.String(), "ALERT keyset cannot be reconciled") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(cl.procs["A"].stderr.String(), "ALERT keyset cannot be reconciled") {
		t.Fatalf("A did not flag the stale member:\n%s", tail(cl.procs["A"].stderr.String()))
	}
	if !strings.Contains(cl.procs["A"].stderr.String(), "restore it from a backup of generation 2") {
		t.Fatal("the alert does not say which member to restore from which generation")
	}
	// A stale member does not stop the other two: A+B keep signing (A reconciled with B alone). The stale member itself is
	// out: it is unresolved and never signs, and with B down A has nobody it can use.
	cl.signUntil(t, "A", "k", "ab-still", 2, pub)
	hc := statusOf(cl.health(t)["C"], "k")
	if hc == nil || hc.Resolved || hc.Generation != 1 {
		t.Fatalf("the stale member must stay unresolved on its old generation, got %v", hc)
	}
	cl.stop("B")
	_, err := cl.signRaw("A", "k", "needs-c", 3)
	if err == nil {
		t.Fatal("A signed with the stale member")
	}
	if k, ok := kindOf(err); !ok || k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
		t.Fatalf("want UNAVAILABLE with B down and C stale, got kind %v: %v", k, err)
	}
	_ = syscall.SIGSTOP
}

func copyDir(t *testing.T, dir string) string {
	t.Helper()
	dst := t.TempDir() + "/copy"
	out, err := execCmd("cp", "-R", dir, dst)
	if err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
	return dst
}

func replaceDir(t *testing.T, dir, from string) {
	t.Helper()
	if out, err := execCmd("rm", "-rf", dir); err != nil {
		t.Fatalf("rm: %v %s", err, out)
	}
	if out, err := execCmd("cp", "-R", from, dir); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
}

func execCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// A restarts while one member is down: A reconciles with the member that is up (when nothing is unfinished) and signs; the
// member that was away is reconciled when it returns.
func TestThresholdAbsentMemberDuringRestart(t *testing.T) {
	cl := newCluster3(t, nil)
	pub := cl.dkg(t, "k")
	for _, down := range []string{"C", "B"} {
		cl.stop(down)
		cl.restart(t, "A")
		cl.waitUp(t, "A")
		// A comes back with the third member down: it must still sign with the one that is up
		cl.signUntil(t, "A", "k", "no-"+down, 40, pub)
		if !strings.Contains(cl.procs["A"].stderr.String(), "keyset reconciled with one member only") {
			t.Fatalf("A did not log the partial reconciliation:\n%s", tail(cl.procs["A"].stderr.String()))
		}
		cl.start(t, down)
		cl.waitReady(t)
		cl.waitConverged3(t, "k", true) // the returning member is reconciled across all three
		cl.signEveryPair(t, "k", pub, "back-"+down)
	}
}

// waitUp waits until a party answers Health on its caller port (its peers may still be down).
func (cl *cluster3) waitUp(t *testing.T, role string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := cl.client[role].Health(ctx(t, 2*time.Second), &pb.HealthRequest{}); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("party %s did not come up", role)
}
