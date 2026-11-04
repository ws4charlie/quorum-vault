package e2e

import (
	"bytes"
	"crypto/ed25519"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// DKG, Node, Derive, Sign, Refresh, Sign again: two separate processes, mTLS, both algorithms, independent verifiers.
func TestTwoProcessFlow(t *testing.T) {
	cl := newCluster(t, nil, false)
	c := cl.client
	x := ctx(t, 90*time.Second)

	// ECDSA / BIP32 through Node
	root, err := c.DKG(x, &pb.DKGRequest{KeysetId: "evm", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "evm")})
	must(t, err)
	hard := []uint32{44, 60, 0}
	node, err := c.Node(x, &pb.NodeRequest{KeysetId: "evm", HardenedPath: hard})
	must(t, err)
	xpub := hdkeychain.NewExtendedKey(chaincfg.MainNetParams.HDPublicKeyID[:], node.PublicKey, node.ChainCode, []byte{0, 0, 0, 0}, 3, 0, false)
	child, err := xpub.Derive(4)
	must(t, err)
	want, _ := child.ECPubKey()
	d, err := c.Derive(x, &pb.DeriveRequest{KeysetId: "evm", HardenedPath: hard, Path: []uint32{4}})
	must(t, err)
	if !bytes.Equal(d.PublicKey, want.SerializeCompressed()) {
		t.Fatalf("derived key %x != BIP32 child of Node %x", d.PublicKey, want.SerializeCompressed())
	}
	sign := func(job string, seed int) {
		dg := dgst(seed)
		r, err := c.Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: job, IntentPackage: []byte("intent")})
		must(t, err)
		verifyECDSA(t, d.PublicKey, dg, r.Signature)
	}
	sign("e-1", 1)
	rr, err := c.Refresh(x, &pb.RefreshRequest{KeysetId: "evm", Admin: cl.env.Admin("refresh", "evm")})
	must(t, err)
	if !bytes.Equal(rr.RootPublicKey, root.RootPublicKey) {
		t.Fatal("root key changed on refresh")
	}
	sign("e-2", 2)

	// Ed25519
	_, err = c.DKG(x, &pb.DKGRequest{KeysetId: "sol", Curve: pb.Curve_CURVE_ED25519, Admin: cl.env.Admin("dkg", "sol")})
	must(t, err)
	ds, err := c.Derive(x, &pb.DeriveRequest{KeysetId: "sol", HardenedPath: []uint32{44, 501, 0}, Path: []uint32{0}})
	must(t, err)
	msg := []byte("solana message")
	for i, job := range []string{"s-1", "s-2"} {
		if i == 1 {
			_, err = c.Refresh(x, &pb.RefreshRequest{KeysetId: "sol", Admin: cl.env.Admin("refresh", "sol")})
			must(t, err)
		}
		r, err := c.Sign(x, &pb.SignRequest{KeyId: ds.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: msg, JobId: job})
		must(t, err)
		if !ed25519.Verify(ds.PublicKey, msg, r.Signature) {
			t.Fatal("ed25519 signature does not verify")
		}
	}
	// B refuses callers on its caller port except Health.
	bc, _ := testenv.Dial(t, cl.callerB, cl.env.CertCaller, cl.env.CertB.Pin)
	if _, err := bc.Sign(x, &pb.SignRequest{KeyId: d.KeyId, JobId: "x", Digest: dgst(1)}); grpcstatus.Code(err) != codes.Unimplemented {
		t.Fatalf("B served Sign: %v", err)
	}
	// No shares or keys in logs.
	for _, p := range []*proc{cl.a, cl.b} {
		if bytes.Contains([]byte(p.stderr.String()), []byte("PRIVATE KEY")) {
			t.Fatal("secret material in logs")
		}
	}
	t.Logf("A log sample: %.400s", cl.a.stderr.String())
}

// Idempotency survives a restart of A, the stored signature is returned byte for byte.
func TestIdempotentSignAcrossRestart(t *testing.T) {
	cl := newCluster(t, nil, false)
	x := ctx(t, 90*time.Second)
	_, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: pb.Curve_CURVE_ED25519, Admin: cl.env.Admin("dkg", "k")})
	must(t, err)
	d, err := cl.client.Derive(x, &pb.DeriveRequest{KeysetId: "k", HardenedPath: []uint32{1}, Path: []uint32{0}})
	must(t, err)
	req := &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "j"}
	first, err := cl.client.Sign(x, req)
	must(t, err)
	cl.a.kill()
	cl.restartA(t)
	var again *pb.SignResponse
	retry(t, 20*time.Second, func() (err error) { again, err = cl.client.Sign(x, req); return })
	if !bytes.Equal(first.Signature, again.Signature) || !again.Replayed {
		t.Fatal("retry after restart did not return the stored signature")
	}
	req.Digest = []byte("other")
	_, err = cl.client.Sign(x, req)
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("different digest, same job id: %v", err)
	}
}

func TestBinaryRefusesBadStartup(t *testing.T) {
	env := testenv.NewEnv(t)
	cfg := env.Config(t, "B", "", testenv.FreeAddr(t), testenv.FreeAddr(t))
	good := env.WriteConfig(t, cfg, "good.json")
	run := func(bin string, args ...string) (int, string) {
		cmd := exec.Command(bin, args...)
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	if code, _ := run(binDev); code == 0 {
		t.Error("started with no -config")
	}
	if code, out := run(binDev, "-config", filepath.Join(env.Dir, "missing.json")); code == 0 {
		t.Errorf("started with a missing config: %s", out)
	}
	bad := *cfg
	bad.Role = "X"
	if code, out := run(binDev, "-config", env.WriteConfig(t, &bad, "bad.json")); code == 0 {
		t.Errorf("started with an invalid config: %s", out)
	}
	// A production build has no allow-all authorizer, whatever the config says.
	if code, out := run(binProd, "-config", good); code == 0 {
		t.Errorf("production build accepted dev-allow-all: %s", out)
	} else if !bytes.Contains([]byte(out), []byte("not available in this build")) {
		t.Errorf("unexpected refusal text: %s", out)
	}
	// The dev build refuses dev-allow-all without the explicit risk phrase.
	noRisk := *cfg
	noRisk.Authorizer.AcceptRisk = ""
	if code, out := run(binDev, "-config", env.WriteConfig(t, &noRisk, "norisk.json")); code == 0 {
		t.Errorf("dev build accepted dev-allow-all without the risk phrase: %s", out)
	}
	// And no authorizer at all.
	none := *cfg
	none.Authorizer = server.AuthorizerConfig{}
	if code, out := run(binDev, "-config", env.WriteConfig(t, &none, "none.json")); code == 0 {
		t.Errorf("started without an authorizer: %s", out)
	}
}
