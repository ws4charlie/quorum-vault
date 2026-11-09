package e2e

import (
	"bytes"
	"strings"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// 2-of-3 Ed25519 specifics (P8-2): what differs from ECDSA is what Sign carries and returns, the sign-once rule, and the
// refusal of one scheme's request on the other scheme's keyset.

func (cl *cluster3) dkgScheme(t *testing.T, id string, sc pb.Scheme) []byte {
	t.Helper()
	r, err := cl.client["A"].DKG(ctx(t, 60*time.Second), &pb.DKGRequest{KeysetId: id, Scheme: sc, Admin: cl.env.Admin("dkg", id)})
	must(t, err)
	return r.RootPublicKey
}

func TestThresholdEd25519SignOnceAndSchemes(t *testing.T) {
	cl := newCluster3S(t, pb.Scheme_SCHEME_ED25519_2OF3, nil)
	pub := cl.dkgScheme(t, "sol", pb.Scheme_SCHEME_ED25519_2OF3)
	epub := cl.dkgScheme(t, "evm", pb.Scheme_SCHEME_ECDSA_2OF3)
	if len(pub) != 32 || len(epub) != 33 {
		t.Fatalf("public keys: ed25519 %d bytes, ecdsa %d bytes", len(pub), len(epub))
	}

	// a whole transaction-sized message, through A (with B), verified with crypto/ed25519
	msg := bytes.Repeat([]byte("solana-tx-message|"), 70) // 1260 bytes
	req := func(key, job string, alg pb.Algorithm, m []byte) *pb.SignRequest {
		return &pb.SignRequest{KeyId: key, Algorithm: alg, Digest: m, JobId: job, IntentPackage: []byte("intent")}
	}
	call := func(via string, r *pb.SignRequest) (*pb.SignResponse, error) {
		c, cancel := context5(60 * time.Second)
		defer cancel()
		return cl.client[via].Sign(c, r)
	}
	r1, err := call("A", req("sol", "job-1", pb.Algorithm_ALGORITHM_ED25519, msg))
	must(t, err)
	verifyEd25519(t, pub, msg, r1.Signature)
	if r1.Replayed || len(r1.Signature) != 64 {
		t.Fatalf("first signature: replayed=%v len=%d", r1.Replayed, len(r1.Signature))
	}

	// sign once: the same job returns the stored signature, byte for byte, and starts no new session
	served := cl.procs["B"].followedSign() + cl.procs["C"].followedSign()
	r2, err := call("A", req("sol", "job-1", pb.Algorithm_ALGORITHM_ED25519, msg))
	must(t, err)
	if !r2.Replayed || !bytes.Equal(r1.Signature, r2.Signature) {
		t.Fatal("a repeated job did not return the stored signature")
	}
	if n := cl.procs["B"].followedSign() + cl.procs["C"].followedSign(); n != served {
		t.Fatalf("a repeated job started a new signing session (%d -> %d)", served, n)
	}
	// a different message under the same job is refused, and the stored signature stays
	_, err = call("A", req("sol", "job-1", pb.Algorithm_ALGORITHM_ED25519, append(append([]byte(nil), msg...), 'x')))
	if err == nil || !strings.Contains(err.Error(), "already used for a different request") {
		t.Fatalf("a different message under one job: %v", err)
	}
	if r3, err := call("A", req("sol", "job-1", pb.Algorithm_ALGORITHM_ED25519, msg)); err != nil || !bytes.Equal(r3.Signature, r1.Signature) {
		t.Fatalf("stored signature changed after a refused request: %v", err)
	}

	// mixed schemes are refused with a message that names both; nothing is signed
	_, err = call("A", req("sol", "mix-1", pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, dgst(1)))
	if err == nil || !strings.Contains(err.Error(), "ed25519-2of3") {
		t.Fatalf("ECDSA request on an Ed25519 keyset: %v", err)
	}
	_, err = call("A", req("evm", "mix-2", pb.Algorithm_ALGORITHM_ED25519, msg))
	if err == nil || !strings.Contains(err.Error(), "ecdsa-2of3") {
		t.Fatalf("Ed25519 request on an ECDSA keyset: %v", err)
	}
	// the other scheme's keyset still signs its own kind
	d := dgst(2)
	re, err := call("A", req("evm", "evm-1", pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, d))
	must(t, err)
	verifyECDSA(t, epub, d, re.Signature)
	// DKG of an existing id in the other scheme, and a curve that does not fit the scheme
	_, err = cl.client["A"].DKG(ctx(t, 20*time.Second), &pb.DKGRequest{KeysetId: "sol", Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Admin: cl.env.Admin("dkg", "sol")})
	if err == nil {
		t.Fatal("DKG of an existing Ed25519 keyset as ECDSA succeeded")
	}
	_, err = cl.client["A"].DKG(ctx(t, 20*time.Second), &pb.DKGRequest{KeysetId: "bad", Scheme: pb.Scheme_SCHEME_ED25519_2OF3, Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "bad")})
	if err == nil || !strings.Contains(err.Error(), "curve") {
		t.Fatalf("Ed25519 scheme on secp256k1: %v", err)
	}
	// message limits: empty and above the wrapper's cap
	_, err = call("A", req("sol", "empty", pb.Algorithm_ALGORITHM_ED25519, nil))
	wantKind(t, err, pb.ErrorKind_ERROR_KIND_INTERNAL)
	_, err = call("A", req("sol", "huge", pb.Algorithm_ALGORITHM_ED25519, make([]byte, 65537)))
	wantKind(t, err, pb.ErrorKind_ERROR_KIND_INTERNAL)
	// Node and Derive remain 2-party HD calls
	_, err = cl.client["A"].Node(ctx(t, 10*time.Second), &pb.NodeRequest{KeysetId: "sol", HardenedPath: []uint32{1}})
	wantKind(t, err, pb.ErrorKind_ERROR_KIND_INTERNAL)

	// B as coordinator (with C) signs a message too, and refresh keeps the key; every pair signs afterwards
	cl.sign(t, "B", "sol", "job-b", 5, pub)
	cl.refresh(t, "sol")
	cl.waitConverged3(t, "sol", true)
	cl.signEveryPair(t, "sol", pub, "ed-refresh")
}
