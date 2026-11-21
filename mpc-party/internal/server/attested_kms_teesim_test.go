//go:build teesim

package server_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease/kmsfake"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// The whole start-up of a Nitro party against a FAKE KMS, with the Nitro document format end to end: the party's mock NSM signs a document with a test
// root, the KMS adapter sends it as Recipient (SigV4-signed JSON over HTTP), the fake KMS verifies it with the real NitroVerifier and the key policy's PCR
// conditions and answers with CMS EnvelopedData (BER, RSAES-OAEP/SHA-256, AES-256-CBC) to the party's RSA key, the sealer opens it and unseals, and the
// two parties run DKG, sign, refresh and restart. Nothing here has run against AWS: docs/runbooks/nitro-first-run.md does that.

const (
	kmsAK    = "AKIAFAKEFORTESTSONLY1"
	kmsToken = "fake-session-token"
)

func (r *attRig) useFakeKMS(t *testing.T) map[string]*kmsfake.Fake {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", kmsAK)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fake-secret-"+hex.EncodeToString([]byte(t.Name()))[:16])
	t.Setenv("AWS_SESSION_TOKEN", kmsToken)
	v, err := attest.NewNitroVerifier(attest.NitroConfig{Roots: []*x509.Certificate{r.CA.Root}})
	if err != nil {
		t.Fatal(err)
	}
	pcr8 := hex.EncodeToString(attest.MeasureCert([]byte("mock signing cert")))
	fakes := map[string]*kmsfake.Fake{}
	for role, p := range r.Parties {
		f, err := kmsfake.New("key-"+role, v, kmsfake.Policy{PCRs: map[int]string{0: p.PCR0Hex(), 8: pcr8}})
		if err != nil {
			t.Fatal(err)
		}
		f.SetCreds(kmsAK, os.Getenv("AWS_SECRET_ACCESS_KEY"), kmsToken)
		t.Cleanup(f.Close)
		fakes[role] = f
	}
	r.kms = func(role, pcr0 string) server.SealerConfig {
		return server.SealerConfig{Type: server.AttestedSealerType,
			Release:  server.ReleaseConfig{Type: "kms", KMS: server.KMSConfig{KeyID: "key-" + role, Region: "eu-central-1", Endpoint: fakes[role].URL}},
			Attester: server.AttesterConfig{Type: "mock", CADir: r.CADir, PCR0: pcr0}}
	}
	return fakes
}

func TestAttestedKMSPairDKGSignRefreshRestart(t *testing.T) {
	r := newAttRig(t)
	fakes := r.useFakeKMS(t)
	c := newAttClusterOn(t, r)
	c.up()
	defer c.down()
	c.waitReady(30 * time.Second)

	c.p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	d := c.p.derive(t, "ks", []uint32{44, 60, 0}, []uint32{0})
	if err := c.sign(d.KeyId, "j1", digest(1), d.PublicKey); err != nil {
		t.Fatal(err)
	}
	if got := len(c.sealA.Held()); got != 2 {
		t.Fatalf("party A holds %d data keys, want 2: %v", got, c.sealA.Held())
	}
	if _, err := c.p.Client.Refresh(ctx30(t), &pb.RefreshRequest{KeysetId: "ks", Admin: c.r.env.Admin("refresh", "ks")}); err != nil {
		t.Fatal(err)
	}
	c.waitResolved("ks", 2)
	if err := c.sign(d.KeyId, "j2", digest(2), d.PublicKey); err != nil {
		t.Fatal(err)
	}
	c.down()
	c.up() // new processes: nothing in memory, KMS releases again from the wrapped keys on disk
	c.waitReady(30 * time.Second)
	c.waitResolved("ks", 2)
	if err := c.sign(d.KeyId, "j3", digest(3), d.PublicKey); err != nil {
		t.Fatal(err)
	}
	for role, f := range fakes {
		var gen, dec int
		for _, call := range f.Calls() {
			if !call.Allowed {
				t.Fatalf("party %s: KMS refused %+v", role, call)
			}
			if call.PCR0 != r.Parties[role].PCR0Hex() {
				t.Fatalf("party %s: KMS saw PCR0 %s", role, call.PCR0)
			}
			switch call.Op {
			case "GenerateDataKey":
				gen++
			case "Decrypt":
				dec++
			}
		}
		if gen < 2 || dec < 2 {
			t.Fatalf("party %s: %d GenerateDataKey and %d Decrypt calls", role, gen, dec)
		}
	}
	// nothing at rest but ciphertext and KMS's wrapped keys, and no log line names a key
	for _, l := range []string{c.logA.String(), c.logB.String()} {
		if strings.Contains(l, "wrapped_dek") || strings.Contains(l, "CiphertextForRecipient") {
			t.Fatal("a log line carries key material")
		}
	}
}

// An image the key policy does not name gets nothing: the sealer reports a refusal of the allowlist kind and holds no key.
func TestAttestedKMSRefusesAnImageTheKeyPolicyDoesNotName(t *testing.T) {
	r := newAttRig(t)
	fakes := r.useFakeKMS(t)
	// A's image
	good, err := server.NewSealerForRole("A", r.sealerConfig("A", ""))
	if err != nil {
		t.Fatal(err)
	}
	as := good.(*server.AttestedSealer)
	defer as.Close()
	if _, err := as.Preload(context.Background(), server.UnlockSet{Fresh: true}); err != nil {
		t.Fatal(err)
	}
	// the operators change the key policy: the old image is out (a key-policy change is the revocation)
	fakes["A"].SetPolicy(kmsfake.Policy{PCRs: map[int]string{0: strings.Repeat("cd", 48)}})
	s2, _ := server.NewSealerForRole("A", r.sealerConfig("A", ""))
	as2 := s2.(*server.AttestedSealer)
	defer as2.Close()
	_, err = as2.Preload(context.Background(), server.UnlockSet{Fresh: true})
	if err == nil || !errors.Is(err, server.ErrKeyRefused) {
		t.Fatalf("want ErrKeyRefused, got %v", err)
	}
	if len(as2.Held()) != 0 || as2.Ready() {
		t.Fatal("a refused sealer holds a key or is ready")
	}
	if as2.Stats()["refused:allowlist"] == 0 {
		t.Fatalf("no allowlist refusal counted: %v", as2.Stats())
	}
	// a debug (all-zero PCR) enclave is refused by KMS too
	s3, _ := server.NewSealerForRole("B", func() server.SealerConfig { c := r.sealerConfig("B", ""); c.Attester.Debug = true; return c }())
	as3 := s3.(*server.AttestedSealer)
	defer as3.Close()
	if _, err := as3.Preload(context.Background(), server.UnlockSet{Fresh: true}); !errors.Is(err, server.ErrKeyRefused) {
		t.Fatalf("debug enclave: %v", err)
	}
}

func TestAttestedKMSConfigIsChecked(t *testing.T) {
	for name, c := range map[string]server.SealerConfig{
		"no key id":      {Type: "attested", Release: server.ReleaseConfig{Type: "kms", KMS: server.KMSConfig{Region: "r"}}, Attester: server.AttesterConfig{Type: "nitro"}},
		"no region":      {Type: "attested", Release: server.ReleaseConfig{Type: "kms", KMS: server.KMSConfig{KeyID: "k"}}, Attester: server.AttesterConfig{Type: "nitro"}},
		"no attester":    {Type: "attested", Release: server.ReleaseConfig{Type: "kms", KMS: server.KMSConfig{KeyID: "k", Region: "r"}}},
		"bad vsock":      {Type: "attested", Release: server.ReleaseConfig{Type: "kms", KMS: server.KMSConfig{KeyID: "k", Region: "r", VsockPort: 2}}, Attester: server.AttesterConfig{Type: "nitro"}},
		"unknown":        {Type: "attested", Release: server.ReleaseConfig{Type: "vault"}, Attester: server.AttesterConfig{Type: "nitro"}},
		"plain endpoint": {Type: "attested", Release: server.ReleaseConfig{Type: "kms", KMS: server.KMSConfig{KeyID: "k", Region: "r", Endpoint: "http://kms.example.com"}}, Attester: server.AttesterConfig{Type: "mock"}},
	} {
		t.Setenv("AWS_ACCESS_KEY_ID", "a")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "b")
		if _, err := server.NewSealerForRole("A", c); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
