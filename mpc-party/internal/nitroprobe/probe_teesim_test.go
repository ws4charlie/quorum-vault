//go:build teesim

package nitroprobe_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease/kmsfake"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/nitroprobe"
)

type rig struct {
	att  *attest.MockAttester
	deps nitroprobe.Deps
	pcr0 string
	kms  *kmsfake.Fake
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ca, err := attest.NewMockCA(time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := attest.NewNitroVerifier(attest.NitroConfig{Roots: []*x509.Certificate{ca.Root}})
	pcr0 := attest.MeasureImage([]byte("probe image"), nil)
	k, err := kmsfake.New("key-p", v, kmsfake.Policy{PCRs: map[int]string{0: hex.EncodeToString(pcr0)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	cl, err := kmsrelease.New(kmsrelease.Config{KeyID: "key-p", Region: "eu-central-1", Endpoint: k.URL,
		Creds: kmsrelease.StaticCreds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.Secret, SessionToken: k.Token}})
	if err != nil {
		t.Fatal(err)
	}
	at := &attest.MockAttester{CA: ca, PCR0: pcr0, PCR8: attest.MeasureCert([]byte("c"))}
	return &rig{att: at, pcr0: hex.EncodeToString(pcr0), kms: k, deps: nitroprobe.Deps{Attester: at, Verifier: v, KMS: cl}}
}

func TestProbeReportsEveryCheck(t *testing.T) {
	r := newRig(t)
	rep := nitroprobe.Run(context.Background(), nitroprobe.Config{}, r.deps)
	if !rep.Verified || rep.Debug || rep.PCRs["0"] != r.pcr0 {
		t.Fatalf("%+v", rep)
	}
	if rep.KMS == nil || !rep.KMS.KeysEqual || rep.KMS.Error != "" || rep.DocumentBytes == 0 || len(rep.Errors) != 0 {
		t.Fatalf("kms %+v errors %v", rep.KMS, rep.Errors)
	}
	if abs(rep.ClockSkewMS) > 5000 {
		t.Fatalf("clock skew %d ms", rep.ClockSkewMS)
	}
	b, _ := json.Marshal(rep)
	for _, banned := range []string{"private", "sealed", "CiphertextForRecipient", "SecretAccessKey"} {
		if strings.Contains(string(b), banned) {
			t.Fatalf("the report names %s", banned)
		}
	}
	if !strings.Contains(rep.Summary(), "keys equal true") {
		t.Fatal(rep.Summary())
	}
}

func TestProbeSaysWhatIsWrong(t *testing.T) {
	r := newRig(t)
	// a debug-mode enclave: the production verifier refuses the document, and KMS refuses the call
	r.att.Debug = true
	rep := nitroprobe.Run(context.Background(), nitroprobe.Config{}, r.deps)
	if rep.Verified || !strings.Contains(rep.VerifyError, "debug") {
		t.Fatalf("debug document verified: %+v", rep)
	}
	if rep.KMS == nil || rep.KMS.KeysEqual || !strings.Contains(rep.KMS.Error, "AccessDeniedException") {
		t.Fatalf("kms %+v", rep.KMS)
	}
	// no KMS configured: the probe still checks the document
	r.att.Debug = false
	r.deps.KMS = nil
	if rep := nitroprobe.Run(context.Background(), nitroprobe.Config{}, r.deps); !rep.Verified || rep.KMS != nil {
		t.Fatalf("%+v", rep)
	}
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
