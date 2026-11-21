// Package nitroprobe is the first-hardware check run INSIDE a Nitro enclave (docs/runbooks/nitro-first-run.md): `mpc-party nitro-probe`. It asks the NSM for a
// real attestation document, verifies it with the production verifier (the pinned AWS root), optionally makes one GenerateDataKey and one Decrypt call to KMS with
// that kind of document, times each step, and sends a JSON report out over vsock (an enclave has no console in production mode). It exists because the simulation
// cannot show these things, and a human on the first day needs one command that shows them. It holds no key: the data key it gets from KMS is compared with
// the one it gets back, by hash, and dropped.
package nitroprobe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease"
)

// Config is probe.json (in the probe image's config directory).
type Config struct {
	ReportVsockPort uint32 `json:"report_vsock_port"` // the parent listens here (CID 3) and prints what arrives
	ExpectPCR0      string `json:"expect_pcr0"`       // the PCR0 eif-build.sh printed; the report says whether the document carries it
	KMS             *struct {
		KeyID          string `json:"key_id"`
		Region         string `json:"region"`
		VsockPort      uint32 `json:"vsock_port"`
		CredsVsockPort uint32 `json:"creds_vsock_port"`
	} `json:"kms"`
}

// Report is what the probe sends. Durations are milliseconds. No field holds key material or a document's private part.
type Report struct {
	Probe         string            `json:"probe"`
	StartedAt     string            `json:"started_at"`     // the enclave's own clock, RFC 3339 UTC: compare with the parent's
	ClockSkewMS   int64             `json:"clock_skew_ms"`  // document timestamp minus the enclave's clock when it was asked for
	RNG           string            `json:"rng_current"`    // /sys/devices/virtual/misc/hw_random/rng_current: nsm-hwrng expected
	MemTotalMiB   int               `json:"mem_total_mib"`  // what the enclave sees
	HeapMiB       int               `json:"heap_alloc_mib"` // Go heap at the end of the probe
	AttestMS      int64             `json:"attest_ms"`      // the NSM call, RSA key generation excluded
	RSAKeyGenMS   int64             `json:"rsa_keygen_ms"`
	DocumentBytes int               `json:"document_bytes"`
	Verified      bool              `json:"verified"` // the production verifier (pinned AWS root) accepted the document
	VerifyError   string            `json:"verify_error,omitempty"`
	ModuleID      string            `json:"module_id,omitempty"`
	Debug         bool              `json:"debug"`
	PCRs          map[string]string `json:"pcrs,omitempty"` // PCR index -> hex, only non-zero ones
	PCR0Matches   *bool             `json:"pcr0_matches_expected,omitempty"`
	KMS           *KMSReport        `json:"kms,omitempty"`
	Errors        []string          `json:"errors,omitempty"`
}

// KMSReport is the optional KMS round trip.
type KMSReport struct {
	GenerateDataKeyMS int64  `json:"generate_data_key_ms"`
	DecryptMS         int64  `json:"decrypt_ms"`
	KeysEqual         bool   `json:"keys_equal"`      // the key GenerateDataKey gave and the one Decrypt returned for its blob
	Error             string `json:"error,omitempty"` // for example "kms refused (400): AccessDeniedException"
}

// Deps are what the probe uses; the command fills them from the device and the config, tests with fakes.
type Deps struct {
	Attester attest.Attester
	Verifier attest.Verifier
	KMS      *kmsrelease.Client // nil: no KMS step
	Now      func() time.Time
	ReadFile func(string) ([]byte, error)
}

func ms(d time.Duration) int64 { return d.Milliseconds() }

// Run does the checks and returns the report. It never returns an error for a failed check: the failure is the report.
func Run(ctx context.Context, cfg Config, d Deps) Report {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.ReadFile == nil {
		d.ReadFile = os.ReadFile
	}
	r := Report{Probe: "qv-nitro-probe/1", StartedAt: d.Now().UTC().Format(time.RFC3339)}
	if b, err := d.ReadFile("/sys/devices/virtual/misc/hw_random/rng_current"); err == nil {
		r.RNG = strings.TrimSpace(string(b))
	}
	if b, err := d.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.Atoi(f[1])
				r.MemTotalMiB = kb / 1024
			}
		}
	}

	var recipient *kmsKey
	t := d.Now()
	pub, open, err := recipientKey(d)
	r.RSAKeyGenMS = ms(d.Now().Sub(t))
	if err != nil {
		r.Errors = append(r.Errors, "recipient key: "+err.Error())
		return finish(&r)
	}
	recipient = &kmsKey{pub: pub, open: open}

	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	ud := []byte("qv-nitro-probe/1")
	t = d.Now()
	doc, err := d.Attester.Attest(nonce, recipient.pub, ud)
	r.AttestMS = ms(d.Now().Sub(t))
	if err != nil {
		r.Errors = append(r.Errors, "attest: "+err.Error())
		return finish(&r)
	}
	r.DocumentBytes = len(doc)
	claims, err := d.Verifier.Verify(doc, attest.Expect{Nonce: nonce, UserData: ud, PublicKey: recipient.pub}, d.Now())
	if err != nil {
		r.VerifyError = err.Error()
	} else {
		r.Verified = true
		r.ModuleID, r.Debug = claims.ModuleID, claims.Debug
		r.ClockSkewMS = ms(claims.Timestamp.Sub(d.Now()))
		r.PCRs = map[string]string{}
		for i, v := range claims.Measurements {
			if !allZero(v) {
				r.PCRs[strconv.Itoa(i)] = hex.EncodeToString(v)
			}
		}
		if cfg.ExpectPCR0 != "" {
			m := strings.EqualFold(cfg.ExpectPCR0, claims.Measurement())
			r.PCR0Matches = &m
		}
	}
	if d.KMS != nil {
		r.KMS = kmsRound(ctx, d)
	}
	return finish(&r)
}

type kmsKey struct {
	pub  []byte
	open func(aad, sealed []byte) ([]byte, error)
}

// recipientKey makes the RSA key of the document (what KMS needs). Without a KMS client the probe makes the same kind of key through a throwaway client, so the timing is the real one.
func recipientKey(d Deps) ([]byte, func(aad, sealed []byte) ([]byte, error), error) {
	if d.KMS != nil {
		return d.KMS.NewRecipient()
	}
	c, err := kmsrelease.New(kmsrelease.Config{KeyID: "probe", Region: "probe", Creds: kmsrelease.StaticCreds{AccessKeyID: "x", SecretAccessKey: "x"}})
	if err != nil {
		return nil, nil, err
	}
	return c.NewRecipient()
}

func kmsRound(ctx context.Context, d Deps) *KMSReport {
	k := &KMSReport{}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rc := attest.RequestContext{Party: "probe", Keyset: "probe", Generations: []uint64{1}, Purpose: attest.PurposeCreate}
	evidence := func() ([]byte, func(aad, sealed []byte) ([]byte, error), error) {
		pub, open, err := d.KMS.NewRecipient()
		if err != nil {
			return nil, nil, err
		}
		ch, _ := d.KMS.Challenge(ctx)
		doc, err := d.Attester.Attest(ch.Nonce, pub, []byte("qv-nitro-probe/1"))
		return doc, open, err
	}
	doc, open, err := evidence()
	if err != nil {
		k.Error = "evidence: " + err.Error()
		return k
	}
	t := d.Now()
	made, err := d.KMS.NewKey(ctx, attest.ReleaseRequest{Evidence: doc, Context: rc})
	k.GenerateDataKeyMS = ms(d.Now().Sub(t))
	if err != nil || len(made.Keys) != 1 {
		k.Error = errText(err, "GenerateDataKey")
		return k
	}
	first, err := open(nil, made.Keys[0].Sealed)
	if err != nil {
		k.Error = "the answer does not open under the document's key: " + err.Error()
		return k
	}
	doc2, open2, err := evidence()
	if err != nil {
		k.Error = "evidence: " + err.Error()
		return k
	}
	rc.Purpose = attest.PurposeUnseal
	t = d.Now()
	rel, err := d.KMS.Release(ctx, attest.ReleaseRequest{Evidence: doc2, Context: rc, Blobs: [][]byte{made.Keys[0].Blob}})
	k.DecryptMS = ms(d.Now().Sub(t))
	if err != nil || len(rel.Keys) != 1 {
		k.Error = errText(err, "Decrypt")
		return k
	}
	second, err := open2(nil, rel.Keys[0].Sealed)
	if err != nil {
		k.Error = "the answer does not open under the document's key: " + err.Error()
		return k
	}
	a, b := sha256.Sum256(first), sha256.Sum256(second)
	k.KeysEqual = a == b && len(first) == 32
	return k
}

func errText(err error, op string) string {
	if err == nil {
		return op + ": unexpected answer"
	}
	var re *kmsrelease.RefusedError
	if errors.As(err, &re) {
		return op + ": " + re.Error()
	}
	return op + ": " + err.Error()
}

func finish(r *Report) Report {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	r.HeapMiB = int(m.HeapAlloc >> 20)
	return *r
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Summary is one line per check for the person at the parent's terminal.
func (r Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "document verified by the production verifier: %v %s\n", r.Verified, r.VerifyError)
	fmt.Fprintf(&b, "debug mode: %v   module: %s   document: %d bytes   attestation: %d ms   rsa keygen: %d ms\n", r.Debug, r.ModuleID, r.DocumentBytes, r.AttestMS, r.RSAKeyGenMS)
	fmt.Fprintf(&b, "clock skew vs the enclave clock: %d ms   rng: %q   memory: %d MiB\n", r.ClockSkewMS, r.RNG, r.MemTotalMiB)
	if r.PCR0Matches != nil {
		fmt.Fprintf(&b, "PCR0 equals the build's: %v\n", *r.PCR0Matches)
	}
	if r.KMS != nil {
		fmt.Fprintf(&b, "KMS: GenerateDataKey %d ms, Decrypt %d ms, keys equal %v %s\n", r.KMS.GenerateDataKeyMS, r.KMS.DecryptMS, r.KMS.KeysEqual, r.KMS.Error)
	}
	return b.String()
}
