//go:build cloudhsm_hw

package server

import (
	"crypto/rand"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

// Real AWS CloudHSM. Not built in CI (build tag cloudhsm_hw) and skipped unless QV_CLOUDHSM_LIB and QV_CLOUDHSM_PIN_FILE are set.
// docs/runbooks/cloudhsm-sealer.md says how to run it. The PIN file holds "user:password" of a crypto user.
//
//	QV_CLOUDHSM_LIB       path of libcloudhsm_pkcs11.so
//	QV_CLOUDHSM_PIN_FILE  file with the crypto user's PIN (mode 0400)
//	QV_CLOUDHSM_TOKEN     token label (default: the only token)
//	QV_CLOUDHSM_OPS       operations per measurement (default 200)
func hwSealer(t *testing.T) *PKCS11Sealer {
	t.Helper()
	lib, pin := os.Getenv("QV_CLOUDHSM_LIB"), os.Getenv("QV_CLOUDHSM_PIN_FILE")
	if lib == "" || pin == "" {
		t.Skip("QV_CLOUDHSM_LIB and QV_CLOUDHSM_PIN_FILE not set")
	}
	tok := os.Getenv("QV_CLOUDHSM_TOKEN")
	if tok == "" {
		tok = "cloudhsm"
	}
	s, err := NewPKCS11Sealer(SealerConfig{Type: "pkcs11", Provider: ProviderCloudHSM, Lib: lib, PinFile: pin, Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCloudHSMHardwareContract(t *testing.T) {
	s := hwSealer(t)
	contractSealer(t, s, nil, func() *PKCS11Sealer { return hwSealer(t) })
}

func TestCloudHSMHardwareLatency(t *testing.T) {
	s := hwSealer(t)
	n := 200
	if v := os.Getenv("QV_CLOUDHSM_OPS"); v != "" {
		if _, err := fmt.Sscan(v, &n); err != nil {
			t.Fatal(err)
		}
	}
	aad := []byte("qv-mpc-party|keyset|v2|A|latency|1|ecdsa")
	secret := make([]byte, 1500) // about the size of a share blob
	rand.Read(secret)
	var seal, open []time.Duration
	var sealed []byte
	start := time.Now()
	for i := 0; i < n; i++ {
		t0 := time.Now()
		b, err := s.Seal(aad, secret)
		if err != nil {
			t.Fatal(err)
		}
		seal = append(seal, time.Since(t0))
		sealed = b
	}
	sealRate := float64(n) / time.Since(start).Seconds()
	start = time.Now()
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if _, err := s.Open(aad, sealed); err != nil {
			t.Fatal(err)
		}
		open = append(open, time.Since(t0))
	}
	openRate := float64(n) / time.Since(start).Seconds()
	pct := func(d []time.Duration, p float64) time.Duration {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return d[int(float64(len(d)-1)*p)]
	}
	t.Logf("seal: p50 %v p99 %v, %.1f/s (one caller)", pct(seal, .5), pct(seal, .99), sealRate)
	t.Logf("open: p50 %v p99 %v, %.1f/s (one caller)", pct(open, .5), pct(open, .99), openRate)
}
