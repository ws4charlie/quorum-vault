package custody_test

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
)

// TestMeasureMPCSealer prints the numbers of docs/measurements/tee-sim.md for the mode it runs in: the PKCS#11 sealer (QV_CUSTODY_SIGNER=mpc) or the
// SIMULATED attested sealer (QV_CUSTODY_TEE=sim too). Not part of the lane: it runs only with QV_TEE_MEASURE=1.
//
//	QV_TEE_MEASURE=1 QV_TEE_KEYSETS=10,50,200 QV_TEE_RATE=30/10 make test-e2e-evm TEST=TestMeasureMPCSealer     (add QV_CUSTODY_TEE=sim for the attested sealer)
//
// QV_TEE_RATE is the brokers' limit per party as per-minute/burst (default: no practical limit; 30/10 is the broker's own default).
func TestMeasureMPCSealer(t *testing.T) {
	requireMPC(t)
	if os.Getenv("QV_TEE_MEASURE") != "1" {
		t.Skip("QV_TEE_MEASURE != 1")
	}
	mode := "pkcs11"
	o := opts{}
	if teeMode() {
		mode = "attested (SIMULATED)"
		to := &mpcstack.TEEOpts{}
		if r := os.Getenv("QV_TEE_RATE"); r != "" {
			a, b, _ := strings.Cut(r, "/")
			to.RatePerMinute, _ = strconv.Atoi(a)
			to.Burst, _ = strconv.Atoi(b)
		}
		o.tee = to
	}
	s, _ := funded(t, o, "c-meas", 40)
	mpc := s.mpc

	// sign latency: the coordinator's own measure of one signature (party A's log, op OP_SIGN), 40 sequential withdrawals after a warm-up one
	s.pay(1, "c-meas", "warm")
	skip := len(opDurations(mpc.A.Output(), "OP_SIGN"))
	s.pay(30, "c-meas", "lat")
	d := opDurations(mpc.A.Output(), "OP_SIGN")[skip:]
	sort.Float64s(d)
	t.Logf("MEASURE mode=%s sign n=%d p50=%.0f ms p95=%.0f ms max=%.0f ms", mode, len(d), pctF(d, 0.5), pctF(d, 0.95), pctF(d, 1))
	for _, r := range []string{"A", "B", "C"} {
		rss, thr, err := mpc.Party(r).RSSAndThreads()
		if err == nil {
			t.Logf("MEASURE mode=%s rss party=%s %d MiB threads=%d (1 keyset, after 31 signatures)", mode, r, rss/1024, thr)
		}
	}

	// start-up with N keysets: kill B, start it again, time until all three parties are ready (every keyset reconciled)
	have := 1
	for _, ns := range strings.Split(envOr("QV_TEE_KEYSETS", "10"), ",") {
		n, _ := strconv.Atoi(strings.TrimSpace(ns))
		for ; have < n; have++ {
			mpc.Derive(have + 100)
		}
		mpc.B.Kill()
		t0 := time.Now()
		mpc.B.Start(t)
		mpc.WaitReady(40 * time.Minute)
		el := time.Since(t0)
		rss, _, _ := mpc.B.RSSAndThreads()
		t.Logf("MEASURE mode=%s startup keysets=%d party=B time-to-ready=%.1f s rss=%d MiB", mode, n, el.Seconds(), rss/1024)
		if mpc.TEE() != nil {
			t.Logf("MEASURE mode=%s startup keysets=%d broker-B released-records=%d", mode, n, mpc.TEE().AuditLines("B", releaseOK, releasedOK))
		}
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func pctF(s []float64, p float64) float64 {
	if len(s) == 0 {
		return 0
	}
	return s[int(float64(len(s)-1)*p)]
}

// opDurations are the duration_ms of every log line of the given op ("OP_SIGN") that succeeded, in order.
func opDurations(log, op string) []float64 {
	var out []float64
	for _, l := range strings.Split(log, "\n") {
		if !strings.Contains(l, `"op":"`+op+`"`) {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || m["outcome"] != "ok" {
			continue
		}
		if v, ok := m["duration_ms"].(float64); ok {
			out = append(out, v)
		}
	}
	return out
}

var _ = fmt.Sprint
