package e2e

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// Measurements through the service on loopback (docs/measurements/mpc-service.md): sign latency per signer pair of a 2-of-3
// keyset against the 2-party HD signature of the same processes, and the time a coordinator loses to a first peer that is down
// or stalled. Run: QV_MEASURE=1 [QV_MEASURE_N=40] [QV_MEASURE_OUT=file] go test ./e2e -run TestMeasureThresholdService -v
func TestMeasureThresholdService(t *testing.T) {
	if os.Getenv("QV_MEASURE") != "1" {
		t.Skip("set QV_MEASURE=1")
	}
	n := 40
	if v := os.Getenv("QV_MEASURE_N"); v != "" {
		fmt.Sscan(v, &n)
	}
	var out strings.Builder
	emit := func(f string, a ...any) { s := fmt.Sprintf(f, a...); out.WriteString(s + "\n"); t.Log(s) }
	stats := func(d []time.Duration) (p50, p95 time.Duration) {
		s := append([]time.Duration(nil), d...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		at := func(p float64) time.Duration {
			i := int(p*float64(len(s))+0.5) - 1
			if i < 0 {
				i = 0
			}
			if i >= len(s) {
				i = len(s) - 1
			}
			return s[i]
		}
		return at(.5), at(.95)
	}
	row := func(name string, d []time.Duration) {
		p50, p95 := stats(d)
		emit("| %s | %d | %d | %d |", name, len(d), p50.Milliseconds(), p95.Milliseconds())
	}
	timeIt := func(f func(i int) error) []time.Duration {
		var d []time.Duration
		for i := 0; i < n+3; i++ { // 3 warm-ups
			s := time.Now()
			if err := f(i); err != nil {
				t.Fatal(err)
			}
			if i >= 3 {
				d = append(d, time.Since(s))
			}
		}
		return d
	}

	cl := newCluster3(t, func(role string, c *server.Config) { c.Limits.RecvTimeoutMS = 1000 })
	x := ctx(t, 20*time.Minute)
	tpub := cl.dkg(t, "evm-t")
	_, err := cl.client["A"].DKG(x, &pb.DKGRequest{KeysetId: "hd", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "hd")})
	must(t, err)
	d, err := cl.client["A"].Derive(x, &pb.DeriveRequest{KeysetId: "hd", HardenedPath: []uint32{44, 60, 0}, Path: []uint32{0}})
	must(t, err)

	emit("Apple Silicon laptop (%s), parties A, B, C and the caller on loopback, production-shaped config, dev build; N per row = %d after 3 warm-ups", "darwin/arm64", n)
	emit("")
	emit("| Signature | N | p50 ms | p95 ms |")
	emit("|---|---:|---:|---:|")
	signA := func(job string, i int) error {
		_, err := cl.signRaw("A", "evm-t", fmt.Sprintf("%s-%d", job, i), 100+i)
		return err
	}
	row("2-party HD key (A+B)", timeIt(func(i int) error {
		_, err := cl.client["A"].Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dgst(i), JobId: fmt.Sprintf("hd-%d", i), IntentPackage: []byte("i")})
		return err
	}))
	row("2-of-3, A coordinates with B (A+B)", timeIt(func(i int) error { return signA("ab", i) }))
	row("2-of-3, B coordinates with C (B+C)", timeIt(func(i int) error {
		_, err := cl.signRaw("B", "evm-t", fmt.Sprintf("bc-%d", i), 200+i)
		return err
	}))
	// A+C: B is down (process gone): A's first attempt fails at once and C signs
	cl.stop("B")
	row("2-of-3, A with B down (killed), signs with C (A+C)", timeIt(func(i int) error { return signA("ac", i) }))
	cl.start(t, "B")
	cl.waitReady(t)
	cl.waitConverged3(t, "evm-t", true)
	// B stalled (SIGSTOP): A waits for B's ACK for one receive timeout (1 s here, 5 s by default) and then uses C
	cl.procs["B"].signal(syscall.SIGSTOP)
	m := n / 4
	if m < 8 {
		m = 8
	}
	var stalled []time.Duration
	for i := 0; i < m; i++ {
		s := time.Now()
		if err := signA("stall", i); err != nil {
			t.Fatal(err)
		}
		stalled = append(stalled, time.Since(s))
	}
	cl.procs["B"].signal(syscall.SIGCONT)
	row("2-of-3, A with B stalled (receive timeout 1 s), signs with C", stalled)
	_ = tpub
	if f := os.Getenv("QV_MEASURE_OUT"); f != "" {
		os.WriteFile(f, []byte(out.String()), 0o644)
	}
}
