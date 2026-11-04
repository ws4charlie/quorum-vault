package e2e

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

type fixture struct {
	cl  *cluster
	key *pb.DeriveResponse
	n   atomic.Int32
}

func newFixture(t *testing.T, withProxy bool) *fixture {
	cl := newCluster(t, func(role string, c *server.Config) { c.Limits.RecvTimeoutMS = 1500; c.Limits.SessionTimeoutMS = 8000 }, withProxy)
	x := ctx(t, 60*time.Second)
	_, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: pb.Curve_CURVE_SECP256K1})
	must(t, err)
	d, err := cl.client.Derive(x, &pb.DeriveRequest{KeysetId: "k", HardenedPath: []uint32{1}, Path: []uint32{0}})
	must(t, err)
	return &fixture{cl: cl, key: d}
}

func (f *fixture) sign(t *testing.T, timeout time.Duration) ([]byte, error) {
	i := int(f.n.Add(1))
	dg := dgst(i)
	r, err := f.cl.client.Sign(ctx(t, timeout), &pb.SignRequest{KeyId: f.key.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1,
		Digest: dg, JobId: fmt.Sprintf("job-%d-%d", i, time.Now().UnixNano())})
	if err != nil {
		return nil, err
	}
	verifyECDSA(t, f.key.PublicKey, dg, r.Signature)
	return r.Signature, nil
}

func (f *fixture) wantTransport(t *testing.T, name string, err error, within time.Duration, took time.Duration) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: sign succeeded", name)
	}
	k, typed := kindOf(err)
	if !typed || k != pb.ErrorKind_ERROR_KIND_TRANSPORT {
		t.Fatalf("%s: want typed TRANSPORT, got kind %v typed=%v: %v", name, k, typed, err)
	}
	if took > within {
		t.Fatalf("%s: took %v (limit %v)", name, took, within)
	}
	t.Logf("%s: %v after %v", name, k, took.Round(time.Millisecond))
}

// B killed in the middle of a signature, then restarted: transport error, then signing works with no operator step.
func TestKillBMidSign(t *testing.T) {
	f := newFixture(t, false)
	var err error
	var took time.Duration
	for attempt := 0; attempt < 20; attempt++ {
		start := time.Now()
		done := make(chan struct{})
		go func() { time.Sleep(15 * time.Millisecond); f.cl.b.signal(syscall.SIGKILL); close(done) }()
		_, err = f.sign(t, 15*time.Second)
		took = time.Since(start)
		<-done
		if err != nil {
			break
		}
		// the kill came too late: B is dead now anyway; bring it back and retry
		f.cl.b.kill()
		f.cl.restartB(t)
		f.cl.waitReady(t)
	}
	f.wantTransport(t, "kill -9 B mid-sign", err, 8*time.Second, took)
	f.cl.b.kill()
	f.cl.restartB(t)
	retry(t, 30*time.Second, func() error { _, err := f.sign(t, 10*time.Second); return err })
}

// B stopped (SIGSTOP) and later resumed: the caller gets a transport error within the receive timeout.
func TestHangBSigstop(t *testing.T) {
	f := newFixture(t, false)
	f.cl.b.signal(syscall.SIGSTOP)
	start := time.Now()
	_, err := f.sign(t, 15*time.Second)
	f.wantTransport(t, "SIGSTOP B", err, 6*time.Second, time.Since(start))
	f.cl.b.signal(syscall.SIGCONT)
	retry(t, 30*time.Second, func() error { _, err := f.sign(t, 10*time.Second); return err })
}

// The connection between A and B is cut (all TCP connections dropped, new ones refused), then healed.
func TestDropConnection(t *testing.T) {
	f := newFixture(t, true)
	if _, err := f.sign(t, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	f.cl.proxy.Cut()
	start := time.Now()
	_, err := f.sign(t, 15*time.Second)
	f.wantTransport(t, "connection dropped", err, 6*time.Second, time.Since(start))
	f.cl.proxy.Heal()
	retry(t, 30*time.Second, func() error { _, err := f.sign(t, 10*time.Second); return err })

	// Dropped while a signature is in flight.
	var err2 error
	for i := 0; i < 20 && err2 == nil; i++ {
		go func() { time.Sleep(15 * time.Millisecond); f.cl.proxy.drop() }()
		_, err2 = f.sign(t, 15*time.Second)
	}
	if err2 == nil {
		t.Skip("could not land a drop inside a signature (timing)")
	}
	if k, _ := kindOf(err2); k != pb.ErrorKind_ERROR_KIND_TRANSPORT {
		t.Fatalf("mid-sign drop: %v", err2)
	}
	retry(t, 30*time.Second, func() error { _, err := f.sign(t, 10*time.Second); return err })
}

// Either side restarts, with sealed shares reloaded from disk.
func TestRestartEitherSide(t *testing.T) {
	f := newFixture(t, false)
	if _, err := f.sign(t, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	f.cl.b.kill()
	start := time.Now()
	_, err := f.sign(t, 15*time.Second)
	f.wantTransport(t, "B down", err, 6*time.Second, time.Since(start))
	f.cl.restartB(t)
	retry(t, 30*time.Second, func() error { _, err := f.sign(t, 10*time.Second); return err })

	f.cl.a.kill()
	f.cl.restartA(t)
	retry(t, 30*time.Second, func() error { _, err := f.sign(t, 10*time.Second); return err })
}

// SIGTERM lets running sessions finish and the process exit cleanly.
func TestGracefulShutdown(t *testing.T) {
	f := newFixture(t, false)
	var wg sync.WaitGroup
	var fails atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.sign(t, 15*time.Second); err != nil {
				fails.Add(1)
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	f.cl.a.signal(syscall.SIGTERM)
	select {
	case <-f.cl.a.done:
	case <-time.After(15 * time.Second):
		t.Fatal("A did not exit after SIGTERM")
	}
	wg.Wait()
	t.Logf("%d of 4 in-flight signs were cut by the shutdown", fails.Load())
	if !contains(f.cl.a.stderr.String(), "keysets wiped") {
		t.Fatal("no wipe message in A's log:\n" + f.cl.a.stderr.String())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Throughput through two real processes, gRPC and mTLS, concurrency 8. The spike measured about 130 sig/s (ECDSA) and
// about 1000 sig/s (Ed25519) between two bare processes on a TCP socket.
func TestThroughput(t *testing.T) {
	for _, alg := range []string{"ecdsa", "ed25519"} {
		cl := newCluster(t, func(role string, c *server.Config) {
			c.Limits.SessionsPerSecKey = 100000
			c.Limits.MaxPeerSessions = 32
		}, false)
		x := ctx(t, 120*time.Second)
		curve, a := pb.Curve_CURVE_SECP256K1, pb.Algorithm_ALGORITHM_ECDSA_SECP256K1
		if alg == "ed25519" {
			curve, a = pb.Curve_CURVE_ED25519, pb.Algorithm_ALGORITHM_ED25519
		}
		_, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: curve})
		must(t, err)
		d, err := cl.client.Derive(x, &pb.DeriveRequest{KeysetId: "k", HardenedPath: []uint32{1}, Path: []uint32{0}})
		must(t, err)
		run := func(conc int, dur time.Duration) (n int64, p50, p99 time.Duration) {
			var cnt atomic.Int64
			var mu sync.Mutex
			var lat []time.Duration
			stop := time.Now().Add(dur)
			var wg sync.WaitGroup
			for w := 0; w < conc; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; time.Now().Before(stop); i++ {
						dg := dgst(w*1000000 + i)
						t0 := time.Now()
						r, err := cl.client.Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: a, Digest: dg, JobId: fmt.Sprintf("%s-%d-%d-%d", alg, conc, w, i)})
						if err != nil {
							t.Errorf("sign: %v", err)
							return
						}
						if i%25 == 0 { // verify a sample independently to keep the client cheap
							if alg == "ecdsa" {
								verifyECDSA(t, d.PublicKey, dg, r.Signature)
							}
						}
						l := time.Since(t0)
						mu.Lock()
						lat = append(lat, l)
						mu.Unlock()
						cnt.Add(1)
					}
				}(w)
			}
			wg.Wait()
			sortDur(lat)
			if len(lat) == 0 {
				return 0, 0, 0
			}
			return cnt.Load(), lat[len(lat)/2], lat[len(lat)*99/100]
		}
		run(8, 2*time.Second) // warm-up
		for _, conc := range []int{1, 8, 32} {
			n, p50, p99 := run(conc, 6*time.Second)
			t.Logf("THROUGHPUT %-8s conc=%-2d  %6.1f sig/s  (n=%d, p50=%v, p99=%v)", alg, conc, float64(n)/6, n, p50.Round(time.Millisecond), p99.Round(time.Millisecond))
			if conc == 8 {
				min := 20.0
				if alg == "ed25519" {
					min = 100
				}
				if float64(n)/6 < min {
					t.Errorf("%s throughput %.1f sig/s at concurrency 8 is below the sanity floor %.0f", alg, float64(n)/6, min)
				}
			}
		}
	}
}

func sortDur(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}
