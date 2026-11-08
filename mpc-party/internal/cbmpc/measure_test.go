package cbmpc

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Measurements for docs/measurements/mpc.md (E23-1): threshold 2-of-3 against the 2-party path, same run, in-process
// and over loopback TCP.
//
//	go test ./internal/cbmpc -run TestMeasure -measure -measure-n 30 -v
//
// Latency is the wall time of one ceremony with all parties in this process (setup of links excluded). CPU is this
// process's user+system time per ceremony, summed over ALL parties, divided by the number of ceremonies. Bytes are the
// protocol payload each party sent (frame headers and clock prefixes excluded). Rounds are the longest chain of
// messages that each wait for the previous one (a Lamport clock carried on every message), i.e. what costs one
// round-trip's latency each on a real network.

var (
	measure  = flag.Bool("measure", false, "run the E23-1 measurements (slow)")
	measureN = flag.Int("measure-n", 30, "ceremonies per row")
)

// party counts what one party sends and carries its Lamport clock.
type party struct {
	mu    sync.Mutex
	clock uint64
	sent  atomic.Int64
	msgs  atomic.Int64
}

type clockTransport struct {
	Transport
	p *party
}

func (c *clockTransport) Send(ctx context.Context, msg []byte) error {
	c.p.mu.Lock()
	c.p.clock++
	ck := c.p.clock
	c.p.mu.Unlock()
	c.p.sent.Add(int64(len(msg)))
	c.p.msgs.Add(1)
	b := make([]byte, 8+len(msg))
	binary.BigEndian.PutUint64(b, ck)
	copy(b[8:], msg)
	return c.Transport.Send(ctx, b)
}

func (c *clockTransport) Recv(ctx context.Context) ([]byte, error) {
	b, err := c.Transport.Recv(ctx)
	if err != nil || len(b) < 8 {
		return b, err
	}
	ck := binary.BigEndian.Uint64(b)
	c.p.mu.Lock()
	if ck > c.p.clock {
		c.p.clock = ck
	}
	c.p.mu.Unlock()
	return b[8:], nil
}

func (c *clockTransport) Close() {
	if x, ok := c.Transport.(interface{ Close() }); ok {
		x.Close()
	}
	if x, ok := c.Transport.(interface{ Close() error }); ok {
		x.Close()
	}
}

type pairFn func(*party, *party) (Transport, Transport) // a connected pair, each end counted for its party

type linkKind struct {
	name string
	mk   pairFn
}

func memPairFn(a, b *party) (Transport, Transport) {
	x, y := NewMemPair()
	return &clockTransport{x, a}, &clockTransport{y, b}
}

func tcpPairFn(a, b *party) (Transport, Transport) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	cb, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	ca := <-ch
	ln.Close()
	return &clockTransport{NewConnTransport(ca, 0), a}, &clockTransport{NewConnTransport(cb, 0), b}
}

type row struct {
	name                      string
	p50, p95                  time.Duration
	rounds                    uint64
	bytesPerParty, msgsPerRun int64
	cpu                       time.Duration
	n                         int
}

func cpuNow() time.Duration {
	var r syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &r)
	return time.Duration(r.Utime.Nano() + r.Stime.Nano())
}

func pct(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(p*float64(len(s))+0.5) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}

// bench runs `once` n times. once builds fresh counted links with mk, runs the ceremony and returns the parties.
func bench(name string, n int, once func() []*party) row {
	var lat []time.Duration
	var rounds uint64
	var bytes, msgs int64
	runtime.GC()
	cpu0 := cpuNow()
	for i := 0; i < n; i++ {
		start := time.Now()
		ps := once()
		lat = append(lat, time.Since(start))
		var sent, m int64
		for _, p := range ps {
			sent += p.sent.Load()
			m += p.msgs.Load()
			if p.clock > rounds {
				rounds = p.clock
			}
		}
		bytes, msgs = sent/int64(len(ps)), m
	}
	cpu := (cpuNow() - cpu0) / time.Duration(n)
	return row{name: name, p50: pct(lat, .5), p95: pct(lat, .95), rounds: rounds, bytesPerParty: bytes, msgsPerRun: msgs, cpu: cpu, n: n}
}

func (r row) md() string {
	return fmt.Sprintf("| %s | %d | %.0f | %.0f | %d | %d | %.0f |", r.name, r.n,
		float64(r.p50.Microseconds())/1000, float64(r.p95.Microseconds())/1000, r.rounds, r.bytesPerParty/1, float64(r.cpu.Microseconds())/1000)
}

func TestMeasure(t *testing.T) {
	if !*measure {
		t.Skip("run with -measure")
	}
	n := *measureN
	ctx := context.Background()
	var out strings.Builder
	emit := func(s string) { out.WriteString(s + "\n"); t.Log(s) }
	emit(fmt.Sprintf("go %s %s/%s, %d CPUs, cb-mpc %s, n=%d per row", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), PinnedCommit[:7], n))

	for _, tr := range []linkKind{{"in-process", memPairFn}, {"loopback TCP", tcpPairFn}} {
		var rows []row
		// ---- threshold 2-of-3
		buildMesh := func() ([NumMembers]*LinkMesh, []*party) {
			ps := []*party{{}, {}, {}}
			var ms [NumMembers]*LinkMesh
			for i := range ms {
				ms[i] = NewLinkMesh(Member(i), map[Member]Transport{})
			}
			for a := 0; a < NumMembers; a++ {
				for b := a + 1; b < NumMembers; b++ {
					x, y := tr.mk(ps[a], ps[b])
					ms[a].links[Member(b)], ms[b].links[Member(a)] = x, y
				}
			}
			return ms, ps
		}
		var ks [NumMembers]*TKey
		rows = append(rows, bench("threshold DKG (3 parties)", n, func() []*party {
			ms, ps := buildMesh()
			defer closeAll(ms)
			errs := trioOn(ctx, ms, func(ctx context.Context, m Member, mesh *LinkMesh) (err error) {
				ks[m].Wipe()
				ks[m], err = TDKG(ctx, mesh, m)
				return
			})
			for _, e := range errs {
				must(t, e)
			}
			return ps
		}))
		rows = append(rows, bench("threshold refresh (3 parties)", n, func() []*party {
			ms, ps := buildMesh()
			defer closeAll(ms)
			var nk [NumMembers]*TKey
			errs := trioOn(ctx, ms, func(ctx context.Context, m Member, mesh *LinkMesh) (err error) {
				nk[m], err = ks[m].Refresh(ctx, mesh)
				return
			})
			for _, e := range errs {
				must(t, e)
			}
			for _, k := range nk {
				k.Wipe()
			}
			return ps
		}))
		rows = append(rows, bench("threshold self-test (3 pairs)", n, func() []*party {
			ms, ps := buildMesh()
			defer closeAll(ms)
			errs := trioOn(ctx, ms, func(ctx context.Context, m Member, mesh *LinkMesh) error {
				return ks[m].SelfTest(ctx, mesh, []byte("m"))
			})
			for _, e := range errs {
				must(t, e)
			}
			return ps
		}))
		for _, pr := range allPairs {
			pr := pr
			rows = append(rows, bench(fmt.Sprintf("threshold sign {%d,%d}", pr[0], pr[1]), n, func() []*party {
				ms, ps := buildMesh()
				defer closeAll(ms)
				a, b := pr[0], pr[1]
				d := digest32(1)
				var wg sync.WaitGroup
				var ea, eb error
				wg.Add(2)
				go func() { defer wg.Done(); _, ea = ks[a].Sign(ctx, ms[a], b, a, d) }()
				go func() { defer wg.Done(); _, eb = ks[b].Sign(ctx, ms[b], a, a, d) }()
				wg.Wait()
				must(t, ea)
				must(t, eb)
				return []*party{ps[a], ps[b]}
			}))
		}
		for _, k := range ks {
			k.Wipe()
		}

		// ---- 2-party (HD keyset, as the hot wallet uses it)
		var k1, k2 *Keyset
		two := func(f func(a, b Transport) (e1, e2 error)) func() []*party {
			return func() []*party {
				pa, pb := &party{}, &party{}
				x, y := tr.mk(pa, pb)
				e1, e2 := f(x, y)
				must(t, e1)
				must(t, e2)
				closeT(x)
				closeT(y)
				return []*party{pa, pb}
			}
		}
		rows = append(rows, bench("2-party DKG (HD keyset)", n, two(func(a, b Transport) (e1, e2 error) {
			var n1, n2 *Keyset
			e1, e2 = bothOn(a, b,
				func(tr Transport) (err error) { n1, err = DKG(ctx, tr, P1, ECDSA); return },
				func(tr Transport) (err error) { n2, err = DKG(ctx, tr, P2, ECDSA); return })
			if k1 != nil {
				k1.Wipe()
				k2.Wipe()
			}
			k1, k2 = n1, n2
			return
		})))
		rows = append(rows, bench("2-party refresh", n, two(func(a, b Transport) (e1, e2 error) {
			var n1, n2 *Keyset
			e1, e2 = bothOn(a, b,
				func(tr Transport) (err error) { n1, err = k1.Refresh(ctx, tr); return },
				func(tr Transport) (err error) { n2, err = k2.Refresh(ctx, tr); return })
			if e1 == nil && e2 == nil {
				k1.Wipe()
				k2.Wipe()
				k1, k2 = n1, n2
			}
			return
		})))
		h, p := []uint32{44, 60, 0}, []uint32{0, 7}
		var s1, s2 *SignKey
		e1, e2 := bothOn2(tr, func(a Transport) (err error) { s1, err = k1.Derive(ctx, a, h, p); return },
			func(b Transport) (err error) { s2, err = k2.Derive(ctx, b, h, p); return })
		must(t, e1)
		must(t, e2)
		d := digest32(1)
		rows = append(rows, bench("2-party sign (key already derived)", n, two(func(a, b Transport) (e1, e2 error) {
			return bothOn(a, b,
				func(tr Transport) (err error) { _, err = s1.Sign(ctx, tr, d); return },
				func(tr Transport) (err error) { _, err = s2.Sign(ctx, tr, d); return })
		})))
		rows = append(rows, bench("2-party derive + sign", n, two(func(a, b Transport) (e1, e2 error) {
			return bothOn(a, b,
				func(tr Transport) error {
					dk, err := k1.Derive(ctx, tr, h, p)
					if err != nil {
						return err
					}
					defer dk.Wipe()
					_, err = dk.Sign(ctx, tr, d)
					return err
				},
				func(tr Transport) error {
					dk, err := k2.Derive(ctx, tr, h, p)
					if err != nil {
						return err
					}
					defer dk.Wipe()
					_, err = dk.Sign(ctx, tr, d)
					return err
				})
		})))
		s1.Wipe()
		s2.Wipe()
		k1.Wipe()
		k2.Wipe()

		emit("")
		emit("### " + tr.name)
		emit("")
		emit("| Ceremony | N | p50 ms | p95 ms | rounds | bytes sent per party | CPU ms (all parties) |")
		emit("|---|---:|---:|---:|---:|---:|---:|")
		for _, r := range rows {
			emit(r.md())
		}
	}
	if f := os.Getenv("QV_MEASURE_OUT"); f != "" {
		os.WriteFile(f, []byte(out.String()), 0o644)
	}
}

func closeAll(ms [NumMembers]*LinkMesh) {
	for _, m := range ms {
		m.Close()
	}
}
func closeT(t Transport) {
	if c, ok := t.(interface{ Close() }); ok {
		c.Close()
	}
}

// bothOn runs fa and fb over an existing connected pair.
func bothOn(a, b Transport, fa, fb func(tr Transport) error) (ea, eb error) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if ea = fa(a); ea != nil {
			closeT(a)
		}
	}()
	go func() {
		defer wg.Done()
		if eb = fb(b); eb != nil {
			closeT(b)
		}
	}()
	wg.Wait()
	return
}

func bothOn2(tr linkKind, fa, fb func(Transport) error) (error, error) {
	x, y := tr.mk(&party{}, &party{})
	defer closeT(x)
	defer closeT(y)
	return bothOn(x, y, fa, fb)
}
