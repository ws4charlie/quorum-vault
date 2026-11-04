package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func selfCPU() float64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
}

func peerCPU(p *Party, m *Mux) float64 {
	res, err := p.call(m, Req{Op: "rusage"})
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(res, 64)
	return f
}

func pct(l []time.Duration, q float64) time.Duration {
	if len(l) == 0 {
		return 0
	}
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	i := int(float64(len(l)-1) * q)
	return l[i]
}

// bench:  bench sign ALG KEY CONC1,CONC2 SECONDS     |  bench dkg ecdsa|eddsa N  |  bench derive ecdsa|eddsa KS N
func benchCmd(p *Party, m *Mux, args []string) error {
	switch args[0] {
	case "dkg", "derive":
		n, _ := strconv.Atoi(args[len(args)-1])
		var lat []time.Duration
		for i := 0; i < n; i++ {
			t := time.Now()
			var err error
			if args[0] == "dkg" {
				_, err = p.call(m, Req{Op: "hd-dkg", Ecdsa: args[1] == "ecdsa", Curve: curveFor(args[1]), Name: fmt.Sprintf("bench-ks-%d", i%2)})
			} else {
				_, err = p.call(m, Req{Op: "hd-derive", Ecdsa: args[1] == "ecdsa", KS: args[2], Name: fmt.Sprintf("bench-k-%d", i), HP: []uint32{44, 60, 0}, NHP: []uint32{0, uint32(i)}})
			}
			if err != nil {
				return err
			}
			lat = append(lat, time.Since(t))
		}
		fmt.Printf("%s %s n=%d p50=%v p99=%v max=%v\n", args[0], args[1], n, pct(lat, .5), pct(lat, .99), pct(lat, 1))
		return nil
	case "sign":
		alg, key, dur := algOf(args[1]), args[2], 10
		concs := args[3]
		if len(args) > 4 {
			dur, _ = strconv.Atoi(args[4])
		}
		msg := make([]byte, 32)
		for _, cs := range strings.Split(concs, ",") {
			c, _ := strconv.Atoi(cs)
			var mu sync.Mutex
			var lat []time.Duration
			var fails int
			stop := time.Now().Add(time.Duration(dur) * time.Second)
			c0, p0 := selfCPU(), peerCPU(p, m)
			tx0, rx0, tf0, rf0 := m.TxBytes.Load(), m.RxBytes.Load(), m.TxFrames.Load(), m.RxFrames.Load()
			t0 := time.Now()
			var wg sync.WaitGroup
			for w := 0; w < c; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; time.Now().Before(stop); i++ {
						msg := append([]byte(nil), msg...)
						msg[0], msg[1], msg[2] = byte(w), byte(i), byte(i>>8)
						t := time.Now()
						_, err := signWith(p, m, alg, key, msg)
						d := time.Since(t)
						mu.Lock()
						if err != nil {
							fails++
						} else {
							lat = append(lat, d)
						}
						mu.Unlock()
					}
				}(w)
			}
			wg.Wait()
			el := time.Since(t0).Seconds()
			c1, p1 := selfCPU(), peerCPU(p, m)
			n := float64(len(lat))
			defer func() {}()
			if n > 0 {
				fmt.Printf("  per sign: p1->p2 %.0f B in %.1f msgs, p2->p1 %.0f B in %.1f msgs\n", float64(m.TxBytes.Load()-tx0)/n, float64(m.TxFrames.Load()-tf0)/n, float64(m.RxBytes.Load()-rx0)/n, float64(m.RxFrames.Load()-rf0)/n)
			}
			fmt.Printf("sign %s conc=%-2d n=%d fails=%d  %.1f sig/s  p50=%v p99=%v  cpu/sig p1=%.1fms p2=%.1fms  (cores busy: p1 %.2f p2 %.2f)\n",
				args[1], c, len(lat), fails, n/el, pct(lat, .5).Round(time.Microsecond), pct(lat, .99).Round(time.Microsecond),
				(c1-c0)/n*1000, (p1-p0)/n*1000, (c1-c0)/el, (p1-p0)/el)
		}
		return nil
	}
	return errors.New("bench: dkg|derive|sign")
}

// loopsign KEY N: sign N times sequentially, print one line per result with timestamps.
func loopSign(p *Party, m *Mux, args []string) error {
	n, _ := strconv.Atoi(args[1])
	msg := make([]byte, 32)
	for i := 0; i < n; i++ {
		msg[0] = byte(i)
		t := time.Now()
		_, err := signWith(p, m, 0, args[0], msg)
		if err != nil {
			fmt.Printf("%s sign #%d FAILED after %v: %v\n", time.Now().Format("15:04:05.000"), i, time.Since(t).Round(time.Millisecond), err)
			os.Exit(3)
		}
		fmt.Printf("%s sign #%d ok %v\n", time.Now().Format("15:04:05.000"), i, time.Since(t).Round(time.Millisecond))
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// crash KIND: ask the peer process to crash from inside the C++ library (1 abort, 2 segv) or Go (3 panic).
func crashPeer(p *Party, m *Mux, args []string) error {
	k, _ := strconv.Atoi(args[0])
	_, err := p.call(m, Req{Op: "crash", Kind: k})
	fmt.Printf("crash kind=%d -> caller sees: %v\n", k, err)
	return nil
}

// fuzz: send malformed protocol messages to the peer's sign session and see whether the peer survives.
func fuzzPeer(p *Party, m *Mux, args []string) error {
	key := args[0]
	pl := []byte(fmt.Sprintf(`{"op":"sign","alg":0,"name":%q,"msg":"%064x"}`, key, 1))
	for i, garbage := range [][]byte{{}, {0xff}, make([]byte, 100), randBytes(4096), randBytes(2 << 20)} {
		s, err := m.Open(pl)
		if err != nil {
			return err
		}
		s.Send(0, garbage)
		s.Send(0, garbage)
		_, err = s.Recv(1)
		fmt.Printf("garbage #%d (%d bytes): peer replied/err = %v\n", i, len(garbage), err)
		s.Close(errors.New("fuzz done"))
	}
	return nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}
