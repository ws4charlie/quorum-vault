// Command party runs ONE side of the 2-party MPC (spike). `serve` = p2 daemon; other commands = p1 client.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	dir     = flag.String("dir", "", "state directory (sealed shares)")
	addr    = flag.String("addr", "127.0.0.1:19001", "p2 listen / p1 dial address")
	delay   = flag.Duration("delay", 0, "one-way delay injected on frames this party sends (rtt/2)")
	timeout = flag.Duration("timeout", 30*time.Second, "per-message receive timeout inside a protocol")
)

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 || *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: party -dir DIR [-addr A] [-delay D] <serve|dkg|derive|sign|...> [args]")
		os.Exit(2)
	}
	cmd := args[0]
	switch cmd {
	case "serve":
		p, err := NewParty(1, *dir)
		die(err)
		ln, err := net.Listen("tcp", *addr)
		die(err)
		fmt.Printf("p2 listening on %s (state %s, %d sealed objects)\n", *addr, *dir, len(p.mem))
		for {
			c, err := ln.Accept()
			die(err)
			m := NewMux(c, 1, *delay, *timeout, p.serve)
			<-m.Done() // one p1 connection at a time
		}
	case "backup-export", "recover", "backup-keygen":
		die(backupCmd(cmd, args[1:]))
		return
	}
	// p1 client commands
	p, err := NewParty(0, *dir)
	die(err)
	var m *Mux
	if cmd != "xpub-vector" {
		c, err := net.DialTimeout("tcp", *addr, 5*time.Second)
		die(err)
		m = NewMux(c, 0, *delay, *timeout, func(s *Session, _ []byte) { s.Close(nil) })
		defer m.Close()
	}
	t0 := time.Now()
	switch cmd {
	case "dkg": // dkg ecdsa|eddsa NAME
		_, err = p.call(m, Req{Op: "hd-dkg", Ecdsa: args[1] == "ecdsa", Curve: curveFor(args[1]), Name: args[2]})
		die(err)
		fmt.Printf("hd-dkg %s %s ok in %v\n", args[1], args[2], time.Since(t0))
	case "derive": // derive ecdsa|eddsa KS NAME HP NHP   (paths comma separated)
		_, err = p.call(m, Req{Op: "hd-derive", Ecdsa: args[1] == "ecdsa", KS: args[2], Name: args[3], HP: u32s(args[4]), NHP: u32s(args[5])})
		die(err)
		fmt.Printf("hd-derive %s ok in %v\n", args[3], time.Since(t0))
	case "sign-hex": // sign-hex ecdsa|eddsa|schnorr KEY HEXMSG -> prints sig hex only
		msg, _ := hex.DecodeString(args[3])
		sig, err := signWith(p, m, algOf(args[1]), args[2], msg)
		die(err)
		fmt.Println(hex.EncodeToString(sig))
	case "sign": // sign ecdsa|eddsa|schnorr KEY MSGTEXT
		sig, err := signWith(p, m, algOf(args[1]), args[2], digestOf(args[1], args[3]))
		die(err)
		fmt.Printf("sig=%x\nsign ok in %v\nverified=%v\n", sig, time.Since(t0), verifySig(p, args[1], args[2], digestOf(args[1], args[3]), sig))
	default:
		die(runScenario(cmd, p, m, args[1:]))
	}
}

func digestOf(alg, text string) []byte {
	if alg == "ecdsa" || alg == "schnorr" {
		h := sha256.Sum256([]byte(text))
		return h[:]
	}
	return []byte(text)
}

func algOf(s string) int {
	switch s {
	case "ecdsa":
		return 0
	case "eddsa":
		return 1
	}
	return 2
}

func curveFor(s string) int {
	if s == "eddsa" {
		return 3
	}
	return 2
}

func u32s(s string) []uint32 {
	var out []uint32
	for _, f := range strings.Split(s, ",") {
		if f == "" {
			continue
		}
		v, err := strconv.ParseUint(f, 10, 32)
		die(err)
		out = append(out, uint32(v))
	}
	return out
}

func signWith(p *Party, m *Mux, alg int, key string, msg []byte) ([]byte, error) {
	res, err := p.call(m, Req{Op: "sign", Alg: alg, Name: key, Msg: hex.EncodeToString(msg)})
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(res)
}
