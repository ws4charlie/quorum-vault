package cbmpc

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestMain doubles as the entry point of the second OS process ("party B") used by the socket tests.
func TestMain(m *testing.M) {
	if os.Getenv("QV_TEST_PARTY2") == "1" {
		runParty2()
		return
	}
	os.Exit(m.Run())
}

type op struct {
	Op       string   `json:"op"`
	Alg      int      `json:"alg"`
	Name     string   `json:"name"`
	Out      string   `json:"out"`
	Hardened []uint32 `json:"hardened"`
	Path     []uint32 `json:"path"`
	Msg      string   `json:"msg"`
}

// runParty2 is party B: a tiny server. For each connection: read one op frame, run the P2 side of the protocol on the
// same connection, reply with nothing (the protocol carries everything), keep results in memory.
func runParty2() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("LISTEN %s\n", ln.Addr())
	keysets := map[string]*Keyset{}
	signkeys := map[string]*SignKey{}
	var mu sync.Mutex
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			tr := NewConnTransport(c, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			raw, err := ReadFrame(c, 1<<16)
			if err != nil {
				return
			}
			var o op
			if json.Unmarshal(raw, &o) != nil {
				return
			}
			var perr error
			switch o.Op {
			case "quit":
				os.Exit(0)
			case "dkg":
				var k *Keyset
				if k, perr = DKG(ctx, tr, P2, Alg(o.Alg)); perr == nil {
					mu.Lock()
					keysets[o.Name] = k
					mu.Unlock()
				}
			case "refresh":
				mu.Lock()
				k := keysets[o.Name]
				mu.Unlock()
				var n *Keyset
				if n, perr = k.Refresh(ctx, tr); perr == nil {
					mu.Lock()
					keysets[o.Name] = n
					mu.Unlock()
				}
			case "derive":
				mu.Lock()
				k := keysets[o.Name]
				mu.Unlock()
				var s *SignKey
				if s, perr = k.Derive(ctx, tr, o.Hardened, o.Path); perr == nil {
					mu.Lock()
					signkeys[o.Out] = s
					mu.Unlock()
				}
			case "node":
				mu.Lock()
				k := keysets[o.Name]
				mu.Unlock()
				_, perr = k.NodeExport(ctx, tr, o.Hardened)
			case "sign":
				mu.Lock()
				s := signkeys[o.Name]
				mu.Unlock()
				msg, _ := hex.DecodeString(o.Msg)
				_, perr = s.Sign(ctx, tr, msg)
			}
			// completion ack: the parent proceeds only after party B stored its result
			ack := "ok"
			if perr != nil {
				ack = "err: " + perr.Error()
				fmt.Fprintf(os.Stderr, "party2 %s failed: %v\n", o.Op, perr)
			}
			WriteFrame(c, []byte(ack))
		}(c)
	}
}

type party2 struct {
	cmd  *exec.Cmd
	addr string
}

func startParty2(t *testing.T) *party2 {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=NONE")
	cmd.Env = append(os.Environ(), "QV_TEST_PARTY2=1")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	must(t, err)
	return &party2{cmd: cmd, addr: strings.TrimPrefix(strings.TrimSpace(line), "LISTEN ")}
}

// do opens a connection to party B, sends the op, and runs the P1 side on the same connection.
func (p *party2) do(ctx context.Context, o op, f func(tr Transport) error) error {
	c, err := net.Dial("tcp", p.addr)
	if err != nil {
		return err
	}
	defer c.Close()
	raw, _ := json.Marshal(o)
	if err := WriteFrame(c, raw); err != nil {
		return err
	}
	if err := f(NewConnTransport(c, 0)); err != nil {
		return err
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	ack, err := ReadFrame(c, 1<<16)
	if err != nil {
		return fmt.Errorf("no completion ack from party B: %w", err)
	}
	if string(ack) != "ok" {
		return fmt.Errorf("party B failed: %s", ack)
	}
	return nil
}

func TestTwoOSProcessesOverSocket(t *testing.T) {
	p2 := startParty2(t)
	ctx := ctx5(t)
	for _, alg := range []Alg{ECDSA, Ed25519} {
		name := alg.String()
		var k *Keyset
		must(t, p2.do(ctx, op{Op: "dkg", Alg: int(alg), Name: name}, func(tr Transport) (err error) { k, err = DKG(ctx, tr, P1, alg); return }))
		defer k.Wipe()
		h, path := []uint32{44, 60, 0}, []uint32{0, 1}
		var s *SignKey
		must(t, p2.do(ctx, op{Op: "derive", Name: name, Out: "c", Hardened: h, Path: path}, func(tr Transport) (err error) {
			s, err = k.Derive(ctx, tr, h, path)
			return
		}))
		defer s.Wipe()
		pub, _ := s.PublicKey()
		var n Node
		must(t, p2.do(ctx, op{Op: "node", Name: name, Hardened: h}, func(tr Transport) (err error) { n, err = k.NodeExport(ctx, tr, h); return }))
		if len(n.ChainCode) != 32 {
			t.Fatal("node export over socket")
		}
		for i := 0; i < 3; i++ {
			msg := digest32(byte(i))
			var sig []byte
			must(t, p2.do(ctx, op{Op: "sign", Name: "c", Msg: hex.EncodeToString(msg)}, func(tr Transport) (err error) { sig, err = s.Sign(ctx, tr, msg); return }))
			if alg == ECDSA {
				verifyECDSA(t, pub, msg, sig)
			} else {
				verifyEd25519(t, pub, msg, sig)
			}
		}
		// refresh across processes, re-derive, same key
		var nk *Keyset
		must(t, p2.do(ctx, op{Op: "refresh", Name: name}, func(tr Transport) (err error) { nk, err = k.Refresh(ctx, tr); return }))
		defer nk.Wipe()
		var s2 *SignKey
		must(t, p2.do(ctx, op{Op: "derive", Name: name, Out: "c2", Hardened: h, Path: path}, func(tr Transport) (err error) {
			s2, err = nk.Derive(ctx, tr, h, path)
			return
		}))
		defer s2.Wipe()
		pub2, _ := s2.PublicKey()
		if hex.EncodeToString(pub) != hex.EncodeToString(pub2) {
			t.Fatal("key changed on refresh across processes")
		}
		msg := digest32(99)
		var sig []byte
		must(t, p2.do(ctx, op{Op: "sign", Name: "c2", Msg: hex.EncodeToString(msg)}, func(tr Transport) (err error) { sig, err = s2.Sign(ctx, tr, msg); return }))
		if alg == ECDSA {
			verifyECDSA(t, pub2, msg, sig)
		} else {
			verifyEd25519(t, pub2, msg, sig)
		}
	}
}

// Killing party B in the middle of signing gives party A a Transport error promptly, and no hang.
func TestPeerKilledMidSign(t *testing.T) {
	p2 := startParty2(t)
	ctx := ctx5(t)
	var k *Keyset
	must(t, p2.do(ctx, op{Op: "dkg", Alg: int(ECDSA), Name: "k"}, func(tr Transport) (err error) { k, err = DKG(ctx, tr, P1, ECDSA); return }))
	defer k.Wipe()
	h := []uint32{1}
	var s *SignKey
	must(t, p2.do(ctx, op{Op: "derive", Name: "k", Out: "c", Hardened: h, Path: []uint32{0}}, func(tr Transport) (err error) {
		s, err = k.Derive(ctx, tr, h, []uint32{0})
		return
	}))
	defer s.Wipe()
	msg := digest32(1)
	// kill 20 ms after the sign starts (a sign takes ~50 ms): the call must fail fast with a transport error
	start := time.Now()
	err := p2.do(ctx, op{Op: "sign", Name: "c", Msg: hex.EncodeToString(msg)}, func(tr Transport) error {
		time.AfterFunc(20*time.Millisecond, func() { p2.cmd.Process.Signal(syscall.SIGKILL) })
		_, err := s.Sign(ctx, tr, msg)
		return err
	})
	if !IsTransport(err) {
		t.Fatalf("want transport error after kill -9 of the peer, got %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}
