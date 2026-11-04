package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"qvspike/cbmpc/cbmpc"
)

// Req is the control message that opens a protocol session. Both parties run exec(req) on their side.
type Req struct {
	Op    string   `json:"op"`
	Ecdsa bool     `json:"ecdsa,omitempty"`
	Curve int      `json:"curve,omitempty"`
	Alg   int      `json:"alg,omitempty"`
	KS    string   `json:"ks,omitempty"`  // keyset name
	Name  string   `json:"name,omitempty"` // name of the key produced / used
	HP    []uint32 `json:"hp,omitempty"`
	NHP   []uint32 `json:"nhp,omitempty"`
	Msg   string   `json:"msg,omitempty"` // hex
	Kind  int      `json:"kind,omitempty"`
}

// Party holds one side's sealed state. Sealing mimics internal/mpc/seal's envelope
// ({"v":1,"iv":b64,"ct":b64}, AES-256-GCM, 12-byte IV, AAD-bound) with a software key instead of a PKCS#11 token.
type Party struct {
	role int
	dir  string
	kek  []byte
	mu   sync.RWMutex
	mem  map[string][]byte
}

func NewParty(role int, dir string) (*Party, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := &Party{role: role, dir: dir, mem: map[string][]byte{}}
	kf := filepath.Join(dir, "seal.key")
	k, err := os.ReadFile(kf)
	if errors.Is(err, os.ErrNotExist) {
		k = make([]byte, 32)
		rand.Read(k)
		err = os.WriteFile(kf, k, 0o600)
	}
	if err != nil {
		return nil, err
	}
	p.kek = k
	matches, _ := filepath.Glob(filepath.Join(dir, "*.sealed"))
	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), ".sealed")
		b, err := p.load(name)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", name, err)
		}
		p.mem[name] = b
	}
	return p, nil
}

func (p *Party) aad(name string) []byte { return []byte(fmt.Sprintf("qv-p5a|p%d|%s", p.role+1, name)) }

func (p *Party) Seal(name string, blob []byte) error {
	blk, _ := aes.NewCipher(p.kek)
	g, _ := cipher.NewGCM(blk)
	iv := make([]byte, 12)
	rand.Read(iv)
	env, _ := json.Marshal(map[string]any{"v": 1, "iv": base64.StdEncoding.EncodeToString(iv),
		"ct": base64.StdEncoding.EncodeToString(g.Seal(nil, iv, blob, p.aad(name)))})
	return os.WriteFile(filepath.Join(p.dir, name+".sealed"), env, 0o600)
}

func (p *Party) load(name string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(p.dir, name+".sealed"))
	if err != nil {
		return nil, err
	}
	var env struct{ IV, CT string }
	var e2 map[string]any
	if err := json.Unmarshal(raw, &e2); err != nil {
		return nil, err
	}
	env.IV, _ = e2["iv"].(string)
	env.CT, _ = e2["ct"].(string)
	iv, _ := base64.StdEncoding.DecodeString(env.IV)
	ct, _ := base64.StdEncoding.DecodeString(env.CT)
	blk, _ := aes.NewCipher(p.kek)
	g, _ := cipher.NewGCM(blk)
	return g.Open(nil, iv, ct, p.aad(name))
}

func (p *Party) Put(name string, b []byte) error {
	p.mu.Lock()
	p.mem[name] = b
	p.mu.Unlock()
	return p.Seal(name, b)
}

func (p *Party) Get(name string) ([]byte, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	b, ok := p.mem[name]
	return b, ok
}

// exec runs one protocol session on this party's side. Same code for p1 and p2.
func (p *Party) exec(s *Session, r Req) (string, error) {
	role := p.role
	switch r.Op {
	case "hd-dkg":
		curve := r.Curve
		if curve == 0 {
			curve = cbmpc.Secp256k1
		}
		ks, err := cbmpc.HDDKG(r.Ecdsa, role, s, curve)
		if err != nil {
			return "", err
		}
		return "", p.Put(r.Name, ks)
	case "hd-refresh":
		ks, ok := p.Get(r.KS)
		if !ok {
			return "", errors.New("unknown keyset")
		}
		nks, err := cbmpc.HDRefresh(r.Ecdsa, role, s, ks)
		if err != nil {
			return "", err
		}
		return "", p.Put(r.KS, nks)
	case "hd-derive":
		ks, ok := p.Get(r.KS)
		if !ok {
			return "", errors.New("unknown keyset")
		}
		key, _, err := cbmpc.HDDerive(r.Ecdsa, role, s, ks, r.HP, r.NHP, nil)
		if err != nil {
			return "", err
		}
		return "", p.Put(r.Name, key)
	case "hd-node":
		ks, ok := p.Get(r.KS)
		if !ok {
			return "", errors.New("unknown keyset")
		}
		q, cc, err := cbmpc.HDNodeECDSA(role, s, ks, r.HP)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(q) + ":" + hex.EncodeToString(cc), nil
	case "dkg2p":
		curve := r.Curve
		if curve == 0 {
			curve = cbmpc.Secp256k1
		}
		k, err := cbmpc.DKG2P(r.Alg, role, s, curve)
		if err != nil {
			return "", err
		}
		return "", p.Put(r.Name, k)
	case "sign":
		k, ok := p.Get(r.Name)
		if !ok {
			return "", errors.New("unknown key " + r.Name)
		}
		msg, _ := hex.DecodeString(r.Msg)
		sig, err := cbmpc.Sign2P(r.Alg, role, s, k, msg)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(sig), nil
	case "rusage":
		if role == 0 {
			b, err := s.Recv(1)
			return string(b), err
		}
		var ru syscall.Rusage
		syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
		cpu := float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
		return fmt.Sprintf("%f", cpu), nil
	case "crash":
		return "", crashNow(r.Kind)
	}
	return "", fmt.Errorf("unknown op %q", r.Op)
}

// serve handles a session requested by the peer. The result stays local; errors abort the peer's session.
func (p *Party) serve(s *Session, payload []byte) {
	var r Req
	if err := json.Unmarshal(payload, &r); err != nil {
		s.Close(err)
		return
	}
	res, err := p.exec(s, r)
	if r.Op == "rusage" && err == nil {
		s.Send(0, []byte(res))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "p%d session %d op=%s failed: %v\n", p.role+1, s.id, r.Op, err)
	}
	if err == nil {
		s.SendFin("")
		time.Sleep(0)
	}
	s.Close(err)
}

// call (p1 side): open a session at the peer and run the same op locally.
func (p *Party) call(m *Mux, r Req) (string, error) {
	pl, _ := json.Marshal(r)
	s, err := m.Open(pl)
	if err != nil {
		return "", err
	}
	res, err := p.exec(s, r)
	if err == nil {
		err = s.WaitFin()
	}
	s.Close(err)
	return res, err
}
