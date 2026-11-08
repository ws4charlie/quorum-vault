package mpcstack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Stack3 is the three-party signing service of E23-3: mpc-party A, B and C (real SoftHSM sealing in qv-party-1/2/3, mTLS with a
// pinned certificate per pair), a qv-cosigner next to B and another next to C (each with its own socket, config and replay guard), and
// an optional session proxy that sits on every link (A-B, A-C, B-C) with shared controls. Every EVM hot shard is its own 2-of-3 keyset
// (Derive(i) runs the DKG). The two-party Stack stays as it is: Bitcoin uses it.
type Stack3 struct {
	t   testing.TB
	Dir string
	Bin Binaries

	CertA, CertB, CertC, CertGW Cert
	certPAB, certPAC, certPBC   Cert
	adminPub                    ed25519.PublicKey
	admin                       ed25519.PrivateKey
	adminSkew                   atomic.Int64

	CallerA, CallerB, CallerC string
	PeerB, PeerC              string
	SockB, SockC              string // the cosigners' unix sockets

	Proxy   *Proxy // one controller for all three links; nil unless Opts.Proxy
	A, B, C *Proc
	Cos     *Proc // B's cosigner
	CosC    *Proc // C's cosigner

	cfg    map[string]string
	client map[string]pb.MpcPartyClient
	conns  []*grpc.ClientConn
	ids    []string // keysets made so far
}

// Start3 writes the party configs and starts C, B and A. The parties boot in the background; WaitReady waits for them.
func Start3(t testing.TB, dir string, bin Binaries, o Opts) *Stack3 {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Stack3{t: t, Dir: dir, Bin: bin, cfg: map[string]string{}, client: map[string]pb.MpcPartyClient{}}
	s.CertA, s.CertB, s.CertC, s.CertGW = NewCert(t, "party-a"), NewCert(t, "party-b"), NewCert(t, "party-c"), NewCert(t, "gateway")
	s.adminPub, s.admin, _ = ed25519.GenerateKey(rand.Reader)
	s.CallerA, s.CallerB, s.CallerC, s.PeerB, s.PeerC = FreeAddr(t), FreeAddr(t), FreeAddr(t), FreeAddr(t), FreeAddr(t)
	s.SockB = filepath.Join(os.TempDir(), fmt.Sprintf("qvcs-b-%d.sock", time.Now().UnixNano()%1e9))
	s.SockC = filepath.Join(os.TempDir(), fmt.Sprintf("qvcs-c-%d.sock", time.Now().UnixNano()%1e9))
	t.Cleanup(func() { os.Remove(s.SockB); os.Remove(s.SockC) })

	// what each party dials and which certificate each side pins
	dialB, dialC := s.PeerB, s.PeerC // A's view of B and C
	dialCfromB := s.PeerC            // B's view of C
	pinAtoB, pinBforA := s.CertB.Pin, s.CertA.Pin
	pinAtoC, pinBtoC := s.CertC.Pin, s.CertC.Pin
	pinCforA, pinCforB := s.CertA.Pin, s.CertB.Pin
	if o.Proxy {
		s.certPAB, s.certPAC, s.certPBC = NewCert(t, "proxy-ab"), NewCert(t, "proxy-ac"), NewCert(t, "proxy-bc")
		s.Proxy = &Proxy{}
		s.Proxy.tn.Store(-1)
		dialB = startLink(t, s.Proxy, s.PeerB, s.CertB.Pin, s.CertA.Pin, s.certPAB)
		dialC = startLink(t, s.Proxy, s.PeerC, s.CertC.Pin, s.CertA.Pin, s.certPAC)
		dialCfromB = startLink(t, s.Proxy, s.PeerC, s.CertC.Pin, s.CertB.Pin, s.certPBC)
		pinAtoB, pinBforA = s.certPAB.Pin, s.certPAB.Pin
		pinAtoC, pinBtoC = s.certPAC.Pin, s.certPBC.Pin
		pinCforA, pinCforB = s.certPAC.Pin, s.certPBC.Pin
	}
	s.cfg["A"] = s.writeParty("A", o, map[string]any{"peer_address": dialB, "peer_pins": []string{pinAtoB}, "peer_c_address": dialC, "peer_c_pins": []string{pinAtoC}})
	s.cfg["B"] = s.writeParty("B", o, map[string]any{"peer_listen": s.PeerB, "peer_pins": []string{pinBforA}, "peer_c_address": dialCfromB, "peer_c_pins": []string{pinBtoC}})
	s.cfg["C"] = s.writeParty("C", o, map[string]any{"peer_listen": s.PeerC, "peer_a_pins": []string{pinCforA}, "peer_b_pins": []string{pinCforB}})
	env := SoftHSMEnv()
	s.C = NewProc(t, "party-C", filepath.Join(dir, "party-C.log"), bin.MPCParty, env, "-config", s.cfg["C"])
	s.B = NewProc(t, "party-B", filepath.Join(dir, "party-B.log"), bin.MPCParty, env, "-config", s.cfg["B"])
	s.A = NewProc(t, "party-A", filepath.Join(dir, "party-A.log"), bin.MPCParty, env, "-config", s.cfg["A"])
	s.C.Start(t)
	s.B.Start(t)
	s.A.Start(t)
	for role, addr := range map[string]string{"A": s.CallerA, "B": s.CallerB, "C": s.CallerC} {
		pin := map[string]string{"A": s.CertA.Pin, "B": s.CertB.Pin, "C": s.CertC.Pin}[role]
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(PinnedTLS(s.CertGW, pin))))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		s.conns = append(s.conns, conn)
		s.client[role] = pb.NewMpcPartyClient(conn)
	}
	return s
}

func startLink(t testing.TB, p *Proxy, target, targetPin, clientPin string, c Cert) string {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(PinnedTLS(c, targetPin))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := PinnedTLS(c, clientPin)
	cfg.ClientAuth = tls.RequireAnyClientCert
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	pb.RegisterPeerServer(srv, linkHandler{p: p, client: pb.NewPeerClient(conn)})
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return ln.Addr().String()
}

type linkHandler struct {
	pb.UnimplementedPeerServer
	p      *Proxy
	client pb.PeerClient
}

func (h linkHandler) Session(in pb.Peer_SessionServer) error { return h.p.session(in, h.client) }

func (s *Stack3) writeParty(role string, o Opts, extra map[string]any) string {
	t := s.t
	own := map[string]Cert{"A": s.CertA, "B": s.CertB, "C": s.CertC}[role]
	crt, key := own.Write(t, s.Dir)
	lim := map[string]any{"recv_timeout_ms": 5000, "session_timeout_ms": 30000, "keygen_recv_timeout_ms": 60000, "sessions_per_sec_key": 100000, "max_peer_sessions": 64}
	if o.RecvTimeoutMS > 0 {
		lim["recv_timeout_ms"] = o.RecvTimeoutMS
	}
	if o.SessionTimeoutMS > 0 {
		lim["session_timeout_ms"] = o.SessionTimeoutMS
	}
	if o.KeygenRecvTimeoutMS > 0 {
		lim["keygen_recv_timeout_ms"] = o.KeygenRecvTimeoutMS
	}
	cfg := map[string]any{
		"role": role, "cert_file": crt, "key_file": key, "caller_pins": []string{s.CertGW.Pin},
		"data_dir": filepath.Join(s.Dir, "data-"+role), "admin_keys": []string{hex.EncodeToString(s.adminPub)},
		"sealer": SealerConfig(role), "limits": lim,
	}
	switch role {
	case "A":
		cfg["caller_listen"] = s.CallerA
		cfg["authorizer"] = map[string]any{"type": "pinned-caller"}
	case "B":
		cfg["caller_listen"] = s.CallerB
		cfg["authorizer"] = map[string]any{"type": "cosigner", "socket": s.SockB, "timeout_ms": 5000}
	case "C":
		cfg["caller_listen"] = s.CallerC
		cfg["authorizer"] = map[string]any{"type": "cosigner", "socket": s.SockC, "timeout_ms": 5000}
	}
	for k, v := range extra {
		cfg[k] = v
	}
	raw, _ := json.MarshalIndent(cfg, "", " ")
	p := filepath.Join(s.Dir, "party-"+role+".json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Health asks one party ("A", "B" or "C").
func (s *Stack3) HealthOf(role string) (*pb.HealthResponse, error) {
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.client[role].Health(c, &pb.HealthRequest{})
}

// Health asks party A.
func (s *Stack3) Health() (*pb.HealthResponse, error) { return s.HealthOf("A") }

// WaitReady waits until A sees B and C, B sees C, and every keyset is reconciled and the same generation on all three parties.
func (s *Stack3) WaitReady(d time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s.ready(true) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("parties not ready\nA: %s\nB: %s\nC: %s", tail(s.A.Output()), tail(s.B.Output()), tail(s.C.Output()))
}

// WaitSigning waits until A can sign with at least one peer: it sees any peer and every keyset is resolved on A. Used after a
// restart of A while another party is down.
func (s *Stack3) WaitSigning(d time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		h, err := s.Health()
		if err == nil {
			ok := true
			for _, k := range h.Keysets {
				if !k.Resolved {
					ok = false
				}
			}
			if ok {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("A is not signing\nA: %s", tail(s.A.Output()))
}

func (s *Stack3) ready(all bool) bool {
	ha, err := s.HealthOf("A")
	if err != nil || len(ha.Peers) != 2 || !ha.Peers[0].Reachable || !ha.Peers[1].Reachable {
		return false
	}
	hb, err := s.HealthOf("B")
	if err != nil || !hb.PeerReachable {
		return false
	}
	hc, err := s.HealthOf("C")
	if err != nil {
		return false
	}
	gens := map[string]uint64{}
	for _, h := range []*pb.HealthResponse{ha, hb, hc} {
		if len(h.Keysets) != len(ha.Keysets) {
			return false
		}
		for _, k := range h.Keysets {
			if !k.Resolved {
				return false
			}
			if g, ok := gens[k.KeysetId]; ok && g != k.Generation {
				return false
			}
			gens[k.KeysetId] = k.Generation
		}
	}
	return true
}

func (s *Stack3) AdminAuth(op, keyset string) *pb.AdminAuth {
	return admin.Sign(s.admin, op, keyset, time.Now().Add(time.Duration(s.adminSkew.Add(1))*time.Second))
}

// DKG is kept so the callers of the two-party stack read the same: every shard has its own keyset, made by Derive.
func (s *Stack3) DKG() {}

// Derive makes the i-th hot shard: a 2-of-3 keyset on A, B and C (an admin signature is checked by all three).
func (s *Stack3) Derive(i int) Shard {
	s.t.Helper()
	id := fmt.Sprintf("hot-%d", i)
	x, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	r, err := s.client["A"].DKG(x, &pb.DKGRequest{KeysetId: id, Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Admin: s.AdminAuth("dkg", id)})
	if err != nil {
		s.t.Fatalf("DKG %s: %v\nA: %s\nB: %s\nC: %s", id, err, tail(s.A.Output()), tail(s.B.Output()), tail(s.C.Output()))
	}
	pk, err := crypto.DecompressPubkey(r.RootPublicKey)
	if err != nil {
		s.t.Fatal(err)
	}
	s.ids = append(s.ids, id)
	return Shard{KeyID: id, Pub65: crypto.FromECDSAPub(pk), Addr: crypto.PubkeyToAddress(*pk)}
}

// RefreshKeyset refreshes one keyset through A (all three parties must be up).
func (s *Stack3) RefreshKeyset(id string) error {
	x, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := s.client["A"].Refresh(x, &pb.RefreshRequest{KeysetId: id, Admin: s.AdminAuth("refresh", id)})
	return err
}

// Refresh refreshes every keyset made so far.
func (s *Stack3) Refresh() error {
	for _, id := range s.ids {
		if err := s.RefreshKeyset(id); err != nil {
			return err
		}
	}
	return nil
}

// UnfreezeKeyset lifts the freeze of one keyset on all three parties with an operator signature.
func (s *Stack3) UnfreezeKeyset(id string) error {
	x, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := s.client["A"].Unfreeze(x, &pb.UnfreezeRequest{KeysetId: id, Admin: s.AdminAuth("unfreeze", id)})
	return err
}

// Unfreeze lifts every freeze party A knows of.
func (s *Stack3) Unfreeze() error {
	h, err := s.Health()
	if err != nil {
		return err
	}
	for _, k := range h.Keysets {
		if k.Frozen {
			if err := s.UnfreezeKeyset(k.KeysetId); err != nil {
				return err
			}
		}
	}
	return nil
}

// FrozenOn reports whether the party says the keyset is frozen.
func (s *Stack3) FrozenOn(role, id string) bool {
	h, err := s.HealthOf(role)
	if err != nil {
		return false
	}
	for _, k := range h.Keysets {
		if k.KeysetId == id {
			return k.Frozen
		}
	}
	return false
}

// Frozen reports whether party A says any keyset is frozen.
func (s *Stack3) Frozen() bool {
	h, err := s.Health()
	if err != nil {
		return false
	}
	for _, k := range h.Keysets {
		if k.Frozen {
			return true
		}
	}
	return false
}

// GatewaySigner is the gateway.json signer entry for one shard: a 2-of-3 signer with coordinators A, then B.
func (s *Stack3) GatewaySigner(sh Shard) gateway.SignerFile {
	crt, key := s.CertGW.Write(s.t, s.Dir)
	return gateway.SignerFile{Backend: "mpc", Scheme: "ecdsa-2of3", KeysetID: sh.KeyID, PublicKey: hex.EncodeToString(sh.Pub65),
		Coordinators: []gateway.MPCSignerFile{
			{Name: "A", Address: s.CallerA, CertFile: crt, KeyFile: key, ServerPin: s.CertA.Pin},
			{Name: "B", Address: s.CallerB, CertFile: crt, KeyFile: key, ServerPin: s.CertB.Pin},
		}}
}

// StartCosigner starts qv-cosigner next to B with its own config and replay-guard database; StartCosignerC next to C, with ITS own.
func (s *Stack3) StartCosigner(cfgPath, guardDSN, gatewayGuardDSN string) {
	s.t.Helper()
	s.Cos = NewProc(s.t, "cosigner-B", filepath.Join(s.Dir, "cosigner-B.log"), s.Bin.Cosigner, nil,
		"-config", cfgPath, "-guard-dsn", guardDSN, "-gateway-guard-dsn", gatewayGuardDSN, "-socket", s.SockB)
	s.StartCosignerAgain()
}

func (s *Stack3) StartCosignerC(cfgPath, guardDSN, gatewayGuardDSN string) {
	s.t.Helper()
	s.CosC = NewProc(s.t, "cosigner-C", filepath.Join(s.Dir, "cosigner-C.log"), s.Bin.Cosigner, nil,
		"-config", cfgPath, "-guard-dsn", guardDSN, "-gateway-guard-dsn", gatewayGuardDSN, "-socket", s.SockC)
	s.StartCosignerCAgain()
}

func (s *Stack3) StartCosignerAgain()  { s.startCos(s.Cos, s.SockB) }
func (s *Stack3) StartCosignerCAgain() { s.startCos(s.CosC, s.SockC) }

func (s *Stack3) startCos(p *Proc, sock string) {
	s.t.Helper()
	p.Start(s.t)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatalf("%s did not start: %s", p.Name, tail(p.Output()))
}

// RestartA/B/C start a killed party again and wait until all three see each other and every keyset is reconciled.
func (s *Stack3) RestartA() { s.A.Start(s.t); s.WaitReady(90 * time.Second) }
func (s *Stack3) RestartB() { s.B.Start(s.t); s.WaitReady(90 * time.Second) }
func (s *Stack3) RestartC() { s.C.Start(s.t); s.WaitReady(90 * time.Second) }

// Party returns the process of a party ("A", "B" or "C").
func (s *Stack3) Party(role string) *Proc {
	switch role {
	case "A":
		return s.A
	case "B":
		return s.B
	}
	return s.C
}
