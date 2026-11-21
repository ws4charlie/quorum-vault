package mpcstack

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
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
	CertCosB, CertCosC          Cert // what the cosigners present on their sockets (the party pins it; the cosigner pins its party)
	certPAB, certPAC, certPBC   Cert
	Admins                      AdminSet // the three admin keys; the parties are configured with them and admin_threshold 2

	CallerA, CallerB, CallerC string
	PeerB, PeerC              string
	SockB, SockC              string // the cosigners' unix sockets

	Proxy   *Proxy // one controller for all three links; nil unless Opts.Proxy
	A, B, C *Proc
	Cos     *Proc // B's cosigner
	CosC    *Proc // C's cosigner

	tee    *TEE
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
	// registered first, so it runs after the parties were stopped: a failed test shows the end of every party's log (the directory is gone afterwards)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, n := range []string{"A", "B", "C"} {
			b, _ := os.ReadFile(filepath.Join(dir, "party-"+n+".log"))
			if len(b) > 12000 {
				b = b[len(b)-12000:]
			}
			t.Logf("---- party-%s.log (end) ----\n%s", n, b)
		}
	})
	s.CertA, s.CertB, s.CertC, s.CertGW = NewCert(t, "party-a"), NewCert(t, "party-b"), NewCert(t, "party-c"), NewCert(t, "gateway")
	s.CertCosB, s.CertCosC = NewCert(t, "cosigner-b"), NewCert(t, "cosigner-c")
	s.Admins = newAdminSet()
	if o.TEE != nil { // simulated enclave: brokers, allowlist and the enrolment of the sealed TLS keys come first; they set the parties' pins
		s.tee = &TEE{s: s, o: *o.TEE}
		s.tee.setup()
	}
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
	if s.tee != nil {
		s.tee.finalize()
	}
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
	var crt, key string
	if s.tee == nil {
		crt, key = own.Write(t, s.Dir)
	}
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
		"data_dir": filepath.Join(s.Dir, "data-"+role), "admin_keys": s.Admins.PublicHex(), "admin_threshold": AdminThreshold,
		"sealer": SealerConfig(role), "limits": lim,
	}
	if s.tee != nil { // simulated enclave: the TLS key is sealed in the data directory, the sealer is the attested one
		delete(cfg, "cert_file")
		delete(cfg, "key_file")
		cfg["tls_sealed"] = true
		cfg["sealer"] = s.tee.sealerCfg(role, nil)
	}
	switch role {
	case "A":
		cfg["caller_listen"] = s.CallerA
		cfg["authorizer"] = map[string]any{"type": "pinned-caller"}
	case "B":
		cfg["caller_listen"] = s.CallerB
		cfg["authorizer"] = map[string]any{"type": "cosigner", "socket": s.SockB, "timeout_ms": 5000, "cosigner_pins": []string{s.CertCosB.Pin}}
	case "C":
		cfg["caller_listen"] = s.CallerC
		cfg["authorizer"] = map[string]any{"type": "cosigner", "socket": s.SockC, "timeout_ms": 5000, "cosigner_pins": []string{s.CertCosC.Pin}}
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

// DKG is kept so the callers of the two-party stack read the same: every shard has its own keyset, made by Derive.
func (s *Stack3) DKG() {}

// Derive makes the i-th hot shard: a 2-of-3 keyset on A, B and C (an admin signature is checked by all three).
func (s *Stack3) Derive(i int) Shard {
	s.t.Helper()
	id := fmt.Sprintf("hot-%d", i)
	x, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	r, err := s.client["A"].DKG(x, s.Admins.DKG(&pb.DKGRequest{KeysetId: id, Scheme: pb.Scheme_SCHEME_ECDSA_2OF3}))
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
	_, err := s.client["A"].Refresh(x, s.Admins.Refresh(&pb.RefreshRequest{KeysetId: id}))
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
	_, err := s.client["A"].Unfreeze(x, s.Admins.Unfreeze(&pb.UnfreezeRequest{KeysetId: id}))
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

// RouteFile is the gateway.json mpc_route section: the gateway probes the caller port of every party. The health rules are the arguments (empty or
// zero: the defaults).
func (s *Stack3) RouteFile(interval string, failCount int, window string, recoverCount int) *gateway.MPCRouteFile {
	crt, key := s.CertGW.Write(s.t, s.Dir)
	return &gateway.MPCRouteFile{
		Parties: []gateway.MPCRouteParty{
			{Name: "A", Address: s.CallerA, CertFile: crt, KeyFile: key, ServerPin: s.CertA.Pin},
			{Name: "B", Address: s.CallerB, CertFile: crt, KeyFile: key, ServerPin: s.CertB.Pin},
			{Name: "C", Address: s.CallerC, CertFile: crt, KeyFile: key, ServerPin: s.CertC.Pin},
		},
		ProbeInterval: interval, FailCount: failCount, FailWindow: window, RecoverCount: recoverCount,
	}
}

// StartCosigner starts qv-cosigner next to B with its own config and replay-guard database; StartCosignerC next to C, with ITS own.
func (s *Stack3) StartCosigner(cfgPath, guardDSN, gatewayGuardDSN string) {
	s.t.Helper()
	crt, key := s.CertCosB.Write(s.t, s.Dir)
	s.Cos = NewProc(s.t, "cosigner-B", filepath.Join(s.Dir, "cosigner-B.log"), s.Bin.Cosigner, nil,
		"-config", cfgPath, "-guard-dsn", guardDSN, "-gateway-guard-dsn", gatewayGuardDSN, "-socket", s.SockB,
		"-socket-cert", crt, "-socket-key", key, "-party-pins", s.CertB.Pin)
	s.StartCosignerAgain()
}

func (s *Stack3) StartCosignerC(cfgPath, guardDSN, gatewayGuardDSN string) {
	s.t.Helper()
	crt, key := s.CertCosC.Write(s.t, s.Dir)
	s.CosC = NewProc(s.t, "cosigner-C", filepath.Join(s.Dir, "cosigner-C.log"), s.Bin.Cosigner, nil,
		"-config", cfgPath, "-guard-dsn", guardDSN, "-gateway-guard-dsn", gatewayGuardDSN, "-socket", s.SockC,
		"-socket-cert", crt, "-socket-key", key, "-party-pins", s.CertC.Pin)
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

// ---- Ed25519 (Solana, P8-4) ----

// Client is the caller client of a party ("A", "B" or "C") with the gateway's identity.
func (s *Stack3) Client(role string) pb.MpcPartyClient { return s.client[role] }

// DKGEd25519 makes a 2-of-3 Ed25519 hot-shard keyset (an admin signature is checked by all three) and returns its 32-byte public key.
func (s *Stack3) DKGEd25519(id string) []byte {
	s.t.Helper()
	x, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	r, err := s.client["A"].DKG(x, s.Admins.DKG(&pb.DKGRequest{KeysetId: id, Scheme: pb.Scheme_SCHEME_ED25519_2OF3}))
	if err != nil {
		s.t.Fatalf("DKG %s: %v\nA: %s\nB: %s\nC: %s", id, err, tail(s.A.Output()), tail(s.B.Output()), tail(s.C.Output()))
	}
	s.ids = append(s.ids, id)
	return r.RootPublicKey
}

// DKGHDEd25519 makes a 2-party Ed25519 HD keyset on A and B (the deposit keys come from it).
func (s *Stack3) DKGHDEd25519(id string) {
	s.t.Helper()
	x, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := s.client["A"].DKG(x, s.Admins.DKG(&pb.DKGRequest{KeysetId: id, Curve: pb.Curve_CURVE_ED25519})); err != nil {
		s.t.Fatalf("HD DKG %s: %v", id, err)
	}
}

// GatewaySignerEd is the gateway's signer entry of a Solana hot shard: the 2-of-3 Ed25519 keyset, coordinators A then B, and when depositKeyset is
// not empty the 2-party HD keyset the deposit keys come from.
func (s *Stack3) GatewaySignerEd(keyset string, pub32 []byte, depositKeyset string, depositPath []uint32) gateway.SignerFile {
	crt, key := s.CertGW.Write(s.t, s.Dir)
	sf := gateway.SignerFile{Backend: "mpc", Scheme: "ed25519-2of3", KeysetID: keyset, PublicKey: hex.EncodeToString(pub32),
		Coordinators: []gateway.MPCSignerFile{
			{Name: "A", Address: s.CallerA, CertFile: crt, KeyFile: key, ServerPin: s.CertA.Pin},
			{Name: "B", Address: s.CallerB, CertFile: crt, KeyFile: key, ServerPin: s.CertB.Pin},
		}}
	if depositKeyset != "" {
		sf.Deposit = &gateway.SignerFile{KeysetID: depositKeyset, HardenedPath: depositPath,
			MPC: &gateway.MPCSignerFile{Address: s.CallerA, CertFile: crt, KeyFile: key, ServerPin: s.CertA.Pin}}
	}
	return sf
}
