//go:build teesim

package teetest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/broker"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// BrokerToken is the SoftHSM token the broker uses in tests: the repository's cold token (scripts/setup-softhsm.sh); the broker's keys have their own
// labels (qv-attest-wrap-<party>), so nothing else in that token is touched.
const BrokerToken = "qv-cold"

// Party is one party's identity at the broker.
type Party struct {
	Role     string
	CertFile string // the party's certificate for the broker link (its own certificate in the tests)
	KeyFile  string
	Pin      [32]byte
	PCR0     []byte
}

// PCR0Hex is the measurement the party's mock attester reports.
func (p *Party) PCR0Hex() string { return hex.EncodeToString(p.PCR0) }

type operator struct {
	name string
	priv ed25519.PrivateKey
}

// Rig is the broker and everything around it.
type Rig struct {
	T        testing.TB
	Dir      string
	CADir    string
	CA       *attest.MockCA
	Broker   *broker.Server
	Addr     string // host:port the broker listens on (stable across Stop and Start)
	URL      string
	Pin      string // hex pin of the broker's certificate
	AuditLog string
	Parties  map[string]*Party

	cfg    broker.Config
	ops    []operator
	seq    int64
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// WriteCert writes a self-signed certificate and key for name into dir and returns the files and the pin.
func WriteCert(t testing.TB, dir, name string) (certFile, keyFile string, pin [32]byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return certFile, keyFile, sha256.Sum256(c.RawSubjectPublicKeyInfo)
}

// PartyCert describes a party whose own certificate (files and pin) is used for the broker link.
type PartyCert struct {
	Role              string
	CertFile, KeyFile string
	Pin               string // hex
}

// New starts a broker for the given parties. Each party's PCR0 is the mock measurement of "party <role> image v1" and is allowlisted for a day.
func New(t testing.TB, parties []PartyCert) *Rig {
	t.Helper()
	dir := t.TempDir()
	pin := testenv.HSMEnv(t) // SoftHSM config and PIN of the repository's tokens (skips, or fails under QV_REQUIRE_HSM, when absent)
	now := time.Now()
	r := &Rig{T: t, Dir: dir, CADir: filepath.Join(dir, "ca"), Parties: map[string]*Party{}}
	var err error
	if r.CA, err = attest.NewMockCA(now, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.CA.Write(r.CADir); err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(dir, "roots.pem")
	os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.CA.Root.Raw}), 0o600)
	opsCfg := attest.OperatorsFile{Keys: map[string]attest.OperatorFile{}, MinOperators: 2}
	for _, n := range []string{"alice", "bob", "carol"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		r.ops = append(r.ops, operator{n, priv})
		opsCfg.Keys[n] = attest.OperatorFile{PublicKey: hex.EncodeToString(pub)}
	}
	bcert, bkey, bpin := WriteCert(t, dir, "broker")
	r.Pin = hex.EncodeToString(bpin[:])
	bparties := map[string]broker.PartyEntry{}
	for _, p := range parties {
		pp := &Party{Role: p.Role, CertFile: p.CertFile, KeyFile: p.KeyFile, PCR0: attest.MeasureImage([]byte("party "+p.Role+" image v1"), []byte("config"))}
		h, _ := hex.DecodeString(p.Pin)
		copy(pp.Pin[:], h)
		r.Parties[p.Role] = pp
		bparties[p.Role] = broker.PartyEntry{CallerPins: []string{p.Pin}}
	}
	pinFile := filepath.Join(dir, "token.pin")
	if err := os.WriteFile(pinFile, []byte(pin), 0o400); err != nil {
		t.Fatal(err)
	}
	r.AuditLog = filepath.Join(dir, "audit.log")
	r.cfg = broker.Config{
		Listen: "127.0.0.1:0", TLSCert: bcert, TLSKey: bkey,
		PKCS11:     broker.PKCS11Config{Token: BrokerToken, PinFile: pinFile},
		TrustRoots: roots, AllowlistFile: filepath.Join(dir, "allowlist.json"), Operators: opsCfg, Parties: bparties,
		AuditLog: r.AuditLog, RatePerMinute: 100000, RateBurst: 100000, ReloadInterval: "0",
	}
	r.SetAllowlist(r.defaultEntries()...)
	if r.Broker, err = broker.Open(r.cfg, broker.Options{}); err != nil {
		t.Fatalf("broker: %v", err)
	}
	t.Cleanup(func() { r.Stop(); r.Broker.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.Addr = ln.Addr().String()
	r.URL = "https://" + r.Addr
	r.serve(ln)
	return r
}

func (r *Rig) defaultEntries() []attest.AllowEntry {
	var out []attest.AllowEntry
	now := time.Now()
	for role, p := range r.Parties {
		out = append(out, attest.AllowEntry{Party: role, Measurement: p.PCR0Hex(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	}
	return out
}

func (r *Rig) serve(ln net.Listener) {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() { r.Broker.ServeListener(ctx, ln); close(r.done) }()
}

// Stop makes the broker unreachable (the listener closes); Start serves again on the same address.
func (r *Rig) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
		<-r.done
		r.cancel = nil
	}
}

func (r *Rig) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", r.Addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		r.T.Fatalf("broker cannot listen again on %s: %v", r.Addr, err)
	}
	r.serve(ln)
}

// SetLimit restarts the broker (same address, same allowlist and audit log) with another rate limit per party; the token buckets start full.
func (r *Rig) SetLimit(perMinute, burst int) {
	r.T.Helper()
	r.Stop()
	r.Broker.Close()
	r.cfg.RatePerMinute, r.cfg.RateBurst = perMinute, burst
	b, err := broker.Open(r.cfg, broker.Options{})
	if err != nil {
		r.T.Fatalf("broker: %v", err)
	}
	r.Broker = b
	r.Start()
}

// SetAllowlist signs the entries with two operators and writes the allowlist file; if the broker is running it reloads (sequence rises each time).
func (r *Rig) SetAllowlist(entries ...attest.AllowEntry) {
	r.T.Helper()
	r.seq++
	l := attest.SignedAllowlist{Seq: r.seq, SignedAt: time.Now().Unix(), Entries: entries}
	for _, op := range r.ops[:2] {
		l = attest.SignAllowlist(op.priv, op.name, l)
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	if err := os.WriteFile(r.cfg.AllowlistFile, b, 0o600); err != nil {
		r.T.Fatal(err)
	}
	if r.Broker != nil {
		if err := r.Broker.Reload(); err != nil {
			r.T.Fatalf("allowlist reload: %v", err)
		}
	}
}

// Allow allowlists measurement pcr0 (hex) for party for a day, besides what is listed now.
func (r *Rig) Allow(party, pcr0 string, current []attest.AllowEntry) []attest.AllowEntry {
	now := time.Now()
	return append(current, attest.AllowEntry{Party: party, Measurement: pcr0, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
}

// Revoke removes the party's entries (the broker refuses it from now on).
func (r *Rig) Revoke(party string) {
	var keep []attest.AllowEntry
	for _, e := range r.defaultEntries() {
		if e.Party != party {
			keep = append(keep, e)
		}
	}
	r.SetAllowlist(keep...)
}

// Restore puts the default entries back.
func (r *Rig) Restore() { r.SetAllowlist(r.defaultEntries()...) }

// Audit reads the broker's audit records.
func (r *Rig) Audit() []broker.Record {
	recs, err := broker.ReadAudit(r.AuditLog)
	if err != nil {
		r.T.Fatal(err)
	}
	return recs
}
