//go:build teesim

package broker

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// The tests use the real broker, the real verifier, a real SoftHSM token (made here, with random PINs, in a temp directory), real mutual TLS with
// pinned keys, and the T1 mock attester. Only the evidence's root of trust is simulated.

var (
	hsmDir   string
	hsmToken = "qv-broker-test"
	hsmPin   string
	hsmErr   error
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "qv-broker-hsm")
	if err != nil {
		panic(err)
	}
	hsmDir = dir
	hsmErr = setupToken(dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func randHex(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }

func setupToken(dir string) error {
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		return errors.New("softhsm2-util not on PATH")
	}
	if err := os.MkdirAll(filepath.Join(dir, "tokens"), 0o700); err != nil {
		return err
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+filepath.Join(dir, "tokens")+"\nobjectstore.backend = file\n"), 0o600); err != nil {
		return err
	}
	os.Setenv("SOFTHSM2_CONF", conf)
	hsmPin = randHex(6)
	out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", hsmToken, "--so-pin", randHex(6), "--pin", hsmPin).CombinedOutput()
	if err != nil {
		return errors.New("softhsm2-util: " + string(out))
	}
	return nil
}

func needHSM(t *testing.T) {
	t.Helper()
	t.Setenv("QV_ENV", "test") // the broker refuses SoftHSM in production (hsm.go)
	if hsmErr != nil {
		if os.Getenv("QV_REQUIRE_HSM") != "" {
			t.Fatalf("SoftHSM is required (QV_REQUIRE_HSM) but unavailable: %v", hsmErr)
		}
		t.Skipf("SoftHSM unavailable: %v", hsmErr)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type opKey struct {
	name string
	priv ed25519.PrivateKey
}

type tlsID struct {
	cert tls.Certificate
	pin  [32]byte
	file struct{ cert, key string }
}

func newTLSID(t *testing.T, dir, name string) *tlsID {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	id := &tlsID{}
	id.file.cert, id.file.key = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	os.WriteFile(id.file.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(id.file.key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	if id.cert, err = tls.LoadX509KeyPair(id.file.cert, id.file.key); err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	id.pin = sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return id
}

type rig struct {
	t      *testing.T
	dir    string
	clk    *clock
	ca     *attest.MockCA
	ops    []opKey
	opsCfg attest.OperatorsFile
	srv    *Server
	ts     *httptest.Server
	cfg    Config
	server *tlsID
	ids    map[string]*tlsID // party -> caller identity
	meas   map[string][]byte // party -> its allowed measurement
	seq    int64
}

type rigOpts struct {
	allowDebug bool
	rate       int
	burst      int
	entries    func(now time.Time, meas map[string][]byte) []attest.AllowEntry
	noStart    bool
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	needHSM(t)
	dir := t.TempDir()
	now := time.Now()
	r := &rig{t: t, dir: dir, clk: &clock{t: now}, ids: map[string]*tlsID{}, meas: map[string][]byte{}}
	var err error
	if r.ca, err = attest.NewMockCA(now, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(dir, "roots.pem")
	os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.ca.Root.Raw}), 0o600)
	r.opsCfg = attest.OperatorsFile{Keys: map[string]attest.OperatorFile{}, MinOperators: 2}
	for _, n := range []string{"alice", "bob", "carol"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		r.ops = append(r.ops, opKey{n, priv})
		r.opsCfg.Keys[n] = attest.OperatorFile{PublicKey: hex.EncodeToString(pub)}
	}
	r.server = newTLSID(t, dir, "broker")
	parties := map[string]PartyEntry{}
	for _, p := range []string{"A", "B"} {
		r.ids[p] = newTLSID(t, dir, "party-"+p)
		parties[p] = PartyEntry{CallerPins: []string{hex.EncodeToString(r.ids[p].pin[:])}}
		r.meas[p] = attest.MeasureImage([]byte("party "+p+" binary v1"), []byte("cfg"))
	}
	pinFile := filepath.Join(dir, "pin")
	os.WriteFile(pinFile, []byte(hsmPin), 0o400)
	entries := []attest.AllowEntry{
		{Party: "A", Measurement: hex.EncodeToString(r.meas["A"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)},
		{Party: "B", Measurement: hex.EncodeToString(r.meas["B"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)},
	}
	if o.entries != nil {
		entries = o.entries(now, r.meas)
	}
	r.cfg = Config{
		Listen: "127.0.0.1:0", TLSCert: r.server.file.cert, TLSKey: r.server.file.key,
		PKCS11:     PKCS11Config{Token: hsmToken, PinFile: pinFile},
		TrustRoots: roots, AllowDebug: o.allowDebug,
		AllowlistFile: filepath.Join(dir, "allowlist.json"), Operators: r.opsCfg, Parties: parties,
		AuditLog: filepath.Join(dir, "audit.log"), RatePerMinute: 100000, RateBurst: 100000, ReloadInterval: "0",
	}
	if o.rate != 0 {
		r.cfg.RatePerMinute, r.cfg.RateBurst = o.rate, o.burst
	}
	r.writeList(entries, 2, 1)
	if o.noStart {
		return r
	}
	r.start()
	return r
}

// writeList signs entries with the first n operators and writes the allowlist file.
func (r *rig) writeList(entries []attest.AllowEntry, n int, seq int64) {
	r.t.Helper()
	l := attest.SignedAllowlist{Seq: seq, SignedAt: r.clk.Now().Unix(), Entries: entries}
	for _, op := range r.ops[:n] {
		l = attest.SignAllowlist(op.priv, op.name, l)
	}
	b, _ := jsonMarshal(l)
	if err := os.WriteFile(r.cfg.AllowlistFile, b, 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.seq = seq
}

func (r *rig) start() {
	r.t.Helper()
	srv, err := Open(r.cfg, Options{Now: r.clk.Now})
	if err != nil {
		r.t.Fatalf("Open: %v", err)
	}
	r.srv = srv
	tc, err := srv.tlsConfigForTest()
	if err != nil {
		r.t.Fatal(err)
	}
	r.ts = httptest.NewUnstartedServer(srv.Handler())
	r.ts.TLS = tc
	r.ts.StartTLS()
	r.t.Cleanup(func() { r.ts.Close(); srv.Close() })
}

func (r *rig) client(id *tlsID) *Client {
	return NewClient(r.ts.URL, id.cert, map[cosigner.Pin]bool{cosigner.Pin(r.server.pin): true})
}

// enclave is the party's side: its TLS identity, its evidence key, and a mock attester that reports a chosen measurement.
type enclave struct {
	r    *rig
	id   *tlsID
	cl   *Client
	at   *attest.MockAttester
	priv *ecdh.PrivateKey
	pub  []byte
}

func (r *rig) enclave(party string) *enclave {
	r.t.Helper()
	e := &enclave{r: r, id: r.ids[party], cl: r.client(r.ids[party])}
	e.at = &attest.MockAttester{CA: r.ca, PCR0: r.meas[party], PCR8: attest.MeasureCert([]byte("mock signing cert")), Now: r.clk.Now}
	var err error
	if e.priv, e.pub, err = attest.NewReleaseKey(); err != nil {
		r.t.Fatal(err)
	}
	return e
}

func gens(g ...uint64) []uint64 { return g }

func ctxOf(party, keyset string, purpose string, g ...uint64) attest.RequestContext {
	return attest.RequestContext{Party: party, Keyset: keyset, Generations: g, Purpose: purpose}
}

// prepare asks for a challenge (or uses nonce when given) and makes evidence bound to it, the context, the blobs and this enclave's TLS key.
func (e *enclave) prepare(c attest.RequestContext, blobs [][]byte, nonce []byte) attest.ReleaseRequest {
	e.r.t.Helper()
	if nonce == nil {
		ch, err := e.cl.Challenge(context.Background())
		if err != nil {
			e.r.t.Fatalf("challenge: %v", err)
		}
		nonce = ch.Nonce
	}
	ev, err := e.at.Attest(nonce, e.pub, c.UserData(blobs, e.id.pin))
	if err != nil {
		e.r.t.Fatal(err)
	}
	return attest.ReleaseRequest{Nonce: nonce, Evidence: ev, Context: c, Blobs: blobs}
}

// newKeys makes data keys through the broker and returns the blobs and the opened keys.
func (e *enclave) newKeys(c attest.RequestContext) (blobs [][]byte, keys [][]byte) {
	e.r.t.Helper()
	req := e.prepare(c, nil, nil)
	resp, err := e.cl.NewKey(context.Background(), req)
	if err != nil {
		e.r.t.Fatalf("newkey: %v", err)
	}
	return e.open(req, resp, blobsOf(resp))
}

func blobsOf(resp attest.ReleaseResponse) (b [][]byte) {
	for _, k := range resp.Keys {
		b = append(b, k.Blob)
	}
	return
}

// open decrypts every released key with this enclave's private key, under the request's own context.
func (e *enclave) open(req attest.ReleaseRequest, resp attest.ReleaseResponse, blobs [][]byte) ([][]byte, [][]byte) {
	e.r.t.Helper()
	ud := req.Context.UserData(req.Blobs, e.id.pin)
	var keys [][]byte
	for _, k := range resp.Keys {
		pt, err := attest.OpenFrom(e.priv, attest.ResponseAAD(ud, req.Nonce, k.Generation), k.Sealed)
		if err != nil {
			e.r.t.Fatalf("open generation %d: %v", k.Generation, err)
		}
		keys = append(keys, pt)
	}
	return blobs, keys
}

func wantRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var re *RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("want refusal %q, got %v", code, err)
	}
	if re.Code != code {
		t.Fatalf("want refusal %q, got %q", code, re.Code)
	}
}

func (r *rig) lastRecord() Record {
	r.t.Helper()
	recs, err := ReadAudit(r.cfg.AuditLog)
	if err != nil || len(recs) == 0 {
		r.t.Fatalf("audit: %v (%d records)", err, len(recs))
	}
	return recs[len(recs)-1]
}

// wrapKeyIsNonExtractable reads the attributes of a party's wrapping key.
func (h *HSM) wrapKeyIsNonExtractable(t *testing.T, party string) bool {
	t.Helper()
	ok := false
	err := h.session(func(s pkcs11SessionHandle) error {
		k, found, err := h.findKey(s, party)
		if err != nil || !found {
			return errors.New("no key")
		}
		attrs, err := h.ctx.GetAttributeValue(s, k, []*pkcs11Attribute{pkcs11NewAttribute(pkcs11CKA_EXTRACTABLE, nil), pkcs11NewAttribute(pkcs11CKA_SENSITIVE, nil)})
		if err != nil {
			return err
		}
		ok = len(attrs[0].Value) == 1 && attrs[0].Value[0] == 0 && len(attrs[1].Value) == 1 && attrs[1].Value[0] == 1
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ok
}
