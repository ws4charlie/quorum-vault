//go:build teesim

package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/brokerclient"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/teetest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// These tests run the attested sealer against the REAL broker (verifier, signed allowlist, audit log, a real SoftHSM token), the mock attester
// of internal/attest and real mutual TLS. Only the evidence's root of trust is simulated.

type attRig struct {
	*teetest.Rig
	t     *testing.T
	env   *testenv.Env
	certs map[string]*server.Config // role -> a config that names the party's certificate files
}

func newAttRig(t *testing.T) *attRig { return newAttRigOn(t, testenv.NewEnv(t)) }

func newAttRigOn(t *testing.T, env *testenv.Env) *attRig {
	t.Helper()
	ca := env.Config(t, "A", "127.0.0.1:1", "127.0.0.1:0", "")
	cb := env.Config(t, "B", "", "127.0.0.1:0", "127.0.0.1:0")
	rig := teetest.New(t, []teetest.PartyCert{
		{Role: "A", CertFile: ca.CertFile, KeyFile: ca.KeyFile, Pin: env.CertA.Pin},
		{Role: "B", CertFile: cb.CertFile, KeyFile: cb.KeyFile, Pin: env.CertB.Pin},
	})
	return &attRig{Rig: rig, t: t, env: env, certs: map[string]*server.Config{"A": ca, "B": cb}}
}

// sealerConfig is the config of the attested sealer of a party; pcr0 is the measurement its mock attester reports ("" = the allowlisted image).
func (r *attRig) sealerConfig(role, pcr0 string) server.SealerConfig {
	if pcr0 == "" {
		pcr0 = r.Parties[role].PCR0Hex()
	}
	c := r.certs[role]
	return server.SealerConfig{Type: server.AttestedSealerType, BrokerURL: r.URL, BrokerPins: []string{r.Pin},
		BrokerCertFile: c.CertFile, BrokerKeyFile: c.KeyFile, Attester: server.AttesterConfig{Type: "mock", CADir: r.CADir, PCR0: pcr0}}
}

func (r *attRig) sealer(role string) *server.AttestedSealer {
	r.t.Helper()
	s, err := server.NewSealerForRole(role, r.sealerConfig(role, ""))
	if err != nil {
		r.t.Fatal(err)
	}
	as := s.(*server.AttestedSealer)
	r.t.Cleanup(as.Close)
	return as
}

// store opens a store on dir with a fresh sealer and asks the broker for the keys (a start of the party).
func (r *attRig) store(role, dir string) (*server.FileStore, *server.AttestedSealer, error) {
	as := r.lone(role, "")
	fs, err := server.NewFileStore(dir, role, as)
	if err != nil {
		r.t.Fatal(err)
	}
	return fs, as, fs.PrepareSealer(context.Background())
}

func (r *attRig) lone(role, pcr0 string) *server.AttestedSealer {
	s, err := server.NewSealerForRole(role, r.sealerConfig(role, pcr0))
	if err != nil {
		r.t.Fatal(err)
	}
	as := s.(*server.AttestedSealer)
	r.t.Cleanup(as.Close)
	return as
}

func lastAudit(t *testing.T, r *attRig) (rule, outcome string) {
	t.Helper()
	recs := r.Audit()
	last := recs[len(recs)-1]
	return last.Rule, last.Outcome
}

func TestAttestedSealerSealsPerGenerationAndRefusesMoves(t *testing.T) {
	r := newAttRig(t)
	ctx := context.Background()
	fsA, sA, err := r.store("A", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = fsA
	aad := []byte("qv-mpc-party|keyset|v2|A|ks|1|ecdsa")
	secret := bytes.Repeat([]byte("share"), 100)
	sealed, err := sA.SealScoped(ctx, server.SealScope{Keyset: "ks", Generation: 1}, aad, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("share")) {
		t.Fatal("plaintext visible")
	}
	got, err := sA.OpenScoped(ctx, server.SealScope{Keyset: "ks", Generation: 1}, aad, sealed)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %v", err)
	}
	// Plain Seal and Open refuse: a key needs a scope.
	if _, err := sA.Seal(aad, secret); err == nil {
		t.Fatal("plain Seal worked")
	}

	// a blob of another party: B's own sealer (released by the broker for B) cannot open A's blob
	_, sB, err := r.store("B", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"another generation": func() error {
			_, e := sA.OpenScoped(ctx, server.SealScope{Keyset: "ks", Generation: 2}, aad, sealed)
			return e
		},
		"another keyset": func() error {
			_, e := sA.OpenScoped(ctx, server.SealScope{Keyset: "other", Generation: 1}, aad, sealed)
			return e
		},
		"other associated data (role, keyset, generation, blob kind)": func() error {
			_, e := sA.OpenScoped(ctx, server.SealScope{Keyset: "ks", Generation: 1}, []byte("qv-mpc-party|tkeyset|v1|A|ks|1"), sealed)
			return e
		},
		"another party": func() error {
			_, e := sB.OpenScoped(ctx, server.SealScope{Keyset: "ks", Generation: 1}, aad, sealed)
			return e
		},
		"flipped ciphertext": func() error {
			var e map[string]any
			json.Unmarshal(sealed, &e)
			ct := []byte(e["ct"].(string))
			ct[len(ct)/2] ^= 1
			e["ct"] = string(ct)
			b, _ := json.Marshal(e)
			_, err := sA.OpenScoped(ctx, server.SealScope{Keyset: "ks", Generation: 1}, aad, b)
			return err
		},
		"a v1 (PKCS#11) envelope": func() error {
			_, e := sA.OpenScoped(ctx, server.SealScope{Keyset: "ks", Generation: 1}, aad, []byte(`{"v":1,"iv":"AAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
			return e
		},
	}
	for name, f := range cases {
		if err := f(); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if err := cases["a v1 (PKCS#11) envelope"](); !errors.Is(err, server.ErrSealedV1) {
		t.Errorf("v1 envelope: want ErrSealedV1, got %v", err)
	}
	// B's attempt to have A's blob released is a broker refusal, audited
	if rule, outcome := lastAudit(t, r); outcome != "refused" || rule == "" {
		t.Errorf("the broker did not audit a refusal for A's blob presented by B: %q %q", rule, outcome)
	}
}

func TestAttestedLocalStateIsSealedAndSurvivesRestart(t *testing.T) {
	r := newAttRig(t)
	dir := t.TempDir()
	fs, _, err := r.store("A", dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	meta := server.KeyMeta{KeyID: "k1", KeysetID: "ks", PublicKey: "04abcdef0123456789secretish"}
	if err := fs.PutKey(ctx, meta); err != nil {
		t.Fatal(err)
	}
	job := server.JobRecord{JobID: "job-1", KeyID: "k1", Digest: "dd", Signature: "5151515151", At: time.Now().UTC()}
	if err := fs.PutJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(dir, "keys", "k1.json")} {
		b, _ := os.ReadFile(f)
		if bytes.Contains(b, []byte("abcdef0123456789")) || !bytes.Contains(b, []byte(`"kid"`)) {
			t.Fatalf("%s is not sealed: %s", f, b)
		}
	}
	jobs, _ := os.ReadDir(filepath.Join(dir, "jobs"))
	jb, _ := os.ReadFile(filepath.Join(dir, "jobs", jobs[0].Name()))
	if bytes.Contains(jb, []byte("5151515151")) {
		t.Fatal("the stored signature is in the clear")
	}
	if _, err := os.Stat(filepath.Join(dir, "local.key.json")); err != nil {
		t.Fatal("no local key file")
	}

	// restart: a new process, no key in memory
	fs2, _, err := r.store("A", dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs2.GetKey(ctx, "k1")
	if err != nil || got.PublicKey != meta.PublicKey {
		t.Fatalf("key after restart: %v %v", got, err)
	}
	if j, err := fs2.GetJob(ctx, "job-1"); err != nil || j.Signature != job.Signature {
		t.Fatalf("job after restart: %v %v", j, err)
	}
	// a record moved to another name does not open (the associated data names kind and name)
	b, _ := os.ReadFile(filepath.Join(dir, "keys", "k1.json"))
	os.WriteFile(filepath.Join(dir, "keys", "k2.json"), b, 0o600)
	if _, err := fs2.GetKey(ctx, "k2"); err == nil {
		t.Fatal("a key record moved to another id opened")
	}
	// a forged (plain) record is refused, not read
	os.WriteFile(filepath.Join(dir, "keys", "k3.json"), []byte(`{"key_id":"k3","public_key":"00"}`), 0o600)
	if _, err := fs2.GetKey(ctx, "k3"); !errors.Is(err, server.ErrLocalUnsealed) {
		t.Fatalf("plain record: %v", err)
	}
}

func TestAttestedSealerDoesNotReadOrMigrateV1Data(t *testing.T) {
	r := newAttRig(t)
	dir := t.TempDir()
	// a directory of a party that ran with the PKCS#11 sealer: plain local state, no local key file
	os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	os.WriteFile(filepath.Join(dir, "keys", "k1.json"), []byte(`{"key_id":"k1"}`), 0o600)
	_, _, err := r.store("A", dir)
	if err == nil || !strings.Contains(err.Error(), "local key") {
		t.Fatalf("want a refusal that names the missing local key, got %v", err)
	}
	// and a generation file with a v1 envelope
	dir2 := t.TempDir()
	os.MkdirAll(filepath.Join(dir2, "keysets", "ks"), 0o700)
	os.WriteFile(filepath.Join(dir2, "keysets", "ks", "g1.json"), []byte(`{"v":2,"alg":1,"role":"A","gen":1,"sealed":"eyJ2IjoxLCJpdiI6IkFBQUFBQUFBQUFBQUFBQUEiLCJjdCI6IkFBQUEifQ=="}`), 0o600)
	if _, _, err := r.store("A", dir2); !errors.Is(err, server.ErrSealedV1) {
		t.Fatalf("v1 generation file: %v", err)
	}
	if r.Audit() != nil {
		for _, rec := range r.Audit() {
			if rec.Event == "release" && rec.Outcome == "released" {
				t.Fatal("the broker released a key for v1 data")
			}
		}
	}
}

func TestAttestedRefusalsAreDistinctAndNothingIsReleased(t *testing.T) {
	r := newAttRig(t)
	dir := t.TempDir()
	fs, _, err := r.store("A", dir) // a good first start makes the local key
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.GetKey(context.Background(), "none"); !errors.Is(err, server.ErrNotFound) {
		t.Fatal(err)
	}

	wrong := attest.MeasureImage([]byte("party A image v2 (not allowlisted)"), []byte("config"))
	for _, c := range []struct {
		name  string
		setup func()
		pcr0  string
		rule  string
	}{
		{"measurement not allowlisted", func() {}, hexOf(wrong), "allowlist:"},
		{"entry revoked", func() { r.Revoke("A") }, "", "allowlist:"},
		{"entry expired", func() {
			r.SetAllowlist(attest.AllowEntry{Party: "A", Measurement: r.Parties["A"].PCR0Hex(), NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
		}, "", "allowlist:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.setup()
			defer r.Restore()
			as := r.lone("A", c.pcr0)
			fs2, _ := server.NewFileStore(dir, "A", as)
			err := fs2.PrepareSealer(context.Background())
			if !errors.Is(err, server.ErrKeyRefused) || !strings.Contains(err.Error(), "allowlist") {
				t.Fatalf("want an allowlist refusal, got %v", err)
			}
			if rule, outcome := lastAudit(t, r); outcome != "refused" || !strings.HasPrefix(rule, c.rule) {
				t.Fatalf("audit: %q %q", rule, outcome)
			}
			if as.Ready() || len(as.Held()) != 0 {
				t.Fatal("the sealer holds a key after a refusal")
			}
			if st := as.Stats(); st["refused:allowlist"] != 1 {
				t.Fatalf("metric: %v", st)
			}
			// a fresh directory: newkey is refused too
			fs3, _ := server.NewFileStore(t.TempDir(), "A", r.lone("A", c.pcr0))
			if err := fs3.PrepareSealer(context.Background()); !errors.Is(err, server.ErrKeyRefused) {
				t.Fatalf("newkey: %v", err)
			}
		})
	}
	// and with the allowlist restored the same directory starts
	if _, _, err := r.store("A", dir); err != nil {
		t.Fatalf("after the allowlist was restored: %v", err)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// replayAPI is a broker client that answers a release with an answer the broker gave earlier to another request.
type replayAPI struct {
	*brokerclient.Client
	stored *attest.ReleaseResponse
}

func (a *replayAPI) Release(ctx context.Context, req attest.ReleaseRequest) (attest.ReleaseResponse, error) {
	if a.stored != nil {
		return *a.stored, nil
	}
	resp, err := a.Client.Release(ctx, req)
	if err == nil {
		a.stored = &resp
	}
	return resp, err
}

func TestAttestedReplayedReleaseResponseIsRefused(t *testing.T) {
	r := newAttRig(t)
	dir := t.TempDir()
	if _, _, err := r.store("A", dir); err != nil { // makes the local key and nothing else
		t.Fatal(err)
	}
	cfg := r.sealerConfig("A", "")
	c := r.certs["A"]
	cert := loadPair(t, c.CertFile, c.KeyFile)
	pin, _ := server.ParsePin(r.Pin)
	api := &replayAPI{Client: brokerclient.NewClient(r.URL, cert, map[server.Pin]bool{pin: true})}
	att, err := attestFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	callerPin, _ := server.ParsePin(r.env.CertA.Pin)
	s1, err := server.NewAttestedSealerWith("A", api, att, callerPin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	fs1, _ := server.NewFileStore(dir, "A", s1)
	if err := fs1.PrepareSealer(context.Background()); err != nil { // the real answer is recorded
		t.Fatal(err)
	}
	// a second start receives the recorded answer to the first request: it is for another nonce, so it does not open
	s2, _ := server.NewAttestedSealerWith("A", api, att, callerPin, nil)
	defer s2.Close()
	fs2, _ := server.NewFileStore(dir, "A", s2)
	if err := fs2.PrepareSealer(context.Background()); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("a replayed release answer was accepted: %v", err)
	}
	if s2.Ready() || len(s2.Held()) != 0 {
		t.Fatal("a key was installed from a replayed answer")
	}
}

// ---- a party pair on attested sealers, restartable ----

type attCluster struct {
	t            *testing.T
	r            *attRig
	cfgA, cfgB   *server.Config
	logA, logB   *syncBuf
	p            *pair
	sealA, sealB *server.AttestedSealer
	fi           *server.FaultInjection
	callerA      string
	callerB      string
	peerB        string
}

func newAttCluster(t *testing.T) *attCluster { return newAttClusterOn(t, newAttRig(t)) }

func newAttClusterOn(t *testing.T, r *attRig) *attCluster {
	c := &attCluster{t: t, r: r, logA: &syncBuf{}, logB: &syncBuf{}, callerA: testenv.FreeAddr(t), callerB: testenv.FreeAddr(t), peerB: testenv.FreeAddr(t)}
	c.cfgB = r.env.Config(t, "B", "", c.callerB, c.peerB)
	c.cfgA = r.env.Config(t, "A", c.peerB, c.callerA, "")
	return c
}

// up starts both parties on their data directories (as a new process: new sealers, nothing in memory).
func (c *attCluster) up() {
	t := c.t
	t.Helper()
	mk := func(cfg *server.Config, role string, log io.Writer, fi *server.FaultInjection) (*server.Server, *server.AttestedSealer) {
		c.cfgA.Sealer = c.r.sealerConfig("A", "")
		c.cfgB.Sealer = c.r.sealerConfig("B", "")
		cfg.Sealer = c.r.sealerConfig(role, "")
		s, err := server.NewSealerForRole(role, cfg.Sealer)
		if err != nil {
			t.Fatal(err)
		}
		as := s.(*server.AttestedSealer)
		fs, err := server.NewFileStore(cfg.DataDir, role, as)
		if err != nil {
			t.Fatal(err)
		}
		srv, err := server.New(server.Options{Config: cfg, Authorizer: allowAll, Logger: logTo(log), FaultInjection: fi, Store: fs})
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		return srv, as
	}
	var b, a *server.Server
	b, c.sealB = mk(c.cfgB, "B", c.logB, nil)
	a, c.sealA = mk(c.cfgA, "A", c.logA, c.fi)
	cl, conn := c.r.env.DialAs(t, c.callerA, c.r.env.CertCaller, c.r.env.CertA.Pin)
	bc, _ := c.r.env.DialAs(t, c.callerB, c.r.env.CertCaller, c.r.env.CertB.Pin)
	c.p = &pair{Env: c.r.env, A: a, B: b, Client: cl, BCall: bc, ConnA: conn}
}

func (c *attCluster) down() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c.p.A.Shutdown(ctx)
	c.p.B.Shutdown(ctx)
}

func (c *attCluster) waitReady(d time.Duration) {
	c.t.Helper()
	deadline := time.Now().Add(d)
	var ea, eb error
	for time.Now().Before(deadline) {
		ea, eb = c.p.A.Ready(time.Now()), c.p.B.Ready(time.Now())
		if ea == nil && eb == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("parties not ready: A: %v, B: %v\nA log: %s\nB log: %s", ea, eb, c.logA.String(), c.logB.String())
}

// waitResolved waits until both parties report the keyset reconciled on one generation.
func (c *attCluster) waitResolved(id string, gen uint64) {
	c.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		h, err := c.p.Client.Health(ctx30(c.t), &pb.HealthRequest{})
		if err == nil {
			for _, k := range h.Keysets {
				if k.KeysetId == id && k.Resolved && (gen == 0 || k.Generation == gen) {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	c.t.Fatalf("keyset %s not resolved on generation %d\nA log: %s", id, gen, c.logA.String())
}

func (c *attCluster) sign(id, job string, dg []byte, pub []byte) error {
	c.t.Helper()
	r, err := c.p.Client.Sign(ctx30(c.t), &pb.SignRequest{KeyId: id, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: job})
	if err != nil {
		return err
	}
	verifyECDSA(c.t, pub, dg, r.Signature)
	return nil
}

func TestAttestedPairDKGSignRefreshRestart(t *testing.T) {
	c := newAttCluster(t)
	c.up()
	defer c.down()
	c.waitReady(30 * time.Second)

	c.p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	d := c.p.derive(t, "ks", []uint32{44, 60, 0}, []uint32{0})
	if err := c.sign(d.KeyId, "j1", digest(1), d.PublicKey); err != nil {
		t.Fatal(err)
	}
	// every key that was released has a scope; generation 1 and the local key
	if got := len(c.sealA.Held()); got != 2 {
		t.Fatalf("party A holds %d data keys, want 2 (local + keyset generation 1): %v", got, c.sealA.Held())
	}

	if _, err := c.p.Client.Refresh(ctx30(t), &pb.RefreshRequest{KeysetId: "ks", Admin: c.r.env.Admin("refresh", "ks")}); err != nil {
		t.Fatal(err)
	}
	c.waitResolved("ks", 2)
	// after the commit the old generation's key is no longer held and its file (with the wrapped key) is gone
	deadline := time.Now().Add(10 * time.Second)
	for len(c.sealA.Held()) != 2 || len(c.sealB.Held()) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("old generation keys still held: A %v B %v", c.sealA.Held(), c.sealB.Held())
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, s := range c.sealA.Held() {
		if s.Keyset == "ks" && s.Generation != 2 {
			t.Fatalf("A holds the key of generation %d", s.Generation)
		}
	}
	if _, err := os.Stat(filepath.Join(c.cfgA.DataDir, "keysets", "ks", "g1.json")); err == nil {
		t.Fatal("the old share file (and its wrapped key) is still on disk")
	}
	if err := c.sign(d.KeyId, "j2", digest(2), d.PublicKey); err != nil {
		t.Fatal(err)
	}

	// restart both: no key survives in memory, the broker releases again, the signature key is unchanged
	c.down()
	c.up()
	c.waitReady(30 * time.Second)
	c.waitResolved("ks", 2)
	if err := c.sign(d.KeyId, "j3", digest(3), d.PublicKey); err != nil {
		t.Fatal(err)
	}
	// the stored signature of j1 survives the restart (sealed idempotency record)
	r, err := c.p.Client.Sign(ctx30(t), &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: digest(1), JobId: "j1"})
	if err != nil || !r.Replayed {
		t.Fatalf("j1 after restart: replayed=%v err=%v", r != nil && r.Replayed, err)
	}

	// nothing at rest but ciphertext: the files of the data directory are the known ones
	var names []string
	filepath.WalkDir(c.cfgA.DataDir, func(p string, de os.DirEntry, err error) error {
		if err == nil && !de.IsDir() {
			rel, _ := filepath.Rel(c.cfgA.DataDir, p)
			names = append(names, rel)
		}
		return nil
	})
	for _, n := range names {
		base := filepath.Base(n)
		if strings.HasSuffix(base, ".key") || strings.Contains(base, "pin") || strings.Contains(base, "secret") {
			t.Errorf("unexpected file in the data directory: %s", n)
		}
	}
	// the broker log shows exactly the attested releases, each for party A or B with its measurement
	var released int
	for _, rec := range c.r.Audit() {
		if rec.Outcome == "released" {
			released++
			if rec.Measurement == "" {
				t.Fatal("a release without a measurement in the audit log")
			}
		}
	}
	if released < 6 {
		t.Fatalf("only %d released records", released)
	}
	// the log of a party names no key
	for _, l := range []string{c.logA.String(), c.logB.String()} {
		if strings.Contains(l, "wrapped_dek") {
			t.Fatal("a log line carries key material")
		}
	}
}

func TestAttestedBrokerDownAtStartThenUp(t *testing.T) {
	c := newAttCluster(t)
	c.r.Stop()
	c.up()
	defer c.down()
	time.Sleep(2 * time.Second)
	err := c.p.A.Ready(time.Now())
	if err == nil || !strings.Contains(err.Error(), "sealer not ready") {
		t.Fatalf("party A is ready (or says why not in other words) with the broker down: %v", err)
	}
	if !strings.Contains(c.logA.String(), "broker is unreachable") {
		t.Fatalf("no log line that names the reason:\n%s", c.logA.String())
	}
	// the party answers its health probe: not ready (503), with no secret in the body
	var m bytes.Buffer
	c.p.A.WriteMetrics(&m)
	if !strings.Contains(m.String(), `qv_mpc_party_sealer_ready{party="A"} 0`) || !strings.Contains(m.String(), `outcome="unreachable"`) {
		t.Fatalf("metrics: %s", m.String())
	}
	// no work is served meanwhile, and nothing falls back to another sealer
	if _, err := c.p.Client.DKG(ctx30(t), &pb.DKGRequest{KeysetId: "ks", Curve: pb.Curve_CURVE_SECP256K1, Admin: c.r.env.Admin("dkg", "ks")}); err == nil {
		t.Fatal("a DKG ran without the data keys")
	}
	c.r.Start()
	c.waitReady(60 * time.Second)
	c.p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	m.Reset()
	c.p.A.WriteMetrics(&m)
	if !strings.Contains(m.String(), `qv_mpc_party_sealer_ready{party="A"} 1`) {
		t.Fatalf("metrics after start: %s", m.String())
	}
}

func TestAttestedNotAllowlistedIsADistinctLineAndMetric(t *testing.T) {
	c := newAttCluster(t)
	c.r.Revoke("A")
	c.up()
	defer c.down()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(c.logA.String(), "ALERT attested sealer: the broker refused to release the data keys because this party's measurement is not allowlisted") {
		if time.Now().After(deadline) {
			t.Fatalf("no distinct allowlist line:\n%s", c.logA.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	var m bytes.Buffer
	c.p.A.WriteMetrics(&m)
	if !strings.Contains(m.String(), `outcome="refused:allowlist"`) {
		t.Fatalf("metrics: %s", m.String())
	}
	if err := c.p.A.Ready(time.Now()); err == nil {
		t.Fatal("ready after a refusal")
	}
	c.r.Restore() // the operators allowlist it again: the party starts without a restart
	c.waitReady(60 * time.Second)
}

func TestAttestedRollbackOfTheDataDirectory(t *testing.T) {
	c := newAttCluster(t)
	c.up()
	defer c.down()
	c.waitReady(30 * time.Second)
	c.p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	d := c.p.derive(t, "ks", []uint32{1}, []uint32{0})
	c.waitResolved("ks", 1)
	c.down()
	snap := t.TempDir()
	copyDir(t, c.cfgA.DataDir, snap) // the host copies A's directory at generation 1
	c.up()
	c.waitReady(30 * time.Second)
	c.waitResolved("ks", 1)
	if _, err := c.p.Client.Refresh(ctx30(t), &pb.RefreshRequest{KeysetId: "ks", Admin: c.r.env.Admin("refresh", "ks")}); err != nil {
		t.Fatal(err)
	}
	c.waitResolved("ks", 2)
	c.down()

	// roll A back to generation 1: the old share, its wrapped key and the sealed state all open (the broker releases the old key again)...
	os.RemoveAll(c.cfgA.DataDir)
	copyDir(t, snap, c.cfgA.DataDir)
	c.up()
	c.waitReady(30 * time.Second)
	// ...but the parties do not serve: reconciliation sees A on generation 1 and B on 2 and refuses
	time.Sleep(3 * time.Second)
	if err := c.sign(d.KeyId, "after-rollback", digest(7), d.PublicKey); err == nil {
		t.Fatal("the rolled-back party signed")
	} else if statusCode(err) != codes.Unavailable && statusCode(err) != codes.FailedPrecondition {
		t.Fatalf("unexpected error: %v", err)
	}
	h, _ := c.p.Client.Health(ctx30(t), &pb.HealthRequest{})
	for _, k := range h.GetKeysets() {
		if k.KeysetId == "ks" && k.Resolved {
			t.Fatal("the rolled-back keyset reports resolved")
		}
	}
	if !strings.Contains(c.logA.String(), "older") && !strings.Contains(c.logA.String(), "stale") {
		t.Logf("A log (no 'older' text found): %s", c.logA.String())
	}
}

func TestAttestedDeletedFreezeRecordIsStillFrozenByThePeer(t *testing.T) {
	c := newAttCluster(t)
	c.fi = &server.FaultInjection{FailSelfTest: func(op, role string) bool { return role == "A" && op == "refresh" }}
	c.up()
	defer c.down()
	c.waitReady(30 * time.Second)
	c.p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	d := c.p.derive(t, "ks", []uint32{1}, []uint32{0})
	if _, err := c.p.Client.Refresh(ctx30(t), &pb.RefreshRequest{KeysetId: "ks", Admin: c.r.env.Admin("refresh", "ks")}); err == nil {
		t.Fatal("refresh passed with a failing self-test")
	}
	if err := c.sign(d.KeyId, "frozen", digest(1), d.PublicKey); err == nil {
		t.Fatal("signed while frozen")
	}
	fz := filepath.Join(c.cfgA.DataDir, "freeze", "ks.json")
	raw, err := os.ReadFile(fz)
	if err != nil || bytes.Contains(raw, []byte("self")) || !bytes.Contains(raw, []byte(`"kid"`)) {
		t.Fatalf("freeze record is not sealed: %v %s", err, raw)
	}
	c.down()

	// a forged record: A cannot tell it from an attack and stays frozen
	os.WriteFile(fz, []byte(`{"keyset_id":"ks","reason":"x"}`), 0o600)
	c.fi = nil
	c.up()
	c.waitReady(30 * time.Second)
	if err := c.sign(d.KeyId, "forged", digest(2), d.PublicKey); err == nil {
		t.Fatal("signed with a forged freeze record")
	}
	c.down()

	// a DELETED record: sealing cannot prevent that. A is unfrozen locally, B still holds its own record and refuses.
	os.Remove(fz)
	c.up()
	c.waitReady(30 * time.Second)
	c.waitResolved("ks", 1)
	err = c.sign(d.KeyId, "deleted", digest(3), d.PublicKey)
	if err == nil {
		t.Fatal("signed although party B is frozen")
	}
	if k, ok := server.KindOfStatus(err); !ok || k != pb.ErrorKind_ERROR_KIND_FROZEN {
		t.Fatalf("want FROZEN (B's record), got %v", err)
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if de.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		if de.Name() == ".lock" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func loadPair(t *testing.T, cert, key string) tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// attestFor builds the same mock attester the party builds from its config.
func attestFor(c server.SealerConfig) (attest.Attester, error) {
	ca, err := attest.LoadMockCA(c.Attester.CADir)
	if err != nil {
		return nil, err
	}
	pcr0, err := hex.DecodeString(c.Attester.PCR0)
	if err != nil {
		return nil, err
	}
	return &attest.MockAttester{CA: ca, PCR0: pcr0, PCR8: attest.MeasureCert([]byte("mock signing cert"))}, nil
}

// The broker answers rate_limited during a start (many keysets, a low limit): the party stays not ready, says so, retries by itself and becomes ready
// without a restart. Every other test runs with the limit off.
func TestAttestedStartRecoversFromRateLimit(t *testing.T) {
	c := newAttCluster(t)
	c.up()
	c.waitReady(30 * time.Second)
	for _, id := range []string{"ks1", "ks2", "ks3", "ks4"} {
		c.p.dkg(t, id, pb.Curve_CURVE_SECP256K1)
	}
	c.down()
	c.r.SetLimit(60, 3) // a start needs 2 calls per keyset plus 2: ten calls, three at once, one more per second
	c.up()
	defer c.down()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(c.logA.String(), "rate_limited") {
		if time.Now().After(deadline) {
			t.Fatalf("the broker never rate limited the start:\n%s", c.logA.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	var m bytes.Buffer
	c.p.A.WriteMetrics(&m)
	if !strings.Contains(m.String(), `outcome="refused:rate_limited"`) {
		t.Fatalf("metrics after a rate limited start: %s", m.String())
	}
	c.waitReady(90 * time.Second) // no restart: the gate retries and only fetches what is still missing
	if err := c.p.A.Ready(time.Now()); err != nil {
		t.Fatal(err)
	}
}
