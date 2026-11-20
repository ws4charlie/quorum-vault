package mpcstack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The tee-sim run mode of the three-party stack (research/TEE.md, task TEE-T4). SIMULATED: the parties are built with -tags teesim, so they
// contain the mock attester; each party runs the ATTESTED sealer against its own qv-attest-broker (a real process with its own SoftHSM token and a
// signed allowlist), keeps its TLS key sealed, and measures its own binary and config file. Nothing here proves isolation; it proves that our code
// does what it must around an enclave. See docs/runbooks/tee-broker.md.
//
// What Start3 does in this mode, in order (a ceremony as an operator would run it):
//  1. a test CA for the evidence, three operator keys, one broker per party (broker A on token qv-party-1, B on qv-party-2, C on qv-party-3);
//  2. an allowlist that holds only each party's ENROLMENT measurement, signed by two operators;
//  3. `mpc-party tls-init` for each party: it attests, makes its TLS key inside, seals it, prints the pin;
//  4. the real party configs are written (they carry those pins), measured, and the allowlist is replaced by one that holds only the running
//     measurements (the enrolment entries are revoked);
//  5. the parties start.

// SimulationMarkerText is the start of server.SimulationMarker, which is in every tee-sim party binary and in none of the production ones.
const SimulationMarkerText = "QV-SIMULATED-ENCLAVE"

// TEEOpts tunes the simulated enclave run mode. The zero value gives a broker without a practical rate limit.
type TEEOpts struct {
	// RatePerMinute and Burst are each broker's limit per party (0: effectively none; the broker's own default is 30 and 10).
	RatePerMinute, Burst int
	// NoAllowlistForRoles are parties whose measurement is NOT put on the allowlist at start (they are refused until AllowParty).
	NoAllowlistForRoles []string
}

// TEE is the simulated enclave side of a Stack3: the brokers, their allowlist and the operators.
type TEE struct {
	s   *Stack3
	o   TEEOpts
	Dir string

	CADir   string
	Brokers map[string]*Proc  // role -> that party's own broker
	Addr    map[string]string // role -> broker address
	Audit   map[string]string // role -> audit log file

	opKeys    []string // operator key files (two of three sign)
	opNames   []string
	opPubs    []string
	cfgPath   map[string]string // role -> broker config
	listPath  map[string]string // role -> allowlist file
	brokerPin map[string]string
	linkCert  map[string]Cert // role -> the party's certificate for the link to the broker
	enroll    map[string]string
	seq       int64
	measured  map[string]string // role -> measurement of the running config (hex)
	allowed   map[string]bool
}

func (t *TEE) roles() []string { return []string{"A", "B", "C"} }

var brokerToken = map[string]string{"A": "qv-party-1", "B": "qv-party-2", "C": "qv-party-3"}

// BuildTeeSim compiles the simulation binaries into dir: mpc-party and qv-attest-broker with -tags teesim, the test CA tool, and the cosigner. The
// party binary is a different file from the production one (Build) and carries server.SimulationMarker.
func BuildTeeSim(dir string) (Binaries, error) {
	root := RepoRoot()
	build := func(workdir, out, pkg string, tags bool) (string, error) {
		p := filepath.Join(dir, out)
		args := []string{"build", "-o", p}
		if tags {
			args = append(args, "-tags", "teesim")
		}
		cmd := exec.Command("go", append(args, pkg)...)
		cmd.Dir = workdir
		if o, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("build %s: %v\n%s", out, err, o)
		}
		return p, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Binaries{}, err
	}
	var b Binaries
	var err error
	mp := filepath.Join(root, "mpc-party")
	if b.MPCParty, err = build(mp, "mpc-party", "./cmd/mpc-party", true); err != nil {
		return b, err
	}
	if b.Broker, err = build(mp, "qv-attest-broker", "./cmd/qv-attest-broker", true); err != nil {
		return b, err
	}
	if b.AttestCA, err = build(mp, "qv-attest-ca", "./internal/attest/cmd/qv-attest-ca", true); err != nil {
		return b, err
	}
	b.Cosigner, err = build(root, "qv-cosigner", "./cmd/qv-cosigner", false)
	return b, err
}

func (t *TEE) run(bin string, args ...string) string {
	t.s.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), append(SoftHSMEnv(), "QV_ENV=test")...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.s.t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

func (t *TEE) write(name string, v any) string {
	t.s.t.Helper()
	b, _ := json.MarshalIndent(v, "", " ")
	p := filepath.Join(t.Dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.s.t.Fatal(err)
	}
	return p
}

func (t *TEE) sealerCfg(role string, extra map[string]any) map[string]any {
	att := map[string]any{"type": "mock", "ca_dir": t.CADir}
	for k, v := range extra {
		att[k] = v
	}
	cert, key := t.linkCert[role].Write(t.s.t, t.Dir)
	return map[string]any{"type": "attested", "broker_url": "https://" + t.Addr[role], "broker_pins": []string{t.brokerPin[role]},
		"broker_cert_file": cert, "broker_key_file": key, "attester": att}
}

// setup runs steps 1 to 3. It sets the pins of the three parties in s.
func (t *TEE) setup() {
	s := t.s
	tb := s.t
	t.Dir = filepath.Join(s.Dir, "tee")
	if err := os.MkdirAll(t.Dir, 0o700); err != nil {
		tb.Fatal(err)
	}
	t.CADir = filepath.Join(t.Dir, "ca")
	t.run(s.Bin.AttestCA, "-dir", t.CADir)
	for _, n := range []string{"alice", "bob", "carol"} {
		kf := filepath.Join(t.Dir, "op-"+n+".key")
		out := t.run(s.Bin.Broker, "allowlist", "keygen", "-key", kf, "-pub", kf+".pub")
		t.opNames, t.opKeys = append(t.opNames, n), append(t.opKeys, kf)
		t.opPubs = append(t.opPubs, strings.TrimSpace(strings.TrimPrefix(out, "public key:")))
	}
	pinFile := filepath.Join(t.Dir, "token.pin")
	pin := ""
	for _, e := range SoftHSMEnv() {
		if v, ok := strings.CutPrefix(e, "QV_HSM_PIN="); ok {
			pin = v
		}
	}
	if err := os.WriteFile(pinFile, []byte(pin), 0o400); err != nil {
		tb.Fatal(err)
	}
	t.Brokers, t.Addr, t.Audit = map[string]*Proc{}, map[string]string{}, map[string]string{}
	t.cfgPath, t.listPath, t.brokerPin, t.linkCert = map[string]string{}, map[string]string{}, map[string]string{}, map[string]Cert{}
	t.enroll, t.measured, t.allowed = map[string]string{}, map[string]string{}, map[string]bool{}
	ops := map[string]any{}
	for i, n := range t.opNames {
		ops[n] = map[string]string{"public_key": t.opPubs[i]}
	}
	rate, burst := t.o.RatePerMinute, t.o.Burst
	if rate == 0 {
		rate = 100000
	}
	if burst == 0 {
		burst = 100000
	}
	for _, r := range t.roles() {
		bc := NewCert(tb, "broker-"+r)
		crt, key := bc.Write(tb, t.Dir)
		t.brokerPin[r] = bc.Pin
		t.linkCert[r] = NewCert(tb, "broker-link-"+r)
		t.Addr[r] = FreeAddr(tb)
		t.Audit[r] = filepath.Join(t.Dir, "audit-"+r+".log")
		t.listPath[r] = filepath.Join(t.Dir, "allowlist-"+r+".json")
		t.cfgPath[r] = t.write("broker-"+r+".json", map[string]any{
			"listen": t.Addr[r], "tls_cert": crt, "tls_key": key,
			"pkcs11":      map[string]string{"token": brokerToken[r], "pin_file": pinFile},
			"trust_roots": filepath.Join(t.CADir, "root.crt"), "allowlist_file": t.listPath[r],
			"operators": map[string]any{"keys": ops, "min_operators": 2},
			"parties":   map[string]any{r: map[string]any{"caller_pins": []string{t.linkCert[r].Pin}}},
			"audit_log": t.Audit[r], "reload_interval": "200ms", "rate_per_minute": rate, "rate_burst": burst,
		})
	}
	// enrolment configs and their measurements
	for _, r := range t.roles() {
		t.enroll[r] = t.write("enroll-"+r+".json", map[string]any{
			"role": r, "data_dir": filepath.Join(s.Dir, "data-"+r), "tls_sealed": true, "sealer": t.sealerCfg(r, nil)})
		t.measured[r] = t.run(s.Bin.AttestCA, "measure", "-binary", s.Bin.MPCParty, "-config", t.enroll[r])
	}
	t.setAllowlist(t.measured, nil)
	for _, r := range t.roles() {
		t.Brokers[r] = NewProc(tb, "broker-"+r, filepath.Join(s.Dir, "broker-"+r+".log"), s.Bin.Broker, append(SoftHSMEnv(), "QV_ENV=test"), "serve", "-config", t.cfgPath[r])
		t.StartBroker(r)
	}
	for _, r := range t.roles() { // step 3: the parties make and seal their TLS keys
		pin := t.run(s.Bin.MPCParty, "tls-init", "-config", t.enroll[r])
		switch r {
		case "A":
			s.CertA = Cert{Name: "party-a", Pin: pin}
		case "B":
			s.CertB = Cert{Name: "party-b", Pin: pin}
		case "C":
			s.CertC = Cert{Name: "party-c", Pin: pin}
		}
	}
}

// finalize is step 4: measure the real configs and allow exactly those.
func (t *TEE) finalize() {
	m := map[string]string{}
	for _, r := range t.roles() {
		m[r] = t.run(t.s.Bin.AttestCA, "measure", "-binary", t.s.Bin.MPCParty, "-config", t.s.cfg[r])
	}
	t.measured = m
	skip := map[string]bool{}
	for _, r := range t.o.NoAllowlistForRoles {
		skip[r] = true
	}
	t.setAllowlist(m, skip)
}

// MeasurementOf is the allowlisted measurement of a party's running config (hex).
func (t *TEE) MeasurementOf(role string) string { return t.measured[role] }

// setAllowlist writes a new signed list (sequence number one higher, two operators) with one entry per party in m (not those in skip) to every broker.
func (t *TEE) setAllowlist(m map[string]string, skip map[string]bool) {
	tb := t.s.t
	t.seq++
	t.allowed = map[string]bool{}
	nb := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	na := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for _, r := range t.roles() {
		args := []string{"allowlist", "new", "-seq", fmt.Sprint(t.seq), "-out", t.listPath[r] + ".tmp"}
		if m[r] != "" && !skip[r] {
			args = append(args, "-entry", strings.Join([]string{r, m[r], nb, na}, ","))
			t.allowed[r] = true
		} else {
			// a list needs an entry: a measurement that no party has (all 0x11) stands for "nothing allowed"
			args = append(args, "-entry", strings.Join([]string{r, strings.Repeat("11", 48), nb, na}, ","))
		}
		t.run(t.s.Bin.Broker, args...)
		for i := 0; i < 2; i++ {
			t.run(t.s.Bin.Broker, "allowlist", "sign", "-in", t.listPath[r]+".tmp", "-key", t.opKeys[i], "-operator", t.opNames[i])
		}
		if err := os.Rename(t.listPath[r]+".tmp", t.listPath[r]); err != nil {
			tb.Fatal(err)
		}
	}
}

// StartBroker starts (again) one party's broker and waits until it accepts connections.
func (t *TEE) StartBroker(role string) {
	t.s.t.Helper()
	t.Brokers[role].Start(t.s.t)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", t.Addr[role], 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.s.t.Fatalf("broker %s did not start: %s", role, tail(t.Brokers[role].Output()))
}

// StopBroker kills one party's broker (the party cannot get its keys until StartBroker).
func (t *TEE) StopBroker(role string) { t.Brokers[role].Kill() }

// Revoke publishes a new allowlist without the party's measurement (every broker gets it; the running parties keep their keys in memory, a
// restart is refused). Allow puts it back.
func (t *TEE) Revoke(role string) {
	skip := map[string]bool{role: true}
	for r, ok := range t.allowed {
		if !ok {
			skip[r] = true
		}
	}
	t.setAllowlist(t.measured, skip)
	time.Sleep(700 * time.Millisecond) // the brokers poll the file every 200 ms
}

// Allow publishes the allowlist with the party's measurement again.
func (t *TEE) Allow(role string) {
	skip := map[string]bool{}
	for r, ok := range t.allowed {
		if !ok && r != role {
			skip[r] = true
		}
	}
	t.setAllowlist(t.measured, skip)
	time.Sleep(700 * time.Millisecond)
}

// AllowMeasurement publishes an allowlist in which the party's allowed measurement is the given one (hex): the image of a different build or config.
func (t *TEE) AllowMeasurement(role, hex string) {
	m := map[string]string{}
	for r, v := range t.measured {
		m[r] = v
	}
	m[role] = hex
	t.setAllowlist(m, nil)
	time.Sleep(700 * time.Millisecond)
}

// Measure computes the mock measurement of a binary and a config file (what a release build would publish).
func (t *TEE) Measure(bin, cfg string) string {
	return t.run(t.s.Bin.AttestCA, "measure", "-binary", bin, "-config", cfg)
}

// AuditLines counts the broker audit records of one party's broker that contain every one of parts.
func (t *TEE) AuditLines(role string, parts ...string) int {
	b, _ := os.ReadFile(t.Audit[role])
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		ok := l != ""
		for _, p := range parts {
			if !strings.Contains(l, p) {
				ok = false
			}
		}
		if ok {
			n++
		}
	}
	return n
}

// ReloadBrokers asks every broker to re-read its allowlist now (SIGHUP).
func (t *TEE) ReloadBrokers() {
	for _, p := range t.Brokers {
		if pid := p.Pid(); pid != 0 && p.Running() {
			_ = syscall.Kill(pid, syscall.SIGHUP)
		}
	}
}

// RestartPartyWith starts party `role` again with another binary and/or config file (nil args keep the stack's own). It returns the new process,
// which replaces the stack's. The party's data directory is the same.
func (t *TEE) RestartPartyWith(role, bin, cfg string) *Proc {
	s := t.s
	if bin == "" {
		bin = s.Bin.MPCParty
	}
	if cfg == "" {
		cfg = s.cfg[role]
	}
	p := NewProc(s.t, "party-"+role, filepath.Join(s.Dir, "party-"+role+".log"), bin, SoftHSMEnv(), "-config", cfg)
	s.Party(role).Kill()
	switch role {
	case "A":
		s.A = p
	case "B":
		s.B = p
	default:
		s.C = p
	}
	p.Start(s.t)
	return p
}

// TEE returns the simulated enclave side (nil unless Opts.TEE was set).
func (s *Stack3) TEE() *TEE { return s.tee }

// ConfigPath is the config file of a party (the one that is measured).
func (s *Stack3) ConfigPath(role string) string { return s.cfg[role] }

// DataDir is the data directory of a party.
func (s *Stack3) DataDir(role string) string { return filepath.Join(s.Dir, "data-"+role) }
