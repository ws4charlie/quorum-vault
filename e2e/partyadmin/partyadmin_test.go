// Package partyadmin_test runs the operator tool qv-party-admin against real mpc-party processes (three parties, real SoftHSM sealing):
// DKG, refresh, freeze and unfreeze through the CLI, and the refusals. No database. Skipped unless QV_MPC_E2E=1 (make test-party-admin).
package partyadmin_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

var (
	bin  mpcstack.Binaries
	tool string
)

func TestMain(m *testing.M) {
	mpcstack.ReaperMain()
	if os.Getenv("QV_MPC_E2E") != "1" {
		fmt.Println("skipped: set QV_MPC_E2E=1 (needs the cb-mpc build; see make test-party-admin)")
		os.Exit(0)
	}
	stop := func() {}
	if s, err := mpcstack.StartReaper(); err == nil {
		stop = s
	}
	dir, err := os.MkdirTemp("", "partyadmin-bin-")
	if err != nil {
		panic(err)
	}
	if bin, err = mpcstack.Build(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if tool, err = mpcstack.BuildPartyAdmin(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.RemoveAll(dir)
	os.Exit(code)
}

// rig is a three-party stack, the operator's key file and the caller flags `send` needs.
type rig struct {
	t       *testing.T
	s       *mpcstack.Stack3
	dir     string
	opKey   string
	callers []string
}

func newRig(t *testing.T, o mpcstack.Opts) *rig {
	t.Helper()
	dir := t.TempDir()
	s := mpcstack.Start3(t, filepath.Join(dir, "stack"), bin, o)
	s.WaitReady(90 * time.Second)
	crt, key := s.CertGW.Write(t, dir)
	r := &rig{t: t, s: s, dir: dir, opKey: filepath.Join(dir, "operator.key")}
	if err := os.WriteFile(r.opKey, []byte(s.AdminSeedHex()), 0o600); err != nil {
		t.Fatal(err)
	}
	r.callers = []string{
		"-party", "A=" + s.CallerA + "@" + s.CertA.Pin, "-party", "B=" + s.CallerB + "@" + s.CertB.Pin, "-party", "C=" + s.CallerC + "@" + s.CertC.Pin,
		"-cert", crt, "-key", key}
	return r
}

func (r *rig) run(args ...string) (string, error) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// sign is the operator's step: a file for one operation, signed one second after the last (the parties accept a signature once, and
// signatures of the same second are equal).
func (r *rig) sign(op, keyset string) string {
	r.t.Helper()
	time.Sleep(1100 * time.Millisecond)
	p := filepath.Join(r.dir, fmt.Sprintf("%s-%s-%d.json", op, keyset, time.Now().UnixNano()))
	if out, err := r.run("sign", "-key", r.opKey, "-op", op, "-keyset", keyset, "-out", p); err != nil {
		r.t.Fatalf("sign: %v\n%s", err, out)
	}
	return p
}

func (r *rig) send(op, authFile string, extra ...string) (string, error) {
	args := append([]string{op, "-auth", authFile}, r.callers...)
	return r.run(append(args, extra...)...)
}

func (r *rig) mustSend(op, keyset string, extra ...string) string {
	r.t.Helper()
	out, err := r.send(op, r.sign(op, keyset), extra...)
	if err != nil {
		r.t.Fatalf("%s %s: %v\n%s", op, keyset, err, out)
	}
	return out
}

func (r *rig) status(extra ...string) (string, error) {
	return r.run(append(append([]string{"status"}, r.callers...), extra...)...)
}

func wantIn(t *testing.T, out string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(out, p) {
			t.Fatalf("output lacks %q:\n%s", p, out)
		}
	}
}

// DKG, refresh, freeze, unfreeze: the whole ceremony through the CLI, sign and send apart.
func TestCeremony(t *testing.T) {
	r := newRig(t, mpcstack.Opts{Proxy: true})

	out := r.mustSend("dkg", "k1", "-scheme", "ecdsa-2of3")
	wantIn(t, out, "OK dkg: keyset k1 generation", "root_public_key: 0", "ecdsa-2of3")
	out = r.mustSend("dkg", "e1", "-scheme", "ed25519-2of3")
	wantIn(t, out, "OK dkg: keyset e1")
	out = r.mustSend("dkg", "h1", "-scheme", "hd", "-curve", "secp256k1")
	wantIn(t, out, "OK dkg: keyset h1")
	st, err := r.status()
	if err != nil {
		t.Fatalf("status: %v\n%s", err, st)
	}
	for _, p := range []string{"party A", "party B", "party C", "keyset k1", "keyset e1", "keyset h1", "frozen=false"} {
		wantIn(t, st, p)
	}

	out = r.mustSend("refresh", "k1")
	wantIn(t, out, "OK refresh: keyset k1 generation 2")

	// freeze: a corrupted message during a refresh makes the parties freeze the keyset themselves (there is no admin call that freezes)
	r.s.Proxy.Tamper(0, 3)
	bad, err := r.send("refresh", r.sign("refresh", "k1"))
	r.s.Proxy.Tamper(0, -1)
	if err == nil {
		t.Fatalf("a refresh over a tampered link succeeded:\n%s", bad)
	}
	deadline := time.Now().Add(60 * time.Second)
	for !(r.s.FrozenOn("A", "k1") && r.s.FrozenOn("B", "k1") && r.s.FrozenOn("C", "k1")) {
		if time.Now().After(deadline) {
			t.Fatalf("k1 did not freeze on all parties:\n%s\n%s", bad, st)
		}
		time.Sleep(time.Second)
	}
	// frozen: refresh is refused by the tool before any call, status shows it
	if out, err := r.send("refresh", r.sign("refresh", "k1")); err == nil || !strings.Contains(out, "is frozen") {
		t.Fatalf("refresh of a frozen keyset: %v\n%s", err, out)
	}
	st, _ = r.status("-keyset", "k1")
	wantIn(t, st, "frozen=true")

	out = r.mustSend("unfreeze", "k1")
	wantIn(t, out, "OK unfreeze: keyset k1 is not frozen on any of the 3 parties")
	if r.s.FrozenOn("A", "k1") || r.s.FrozenOn("B", "k1") || r.s.FrozenOn("C", "k1") {
		t.Fatal("still frozen")
	}
	// unfreezing what is not frozen, a second DKG of a name in use, a refresh of a keyset nobody has: refused before any call
	for _, c := range []struct{ op, keyset, want string }{{"unfreeze", "k1", "is not frozen"}, {"dkg", "k1", "already exists"}, {"refresh", "nope", "does not exist"}} {
		if out, err := r.send(c.op, r.sign(c.op, c.keyset)); err == nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %v\n%s", c.op, c.keyset, err, out)
		}
	}
}

// The parties refuse what is wrong with an authorisation, whatever the tool checks first. The tool's own window check is turned off (-window)
// where the party's must be the one that says no.
func TestPartiesRefuse(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	r.mustSend("dkg", "k2", "-scheme", "ecdsa-2of3")

	opPriv, err := admin.ReadKeyFile(r.opKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile := func(f admin.File) string {
		p := filepath.Join(r.dir, fmt.Sprintf("x-%d.json", time.Now().UnixNano()))
		if err := os.WriteFile(p, f.JSON(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// expired: signed 10 minutes ago
	old, _ := admin.NewFile(opPriv, "refresh", "k2", time.Now().Add(-10*time.Minute))
	if out, err := r.send("refresh", writeFile(old)); err == nil || !strings.Contains(out, "outside the") {
		t.Fatalf("tool did not refuse an expired file: %v\n%s", err, out)
	}
	out, err := r.send("refresh", writeFile(old), "-window", "24h")
	if err == nil || !strings.Contains(out, "outside the accepted window") {
		t.Fatalf("parties accepted an expired authorisation: %v\n%s", err, out)
	}

	// an operator key the parties do not know
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	sf, _ := admin.NewFile(stranger, "refresh", "k2", time.Now())
	if out, err := r.send("refresh", writeFile(sf)); err == nil || !strings.Contains(out, "not a configured admin key") {
		t.Fatalf("unknown operator key: %v\n%s", err, out)
	}

	// used once: the second send of the same file is refused by the parties
	time.Sleep(1100 * time.Millisecond)
	once := r.sign("refresh", "k2")
	if out, err := r.send("refresh", once); err != nil {
		t.Fatalf("first send: %v\n%s", err, out)
	}
	if out, err := r.send("refresh", once); err == nil || !strings.Contains(out, "signature already used") {
		t.Fatalf("reused authorisation: %v\n%s", err, out)
	}

	// Another operation or another keyset: the tool cannot send such a file (it calls what the file says), so call the party as a thief with a
	// caller certificate would.
	if err := wrongUse(r, "unfreeze", "k2", func(a *pb.AdminAuth) error { return callRefresh(r, "k2", a) }); err == nil {
		t.Fatal("an unfreeze authorisation was accepted for a refresh")
	}
	if err := wrongUse(r, "refresh", "k3", func(a *pb.AdminAuth) error { return callRefresh(r, "k2", a) }); err == nil {
		t.Fatal("an authorisation for keyset k3 was accepted for k2")
	}
	// and none of it changed the keyset: still generation 2 (one refresh), not frozen, all parties agree
	st, err := r.status("-keyset", "k2")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, st)
	}
	wantIn(t, st, "generation 2", "frozen=false")
}

func wrongUse(r *rig, op, keyset string, call func(*pb.AdminAuth) error) error {
	priv, _ := admin.ReadKeyFile(r.opKey)
	f, _ := admin.NewFile(priv, op, keyset, time.Now().Add(time.Duration(time.Now().UnixNano()%1000)*time.Millisecond))
	a, _ := f.Auth()
	return call(a)
}

func callRefresh(r *rig, keyset string, a *pb.AdminAuth) error {
	x, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := r.s.Client("A").Refresh(x, &pb.RefreshRequest{KeysetId: keyset, Admin: a})
	return err
}

// The tool refuses without a file, and when parties disagree or are away, before and after.
func TestLocalRefusalsAndDisagreement(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	r.mustSend("dkg", "k4", "-scheme", "ecdsa-2of3")

	if out, err := r.run(append([]string{"refresh"}, r.callers...)...); err == nil || !strings.Contains(out, "-auth is required") {
		t.Fatalf("send without a file: %v\n%s", err, out)
	}

	// C is away: status says so and fails; a refresh is refused before it uses the signature
	r.s.C.Stop()
	st, err := r.status()
	if err == nil || !strings.Contains(st+err.Error(), "party C") {
		t.Fatalf("status with C down: %v\n%s", err, st)
	}
	file := r.sign("refresh", "k4")
	if out, err := r.send("refresh", file); err == nil || !strings.Contains(out, "DISAGREE") {
		t.Fatalf("refresh with C down: %v\n%s", err, out)
	}
	// the file was not used up: with C back it works
	r.s.C.Start(t)
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := r.status(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("C did not come back")
		}
		time.Sleep(2 * time.Second)
	}
	if out, err := r.send("refresh", file); err != nil {
		t.Fatalf("refresh after C is back: %v\n%s", err, out)
	}
}
