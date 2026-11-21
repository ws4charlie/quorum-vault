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

	"google.golang.org/protobuf/proto"

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

// rig is a three-party stack, the three admins' key files (two of them sign) and the caller flags `send` needs.
type rig struct {
	t       *testing.T
	s       *mpcstack.Stack3
	dir     string
	opKeys  []string
	callers []string
	policy  []string // what `send` checks a file against before it contacts a party
}

func newRig(t *testing.T, o mpcstack.Opts) *rig {
	t.Helper()
	dir := t.TempDir()
	s := mpcstack.Start3(t, filepath.Join(dir, "stack"), bin, o)
	s.WaitReady(90 * time.Second)
	crt, key := s.CertGW.Write(t, dir)
	r := &rig{t: t, s: s, dir: dir}
	for i, pub := range s.Admins.PublicHex() {
		k := filepath.Join(dir, fmt.Sprintf("admin%d.key", i))
		if err := os.WriteFile(k, []byte(s.Admins.SeedHex(i)), 0o600); err != nil {
			t.Fatal(err)
		}
		r.opKeys = append(r.opKeys, k)
		r.policy = append(r.policy, "-admin-key", pub)
	}
	r.policy = append(r.policy, "-threshold", fmt.Sprint(mpcstack.AdminThreshold))
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

// request makes the request file of one operation (the first admin's machine) and has the admins in `by` sign it in turn (their machines), as the
// runbook says. The parties accept a file once; every call makes a new one.
func (r *rig) request(op, keyset string, by []int, reqArgs ...string) string {
	r.t.Helper()
	p := filepath.Join(r.dir, fmt.Sprintf("%s-%s-%d.json", op, keyset, time.Now().UnixNano()))
	if out, err := r.run(append([]string{"request", "-op", op, "-keyset", keyset, "-out", p}, reqArgs...)...); err != nil {
		r.t.Fatalf("request: %v\n%s", err, out)
	}
	for _, i := range by {
		if out, err := r.run("sign", "-key", r.opKeys[i], "-in", p); err != nil {
			r.t.Fatalf("sign by admin %d: %v\n%s", i, err, out)
		}
	}
	return p
}

// sign is a request for op signed by admins 0 and 2 (two of three).
func (r *rig) sign(op, keyset string, reqArgs ...string) string {
	r.t.Helper()
	return r.request(op, keyset, []int{0, 2}, reqArgs...)
}

func (r *rig) send(op, authFile string, extra ...string) (string, error) {
	args := append(append([]string{op, "-auth", authFile}, r.callers...), r.policy...)
	return r.run(append(args, extra...)...)
}

// mustSend signs and sends; for a dkg the scheme and curve flags go to both steps (the request holds them; the tool checks they match).
func (r *rig) mustSend(op, keyset string, extra ...string) string {
	r.t.Helper()
	var reqArgs []string
	if op == "dkg" {
		reqArgs = extra
	}
	out, err := r.send(op, r.sign(op, keyset, reqArgs...), extra...)
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

// The parties refuse what is wrong with an authorisation, whatever the tool checks first: a call made straight to party A (the way a thief with a caller
// certificate would) with a v2 authorization that is too short of signers, signed by a stranger, expired, used before, for another field, keyset or
// operation, or in the old v1 form. The tool's own checks refuse the first ones before any party is contacted (TestToolRefusesBeforeSending).
func TestPartiesRefuse(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	r.mustSend("dkg", "k2", "-scheme", "ecdsa-2of3")
	ad := r.s.Admins
	now := time.Now()
	valid := func(keys ...ed25519.PrivateKey) *pb.AdminAuth {
		a, err := admin.Authorize("refresh", &pb.RefreshRequest{KeysetId: "k2"}, "", now, now.Add(10*time.Minute), keys...)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		auth *pb.AdminAuth
		want string
	}{
		"one signer of two":  {valid(ad.Key(0)), "1 signature(s), 2 needed"},
		"the same key twice": {valid(ad.Key(1), ad.Key(1)), "twice"},
		"a stranger":         {valid(ad.Key(0), stranger), "not a configured admin key"},
		"the old v1 form":    {admin.Sign(ad.Key(0), "refresh", "k2", now), "no longer accepts the v1"},
	} {
		if err := callRefresh(r, "k2", c.auth); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
	old := time.Now().Add(-20 * time.Minute)
	expired, _ := admin.Authorize("refresh", &pb.RefreshRequest{KeysetId: "k2"}, "", old, old.Add(10*time.Minute), ad.Key(0), ad.Key(2))
	if err := callRefresh(r, "k2", expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired: %v", err)
	}
	// another keyset or operation than the one signed
	for name, a := range map[string]*pb.AdminAuth{
		"keyset k3":     mustAuth(t, "refresh", &pb.RefreshRequest{KeysetId: "k3"}, ad),
		"an unfreeze":   mustAuth(t, "unfreeze", &pb.UnfreezeRequest{KeysetId: "k2"}, ad),
		"another field": mustAuth(t, "dkg", &pb.DKGRequest{KeysetId: "k2", Scheme: pb.Scheme_SCHEME_ECDSA_2OF3}, ad),
	} {
		if err := callRefresh(r, "k2", a); err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Errorf("an authorisation for %s was accepted for a refresh of k2: %v", name, err)
		}
	}
	// a DKG signed for one scheme and sent with another
	x, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	signed := mustAuth(t, "dkg", &pb.DKGRequest{KeysetId: "k9", Scheme: pb.Scheme_SCHEME_ECDSA_2OF3}, ad)
	if _, err := r.s.Client("A").DKG(x, &pb.DKGRequest{KeysetId: "k9", Scheme: pb.Scheme_SCHEME_ED25519_2OF3, Admin: signed}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a DKG with a scheme that was not signed: %v", err)
	}

	// used once: the second send of the same file is refused by the parties
	once := r.sign("refresh", "k2")
	if out, err := r.send("refresh", once); err != nil {
		t.Fatalf("first send: %v\n%s", err, out)
	}
	if out, err := r.send("refresh", once); err == nil || !strings.Contains(out, "already used") {
		t.Fatalf("reused authorisation: %v\n%s", err, out)
	}
	// and none of it changed the keyset: still generation 2 (one refresh), not frozen, all parties agree
	st, err := r.status("-keyset", "k2")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, st)
	}
	wantIn(t, st, "generation 2", "frozen=false")
}

func mustAuth(t *testing.T, op string, body proto.Message, ad mpcstack.AdminSet) *pb.AdminAuth {
	t.Helper()
	now := time.Now()
	a, err := admin.Authorize(op, body, "", now, now.Add(10*time.Minute), ad.Key(0), ad.Key(2))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func callRefresh(r *rig, keyset string, a *pb.AdminAuth) error {
	x, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := r.s.Client("A").Refresh(x, &pb.RefreshRequest{KeysetId: keyset, Admin: a})
	return err
}

// The tool refuses, before it contacts any party, a file the parties would refuse: too few signatures, a signer they do not know, expired, the
// wrong domain, a scheme other than the file's. `verify` says the same without sending.
func TestToolRefusesBeforeSending(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	r.mustSend("dkg", "k5", "-scheme", "ecdsa-2of3")
	one := r.request("refresh", "k5", []int{1})
	if out, err := r.send("refresh", one); err == nil || !strings.Contains(out, "1 signature(s), 2 needed") || !strings.Contains(out, "nothing was sent") {
		t.Fatalf("one signature: %v\n%s", err, out)
	}
	if out, err := r.run(append([]string{"verify", "-in", one}, r.policy...)...); err == nil || !strings.Contains(out, "1 signature(s), 2 needed") {
		t.Fatalf("verify, one signature: %v\n%s", err, out)
	}
	if out, err := r.run(append([]string{"sign", "-key", r.opKeys[0], "-in", one}, "-out", one)...); err != nil {
		t.Fatalf("second signature: %v\n%s", err, out)
	}
	if out, err := r.run(append([]string{"verify", "-in", one}, r.policy...)...); err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("verify, two signatures: %v\n%s", err, out)
	}
	if out, err := r.send("refresh", one); err != nil {
		t.Fatalf("two signatures: %v\n%s", err, out)
	}
	// a stranger as the second signer
	strangerKey := filepath.Join(r.dir, "stranger.key")
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(strangerKey, []byte(fmt.Sprintf("%x", sk.Seed())), 0o600)
	bad := r.request("refresh", "k5", []int{1})
	if out, err := r.run("sign", "-key", strangerKey, "-in", bad); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := r.send("refresh", bad); err == nil || !strings.Contains(out, "not a configured admin key") {
		t.Fatalf("stranger: %v\n%s", err, out)
	}
	// the scheme in the flags is not the request's
	dk := r.sign("dkg", "k6", "-scheme", "ecdsa-2of3")
	if out, err := r.send("dkg", dk, "-scheme", "ed25519-2of3"); err == nil || !strings.Contains(out, "the file decides") {
		t.Fatalf("scheme: %v\n%s", err, out)
	}
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
