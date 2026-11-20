package btce2e

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/idp"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// A whole replacement of the Bitcoin account key (K6), driven by qv-rekey on the real binaries: the parties make a second 2-party HD keyset, two operators
// sign the zone's records, the gateway and the cosigner judge by them. Deposits to old and new addresses are credited; the old addresses are swept with the
// old key to the NEW hot shard, the new ones with the new key; the old hot shard is drained into the new one; withdrawals go out from the new hot shard;
// Reconcile is clean at every step; the worker is killed in the middle of the drain.

var slugTree = regexp.MustCompile(`[^a-z0-9]+`)

func (s *system) treeID() string { return "qv-us/" + s.chain + "/deposit-tree/0" }

func (s *system) rekeyTool(dir string, args ...string) (string, error) {
	s.t.Helper()
	tok := filepath.Join(s.dir, "admin.token")
	if err := os.WriteFile(tok, []byte(strings.TrimPrefix(idp.Bearer("ops"), "Bearer ")), 0o600); err != nil { // a fresh login: the routes need step-up
		s.t.Fatal(err)
	}
	base := []string{args[0], "-dir", dir, "-config", s.gwPath, "-guard-dsn", "gateway=" + s.gwGuard, "-guard-dsn", "cosigner-b=" + s.cosGuard,
		"-core", s.apiURL, "-core-ca", filepath.Join(pkitest.Root(), pki.ZoneBusiness, "ca.crt"), "-token-file", tok}
	cmd := exec.Command(filepath.Join(binDir, "qv-rekey"), append(base, args[1:]...)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *system) rekeyMust(dir string, args ...string) string {
	s.t.Helper()
	out, err := s.rekeyTool(dir, args...)
	if err != nil {
		s.t.Fatalf("qv-rekey %v: %v\n%s", args, err, out)
	}
	return out
}

// treeChange makes the zone's record the way two operators do offline and returns the joined file.
func (s *system) treeChange(name string, seq int, args ...string) string {
	s.t.Helper()
	bin := filepath.Join(binDir, "qv-keysets")
	f := filepath.Join(s.dir, "tree-"+name+".json")
	run := func(a ...string) {
		s.t.Helper()
		if out, err := exec.Command(bin, a...).CombinedOutput(); err != nil {
			s.t.Fatalf("qv-keysets %v: %v\n%s", a, err, out)
		}
	}
	run(append([]string{"sign", "-seq", fmt.Sprint(seq), "-shard", s.treeID(), "-operator", "op1", "-key", s.keyFile("op1", s.ops["op1"]), "-out", f}, args...)...)
	run("sign", "-operator", "op2", "-key", s.keyFile("op2", s.ops["op2"]), "-join", f, "-out", f)
	return f
}

// partyAuthFor is the admins' authorisation of the DKG on the parties (a v2 request signed by two of the three admin keys), made right before it is used.
func (s *system) partyAuthFor(keyset string) string {
	s.t.Helper()
	return s.mpc.Admins.DKGRequestFile(s.t, s.dir, keyset, pb.Scheme_SCHEME_UNSPECIFIED, pb.Curve_CURVE_SECP256K1)
}

func (s *system) treeKeysets() []map[string]any {
	s.t.Helper()
	code, out := s.call("GET", "/v2/keysets", nil)
	if code != 200 {
		s.t.Fatalf("GET /v2/keysets: %d %v", code, out)
	}
	var res []map[string]any
	if l, ok := out["keysets"].([]any); ok {
		for _, e := range l {
			if m, ok := e.(map[string]any); ok && m["shard_id"] == s.treeID() {
				res = append(res, m)
			}
		}
	}
	return res
}

// keyRefsOfJobs lists the key references the gateway was asked to sign under, oldest first.
func (s *system) keyRefsOfJobs() []string {
	rows, err := s.pool.Query(s.ctx, `SELECT key_ref FROM sign_jobs WHERE chain=$1 ORDER BY created_at, id`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

func (s *system) hotUnder(path string) int64 {
	var v int64
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(SUM(value),0) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND status IN ('available','reserved') AND path=$2`, s.chain, path).Scan(&v); err != nil {
		s.t.Fatal(err)
	}
	return v
}

func TestRekeyDepositKeyReplacementDrivenByTheTool(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, sweep: true, minSweep: "1000000", feeCaps: &feeCapsOpts{operators: 3}})
	stop := s.keepMining()
	defer func() { stop() }()
	// Reconcile compares the books with the chain at a pinned height: it needs the chain to stand still for a moment, so the miner stops around it.
	clean := func() {
		t.Helper()
		stop()
		s.reconcileClean()
		stop = s.keepMining()
	}
	s.fundHot(60_000_000)

	// Before: a deposit to a generation 1 address is swept to the hot shard, with the configured key.
	s.deposit("c1", 5_000_000)
	s.untilSweepsConfirmed(1, 120*time.Second)
	old1 := s.addressOf("c1")
	clean()
	if g := s.treeKeysets(); len(g) != 1 || g[0]["state"] != "active" {
		t.Fatalf("the tree before: %v", g)
	}

	// Open, make the key (a DKG on the parties), register the candidate in the zone and the core.
	dir := filepath.Join(s.dir, "rekey")
	s.rekeyMust(dir, "open", "-shard", s.treeID(), "-mode", "mpc", "-reason", "e2e")
	keyset := strings.Trim(slugTree.ReplaceAllString(strings.ToLower(s.treeID()), "-"), "-") + "-g2"
	s.rekeyMust(dir, "dkg", "-admin-auth", s.partyAuthFor(keyset))
	var plan struct {
		KeyRef    string `json:"key_ref"`
		PublicKey string `json:"public_key"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &plan); err != nil || plan.KeyRef != keyset || !strings.HasPrefix(plan.PublicKey, "tpub") && !strings.HasPrefix(plan.PublicKey, "vpub") && !strings.HasPrefix(plan.PublicKey, "xpub") {
		t.Fatalf("plan %+v (%v)", plan, err)
	}
	if out := s.rekeyMust(dir, "candidate"); !strings.Contains(out, "qv-keysets sign") {
		t.Fatalf("candidate without a record should say what to sign:\n%s", out)
	}
	s.rekeyMust(dir, "candidate", "-change", s.treeChange("cand", 1, "-action", "register-candidate", "-generation", "2", "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey))
	if g := s.treeKeysets(); len(g) != 2 || g[1]["state"] != "candidate" {
		t.Fatalf("the tree with a candidate: %v", g)
	}
	// Nothing changed for customers: a candidate gets no address, and a generation 1 deposit is swept as before.
	if got := s.depositAddressOf("c1"); got["generation"] != float64(1) {
		t.Fatalf("a candidate served an address: %v", got)
	}
	clean()

	acct := s.treeAccount(plan.PublicKey)
	hot1, _ := acct.Address([]uint32{1, 0})
	hot2, _ := acct.AddressAt(2, []uint32{1, 0})
	dep2, _ := acct.AddressAt(2, []uint32{0, 7})
	// A candidate signs nothing: a job from generation 2 is refused by the zone, whatever it pays.
	s.mustRefuseHostile(acct, "h-cand", "sweep", 2, []uint32{0, 7}, dep2, hot2, "candidate")

	// A withdrawal is asked for while the old key drains and no key is active: it waits, then goes out from the NEW hot shard.
	dest := s.node.fresh()
	s.rekeyMust(dir, "drain-start", "-cap", "BTC=80000000", "-window", "90",
		"-change", s.treeChange("drain", 2, "-action", "start-draining", "-generation", "1", "-successor", "2", "-cap", "BTC=80000000", "-window", "90"))
	w := s.withdraw("ini", "w-during", "c1", dest, 1_000_000)
	s.holds(3*time.Second, "the withdrawal waits while no key is active", func() bool {
		st := s.getWd(w.ID).Status
		return st != "broadcast" && st != "confirmed" && st != "failed"
	})
	// The old generation is draining: no withdrawal from it, whatever the approvals.
	s.mustRefuseHostile(acct, "h-drain-wd", "withdrawal", 1, []uint32{1, 0}, hot1, s.node.fresh(), "draining")
	s.rekeyMust(dir, "activate", "-change", s.treeChange("act", 3, "-action", "activate", "-generation", "2"))
	s.restartWorker() // the worker dies in the middle of the replacement
	s.gateway.stop()  // and so does the gateway: it starts again from its own guard database and finds the same records
	s.startGateway()
	s.waitFor(180*time.Second, "the waiting withdrawal confirms", func() bool { return s.getWd(w.ID).Status == "confirmed" })
	if got := s.hotUnder("g2/1/0"); got == 0 {
		t.Fatalf("no hot output under generation 2 after a withdrawal from the new shard (rows %v)", s.keyRefsOfJobs())
	}

	// New customers and customers who ask again get generation 2 addresses; deposits to old and new are credited.
	fresh := s.newCustomer("c2")
	again := s.depositAddressOf("c1")
	if again["generation"] != float64(2) || again["address"] == old1 {
		t.Fatalf("after the replacement: %v", again)
	}
	s.node.pay(map[string]string{old1: btcAmount(6_000_000), again["address"].(string): btcAmount(7_000_000), fresh: btcAmount(8_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("c2", 8_000_000, 90*time.Second)
	s.untilSweepsConfirmed(4, 180*time.Second) // the first one, and these three
	refs := s.keyRefsOfJobs()
	var g2 int
	for _, r := range refs {
		if strings.HasPrefix(r, "g2/0/") {
			g2++
		}
	}
	if g2 < 2 {
		t.Fatalf("the generation 2 addresses were not signed under generation 2 keys: %v", refs)
	}
	// Every coin the sweeps brought is on the new hot shard.
	s.waitFor(60*time.Second, "sweeps land under the new hot shard", func() bool { return s.hotUnder("g2/1/0") >= 6_000_000+7_000_000+8_000_000 })

	// The old hot shard drains into the new one.
	s.waitFor(240*time.Second, "the old hot shard is drained", func() bool {
		g := s.treeKeysets()
		d, _ := g[0]["drain"].(map[string]any)
		return len(g) == 2 && d != nil && d["state"] == "drained"
	})
	if left := s.hotUnder("1/0"); left > 1000 {
		t.Fatalf("%d sats left under the old hot shard", left)
	}
	clean()

	// Retire waits for the window: inside it the tool refuses; after it (and with nothing left to sweep) it goes through.
	early := s.treeChange("ret-early", 4, "-action", "retire", "-generation", "1")
	if out, err := s.rekeyTool(dir, "retire", "-change", early); err == nil || !strings.Contains(out, "stay swept until") {
		t.Fatalf("retire inside the window: %v\n%s", err, out)
	}
	s.waitFor(2*time.Minute, "the window has passed", func() bool {
		var n int
		_ = s.pool.QueryRow(s.ctx, `SELECT count(*) FROM keysets WHERE shard_id=$1 AND generation=1 AND state_changed_at < now() - interval '95 seconds'`, s.treeID()).Scan(&n)
		return n == 1
	})
	s.rekeyMust(dir, "retire", "-change", s.treeChange("ret", 4, "-action", "retire", "-generation", "1"))
	if g := s.treeKeysets(); g[0]["state"] != "retired" {
		t.Fatalf("after retire: %v", g)
	}
	// Retired: nothing of generation 1 signs, to any address.
	dep1, _ := acct.Address([]uint32{0, 9})
	s.mustRefuseHostile(acct, "h-ret-sweep", "sweep", 1, []uint32{0, 9}, dep1, hot2, "retired")
	s.mustRefuseHostile(acct, "h-ret-wd", "withdrawal", 1, []uint32{1, 0}, hot1, s.node.fresh(), "retired")
	clean()
	_ = hex.EncodeToString
}
