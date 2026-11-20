package sole2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/idp"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// A replacement of the Solana deposit node (K6) driven by qv-rekey on the real binaries: a second Ed25519 HD keyset on the parties, operator-signed records
// in the gateway's and both cosigners' guard databases. Deposits to old and new addresses are credited and swept, the old ones with the old key and the new
// ones with the new key, into the same hot shard; retire waits for the signed window and for the old addresses to be empty. The hot shard is not replaced here (K4).
// (Not run locally: the local validator of the machine that wrote it does not finalize slots; CI runs it.)

var slugSol = regexp.MustCompile(`[^a-z0-9]+`)

func (s *wdSys) treeID() string { return "qv-us/" + s.chain + "/deposit-tree/0" }

func (s *wdSys) opKey(name string, priv ed25519.PrivateKey) string {
	p := filepath.Join(s.dir, name+".key")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

func (s *wdSys) rekeyTool(dir string, args ...string) (string, error) {
	tok := filepath.Join(s.dir, "admin.token")
	if err := os.WriteFile(tok, []byte(strings.TrimPrefix(idp.Bearer("ops"), "Bearer ")), 0o600); err != nil {
		s.t.Fatal(err)
	}
	base := []string{args[0], "-dir", dir, "-config", s.gwPath, "-guard-dsn", "gateway=" + s.guard, "-guard-dsn", "cosigner-b=" + s.cosGuards[0], "-guard-dsn", "cosigner-c=" + s.cosGuards[1],
		"-core", s.apiURL, "-core-ca", filepath.Join(pkitest.Root(), pki.ZoneBusiness, "ca.crt"), "-token-file", tok}
	out, err := exec.Command(filepath.Join(binDir, "qv-rekey"), append(base, args[1:]...)...).CombinedOutput()
	return string(out), err
}

func (s *wdSys) rekeyMust(dir string, args ...string) string {
	s.t.Helper()
	out, err := s.rekeyTool(dir, args...)
	if err != nil {
		s.t.Fatalf("qv-rekey %v: %v\n%s", args, err, out)
	}
	return out
}

func (s *wdSys) treeChange(ops map[string]ed25519.PrivateKey, name string, seq int, args ...string) string {
	s.t.Helper()
	bin := filepath.Join(binDir, "qv-keysets")
	f := filepath.Join(s.dir, "tree-"+name+".json")
	run := func(a ...string) {
		s.t.Helper()
		if out, err := exec.Command(bin, a...).CombinedOutput(); err != nil {
			s.t.Fatalf("qv-keysets %v: %v\n%s", a, err, out)
		}
	}
	run(append([]string{"sign", "-seq", fmt.Sprint(seq), "-shard", s.treeID(), "-operator", "op1", "-key", s.opKey("op1", ops["op1"]), "-out", f}, args...)...)
	run("sign", "-operator", "op2", "-key", s.opKey("op2", ops["op2"]), "-join", f, "-out", f)
	return f
}

func (s *wdSys) partyAuthFor(keyset string) string {
	key := filepath.Join(s.dir, "party-admin.key")
	if err := os.WriteFile(key, []byte(s.m3.AdminSeedHex()), 0o600); err != nil {
		s.t.Fatal(err)
	}
	f := filepath.Join(s.dir, "party-auth.json")
	if out, err := exec.Command(filepath.Join(binDir, "qv-keysets"), "party-auth", "-key", key, "-op", "dkg", "-keyset", keyset, "-out", f).CombinedOutput(); err != nil {
		s.t.Fatalf("party-auth: %v\n%s", err, out)
	}
	return f
}

func (s *wdSys) keyRefs() []string {
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

func (s *wdSys) treeStates() map[int]string {
	rows, err := s.pool.Query(s.ctx, `SELECT generation, state FROM keysets WHERE shard_id=$1`, s.treeID())
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var g int
		var st string
		if err := rows.Scan(&g, &st); err != nil {
			s.t.Fatal(err)
		}
		out[g] = st
	}
	return out
}

func TestSwFlowsDepositKeyReplacementDrivenByTheTool(t *testing.T) {
	ops := map[string]ed25519.PrivateKey{}
	s := newWdSystem(t, wdOpts{minSweep: "5000000", batch: 3, gwTweak: func(gf *gateway.File) {
		gf.Operators = &gateway.OperatorsFile{Keys: map[string]gateway.OperatorFile{}, MinOperators: 2}
		for _, n := range []string{"op1", "op2", "op3"} {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			ops[n] = priv
			gf.Operators.Keys[n] = gateway.OperatorFile{PublicKey: hex.EncodeToString(pub)}
		}
	}})
	old := s.depositAddr("c1")
	s.paySOL(old, 2*oneSOL)
	s.waitDeposits("c1", 2*oneSOL, 0)
	s.waitSwept("generation 1 swept before the replacement", "SOL", old)
	s.reconcileClean("before the replacement")

	// open, DKG of a second Ed25519 HD keyset on the parties, candidate
	dir := filepath.Join(s.dir, "rekey")
	s.rekeyMust(dir, "open", "-shard", s.treeID(), "-mode", "mpc", "-reason", "e2e")
	keyset := strings.Trim(slugSol.ReplaceAllString(strings.ToLower(s.treeID()), "-"), "-") + "-g2"
	s.rekeyMust(dir, "dkg", "-admin-auth", s.partyAuthFor(keyset))
	var plan struct {
		KeyRef    string `json:"key_ref"`
		PublicKey string `json:"public_key"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &plan); err != nil || plan.KeyRef != keyset || strings.Count(plan.PublicKey, ":") != 1 {
		t.Fatalf("plan %+v (%v)", plan, err)
	}
	s.rekeyMust(dir, "candidate", "-change", s.treeChange(ops, "cand", 1, "-action", "register-candidate", "-generation", "2", "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey))
	if st := s.treeStates(); st[2] != "candidate" {
		t.Fatalf("tree %v", st)
	}
	s.rekeyMust(dir, "drain-start", "-window", "60", "-change", s.treeChange(ops, "drain", 2, "-action", "start-draining", "-generation", "1", "-successor", "2", "-window", "60"))
	s.rekeyMust(dir, "activate", "-change", s.treeChange(ops, "act", 3, "-action", "activate", "-generation", "2"))
	s.restartWorker() // the worker dies in the middle of the replacement

	// generation 2 addresses; deposits to old and new are credited and swept: the old with the old key, the new with the new key, to the same hot shard
	fresh := s.depositAddr("c2")
	again := s.depositAddressOf("c1")
	cur, _ := again["address"].(string)
	if again["generation"] != float64(2) || cur == old || fresh == old {
		t.Fatalf("after the replacement: old %s, c1 %v, c2 %s", old, again, fresh)
	}
	s.paySOL(old, 3*oneSOL)
	s.paySOL(cur, 6*oneSOL)
	s.paySOL(fresh, 7*oneSOL)
	s.waitDeposits("c1", 2*oneSOL+3*oneSOL+6*oneSOL, 0)
	s.waitDeposits("c2", 7*oneSOL, 0)
	s.waitSwept("old and new addresses swept", "SOL", old, cur, fresh)
	var g1, g2 int
	for _, r := range s.keyRefs() {
		switch {
		case strings.HasPrefix(r, "g2/d/"):
			g2++
		case strings.HasPrefix(r, "d/"):
			g1++
		}
	}
	if g1 < 2 || g2 < 2 {
		t.Fatalf("keys of the sweeps: %d under generation 1, %d under generation 2 (%v)", g1, g2, s.keyRefs())
	}
	s.reconcileClean("with two deposit key generations")

	// retire: refused inside the window; after it, with the old addresses empty, it goes through
	early := s.treeChange(ops, "ret-early", 4, "-action", "retire", "-generation", "1")
	if out, err := s.rekeyTool(dir, "retire", "-change", early); err == nil || !strings.Contains(out, "stay swept until") {
		t.Fatalf("retire inside the window: %v\n%s", err, out)
	}
	s.waitFor(2*time.Minute, "the window has passed", func() bool {
		var n int
		_ = s.pool.QueryRow(context.Background(), `SELECT count(*) FROM keysets WHERE shard_id=$1 AND generation=1 AND state_changed_at < now() - interval '65 seconds'`, s.treeID()).Scan(&n)
		return n == 1
	})
	s.rekeyMust(dir, "retire", "-change", s.treeChange(ops, "ret", 4, "-action", "retire", "-generation", "1"))
	if st := s.treeStates(); st[1] != "retired" {
		t.Fatalf("tree %v", st)
	}
	_ = pb.Curve_CURVE_ED25519
	s.reconcileClean("after the retirement")
}
