package btce2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Jobs written straight into the job table, as the business zone (or an attacker who owns it) could, to see what the zone's own rules say about each state of
// a generation. The outpoints are made up: the zone never reads the chain, and nothing is ever broadcast.

// treeAccount is the account the zone derives with once generation 2 is known: the system's xpub and the plan's.
func (s *system) treeAccount(xpub2 string) *btc.Account {
	s.t.Helper()
	a, err := btc.NewAccount("regtest", s.xpub)
	if err != nil {
		s.t.Fatal(err)
	}
	a.SetGenerationLoader(func(g uint32) (string, error) {
		if g == 2 {
			return xpub2, nil
		}
		return "", fmt.Errorf("no generation %d", g)
	})
	return a
}

// hostile writes one job (one input of 500000 sats at path under generation gen, one output) and returns its final status and reason.
func (s *system) hostileTreeJob(acct *btc.Account, id, kind string, gen uint32, path []uint32, from, to string) (string, string) {
	s.t.Helper()
	var tx [32]byte
	rand.Read(tx[:])
	in := btc.PayloadInput{TxID: hex.EncodeToString(tx[:]), Vout: 0, Value: 500_000, Path: path, Sequence: btc.SequenceRBF}
	if gen > 1 {
		in.Gen = gen
	}
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{in}, Outputs: []btc.PayloadOutput{{Address: to, Value: 499_000}}}
	amount := "500000"
	if kind == "withdrawal" { // from is the shard the change goes back to: a payment of 100000 and the rest as change
		p.Outputs = []btc.PayloadOutput{{Address: to, Value: 100_000}, {Address: from, Value: 399_000}}
		amount = "100000"
	}
	u, err := btc.BuildUnsigned(p, acct)
	if err != nil {
		s.t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	it := signjob.Intent{Kind: kind, ID: id, Chain: s.chain, PartitionID: s.part, Asset: "BTC", From: from, To: to, Amount: amount}
	if kind == "withdrawal" {
		it.From = ""
	}
	switch kind {
	case "withdrawal":
		it.RequestedBy = "initiator"
		it.NotAfter = time.Now().Add(10 * time.Minute).Unix()
	case signjob.KindDrain:
		it.NotAfter = time.Now().Add(10 * time.Minute).Unix()
	}
	ib, _ := json.Marshal(it)
	job := signjob.Job{ID: id, PartitionID: s.part, KeyRef: chain.KeyPathAt(int(gen), btc.PathString(path)), Chain: s.chain, Intent: ib, Digest: u.Digests[0], Payload: raw}
	if kind == "withdrawal" {
		h := it.Hash()
		job.Approvals = []signjob.Approval{{Actor: "alice", Signature: ed25519.Sign(s.approv["alice"], h[:])}}
	}
	t, err := s.pool.Begin(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := signjob.Enqueue(s.ctx, t, job); err != nil {
		t.Rollback(s.ctx)
		s.t.Fatal(err)
	}
	if err := t.Commit(s.ctx); err != nil {
		s.t.Fatal(err)
	}
	var status, reason string
	s.waitFor(90*time.Second, "the zone to decide on "+id, func() bool {
		s.pool.QueryRow(s.ctx, `SELECT status, COALESCE(reject_reason,'') FROM sign_jobs WHERE id=$1`, id).Scan(&status, &reason)
		return status == "done" || status == "rejected" || status == "failed"
	})
	return status, reason
}

func (s *system) mustRefuseHostile(acct *btc.Account, id, kind string, gen uint32, path []uint32, from, to, why string) {
	s.t.Helper()
	status, reason := s.hostileTreeJob(acct, id, kind, gen, path, from, to)
	if status == "done" {
		s.t.Fatalf("the zone SIGNED %s (%s, generation %d)", id, kind, gen)
	}
	if !strings.Contains(reason, why) {
		s.t.Fatalf("%s: status %s reason %q, want it to contain %q", id, status, reason, why)
	}
}

func (s *system) mustSignHostile(acct *btc.Account, id, kind string, gen uint32, path []uint32, from, to string) {
	s.t.Helper()
	if status, reason := s.hostileTreeJob(acct, id, kind, gen, path, from, to); status != "done" {
		s.t.Fatalf("the zone refused %s (%s, generation %d): %s %s", id, kind, gen, status, reason)
	}
}

// startReplacement runs open, dkg and candidate (generation 2 as a candidate) and returns the plan's identity.
func (s *system) startReplacement(dir string, ops map[string]ed25519.PrivateKey) (keyRef, xpub2 string) {
	s.t.Helper()
	s.rekeyMust(dir, "open", "-shard", s.treeID(), "-mode", "mpc", "-reason", "e2e")
	keyset := strings.Trim(slugTree.ReplaceAllString(strings.ToLower(s.treeID()), "-"), "-") + "-g2"
	s.rekeyMust(dir, "dkg", "-admin-auth", s.partyAuthFor(keyset))
	var plan struct {
		KeyRef    string `json:"key_ref"`
		PublicKey string `json:"public_key"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		s.t.Fatal(err)
	}
	if err := json.Unmarshal(b, &plan); err != nil {
		s.t.Fatal(err)
	}
	s.rekeyMust(dir, "candidate", "-change", s.treeChange("cand", 1, "-action", "register-candidate", "-generation", "2", "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey))
	return plan.KeyRef, plan.PublicKey
}

// A compromised generation: the emergency order (drain-start -compromised). The zone signs only sweeps and drains to the successor from it, never a
// withdrawal, never a sweep to its own hot shard, and it is never retired.
func TestRekeyCompromisedGenerationOnlySweepsAndDrainsToTheSuccessor(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, sweep: true, minSweep: "1000000", feeCaps: &feeCapsOpts{operators: 3}})
	stop := s.keepMining()
	defer func() { stop() }()
	s.fundHot(60_000_000)
	dir := filepath.Join(s.dir, "rekey")
	_, xpub2 := s.startReplacement(dir, s.ops)
	acct := s.treeAccount(xpub2)
	hot1, _ := acct.Address([]uint32{1, 0})
	hot2, _ := acct.AddressAt(2, []uint32{1, 0})
	dep1, _ := acct.Address([]uint32{0, 9})
	if hot1 != s.hotAddr {
		t.Fatalf("hot shard %s, want %s", hot1, s.hotAddr)
	}
	s.rekeyMust(dir, "drain-start", "-compromised", "-cap", "BTC=80000000",
		"-change", s.treeChange("comp", 2, "-action", "mark-compromised", "-generation", "1", "-successor", "2", "-cap", "BTC=80000000"))
	s.rekeyMust(dir, "activate", "-change", s.treeChange("act", 3, "-action", "activate", "-generation", "2"))

	// What the compromised generation may still sign: a sweep to the successor's hot shard. What it may not: a withdrawal, a sweep to its own shard.
	s.mustSignHostile(acct, "h-sweep-ok", "sweep", 1, []uint32{0, 9}, dep1, hot2)
	s.mustRefuseHostile(acct, "h-sweep-own", "sweep", 1, []uint32{0, 9}, dep1, hot1, "successor")
	s.mustRefuseHostile(acct, "h-wd", "withdrawal", 1, []uint32{1, 0}, hot1, s.node.fresh(), "compromised")

	// The real drain runs to the end, and the tool never retires a compromised generation.
	s.waitFor(240*time.Second, "the compromised hot shard is drained", func() bool {
		g := s.treeKeysets()
		d, _ := g[0]["drain"].(map[string]any)
		return len(g) == 2 && g[0]["state"] == "compromised" && d != nil && d["state"] == "drained"
	})
	if left := s.hotUnder("1/0"); left > 1000 {
		t.Fatalf("%d sats left under the compromised hot shard", left)
	}
	stop()
	s.reconcileClean()
	stop = s.keepMining()
	if out, err := s.rekeyTool(dir, "retire", "-change", s.treeChange("ret", 4, "-action", "retire", "-generation", "1")); err == nil || !strings.Contains(out, "compromised") {
		t.Fatalf("retire of a compromised generation: %v\n%s", err, out)
	}
}
