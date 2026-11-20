package btce2e

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// secondDepositXpub is the deposit key of generation 2 in these tests: a fixed software account key, whose public half is all the core needs to derive
// and watch addresses. (The signing zone pins generation 1's key until K6 teaches it later generations, so a generation-2 address cannot be swept here.)
func secondDepositXpub(t *testing.T) string { return secondDepositXpubOf(t, 0x5a) }

// secondDepositXpubOf is that key for a seed byte: tests of one group share the node, so each uses its own key and never meets another's coins.
func secondDepositXpubOf(t *testing.T, seed byte) string {
	t.Helper()
	m, err := hdkeychain.NewMaster(bytes.Repeat([]byte{seed}, 32), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	k := m
	for _, n := range []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart} {
		if k, err = k.Derive(n); err != nil {
			t.Fatal(err)
		}
	}
	p, err := k.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	return p.String()
}

// rotateDepositKey registers generation 2 of the chain's deposit tree and makes it the active one, as K6's operator flow will (generation 1 drains).
func (s *system) rotateDepositKey(xpub string) {
	s.t.Helper()
	id, err := partition.DepositTreeID("qv-us", s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	tx, err := s.pool.Begin(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer tx.Rollback(s.ctx)
	if _, err := partition.RegisterCandidate(s.ctx, tx, "e2e", id, xpub, "", nil); err != nil {
		s.t.Fatal(err)
	}
	if _, err := partition.StartDraining(s.ctx, tx, "e2e", id, 1); err != nil {
		s.t.Fatal(err)
	}
	if _, err := partition.Activate(s.ctx, tx, "e2e", id, 2); err != nil {
		s.t.Fatal(err)
	}
	if err := tx.Commit(s.ctx); err != nil {
		s.t.Fatal(err)
	}
}

// depositAddressOf asks for the customer's address and returns the whole answer.
func (s *system) depositAddressOf(customer string) map[string]any {
	s.t.Helper()
	code, out := s.call("POST", "/v2/customers/"+customer+"/deposit-addresses", map[string]any{"chain": s.chain})
	if code != 200 {
		s.t.Fatalf("deposit address of %s: %d %v", customer, code, out)
	}
	return out
}

// olderOf lists the older watched addresses an answer carries.
func olderOf(out map[string]any) []string {
	var r []string
	if l, ok := out["older_addresses"].([]any); ok {
		for _, e := range l {
			r = append(r, e.(map[string]any)["address"].(string))
		}
	}
	return r
}

func (s *system) reconcileCleanDeposits() {
	s.t.Helper()
	s.waitFor(90*time.Second, "Reconcile is clean with the deposit comparison run", func() bool {
		r := s.reconcile()
		return r.Clean && r.has("deposit_addresses")
	})
}

// A key replacement leaves every deposit address working: a new customer gets a generation-2 address, a customer who asks again gets one beside the old, and
// deposits to all of them are credited to the right customer, with Reconcile clean.
func TestDepositAddressesOfTwoKeyGenerations(t *testing.T) {
	s := newSystem(t, opts{})
	old := s.newCustomer("g1")
	first := s.depositAddressOf("g1")
	if first["generation"] != float64(1) || olderOf(first) != nil {
		t.Fatalf("before the replacement: %v", first)
	}
	s.node.pay(map[string]string{old: btcAmount(1_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("g1", 1_000_000, 60*time.Second)

	s.rotateDepositKey(secondDepositXpub(t))

	fresh := s.newCustomer("g2") // a new customer: generation 2
	again := s.depositAddressOf("g1")
	if again["generation"] != float64(2) || again["address"] == old || fresh == old || fresh == again["address"] {
		t.Fatalf("after the replacement: old %s, g1 %v, g2 %s", old, again, fresh)
	}
	if o := olderOf(again); len(o) != 1 || o[0] != old {
		t.Fatalf("the old address is not offered as an older one: %v", again)
	}
	if got := s.depositAddressOf("g1"); got["address"] != again["address"] { // asking twice changes nothing
		t.Fatalf("asked twice: %v then %v", again, got)
	}
	if !strings.HasPrefix(fresh, "bcrt1q") {
		t.Fatalf("generation 2 address %q", fresh)
	}

	// a deposit to the old address after the replacement, one to g1's new address, one to the other customer's
	s.node.pay(map[string]string{old: btcAmount(2_000_000)})
	s.node.pay(map[string]string{again["address"].(string): btcAmount(3_000_000)})
	s.node.pay(map[string]string{fresh: btcAmount(4_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("g1", 1_000_000+2_000_000+3_000_000, 60*time.Second)
	s.waitAvailable("g2", 4_000_000, 60*time.Second)
	if n := s.count(`SELECT count(*) FROM deposit_addresses WHERE chain=$1 AND generation=2`, s.chain); n != 2 {
		t.Fatalf("%d generation 2 addresses", n)
	}
	s.reconcileCleanDeposits()
}

// A generation the signing zone has no signed record for (here: registered in the core only) cannot be swept, and that must fail safe, for the old
// address too (the core now pays the new generation's hot shard, which the zone does not know): the deposits are credited, the zone refuses the sweeps with
// a reason, the outputs are released and visible to Reconcile (clean), the generation 2 address raises one ALERT and is left alone with a back-off instead of
// being retried in a storm. The state-rule versions (candidate, draining, retired, compromised) and the full replacement are in
// TestRekeyDepositKeyReplacementDrivenByTheTool and the gateway's deposit_rekey_test.go.
func TestSweepOfAGenerationTheZoneDoesNotKnowIsRefusedSafely(t *testing.T) {
	s := sweepSystem(t, opts{retryAfter: "20s"}, 0)
	stop := s.keepMining()
	defer stop()
	old := s.newCustomer("g1")
	s.rotateDepositKey(secondDepositXpubOf(t, 0x6b))
	cur := s.depositAddressOf("g1")["address"].(string)
	before := s.onChain(cur)
	s.node.pay(map[string]string{old: btcAmount(20_000_000), cur: btcAmount(30_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("g1", 50_000_000, 60*time.Second)

	s.waitFor(120*time.Second, "both sweeps refused", func() bool {
		var a, b bool
		for _, w := range s.sweepRows() {
			a = a || (w.From == old && w.Status == "failed")
			b = b || (w.From == cur && w.Status == "failed")
		}
		return a && b
	})
	s.node.mine(1, "")
	for _, w := range s.sweepRows() {
		if w.Status == "failed" && w.Reason == "" {
			t.Fatalf("the refused sweep %s has no reason", w.ID)
		}
	}
	for _, a := range []string{old, cur} {
		if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND address=$2 AND status='available'`, s.chain, a); n != 1 {
			t.Fatalf("%d available outputs at %s", n, a)
		}
	}
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE chain=$1 AND status='done' AND created_at > now() - interval '1 hour' AND key_ref LIKE 'g%'`, s.chain); n != 0 {
		t.Fatalf("%d jobs of a later generation were signed", n)
	}
	if got := s.onChain(cur); got != before+30_000_000 {
		t.Fatalf("the generation 2 address holds %d", got)
	}
	s.reconcileClean()
	var alerts int
	b, _ := os.ReadFile(s.worker.log)
	bc, _ := os.ReadFile(s.core.log)
	for _, l := range strings.Split(string(b)+string(bc), "\n") {
		if strings.Contains(l, "refused the sweep of a deposit address of a later key generation") {
			alerts++
		}
	}
	if alerts == 0 {
		t.Fatal("no ALERT for the refused sweep of a later generation")
	}
}
