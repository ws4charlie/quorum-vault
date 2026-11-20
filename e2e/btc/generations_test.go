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

// An address of the old generation is still swept, with the old key, after the replacement: the zone signs it as ever, the full amount reaches the hot
// shard, the customer keeps the balance, and the generation-2 address of the same customer holds its deposit below the sweep floor, credited.
func TestSweepOfAnOldGenerationAddressAfterTheReplacement(t *testing.T) {
	s := sweepSystem(t, opts{minSweep: "5000000"}, 0)
	old := s.newCustomer("g1")
	s.rotateDepositKey(secondDepositXpub(t))
	cur := s.depositAddressOf("g1")["address"].(string)
	if cur == old {
		t.Fatal("no generation 2 address")
	}
	s.node.pay(map[string]string{old: btcAmount(30_000_000), cur: btcAmount(1_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("g1", 31_000_000, 60*time.Second)
	s.untilSweepsConfirmed(1, 120*time.Second)
	sw := s.sweepRows()
	if len(sw) != 1 || sw[0].From != old || sw[0].Moved != 30_000_000 || sw[0].Inputs != 1 {
		t.Fatalf("sweeps %+v", sw)
	}
	var kr string
	if err := s.pool.QueryRow(s.ctx, `SELECT key_ref FROM sign_jobs WHERE chain=$1 ORDER BY created_at LIMIT 1`, s.chain).Scan(&kr); err != nil || strings.HasPrefix(kr, "g") {
		t.Fatalf("the sweep of a generation 1 address was signed under key %q (%v)", kr, err)
	}
	if got := s.onChain(cur); got != 1_000_000 {
		t.Fatalf("the generation 2 address holds %d", got)
	}
	s.reconcileClean()
}

// A generation-2 deposit cannot be swept before K6 (the signing zone pins generation 1's key), and that must fail safe: the deposit is credited, the zone refuses
// the sweep with a reason, the outputs are released and visible to Reconcile (clean), the address is left alone with a growing back-off instead of being retried
// in a storm, and generation-1 sweeps go on, before and after.
func TestSweepOfASecondGenerationAddressIsRefusedSafely(t *testing.T) {
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

	// the old address is swept; the generation-2 address's sweep fails with a reason
	s.waitFor(120*time.Second, "generation 1 swept and generation 2 refused", func() bool {
		var ok, bad bool
		for _, w := range s.sweepRows() {
			ok = ok || (w.From == old && w.Status == "confirmed")
			bad = bad || (w.From == cur && w.Status == "failed")
		}
		return ok && bad
	})
	s.node.mine(1, "")
	var reason string
	for _, w := range s.sweepRows() {
		if w.From == cur {
			reason = w.Reason
		}
	}
	t.Logf("generation 2 sweep refused: %s", reason)
	if reason == "" {
		t.Fatal("the refused sweep has no reason")
	}
	// nothing of generation 2 was signed or sent; its output is available again and the books are unchanged
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND address=$2 AND status='available'`, s.chain, cur); n != 1 {
		t.Fatalf("%d available outputs at the generation 2 address", n)
	}
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE chain=$1 AND key_ref LIKE 'g2/%' AND status='done'`, s.chain); n != 0 {
		t.Fatalf("%d generation 2 jobs were signed", n)
	}
	if got := s.onChain(cur); got != before+30_000_000 {
		t.Fatalf("the generation 2 address holds %d", got)
	}
	s.reconcileClean()

	// no retry storm: the address is left alone for the back-off, so at most one more attempt in the next 25 seconds
	n0 := 0
	for _, w := range s.sweepRows() {
		if w.From == cur {
			n0++
		}
	}
	time.Sleep(25 * time.Second)
	n1 := 0
	for _, w := range s.sweepRows() {
		if w.From == cur {
			n1++
		}
		if w.From == cur && w.Status != "failed" && w.Status != "planned" && w.Status != "building" {
			t.Logf("generation 2 sweep %s is %s", w.ID, w.Status)
		}
	}
	if n1 > n0+1 {
		t.Fatalf("%d sweeps of the generation 2 address after %d: a retry storm", n1, n0)
	}
	// generation 1 is not blocked by it: a later deposit to the old address is swept
	s.node.pay(map[string]string{old: btcAmount(10_000_000)})
	s.node.mine(6, "")
	s.waitAvailable("g1", 60_000_000, 60*time.Second)
	s.waitFor(120*time.Second, "a second generation 1 sweep", func() bool {
		n := 0
		for _, w := range s.sweepRows() {
			if w.From == old && w.Status == "confirmed" {
				n++
			}
		}
		return n >= 2
	})
	s.reconcileClean()
	for _, p := range []*proc{s.core, s.worker, s.gateway} {
		if p == nil {
			continue
		}
		b, _ := os.ReadFile(p.log)
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, "ALERT") {
				t.Logf("%s: %s", p.name, l)
			}
		}
	}
}
