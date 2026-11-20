package sole2e

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"filippo.io/edwards25519"

	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// secondDepositNode is the deposit node of generation 2 in these tests: a random Ed25519 point and chain code, a public node no one holds the key of. (The signing
// zone pins generation 1's node until K6 teaches it later generations, so a generation-2 address cannot be swept here.)
func secondDepositNode(t *testing.T) string {
	t.Helper()
	var b [64]byte
	rand.Read(b[:])
	sc, err := edwards25519.NewScalar().SetUniformBytes(b[:])
	if err != nil {
		t.Fatal(err)
	}
	cc := make([]byte, 32)
	rand.Read(cc)
	return hex.EncodeToString(edwards25519.NewIdentityPoint().ScalarBaseMult(sc).Bytes()) + ":" + hex.EncodeToString(cc)
}

func (s *system) rotateDepositKey(identity string) {
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
	if _, err := partition.RegisterCandidate(s.ctx, tx, "e2e", id, identity, "", nil); err != nil {
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

func (s *system) depositAddressOf(customer string) map[string]any {
	s.t.Helper()
	code, out := s.call("POST", "/v2/customers/"+customer+"/deposit-addresses", map[string]any{"chain": s.chain})
	if code != 200 {
		s.t.Fatalf("deposit address of %s: %d %v", customer, code, out)
	}
	return out
}

func olderOf(out map[string]any) []string {
	var r []string
	if l, ok := out["older_addresses"].([]any); ok {
		for _, e := range l {
			r = append(r, e.(map[string]any)["address"].(string))
		}
	}
	return r
}

// A key replacement leaves every deposit address working: the old address is still swept with the old key, a new customer and a returning one get
// generation-2 addresses, and every deposit is credited to its own customer, with Reconcile clean.
func TestSwFlowsDepositKeyGenerations(t *testing.T) {
	s := newWdSystem(t, wdOpts{minSweep: "5000000", batch: 3})
	old := s.depositAddr("g1")
	if first := s.depositAddressOf("g1"); first["generation"] != float64(1) || olderOf(first) != nil {
		t.Fatalf("before the replacement: %v", first)
	}
	s.paySOL(old, 2*oneSOL)
	s.waitDeposits("g1", 2*oneSOL, 0)
	s.waitSwept("generation 1 swept before the replacement", "SOL", old)

	s.rotateDepositKey(secondDepositNode(t))

	fresh := s.depositAddr("g2")
	again := s.depositAddressOf("g1")
	cur, _ := again["address"].(string)
	if again["generation"] != float64(2) || cur == old || fresh == old || fresh == cur {
		t.Fatalf("after the replacement: old %s, g1 %v, g2 %s", old, again, fresh)
	}
	if o := olderOf(again); len(o) != 1 || o[0] != old {
		t.Fatalf("the old address is not offered as an older one: %v", again)
	}
	if got := s.depositAddressOf("g1"); got["address"] != cur {
		t.Fatalf("asked twice: %v then %v", again, got)
	}

	// a late deposit to the old address is credited and swept with generation 1's key; deposits below the sweep floor stay on the generation-2 addresses
	s.paySOL(old, 3*oneSOL)
	s.paySOL(cur, 1_000_000)
	s.paySOL(fresh, 2_000_000)
	s.waitDeposits("g1", 5*oneSOL+1_000_000, 0)
	s.waitDeposits("g2", 2_000_000, 0)
	s.waitSwept("the old address swept after the replacement", "SOL", old)
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE chain=$1 AND key_ref LIKE 'g%'`, s.chain); n != 0 {
		t.Fatalf("%d jobs were signed under a later generation's key", n)
	}
	s.waitScanned()
	s.holds(3*time.Second, "the generation 2 addresses keep their deposits", func() bool {
		return s.lamports(cur) == 1_000_000 && s.lamports(fresh) == 2_000_000
	})
	s.reconcileClean("with two key generations")
}
