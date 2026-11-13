package sole2e

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
)

// refillOpts is a pool with one hot shard that starts dry and a cold address whose key is in the offline token: the planner asks for refills at once.
func refillOpts(k *solKit, stuck string) wdOpts {
	return wdOpts{
		pool: 3, shards: 1, coldAddr: k.addr, refillStuck: stuck,
		seedSOL: []uint64{oneSOL / 2}, seedTKN: []uint64{0},
		cold: map[string]coldBand{
			"SOL": {low: fmt.Sprint(2 * oneSOL), high: fmt.Sprint(1000 * oneSOL), target: fmt.Sprint(10 * oneSOL)},
			"TKN": {low: fmt.Sprint(100 * tknUnit), high: fmt.Sprint(1_000_000 * tknUnit), target: fmt.Sprint(1_000 * tknUnit)},
		},
	}
}

// ready sets the cold address up (funded, nonce accounts, token account) once the system is running.
func (s *wdSys) coldReady(k *solKit) {
	s.t.Helper()
	k.configure(s)
	s.fundCold(30*oneSOL, 0)
	s.waitFinalized("the cold address to be funded", func() bool { return s.lamports(s.coldAdr) >= 30*oneSOL })
	s.coldSetup(k)
	s.fundCold(0, 5_000*tknUnit)
}

// The refill ceremony for SOL and for the token: the planner asks, an operator exports the request, two operators approve it offline, the offline
// signer signs on the cold address's durable nonce, the signed file is imported and broadcast, and the books follow the chain at every step.
func TestColdRefillCeremony(t *testing.T) {
	k := newSolKit(t)
	s := newWdSystem(t, refillOpts(k, ""))
	s.coldReady(k)
	stop := s.watchReconcile()

	// ---- SOL: the attacks on the ceremony, then the honest one ----
	r := s.waitRefill("SOL", "requested", 90*time.Second)
	rf1 := s.exportRefill(r.ID)
	if rf1.Request.NonceAccount == "" || rf1.Request.NonceValue == "" || rf1.Request.From != k.addr {
		t.Fatalf("the request does not name the cold address's nonce: %+v", rf1.Request)
	}
	t.Run("the_offline_signer_refuses", func(t *testing.T) {
		tamper := func(name string, mod func(q *coldsign.SOLRequest)) {
			q := rf1.Request
			mod(&q)
			f := q.File()
			if _, out, err := k.ceremony("atk-"+name, f, "alice", "bob"); err == nil {
				t.Errorf("%s: signed", name)
			} else if !strings.Contains(out, "refuse") && !strings.Contains(out, "qv-cold") {
				t.Errorf("%s: %s", name, out)
			}
		}
		tamper("to-a-stranger", func(q *coldsign.SOLRequest) { q.To = s.freshAddr() })
		tamper("to-the-cold-address", func(q *coldsign.SOLRequest) { q.To = k.addr })
		tamper("a-nonce-of-another-key", func(q *coldsign.SOLRequest) { q.NonceAccount = s.freshAddr() })
		tamper("above-the-cap", func(q *coldsign.SOLRequest) { q.Amount = fmt.Sprint(101 * oneSOL) })
		tamper("a-huge-fee", func(q *coldsign.SOLRequest) { q.ComputeUnitPrice = maxMicro + 1 })
		tamper("another-asset-as-sol", func(q *coldsign.SOLRequest) { q.Mint = s.mint.addr() })
		// one approval is not enough, nor is the same operator twice, nor an approval of another request
		if _, _, err := k.ceremony("one", rf1, "alice"); err == nil {
			t.Error("one approval signed")
		}
		if _, _, err := k.ceremony("twice", rf1, "alice", "alice"); err == nil {
			t.Error("one operator counted twice")
		}
		// a damaged request file (its hash does not match) is refused by the approving operator
		bad := rf1
		bad.Request.Amount = "1"
		if _, err := k.approve("damaged", "alice", bad); err == nil {
			t.Error("an operator approved a damaged file")
		}
	})

	// the honest ceremony, twice for the same nonce value: the first signed file is a request that was exported before a fee raise
	sg1, out, err := k.ceremony("sol-1", rf1, "alice", "bob")
	if err != nil {
		t.Fatalf("ceremony: %v\n%s", err, out)
	}
	rf2 := s.exportRefill(r.ID) // a re-export: the same nonce value, a higher price
	if rf2.Request.NonceValue != rf1.Request.NonceValue || rf2.Request.ComputeUnitPrice <= rf1.Request.ComputeUnitPrice || rf2.Request.Revision != rf1.Request.Revision+1 {
		t.Fatalf("the re-export is not a replacement of the first: %+v then %+v", rf1.Request, rf2.Request)
	}
	t.Run("the_online_side_refuses", func(t *testing.T) {
		// the file signed for the first export no longer answers the current export
		s.refuseImport("a file for an older revision", r.ID, sg1)
		// the same nonce value cannot be signed offline for another payment (a re-export that changes the amount)
		q := rf2.Request
		q.Amount, q.Revision, q.ComputeUnitPrice = fmt.Sprint(oneSOL), 3, q.ComputeUnitPrice+1
		if _, out, err := k.ceremony("reexport", q.File(), "alice", "bob"); err == nil || !strings.Contains(out, "already signed for a different payment") {
			t.Errorf("a different payment on a signed nonce value: err %v\n%s", err, out)
		}
	})
	sg2, out, err := k.ceremony("sol-2", rf2, "bob", "carol")
	if err != nil {
		t.Fatalf("ceremony 2: %v\n%s", err, out)
	}
	// a file with an altered transaction, or for another request id
	bad := sg2
	raw := []byte(bad.RawTx)
	raw[len(raw)-3] ^= 1 // flips a hex digit of the message
	bad.RawTx = string(raw)
	s.refuseImport("an altered transaction", r.ID, bad)
	other := sg2
	other.RequestID = "rf-someone-else"
	s.refuseImport("another request's file", r.ID, other)
	if code, res := s.importRefill(r.ID, sg2); code != 200 {
		t.Fatalf("import: %d %v", code, res)
	}
	if code, _ := s.importRefill(r.ID, sg2); code != 200 {
		t.Fatalf("the same file again: %d", code)
	}
	s.refuseImport("the older file after the newer one", r.ID, sg1)
	if code, _ := s.call("POST", "/v2/refills/"+r.ID+"/export", nil); code != 400 {
		t.Fatalf("a signed request was exported again: %d", code)
	}
	s.waitRefill("SOL", "confirmed", 120*time.Second)
	// the replaced version never lands: the nonce value is spent
	s.sendDirect(mustRaw(t, sg1.RawTx))
	time.Sleep(2 * time.Second)
	if st := s.statusOf(sg1.TxHash); st != nil && st.Status != "" {
		t.Fatalf("the replaced refill landed too: %+v", st)
	}
	if got := s.shardBalance(0, "SOL"); got < 9*oneSOL+oneSOL/2 || got > 10*oneSOL+oneSOL/2 {
		t.Fatalf("the hot shard holds %d lamports after the refill, want about its target of 10 SOL", got)
	}

	// ---- the token ----
	tr := s.waitRefill("TKN", "requested", 90*time.Second)
	rfT := s.exportRefill(tr.ID)
	if rfT.Request.Mint != s.mint.addr() {
		t.Fatalf("the token request names mint %q", rfT.Request.Mint)
	}
	sgT, out, err := k.ceremony("tkn", rfT, "alice", "carol")
	if err != nil {
		t.Fatalf("token ceremony: %v\n%s", err, out)
	}
	if code, res := s.importRefill(tr.ID, sgT); code != 200 {
		t.Fatalf("import: %d %v", code, res)
	}
	s.waitRefill("TKN", "confirmed", 120*time.Second)
	if got := s.shardBalance(0, "TKN"); got != 1_000*tknUnit {
		t.Fatalf("the hot shard holds %d tokens, want its target %d", got, 1_000*tknUnit)
	}
	if got := s.coldBalance("TKN"); got != 4_000*tknUnit {
		t.Fatalf("the cold address holds %d tokens, want %d", got, 4_000*tknUnit)
	}
	s.holds(5*time.Second, "nothing more is asked once the shard is above its low-water mark", func() bool {
		for _, x := range s.refills() {
			if x.Status != "confirmed" {
				return false
			}
		}
		return true
	})
	if bad := stop(); len(bad) > 0 {
		t.Fatalf("Reconcile failed during the refills: %v", bad)
	}
	s.reconcileClean("after both refills")
	_ = hex.EncodeToString
}
