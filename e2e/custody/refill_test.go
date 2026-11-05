package custody_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Cold to hot: a hot wallet below its low-water mark gets a refill request, and people run an offline ceremony (the real qv-cold
// binary, on files) before anything moves.

func refillOpts(stuck string) opts {
	return opts{cold: &coldOpts{coldHSM: true, refillStuck: stuck,
		ethLow: eth(150).String(), ethHigh: eth(400).String(), ethTarget: eth(160).String(), usdtHigh: hugeMark}}
}

// fundedCold puts 100 ETH in the cold address and books it, as an operator would.
func (s *system) fundedCold(id string) {
	s.t.Helper()
	s.fundETH(s.coldAddr, eth(100))
	if err := s.svc.FundCold(s.ctx, id, 0, "ETH", eth(100)); err != nil {
		s.t.Fatal(err)
	}
}

// openRefill waits for the planner's refill request and returns its ID.
func (s *system) openRefill() string {
	s.t.Helper()
	var id string
	s.waitFor(60*time.Second, "a refill request", func() bool {
		code, out := s.call("GET", "/v2/refills", nil, nil)
		if code != 200 {
			return false
		}
		for _, r := range out["refills"].([]any) {
			m := r.(map[string]any)
			if m["status"] == "requested" {
				id = m["id"].(string)
				return true
			}
		}
		return false
	})
	return id
}

func (s *system) refillStatus(id string) string {
	_, out := s.call("GET", "/v2/refills/"+id, nil, nil)
	st, _ := out["status"].(string)
	return st
}

func (s *system) exportRefill(id string) coldsign.RequestFile {
	s.t.Helper()
	code, out := s.call("POST", "/v2/refills/"+id+"/export", map[string]string{"X-Actor": "ops"}, nil)
	if code != 200 {
		s.t.Fatalf("export: %d %v", code, out)
	}
	b, _ := json.Marshal(out)
	var rf coldsign.RequestFile
	if err := json.Unmarshal(b, &rf); err != nil {
		s.t.Fatal(err)
	}
	return rf
}

func (s *system) importRefill(id string, sg coldsign.Signed) (int, map[string]any) {
	return s.call("POST", "/v2/refills/"+id+"/import", map[string]string{"X-Actor": "ops"}, sg)
}

func (s *system) ceremonyOK(name string, rf coldsign.RequestFile, who ...string) coldsign.Signed {
	s.t.Helper()
	sg, out, err := s.cold.ceremony(name, rf, who...)
	if err != nil {
		s.t.Fatalf("ceremony %s: %v\n%s", name, err, out)
	}
	return sg
}

func (s *system) alertCount(sub string) int { return strings.Count(readFile(s.worker.log), sub) }

func TestRefillCeremonyEndToEnd(t *testing.T) {
	s := newSystem(t, refillOpts(""))
	s.fundedCold("cold-funding-1")
	s.reconcileClean() // outside funding is booked, so the cold check is exact

	// Hot holds 100 ETH, below its 150 mark: one request to bring it to 160, and an ALERT that names it.
	id := s.openRefill()
	s.waitFor(30*time.Second, "the ALERT naming the refill", func() bool {
		return strings.Contains(readFile(s.worker.log), id) && s.alertCount("needs a refill from cold storage") == 1
	})
	if n := s.count(`SELECT count(*) FROM refills`); n != 1 {
		t.Fatalf("%d refill rows", n)
	}

	rf := s.exportRefill(id)
	r := rf.Request
	if r.Amount != eth(60).String() || r.From != s.coldAddr.Hex() || r.To != s.shardAddr[0].Hex() || r.Nonce != 0 || r.Revision != 1 {
		t.Fatalf("request = %+v", r)
	}
	if rf.RequestHash != r.HashHex() {
		t.Fatal("the exported hash is not the request's hash")
	}

	// The ceremony: inspect, two approvals, the HSM signs. Nothing moves until the signed file is imported.
	out, err := s.cold.run("inspect", "-config", s.cold.cfgPath, "-request", s.cold.file("e2e-request.json", rf))
	if err != nil || !strings.Contains(out, "to        "+s.shardAddr[0].Hex()) || !strings.Contains(out, "60 (60000000000000000000 base units)") || !strings.Contains(out, "enforced in software") {
		t.Fatalf("inspect: %v\n%s", err, out)
	}
	if s.ethBalance(s.shardAddr[0]).Cmp(eth(100)) != 0 {
		t.Fatal("hot balance changed before the ceremony")
	}
	signed := s.ceremonyOK("e2e", rf, "alice", "bob")

	code, res := s.importRefill(id, signed)
	if code != 200 {
		t.Fatalf("import: %d %v", code, res)
	}
	s.waitFor(90*time.Second, "the refill to confirm", func() bool { return s.refillStatus(id) == "confirmed" })
	s.waitIdle(60 * time.Second)

	if got := s.ethBalance(s.shardAddr[0]); got.Cmp(eth(160)) != 0 {
		t.Fatalf("hot holds %s, want 160 ETH", got)
	}
	cold := s.ethBalance(s.coldAddr)
	if fee := new(big.Int).Sub(eth(40), cold); fee.Sign() <= 0 || fee.Cmp(big.NewInt(1e16)) > 0 {
		t.Fatalf("cold holds %s: expected 40 ETH less a small fee", cold)
	}
	if n, _ := s.ec.NonceAt(s.ctx, s.coldAddr, nil); n != 1 {
		t.Fatalf("cold nonce = %d, want 1", n)
	}
	if p := s.posted(custody.RefillAccount(s.chainName, "ETH")); p.Sign() != 0 {
		t.Fatalf("refill clearing account holds %s", p)
	}
	s.reconcileClean()

	// The same file again changes nothing: still one transaction.
	if code, _ := s.importRefill(id, signed); code != 200 {
		t.Fatalf("second import of the same file: %d", code)
	}
	if n, _ := s.ec.NonceAt(s.ctx, s.coldAddr, nil); n != 1 {
		t.Fatalf("cold nonce = %d after importing twice", n)
	}
	t.Logf("refill ceremony ok: %s ETH moved cold -> hot, tx %s, Reconcile clean", "60", signed.TxHash)
}

func TestRefillImportAndReexportAttacks(t *testing.T) {
	s := newSystem(t, refillOpts(""))
	s.fundedCold("cold-funding-1")
	id := s.openRefill()

	rf1 := s.exportRefill(id)
	signed1 := s.ceremonyOK("r1", rf1, "alice", "bob")

	// A tampered file, a file for another request, a bad shape.
	tam := signed1
	raw, _ := hex.DecodeString(signed1.RawTx)
	raw[len(raw)-3] ^= 1
	tam.RawTx = hex.EncodeToString(raw)
	if code, out := s.importRefill(id, tam); code != 400 {
		t.Fatalf("tampered file: %d %v", code, out)
	}
	other := signed1
	other.RequestID = "rf-someone-else"
	if code, out := s.importRefill(id, other); code != 400 || !strings.Contains(out["error"].(string), "is for request rf-someone-else") {
		t.Fatalf("file for another request: %d %v", code, out)
	}
	wrongHash := signed1
	wrongHash.RequestHash = strings.Repeat("ab", 32)
	if code, out := s.importRefill(id, wrongHash); code != 400 || !strings.Contains(out["error"].(string), "re-exported, or this is another request") {
		t.Fatalf("file answering another hash: %d %v", code, out)
	}
	if s.refillStatus(id) != "requested" {
		t.Fatal("a refused file changed the refill")
	}

	// Stale nonce: the cold address spent a transaction meanwhile. The request is re-exported (a new revision and nonce) and a new
	// ceremony runs; the file of the old ceremony can no longer be imported.
	if err := s.rc.CallContext(s.ctx, nil, "anvil_impersonateAccount", s.coldAddr); err != nil {
		t.Fatal(err)
	}
	before := s.ethBalance(s.coldAddr)
	var opTx string
	if err := s.rc.CallContext(s.ctx, &opTx, "eth_sendTransaction", map[string]any{"from": s.coldAddr, "to": randAddr(), "value": hexutil.EncodeBig(big.NewInt(1)), "gas": "0x5208"}); err != nil {
		t.Fatal(err)
	}
	s.waitFor(30*time.Second, "the operator's transaction to mine", func() bool {
		_, err := s.ec.TransactionReceipt(s.ctx, common.HexToHash(opTx))
		return err == nil
	})
	s.fundETH(s.coldAddr, before) // the books know nothing of this spend: put the balance back, the nonce stays moved
	rf2 := s.exportRefill(id)
	if rf2.Request.Nonce != 1 || rf2.Request.Revision != 2 || rf2.RequestHash == rf1.RequestHash {
		t.Fatalf("re-export = nonce %d revision %d, hash equal %v", rf2.Request.Nonce, rf2.Request.Revision, rf2.RequestHash == rf1.RequestHash)
	}
	if code, out := s.importRefill(id, signed1); code != 400 || !strings.Contains(out["error"].(string), "re-exported") {
		t.Fatalf("old ceremony's file after a re-export: %d %v", code, out)
	}

	// Offline: the same nonce may not be signed twice with different content (a durable record), here a smaller amount.
	cheat := rf2.Request
	cheat.Amount = eth(1).String()
	signed2 := s.ceremonyOK("r2", rf2, "alice", "bob")
	if _, out, err := s.cold.ceremony("cheat", cheat.File(), "alice", "bob"); err == nil || !strings.Contains(out, "already signed for different content") {
		t.Fatalf("a second content at nonce 1 was signed: err=%v\n%s", err, out)
	}

	if code, out := s.importRefill(id, signed2); code != 200 {
		t.Fatalf("import of the new ceremony: %d %v", code, out)
	}
	s.waitFor(90*time.Second, "the refill to confirm", func() bool { return s.refillStatus(id) == "confirmed" })

	// After it confirmed, the old file still cannot be broadcast: it shares nonce 0 with a transaction that mined.
	if code, _ := s.importRefill(id, signed1); code != 400 {
		t.Fatalf("old file after confirmation: %d", code)
	}
	if n, _ := s.ec.NonceAt(s.ctx, s.coldAddr, nil); n != 2 {
		t.Fatalf("cold nonce = %d, want 2 (the operator's transaction and the refill)", n)
	}
	s.waitIdle(60 * time.Second)
	s.reconcileClean()
}

// A refill that was broadcast but does not mine raises one ALERT, is not retried with another nonce, and completes when it mines.
func TestRefillNotConfirmingAlertsOnceAndIsNeverRetried(t *testing.T) {
	s := newSystem(t, refillOpts("3s"))
	s.fundedCold("cold-funding-1")
	id := s.openRefill()
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	signed := s.ceremonyOK("stuck", s.exportRefill(id), "alice", "carol")
	if code, out := s.importRefill(id, signed); code != 200 {
		t.Fatalf("import: %d %v", code, out)
	}
	s.waitFor(60*time.Second, "the refill to be broadcast", func() bool { return s.refillStatus(id) == "broadcast" })
	s.waitFor(60*time.Second, "the ALERT", func() bool { return s.alertCount("a cold refill was broadcast and has not confirmed") == 1 })
	s.waitFor(30*time.Second, "the flag", func() bool { return s.count(`SELECT count(*) FROM refills WHERE stuck_alerted`) == 1 })
	if latest, _ := s.ec.NonceAt(s.ctx, s.coldAddr, nil); latest != 0 {
		t.Fatalf("the refill mined while mining was off")
	}
	if pending, _ := s.ec.PendingNonceAt(s.ctx, s.coldAddr); pending != 1 {
		t.Fatalf("pending nonce %d: exactly the one signed transaction may be in the pool", pending)
	}
	s.automine(true)
	s.mine()
	s.waitFor(90*time.Second, "the refill to confirm", func() bool { return s.refillStatus(id) == "confirmed" })
	if n := s.alertCount("a cold refill was broadcast and has not confirmed"); n != 1 {
		t.Fatalf("%d stuck ALERTs, want 1", n)
	}
	s.waitIdle(60 * time.Second)
	s.reconcileClean()
}

// The worker is killed around the import, the broadcast and the settlement; each restart finishes the refill once.
func TestRefillCrashAtEveryBoundary(t *testing.T) {
	o := refillOpts("")
	o.cold.ethLow, o.cold.ethHigh, o.cold.ethTarget = "0", hugeMark, "1" // the worker never asks by itself; the test does
	o.cold.ethHigh = hugeMark
	s := newSystem(t, o)
	s.fundedCold("cold-funding-1")
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("refill crash test, at " + current)
		}
	})
	five := eth(5)
	received := new(big.Int)
	for i, point := range []string{"after_send", "after_record", "after_confirm", "after_settle"} {
		fp := "refill." + point
		current = fp
		s.worker.stop()
		s.startWorker(fp)
		// Put the hot wallet exactly 5 ETH short of a target: it is "below" a low mark the test sets just above it.
		free := s.mirrored(custody.HotAccount(s.hotPart("ETH")))
		s.setLimits("ETH", new(big.Int).Add(free, big.NewInt(1)), hugeBig(), new(big.Int).Add(free, five))
		if _, err := s.svc.PlanColdMoves(s.ctx, nullLog); err != nil {
			t.Fatal(err)
		}
		id := s.openRefill()
		rf := s.exportRefill(id)
		if rf.Request.Amount != five.String() || rf.Request.Nonce != uint64(i) {
			t.Fatalf("%s: request %+v", fp, rf.Request)
		}
		signed := s.ceremonyOK("crash-"+point, rf, "bob", "carol")
		if code, out := s.importRefill(id, signed); code != 200 {
			t.Fatalf("%s: import %d %v", fp, code, out)
		}
		if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
			t.Fatalf("%s: worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		s.startWorker("")
		s.waitFor(120*time.Second, fp+": the refill to confirm", func() bool { return s.refillStatus(id) == "confirmed" })
		received.Add(received, five)
		s.waitIdle(60 * time.Second)
		if n, _ := s.ec.NonceAt(s.ctx, s.coldAddr, nil); n != uint64(i+1) {
			t.Fatalf("%s: cold nonce %d, want %d (one transaction per refill)", fp, n, i+1)
		}
		if got := new(big.Int).Sub(s.ethBalance(s.shardAddr[0]), eth(100)); got.Cmp(received) != 0 {
			t.Fatalf("%s: hot received %s, want exactly %s", fp, got, received)
		}
		s.reconcileClean()
		t.Logf("refill crash %-20s ok: recovered, one transfer of 5 ETH, Reconcile clean", fp)
	}
}

func hugeBig() *big.Int { n, _ := new(big.Int).SetString(hugeMark, 10); return n }

var _ = common.Address{}
