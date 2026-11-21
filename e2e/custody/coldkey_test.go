package custody_test

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Cold key replacement (K7b, EVM): funds sit under cold key A; a new key B is made; the switch order of docs/runbooks/cold-key-replacement.md is
// followed: pin B in both zones, hot-to-cold moves go to B, A stays watched, A's funds move by cold-to-cold ceremonies (the real qv-cold on files, the
// destination pinned in A's own offline config), a refill from B works while A still holds money, and A ends empty with Reconcile clean throughout.

// moveFromOld opens the next cold-to-cold request of the replacement, runs its ceremony with the old key's offline signer and imports the file.
func (s *system) coldMoveStep(kit, newKit *coldKit, name string, wantAsset string) string {
	s.t.Helper()
	code, out := s.call("POST", "/v2/cold/moves", map[string]string{"X-Actor": "ops"}, nil)
	if code != 201 {
		s.t.Fatalf("%s: open cold move: %d %v", name, code, out)
	}
	id := out["id"].(string)
	if out["kind"] != "cold-move" || out["asset"] != wantAsset {
		s.t.Fatalf("%s: request %v, want a cold-move of %s", name, out, wantAsset)
	}
	// Asking again returns the same open request: one at a time, so one nonce.
	if code2, out2 := s.call("POST", "/v2/cold/moves", map[string]string{"X-Actor": "ops"}, nil); code2 != 201 || out2["id"] != id {
		s.t.Fatalf("%s: second ask: %d %v", name, code2, out2)
	}
	rf := s.exportRefill(id)
	// A second export of an open move is the same request, the same hash: a stray re-export cannot strand a ceremony. A rebuild needs a reason and the
	// offline confirmation.
	if again := s.exportRefill(id); again.RequestHash != rf.RequestHash {
		s.t.Fatalf("%s: a second export replaced the request (%s, then %s)", name, rf.RequestHash, again.RequestHash)
	}
	if code, out := s.call("POST", "/v2/refills/"+id+"/rebuild", map[string]string{"X-Actor": "ops"}, map[string]any{"reason": "test"}); code != 400 {
		s.t.Fatalf("%s: a rebuild without the offline confirmation answered %d %v", name, code, out)
	}
	if name == "mv-usdt" { // the explicit, audited way to start again: a new revision with a new hash
		if code, out := s.call("POST", "/v2/refills/"+id+"/rebuild", map[string]string{"X-Actor": "ops"}, map[string]any{"reason": "test: fees moved", "offline_record_cleared": true}); code != 200 {
			s.t.Fatalf("%s: rebuild: %d %v", name, code, out)
		}
		next := s.exportRefill(id)
		if next.RequestHash == rf.RequestHash || next.Request.Revision != rf.Request.Revision+1 {
			s.t.Fatalf("%s: the rebuilt request is %+v after %+v", name, next.Request, rf.Request)
		}
		rf = next
	}
	if rf.Request.Kind != coldsign.KindColdMove || rf.Request.To != newKit.addr.Hex() || rf.Request.From != kit.addr.Hex() {
		s.t.Fatalf("%s: request %+v", name, rf.Request)
	}
	signed := s.ceremonyWith(kit, name, rf, "alice", "bob")
	if code, res := s.importRefill(id, signed); code != 200 {
		s.t.Fatalf("%s: import: %d %v", name, code, res)
	}
	s.waitFor(90*time.Second, name+" to confirm", func() bool { return s.refillStatus(id) == "confirmed" })
	return id
}

func (s *system) ceremonyWith(kit *coldKit, name string, rf coldsign.RequestFile, who ...string) coldsign.Signed {
	s.t.Helper()
	sg, out, err := kit.ceremony(name, rf, who...)
	if err != nil {
		s.t.Fatalf("ceremony %s: %v\n%s", name, err, out)
	}
	return sg
}

func TestColdKeyReplacementEVM(t *testing.T) {
	s := newSystem(t, opts{cold: &coldOpts{coldHSM: true, ethLow: "0", ethHigh: hugeMark, usdtHigh: hugeMark}})
	old := s.cold // key A
	s.fundedCold("cold-funding-eth")
	s.mintUSDT(s.coldAddr, 500_000_000)
	if err := s.svc.FundCold(s.ctx, "cold-funding-usdt", 0, "USDT", big.NewInt(500_000_000)); err != nil {
		t.Fatal(err)
	}
	s.reconcileClean()

	// 1. The new cold key is made, with its own offline config; the old key's offline config pins the new address as the only place it may send a move.
	nk := newColdKey(t, s, "cold2")
	nk.configure(s)
	old.cfg.ColdMove = &coldsign.ColdMoveConfig{NewCold: nk.addr.Hex(), MaxAmount: map[string]string{"ETH": eth(1000).String(), "USDT": "1000000000000"}}
	old.write()

	// 2. The switch: the new address is pinned in the signing zone and in the business config, the old one is listed as retiring (watched, reconciled).
	oldAddr := s.coldAddr
	s.gf.Chains[s.chainName].EVM.ColdAddresses = map[string]string{"omnibus/native": nk.addr.Hex(), "omnibus/token": nk.addr.Hex()}
	s.restartZone(s.shardAddr[0])
	s.worker.stop()
	s.core.stop()
	s.cf.Cold.Addresses = map[string]string{"omnibus/native": nk.addr.Hex(), "omnibus/token": nk.addr.Hex()}
	s.cf.Cold.Retiring = map[string]string{"omnibus/native": oldAddr.Hex(), "omnibus/token": oldAddr.Hex()}
	writeJSON(t, s.cfgPath, s.cf)
	s.svc.Cfg.EVM.ColdAddresses["omnibus/native"], s.svc.Cfg.EVM.ColdAddresses["omnibus/token"] = nk.addr, nk.addr
	s.svc.Cfg.ColdRetiring = s.cf.Cold.Retiring
	s.startCore()
	s.startWorker("")
	s.reconcileClean() // the old address is counted with the new one: the cold check stays exact

	// 3. A hot-to-cold move after the switch goes to the NEW address (the zone's pin).
	s.setLimits("ETH", new(big.Int), eth(80), eth(70))
	if mv, err := s.svc.PlanColdMoves(s.ctx, nullLog); err != nil || len(mv) != 1 {
		t.Fatalf("PlanColdMoves = %v, %v", mv, err)
	}
	s.waitFor(120*time.Second, "the hot-to-cold move to confirm", func() bool { return s.coldMoves("confirmed") == 1 })
	s.waitIdle(60 * time.Second)
	if got := s.ethBalance(nk.addr); got.Cmp(eth(30)) != 0 {
		t.Fatalf("new cold holds %s, want the 30 ETH moved from hot", got)
	}
	if got := s.ethBalance(oldAddr); got.Cmp(eth(100)) != 0 {
		t.Fatalf("old cold holds %s, want it untouched at 100 ETH", got)
	}
	s.reconcileClean()

	// 4. The old key's token balance moves first (the native coin pays its gas), by ceremony, to the pinned address.
	s.setLimits("ETH", new(big.Int), eth(1_000_000), eth(70)) // the hot-to-cold planner rests
	s.coldMoveStep(old, nk, "mv-usdt", "USDT")
	if got := s.usdtBalance(nk.addr); got.Cmp(big.NewInt(500_000_000)) != 0 {
		t.Fatalf("new cold holds %s USDT", got)
	}
	if got := s.usdtBalance(oldAddr); got.Sign() != 0 {
		t.Fatalf("old cold still holds %s USDT", got)
	}
	s.waitIdle(60 * time.Second)
	s.reconcileClean()

	// 5. A refill during the replacement comes from the NEW cold key (it holds 30 ETH) while the old one still holds 100.
	hot := s.mirrored(custody.HotAccount(s.hotPart("ETH")))
	target := new(big.Int).Add(hot, eth(25))
	s.setLimits("ETH", new(big.Int).Add(hot, eth(1)), eth(1_000_000), target)
	if _, err := s.svc.PlanColdMoves(s.ctx, nullLog); err != nil {
		t.Fatal(err)
	}
	rid := s.openRefill()
	rrf := s.exportRefill(rid)
	if rrf.Request.From != nk.addr.Hex() || rrf.Request.Kind != "" {
		t.Fatalf("refill request %+v, want a refill from the new cold address", rrf.Request)
	}
	if code, res := s.importRefill(rid, s.ceremonyWith(nk, "refill-new", rrf, "alice", "carol")); code != 200 {
		t.Fatalf("import refill: %d %v", code, res)
	}
	s.waitFor(90*time.Second, "the refill to confirm", func() bool { return s.refillStatus(rid) == "confirmed" })
	s.setLimits("ETH", new(big.Int), eth(1_000_000), eth(70))
	s.waitIdle(60 * time.Second)
	s.reconcileClean()

	// 6. The native coin moves last, everything but its own fee: the old address ends at exactly zero.
	s.coldMoveStep(old, nk, "mv-eth", "ETH")
	if got := s.ethBalance(oldAddr); got.Sign() != 0 {
		t.Fatalf("old cold holds %s ETH after the move, want 0", got)
	}
	if code, out := s.call("POST", "/v2/cold/moves", map[string]string{"X-Actor": "ops"}, nil); code != 200 || out["done"] != true {
		t.Fatalf("after the last move: %d %v", code, out)
	}
	if n, _ := s.ec.NonceAt(s.ctx, oldAddr, nil); n != 2 {
		t.Fatalf("old cold nonce = %d, want 2 (one token move, one native move)", n)
	}
	s.waitIdle(60 * time.Second)
	rep := s.reconcileClean()
	cold := 0
	for _, c := range rep.Checks {
		if c.Name == "cold" {
			cold++
		}
	}
	if cold != 2 {
		t.Fatalf("Reconcile made %d cold checks, want 2", cold)
	}
	if p := s.posted(custody.RefillAccount(s.chainName, "ETH")); p.Sign() != 0 {
		t.Fatalf("refill clearing account holds %s: a cold-to-cold move books no clearing", p)
	}

	// 7. The old key's offline signer refuses anything else: another destination (the hot shard, the old address itself) and a refill.
	for name, mut := range map[string]func(r *coldsign.Request){
		"to a hot shard": func(r *coldsign.Request) { r.To = s.shardAddr[0].Hex() },
		"to a stranger":  func(r *coldsign.Request) { r.To = randAddr().Hex() },
	} {
		r := coldsign.Request{Version: coldsign.RequestVersion, ID: "evil-" + name, Revision: 1, Chain: s.chainName, ChainID: 11155111, Pool: "omnibus", Kind: coldsign.KindColdMove,
			Asset: "ETH", From: oldAddr.Hex(), To: nk.addr.Hex(), Amount: "1", Nonce: 7, Gas: 21000, MaxFeePerGas: "3000000000", MaxPriorityFeePerGas: "1000000000"}
		mut(&r)
		if _, out, err := old.ceremony("evil", r.File(), "alice", "bob"); err == nil || !strings.Contains(out, "pinned") && !strings.Contains(out, "not one of") {
			t.Errorf("%s: the old key's signer did not refuse: %v\n%s", name, err, out)
		}
	}
	b, _ := json.Marshal(rep.Checks)
	t.Logf("cold key replaced: old %s empty, new %s holds the treasury; Reconcile clean (%d bytes of checks)", oldAddr, nk.addr, len(b))
}
