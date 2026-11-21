package sole2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

func custodyLimit(low, high, target uint64) custody.LimitFile {
	return custody.LimitFile{Low: fmt.Sprint(low), High: fmt.Sprint(high), Target: fmt.Sprint(target)}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// Cold key replacement (K7b, Solana): the old cold address holds SOL, tokens and a pool of nonce accounts; a new key is made; the switch of
// docs/runbooks/cold-key-replacement.md is made (the new address pinned in the zone and the core, the old one listed as retiring); the new address is set up
// and a hot-to-cold move goes to it; a refill from the new cold key works while the old address still holds money; the old address is emptied by ceremonies of
// the old key (tokens, then SOL, then its nonce accounts, the rent going to the new address) and ends at exactly zero; Reconcile is clean throughout.

func (s *wdSys) coldMoveStepSOL(old, nw *solKit, name string) (done bool, kind string) {
	s.t.Helper()
	code, out := s.call("POST", "/v2/cold-move/export", map[string]string{"pool": "omnibus"})
	if code != 200 {
		s.t.Fatalf("%s: export: %d %v", name, code, out)
	}
	if out["done"] == true {
		return true, ""
	}
	var rf coldsign.SOLRequestFile
	s.via(out, &rf)
	if rf.Request.To != nw.addr || rf.Request.From != old.addr {
		s.t.Fatalf("%s: request %+v", name, rf.Request)
	}
	sg, o, err := old.ceremony(name, rf, "alice", "bob")
	if err != nil {
		s.t.Fatalf("%s: the old key's ceremony refused: %v\n%s", name, err, o)
	}
	if code, res := s.call("POST", "/v2/cold-move/submit", map[string]any{"request": rf.Request, "signed": sg}); code != 200 {
		s.t.Fatalf("%s: submit: %d %v", name, code, res)
	}
	return false, rf.Request.Kind
}

func TestColdKeyReplacementSOL(t *testing.T) {
	old := newSolKit(t)
	nk := newSolKit(t)
	inert := map[string]coldBand{
		"SOL": {low: "0", high: fmt.Sprint(1000 * oneSOL), target: fmt.Sprint(10 * oneSOL)},
		"TKN": {low: "0", high: fmt.Sprint(1_000_000 * tknUnit), target: fmt.Sprint(1_000 * tknUnit)},
	}
	s := newWdSystem(t, wdOpts{pool: 3, shards: 1, coldAddr: old.addr, seedSOL: []uint64{30 * oneSOL}, seedTKN: []uint64{0}, cold: inert})
	s.coldReady(old)
	nk.configure(s)
	old.cfg.ColdMove = &coldsign.SOLColdMoveConfig{NewCold: nk.addr, MaxAmount: map[string]string{"SOL": fmt.Sprint(1000 * oneSOL), "TKN": fmt.Sprint(1_000_000 * tknUnit)}}
	old.write()
	stop := s.watchReconcile()
	oldSOL, oldTKN := s.lamports(old.addr), s.tokensOf(old.addr)
	if oldSOL < 29*oneSOL || oldTKN != 5_000*tknUnit {
		t.Fatalf("the old cold address holds %d lamports and %d tokens", oldSOL, oldTKN)
	}
	s.reconcileClean("before the replacement")

	// The switch: the zone (gateway and both cosigners) and the core.
	s.gf.Chains[s.chain].SOL.ColdAddresses = map[string]string{"omnibus": nk.addr}
	writeJSONFile(t, s.gwPath, s.gf)
	cos := s.gf
	cos.Signers = nil
	writeJSONFile(t, fmt.Sprintf("%s/cosigner-b.json", s.dir), cos)
	writeJSONFile(t, fmt.Sprintf("%s/cosigner-c.json", s.dir), cos)
	s.gateway.Stop()
	s.m3.Cos.Stop()
	s.m3.StartCosignerAgain()
	s.m3.CosC.Stop()
	s.m3.StartCosignerCAgain()
	s.startGateway()
	s.m3.WaitSigning(90 * time.Second)
	s.worker.stop()
	s.core.stop()
	s.cf.Cold.Addresses = map[string]string{"omnibus": nk.addr}
	s.cf.Cold.Retiring = map[string]string{"omnibus": old.addr}
	s.cf.Cold.Limits["SOL"] = custodyLimit(2*oneSOL, 25*oneSOL, 12*oneSOL) // the shard holds 30 SOL: 18 go to cold, to the NEW address
	writeJSONFile(t, s.cfgPath, s.cf)
	s.svc.Cfg.SOL.ColdAddresses["omnibus"] = nk.addr
	s.svc.Cfg.ColdRetiring = s.cf.Cold.Retiring
	s.startWorker("")
	s.startCore()
	s.reconcileClean("after the switch")

	// The new address is set up (nonce accounts, token account) and a hot-to-cold move goes to it.
	s.coldSetup(nk)
	s.waitFor(240*time.Second, "the hot-to-cold move to the new address", func() bool { return s.movesDone("cold_moves") >= 1 && s.openMoves() == 0 })
	if got := s.lamports(nk.addr); got < 15*oneSOL {
		t.Fatalf("the new cold address holds %d lamports after the move", got)
	}
	if got := s.lamports(old.addr); got != oldSOL {
		t.Fatalf("the old cold address holds %d lamports, want it untouched at %d", got, oldSOL)
	}
	s.reconcileClean("after the hot-to-cold move")

	// A refill during the replacement comes from the NEW cold key: the shard falls below a raised low mark.
	s.cf.Cold.Limits["SOL"] = custodyLimit(20*oneSOL, 1000*oneSOL, 25*oneSOL)
	writeJSONFile(t, s.cfgPath, s.cf)
	s.worker.stop()
	s.startWorker("")
	r := s.waitRefill("SOL", "requested", 120*time.Second)
	rf := s.exportRefill(r.ID)
	if rf.Request.From != nk.addr || rf.Request.Kind == coldsign.KindSOLColdMove {
		t.Fatalf("refill request %+v, want a refill from the new cold address", rf.Request)
	}
	sg, out, err := nk.ceremony("refill-new", rf, "alice", "carol")
	if err != nil {
		t.Fatalf("the new key's ceremony refused: %v\n%s", err, out)
	}
	if code, res := s.importRefill(r.ID, sg); code != 200 {
		t.Fatalf("import refill: %d %v", code, res)
	}
	s.waitRefill("SOL", "confirmed", 180*time.Second)
	s.cf.Cold.Limits["SOL"] = custodyLimit(0, 1000*oneSOL, 15*oneSOL) // the planner rests
	writeJSONFile(t, s.cfgPath, s.cf)
	s.worker.stop()
	s.startWorker("")
	s.reconcileClean("after the refill from the new key")

	// The old address is emptied by the old key's ceremonies: tokens, SOL, then its nonce accounts.
	var kinds []string
	for i := 0; i < 8; i++ {
		done, kind := s.coldMoveStepSOL(old, nk, fmt.Sprintf("mv-%d", i))
		if done {
			break
		}
		kinds = append(kinds, kind)
		s.reconcileClean("after step " + kind)
	}
	if len(kinds) != 3 || kinds[0] != coldsign.KindSOLColdMove || kinds[1] != coldsign.KindSOLColdMove || kinds[2] != coldsign.KindSOLColdMoveClose {
		t.Fatalf("the steps were %v, want a token move, a SOL move, the nonce close", kinds)
	}
	if got := s.lamports(old.addr); got != 0 {
		t.Fatalf("the old cold address holds %d lamports, want 0", got)
	}
	if got := s.tokensOf(old.addr); got != 0 {
		t.Fatalf("the old cold address holds %d tokens, want 0", got)
	}
	if got := s.tokensOf(nk.addr); got != 5_000*tknUnit {
		t.Fatalf("the new cold address holds %d tokens, want all 5000", got)
	}
	if code, out := s.call("POST", "/v2/cold-move/export", map[string]string{"pool": "omnibus"}); code != 200 || out["done"] != true {
		t.Fatalf("after the last step: %d %v", code, out)
	}
	if bad := stop(); len(bad) > 0 {
		t.Fatalf("Reconcile failed during the replacement: %v", bad)
	}
	s.reconcileClean("at the end")

	// The old key's offline signer refuses anything else, through the real binary.
	good := rf.Request
	for name, dest := range map[string]string{"hot": s.hotAddrs()[0], "stranger": s.freshAddr(), "old-itself": old.addr} {
		q := good
		q.Kind, q.To, q.ID, q.From = coldsign.KindSOLColdMove, dest, "evil-"+name, old.addr
		if _, o, err := old.ceremony("evil-"+name, q.File(), "alice", "bob"); err == nil || !contains(o, "pinned new cold address") {
			t.Errorf("%s: the old key's signer did not refuse: %v\n%s", name, err, o)
		}
	}
}
