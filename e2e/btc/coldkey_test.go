package btce2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

// Cold key replacement (K7b, Bitcoin): the old cold address holds three outputs; a new key is made; the switch of docs/runbooks/cold-key-replacement.md is made
// (the new address pinned in the zone and the core, the old one listed as retiring); a hot-to-cold move goes to the NEW address; a refill from the new cold key
// works while the old address still holds money; the old address is emptied in two rounds (max_inputs 2, no change); Reconcile is clean throughout.

// newKit makes a cold key in the qv-cold token with its own three operators and offline config, like newColdKit, in directory name.
func (s *system) newKit(name string) *coldKit {
	t := s.t
	k := &coldKit{dir: filepath.Join(s.dir, name)}
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyJSON := filepath.Join(k.dir, "key.json")
	s.runCold("keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_HSM_PIN", "-network", "regtest", "-out", keyJSON)
	var key map[string]string
	b, _ := os.ReadFile(keyJSON)
	json.Unmarshal(b, &key)
	k.addr = key["btc_address"]
	ops := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := os.WriteFile(filepath.Join(k.dir, n+".key"), []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
			t.Fatal(err)
		}
		ops[n] = hex.EncodeToString(pub)
	}
	cfg := coldsign.BTCConfig{Family: "btc", Network: "regtest", Chain: s.chain, Pool: "omnibus", Operators: ops, Threshold: 2, HotShards: []string{s.hotAddr},
		MaxAmount: 1_000_000_000, MaxFeeSats: 100_000, MaxFeeRate: 200, MaxInputs: 20, PublicKey: key["btc_public_key"],
		HSM: coldsign.HSMConfig{Token: "qv-cold", PinEnv: "QV_HSM_PIN", KeyID: key["key_id"]}, RecordDir: filepath.Join(k.dir, "record")}
	k.cfgPath = filepath.Join(k.dir, "cfg.json")
	writeJSONFile(t, k.cfgPath, cfg)
	return k
}

// kitCeremony signs a request file with the kit's offline signer (two approvals) and returns the signed file's path.
func (s *system) kitCeremony(k *coldKit, reqPath string) (string, string, error) {
	s.t.Helper()
	args := []string{"sign", "-config", k.cfgPath, "-request", reqPath}
	for _, op := range []string{"alice", "bob"} {
		ap := strings.TrimSuffix(reqPath, ".request.json") + "." + op + ".approval.json"
		if out, err := s.runColdErr("approve", "-operator", op, "-key", filepath.Join(k.dir, op+".key"), "-request", reqPath, "-out", ap); err != nil {
			return "", out, err
		}
		args = append(args, "-approval", ap)
	}
	signed := strings.TrimSuffix(reqPath, ".request.json") + ".signed.json"
	out, err := s.runColdErr(append(args, "-out", signed)...)
	return signed, out, err
}

func (s *system) refillStatusOf(id string) string {
	_, out := s.call("GET", "/v2/refills/"+id, nil)
	st, _ := out["status"].(string)
	return st
}

func (s *system) coldAvailableAt(addr string) (rows int, sats int64) {
	s.t.Helper()
	if err := s.pool.QueryRow(s.ctx, `SELECT count(*), COALESCE(SUM(value),0)::bigint FROM btc_utxos WHERE chain=$1 AND cold AND address=$2 AND status='available'`, s.chain, addr).Scan(&rows, &sats); err != nil {
		s.t.Fatal(err)
	}
	return
}

// coldMoveRound opens the next cold-to-cold request, runs the old key's ceremony and waits for the move to confirm. It returns the request.
func (s *system) coldMoveRound(old, nw *coldKit, name string) coldsign.BTCRequest {
	s.t.Helper()
	code, out := s.call("POST", "/v2/cold/moves", nil)
	if code != 201 || out["kind"] != "cold-move" {
		s.t.Fatalf("%s: open cold move: %d %v", name, code, out)
	}
	id := out["id"].(string)
	if code2, out2 := s.call("POST", "/v2/cold/moves", nil); code2 != 201 || out2["id"] != id {
		s.t.Fatalf("%s: a second ask must return the open request: %d %v", name, code2, out2)
	}
	req := s.exportRefill(id, name)
	var rf coldsign.BTCRequestFile
	b, _ := os.ReadFile(req)
	if b2, _ := os.ReadFile(s.exportRefill(id, name+"-again")); string(b2) != string(b) {
		s.t.Fatalf("%s: a second export replaced the request", name)
	}
	if code, out := s.call("POST", "/v2/refills/"+id+"/rebuild", map[string]any{"reason": "test"}); code != 400 {
		s.t.Fatalf("%s: a rebuild without the offline confirmation answered %d %v", name, code, out)
	}
	if err := json.Unmarshal(b, &rf); err != nil {
		s.t.Fatal(err)
	}
	if rf.Request.Kind != coldsign.KindColdMove || len(rf.Request.Outputs) != 1 || rf.Request.Outputs[0].Address != nw.addr || rf.Request.From != old.addr {
		s.t.Fatalf("%s: request %+v", name, rf.Request)
	}
	signed, out3, err := s.kitCeremony(old, req)
	if err != nil {
		s.t.Fatalf("%s: the old key's ceremony refused: %v\n%s", name, err, out3)
	}
	if code, body := s.importRefill(id, signed); code != 200 {
		s.t.Fatalf("%s: import: %d %s", name, code, body)
	}
	stop := s.keepMining()
	defer stop()
	s.waitFor(120*time.Second, name+" to confirm", func() bool { return s.refillStatusOf(id) == "confirmed" })
	return rf.Request
}

func TestColdKeyReplacementBTC(t *testing.T) {
	s := refillSystem(t, opts{coldLow: "12000000", coldHigh: "40000000", coldTarget: "20000000", maxInputs: 2})
	old := s.kit // key A, the pool's cold key
	s.fundHot(20_000_000)
	s.deposit("c1", 20_000_000)
	for i := 0; i < 3; i++ {
		s.node.pay(map[string]string{old.addr: btcAmount(30_000_000)})
	}
	s.node.mine(6, "")
	s.waitFor(60*time.Second, "the old cold outputs are recorded", func() bool { n, _ := s.coldAvailableAt(old.addr); return n == 3 })
	s.node.mine(8, "")
	s.reconcileClean()

	// 1. The new key, and the old key's offline config pinning it.
	nk := s.newKit("cold2")
	var oc coldsign.BTCConfig
	ob, _ := os.ReadFile(old.cfgPath)
	if err := json.Unmarshal(ob, &oc); err != nil {
		t.Fatal(err)
	}
	oc.ColdMove = &coldsign.BTCColdMoveConfig{NewCold: nk.addr, MaxAmount: 500_000_000}
	writeJSONFile(t, old.cfgPath, oc)

	// 2. The switch: the zone (gateway and cosigner) and the core.
	s.gwFile.Chains[s.chain].BTC.ColdAddresses = map[string]string{"omnibus/native": nk.addr}
	writeJSONFile(t, s.gwPath, s.gwFile)
	cos := s.gwFile
	cos.Signers = nil
	writeJSONFile(t, filepath.Join(s.dir, "cosigner.json"), cos)
	s.gateway.stop()
	s.mpc.Cos.Stop()
	s.mpc.StartCosignerAgain()
	s.startGateway()
	s.worker.stop()
	s.core.stop()
	s.cf.Cold.Addresses = map[string]string{"omnibus/native": nk.addr}
	s.cf.Cold.Retiring = map[string]string{"omnibus/native": old.addr}
	s.writeConfig(s.cf)
	s.startWorker()
	s.startCore()
	s.reconcileClean() // the old address is counted with the new one

	// 3. A hot-to-cold move after the switch goes to the NEW address (the zone's pin).
	s.fundHot(30_000_000)
	s.untilColdMoves(1, 150*time.Second)
	s.waitFor(60*time.Second, "the move's output at the new cold address", func() bool { n, _ := s.coldAvailableAt(nk.addr); return n == 1 })
	if got := s.onChain(old.addr); got != 90_000_000 {
		t.Fatalf("the old cold address holds %d, want it untouched at 90000000", got)
	}
	s.node.mine(8, "")
	s.reconcileClean()

	// 4. A refill during the replacement comes from the NEW cold key.
	w := s.withdraw("ini", "k-cold-1", "c1", s.node.fresh(), 12_000_000)
	s.settle(w.ID)
	rf := s.refillIn("requested", 60*time.Second)
	req := s.exportRefill(rf.ID, "refill-new")
	var rfile coldsign.BTCRequestFile
	rb, _ := os.ReadFile(req)
	json.Unmarshal(rb, &rfile)
	if rfile.Request.From != nk.addr || rfile.Request.Kind != "" {
		t.Fatalf("refill request %+v, want a refill from the new cold address", rfile.Request)
	}
	signed, out, err := s.kitCeremony(nk, req)
	if err != nil {
		t.Fatalf("the new key's ceremony refused: %v\n%s", err, out)
	}
	if code, body := s.importRefill(rf.ID, signed); code != 200 {
		t.Fatalf("import refill: %d %s", code, body)
	}
	s.untilRefillConfirmed(rf.ID, 120*time.Second)
	s.node.mine(8, "")
	s.reconcileClean()

	// 5. The old address is emptied in two rounds: max_inputs is 2, three outputs, no change.
	r1 := s.coldMoveRound(old, nk, "mv-1")
	if len(r1.Inputs) != 2 {
		t.Fatalf("round 1 spends %d inputs, want 2", len(r1.Inputs))
	}
	s.node.mine(8, "")
	s.reconcileClean()
	if n, _ := s.coldAvailableAt(old.addr); n != 1 {
		t.Fatalf("%d outputs left at the old address, want 1", n)
	}
	r2 := s.coldMoveRound(old, nk, "mv-2")
	if len(r2.Inputs) != 1 {
		t.Fatalf("round 2 spends %d inputs, want 1", len(r2.Inputs))
	}
	s.node.mine(8, "")
	if code, out := s.call("POST", "/v2/cold/moves", nil); code != 200 || out["done"] != true {
		t.Fatalf("after the last round: %d %v", code, out)
	}
	if got := s.onChain(old.addr); got != 0 {
		t.Fatalf("the old cold address holds %d after the move, want 0", got)
	}
	if n, _ := s.coldAvailableAt(old.addr); n != 0 {
		t.Fatalf("%d outputs still recorded at the old address", n)
	}
	if got := s.posted("refill:" + s.chain + ":BTC").Int64(); got != 0 {
		t.Fatalf("refill clearing account %d: a cold-to-cold move books no clearing", got)
	}
	s.ledgerOK()
	s.reconcileClean()

	// 6. The old key's offline signer refuses anything else, through the real binary: a destination that is a hot address, a stranger, the old address itself.
	good := s.exportRequestForRefusals(old, nk)
	for name, dest := range map[string]string{"hot": s.hotAddr, "stranger": s.node.fresh(), "old-itself": old.addr} {
		q := good
		q.Outputs = []coldsign.BTCOutput{{Address: dest, Value: q.Outputs[0].Value}}
		p := filepath.Join(old.dir, "evil-"+name+".request.json")
		writeJSONFile(t, p, q.File())
		if _, out, err := s.kitCeremony(old, p); err == nil || !strings.Contains(out, "pinned new cold address") {
			t.Errorf("%s: the old key's signer did not refuse: %v\n%s", name, err, out)
		}
	}
}

// exportRequestForRefusals is a well-formed cold-move request over a made-up outpoint, for the refusal checks (nothing is imported).
func (s *system) exportRequestForRefusals(old, nw *coldKit) coldsign.BTCRequest {
	return coldsign.BTCRequest{Version: coldsign.BTCRequestVersion, ID: "evil", Revision: 1, Network: "regtest", Chain: s.chain, Pool: "omnibus", From: old.addr,
		Kind: coldsign.KindColdMove, Inputs: []coldsign.BTCInput{{TxID: strings.Repeat("ab", 32), Vout: 0, Value: 5_000_000, Address: old.addr}},
		Outputs: []coldsign.BTCOutput{{Address: nw.addr, Value: 4_990_000}}}
}
