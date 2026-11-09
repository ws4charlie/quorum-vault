package btce2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

// refillRequest is the request the core holds for the refill (the newest export).
func (s *system) refillRequest(id string) coldsign.BTCRequest {
	s.t.Helper()
	var raw []byte
	if err := s.pool.QueryRow(s.ctx, `SELECT request FROM refills WHERE id=$1`, id).Scan(&raw); err != nil {
		s.t.Fatal(err)
	}
	var r coldsign.BTCRequest
	if err := json.Unmarshal(raw, &r); err != nil {
		s.t.Fatal(err)
	}
	return r
}

func (s *system) writeRequest(name string, r coldsign.BTCRequest) string {
	s.t.Helper()
	b, _ := json.Marshal(r.File())
	p := filepath.Join(s.kit.dir, name+".request.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

func (s *system) signedTxID(path string) string {
	s.t.Helper()
	b, _ := os.ReadFile(path)
	var sg coldsign.BTCSigned
	json.Unmarshal(b, &sg)
	return sg.TxID
}

func (s *system) refillAttempts() int {
	return s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND owner_kind='refill' AND broadcast_at IS NOT NULL`, s.chain)
}

func (s *system) attemptRaw(txid string) []byte {
	var raw []byte
	if err := s.pool.QueryRow(s.ctx, `SELECT raw FROM btc_attempts WHERE chain=$1 AND txid=$2`, s.chain, txid).Scan(&raw); err != nil {
		s.t.Fatal(err)
	}
	return raw
}

// brokenRefill runs the first ceremony and waits until the refill is broadcast (nothing mines it, so it is stuck).
func brokenRefill(t *testing.T, o opts, coldSats ...int64) (*system, rfRow, string) {
	t.Helper()
	s, rf := lowShardN(t, o, coldSats...)
	s.ceremony(rf.ID, "orig")
	b := s.refillIn("broadcast", 60*time.Second)
	if b.ID != rf.ID {
		t.Fatalf("refill %+v", b)
	}
	return s, rf, b.Tx
}

// replaceCeremony exports a new revision, signs it offline and imports it; it returns the replacement's txid.
func (s *system) replaceCeremony(id, name string) string {
	s.t.Helper()
	req := s.exportRefill(id, name)
	signed, out, err := s.signRefill(req)
	if err != nil {
		s.t.Fatalf("the ceremony refused the replacement: %v\n%s", err, out)
	}
	if code, body := s.importRefill(id, signed); code != 200 {
		s.t.Fatalf("import of the replacement: %d %s", code, body)
	}
	return s.signedTxID(signed)
}

// A refill that does not confirm is re-exported with a higher fee over the same inputs, signed in a second ceremony, imported and sent; the replacement
// confirms and its fee and its change are the ones booked. Reconcile is clean at each stage.
func TestRefillStuckIsReplacedAndTheReplacementConfirms(t *testing.T) {
	s, rf, orig := brokenRefill(t, opts{}, 15_000_000)
	s.mustBeClean("the original in the mempool")
	origFee := s.attemptFee(orig)

	s.worker.stop()
	repl := s.replaceCeremony(rf.ID, "repl")
	s.mustBeClean("the replacement signed, not sent")
	if repl == orig {
		t.Fatal("no replacement")
	}
	s.startWorker()
	s.waitFor(150*time.Second, "the replacement is sent", func() bool { return s.refillAttempts() == 2 }) // a restarted worker picks the workflow up after its heartbeat timeout
	s.worker.stop()
	s.mustBeClean("the replacement in the mempool")
	if fr := s.attemptFee(repl); fr <= origFee {
		t.Fatalf("the replacement pays %d, the original %d", fr, origFee)
	}
	var in struct{ Txid string }
	if err := s.node.root.Call(s.ctx, &in, "getrawtransaction", orig, true); err == nil {
		t.Fatal("the original is still in the mempool after the replacement")
	}
	s.node.mine(1, "")
	s.mustBeClean("one confirmation")
	s.node.mine(1, "")
	s.mustBeClean("at the spend depth, not settled")
	s.node.mine(1, "")
	s.mustBeClean("past the spend depth, not settled")
	s.startWorker()
	done := s.refillIn("confirmed", 90*time.Second)
	fr := s.attemptFee(repl)
	if done.ID != rf.ID || done.Tx != repl || done.Fee != fr {
		t.Fatalf("refill %+v, the replacement %s paid %d (the original %d)", done, repl, fr, origFee)
	}
	if got := s.posted("refill:" + s.chain + ":BTC").Int64(); got != 0 {
		t.Fatalf("refill clearing account %d", got)
	}
	if want := 15_000_000 - done.Amount - fr; s.coldRows("available") != 1 || s.coldValue("available") != want {
		t.Fatalf("cold change %d (%d rows), want the replacement's %d", s.coldValue("available"), s.coldRows("available"), want)
	}
	if got := s.posted("cold:" + s.part).Int64(); got != -(15_000_000 - done.Amount - fr) {
		t.Fatalf("cold account %d", got)
	}
	s.ledgerOK()
	s.node.mine(8, "")
	s.reconcileClean()
}

// The same, but the original is the one that confirms: a miner that never saw the replacement includes it. The fee booked and the cold change recorded are
// the original's.
func TestRefillStuckAndTheOriginalConfirmsAfterTheReplacementWasSigned(t *testing.T) {
	s, rf, orig := brokenRefill(t, opts{}, 15_000_000)
	origFee := s.attemptFee(orig)
	repl := s.replaceCeremony(rf.ID, "repl")
	s.waitFor(60*time.Second, "the replacement is sent", func() bool { return s.refillAttempts() == 2 })
	raw := s.attemptRaw(orig)
	var out json.RawMessage
	if err := s.node.root.Call(s.ctx, &out, "generateblock", s.node.fresh(), []string{fmt.Sprintf("%x", raw)}); err != nil {
		t.Fatalf("a block with the original: %v", err)
	}
	s.node.mine(1, s.node.fresh())
	done := s.refillIn("confirmed", 90*time.Second)
	if done.Tx != orig || done.Fee != origFee {
		t.Fatalf("refill %+v: the original %s paid %d, the replacement %s paid %d", done, orig, origFee, repl, s.attemptFee(repl))
	}
	if want := 15_000_000 - done.Amount - origFee; s.coldValue("available") != want {
		t.Fatalf("cold change %d, want the original's %d", s.coldValue("available"), want)
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2`, s.chain, repl) != 0 {
		t.Fatal("the replacement's change was recorded though it never confirmed")
	}
	var in struct{ Txid string }
	if err := s.node.root.Call(s.ctx, &in, "getrawtransaction", repl, true); err == nil {
		t.Fatal("the replacement is known to the node after the original confirmed")
	}
	s.ledgerOK()
	s.node.mine(8, "")
	s.reconcileClean()
}

// Without change nothing can pay a higher fee: the ALERT says so, the export is refused, the refill keeps waiting and confirms when it is mined.
func TestRefillStuckWithNoChangeAlertsAndWaits(t *testing.T) {
	s, rf, _ := brokenRefill(t, opts{refillStuck: "4s"}, 10_000_000) // less than the need: the payment takes all but the fee
	if r := s.refillRequest(rf.ID); len(r.Outputs) != 1 {
		t.Fatalf("the request has %d outputs, want no change", len(r.Outputs))
	}
	s.waitFor(60*time.Second, "the ALERT that it cannot be fee-bumped", func() bool { return s.workerLogHas("cannot be fee-bumped") })
	code, body := s.rawCall("POST", "/v2/refills/"+rf.ID+"/export", nil)
	if code == 200 || !strings.Contains(string(body), "cannot be fee-bumped") {
		t.Fatalf("export of a refill with no change: %d %s", code, body)
	}
	s.holds(4*time.Second, "the refill waits, it is not failed", func() bool { return s.refillRows()[0].Status == "broadcast" })
	s.node.mine(2, "")
	if done := s.refillIn("confirmed", 60*time.Second); done.ID != rf.ID {
		t.Fatalf("refill %+v", done)
	}
	s.ledgerOK()
}

// What the offline side will not sign as a replacement, and the fee attacks, through real files between the core and qv-cold: a lower fee, other
// inputs, a changed value of a signed outpoint, a request of another pool, and a request that names another pool's outpoint.
func TestRefillOfflineRefusesWhatIsNotAReplacementAndTheFeeAttacks(t *testing.T) {
	s, rf, _ := brokenRefill(t, opts{}, 10_000_000, 10_000_000, 10_000_000)
	r1 := s.refillRequest(rf.ID)
	if len(r1.Inputs) != 2 || len(r1.Outputs) != 2 {
		t.Fatalf("request %+v: want two inputs and change", r1)
	}
	refused := func(what, want string, r coldsign.BTCRequest) {
		t.Helper()
		_, out, err := s.signRefill(s.writeRequest(strings.ReplaceAll(what, " ", "-"), r))
		if err == nil || !strings.Contains(out+err.Error(), want) {
			t.Fatalf("%s: want a refusal containing %q, got %v\n%s", what, want, err, out)
		}
	}
	// A replacement that pays the same or less is not a replacement.
	lower := r1
	lower.Revision = 5
	lower.Outputs = []coldsign.BTCOutput{r1.Outputs[0], {Address: r1.Outputs[1].Address, Value: r1.Outputs[1].Value + 100}}
	refused("lower fee", "must pay more", lower)
	// The same payment from other inputs is another transaction spending a signed outpoint.
	var third string
	s.pool.QueryRow(s.ctx, `SELECT txid FROM btc_utxos WHERE chain=$1 AND cold AND status='available'`, s.chain).Scan(&third)
	other := r1
	other.Revision = 6
	other.Inputs = []coldsign.BTCInput{r1.Inputs[0], {TxID: third, Vout: 0, Value: 10_000_000, Address: r1.From}}
	refused("other inputs", "only a replacement of that same transaction", other)
	// The fee attack: a signed outpoint with a smaller value next to a new outpoint (to hide a larger fee).
	lie := r1
	lie.Revision = 7
	lie.Inputs = []coldsign.BTCInput{{TxID: r1.Inputs[0].TxID, Vout: r1.Inputs[0].Vout, Value: r1.Inputs[0].Value - 5_000_000, Address: r1.From}, {TxID: third, Vout: 0, Value: 10_000_000, Address: r1.From}}
	lie.Outputs = []coldsign.BTCOutput{{Address: r1.Outputs[0].Address, Value: 14_990_000}}
	refused("changed value", "a second value for a signed outpoint is refused", lie)

	// Two pools: a second cold key with its own config and record. A request for pool A sent to pool B, and a request of pool B that names pool A's outpoint.
	keyJSON := filepath.Join(s.kit.dir, "key2.json")
	s.runCold("keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_HSM_PIN", "-network", "regtest", "-out", keyJSON)
	var key map[string]string
	kb, _ := os.ReadFile(keyJSON)
	json.Unmarshal(kb, &key)
	var cfg coldsign.BTCConfig
	cb, _ := os.ReadFile(s.kit.cfgPath)
	json.Unmarshal(cb, &cfg)
	cfg.Pool, cfg.PublicKey = "retail", key["btc_public_key"]
	cfg.HSM.KeyID, cfg.RecordDir = key["key_id"], filepath.Join(s.kit.dir, "record-retail")
	cfg2 := filepath.Join(s.kit.dir, "cfg-retail.json")
	writeJSONFile(t, cfg2, cfg)
	signB := func(r coldsign.BTCRequest) (string, error) {
		req := s.writeRequest("pool-b", r)
		args := []string{"sign", "-config", cfg2, "-request", req}
		for _, op := range []string{"alice", "bob"} {
			ap := req + "." + op + ".approval.json"
			s.runCold("approve", "-operator", op, "-key", filepath.Join(s.kit.dir, op+".key"), "-request", req, "-out", ap)
			args = append(args, "-approval", ap)
		}
		out, err := s.runColdErr(args...)
		return out, err
	}
	if out, err := signB(r1); err == nil || !strings.Contains(out, "this signer holds pool") && !strings.Contains(out, "cold address is") {
		t.Fatalf("pool B signed a request for pool A: %v\n%s", err, out)
	}
	steal := r1
	steal.Pool, steal.From, steal.Revision = "retail", key["btc_address"], 9
	if out, err := signB(steal); err == nil || !strings.Contains(out, "every input must be from the cold address") {
		t.Fatalf("pool B signed a request that names pool A's outpoints: %v\n%s", err, out)
	}
	if entries, _ := os.ReadDir(filepath.Join(s.kit.dir, "record-retail", "btc", "outpoints")); len(entries) != 0 {
		t.Fatalf("pool B's record holds %d outpoints though it signed nothing", len(entries))
	}
	s.ledgerOK()
}

// A request that was signed offline but never imported expires online; the offline record still pins its outpoints to that intent. The next refill keeps
// that intent (the same inputs and payment, a higher fee), so the record accepts it, and the old file can never pay in addition: it spends the same
// inputs, so at most one of the two confirms.
func TestRefillSignedButNeverImportedIsReplacedByTheNextRefill(t *testing.T) {
	s, rf := lowShard(t, opts{refillTTL: "25s"}, 15_000_000)
	req1 := s.exportRefill(rf.ID, "lost")
	signedLost, out, err := s.signRefill(req1)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	r1 := s.refillRequest(rf.ID)
	got := s.refillIn("failed", 90*time.Second)
	if got.ID != rf.ID || !strings.Contains(got.Reason, "not imported") {
		t.Fatalf("refill %+v", got)
	}
	// The planner opens another; its first export keeps the intent of the lost one.
	var next rfRow
	s.waitFor(60*time.Second, "the next refill", func() bool {
		for _, r := range s.refillRows() {
			if r.Status == "requested" && r.ID != rf.ID {
				next = r
			}
		}
		return next.ID != ""
	})
	s.ceremony(next.ID, "next") // the ceremony fails the test if qv-cold refuses
	r2 := s.refillRequest(next.ID)
	f1, _ := r1.Fee()
	f2, _ := r2.Fee()
	if len(r2.Inputs) != len(r1.Inputs) || r2.Inputs[0].TxID != r1.Inputs[0].TxID || r2.Outputs[0] != r1.Outputs[0] || f2 <= f1 {
		t.Fatalf("the next request %+v does not keep the intent of the lost one %+v (fees %d, %d)", r2, r1, f2, f1)
	}
	done := s.untilRefillConfirmed(next.ID, 120*time.Second)
	if uint64(done.Amount) != r1.Outputs[0].Value {
		t.Fatalf("refill %+v", done)
	}
	// The lost file, sent by hand now, spends inputs that are spent: it cannot pay a second time.
	var lost coldsign.BTCSigned
	lb, _ := os.ReadFile(signedLost)
	json.Unmarshal(lb, &lost)
	var txid string
	if err := s.node.root.Call(s.ctx, &txid, "sendrawtransaction", lost.RawTx); err == nil {
		t.Fatal("the lost signed file was accepted by the node after its inputs were spent")
	}
	s.ledgerOK()
	s.node.mine(8, "")
	s.reconcileClean()
}

// The lost signed file is sent by hand after the request expired, before anything replaces it: the coins go from cold to the hot shard, which is what the
// refill was for, so nothing is lost; the books do not know, and Reconcile names it (a cold output spent behind our back).
func TestRefillTheLostSignedFileBroadcastByHandIsNamedByReconcile(t *testing.T) {
	s, rf := lowShard(t, opts{refillTTL: "25s"}, 15_000_000)
	hotChainBefore := s.onChain(s.hotAddr)
	signedLost, out, err := s.signRefill(s.exportRefill(rf.ID, "lost"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	s.refillIn("failed", 90*time.Second)
	var lost coldsign.BTCSigned
	lb, _ := os.ReadFile(signedLost)
	json.Unmarshal(lb, &lost)
	var txid string
	if err := s.node.root.Call(s.ctx, &txid, "sendrawtransaction", lost.RawTx); err != nil {
		t.Fatalf("by hand: %v", err)
	}
	s.node.mine(8, "")
	s.waitFor(60*time.Second, "the scan books the payment to the hot shard as funding", func() bool { return s.cursor() >= s.node.height()-5 })
	if s.onChain(s.hotAddr) <= hotChainBefore {
		t.Fatal("the hot shard did not receive the payment")
	}
	var r recon
	s.waitFor(60*time.Second, "Reconcile names the cold output", func() bool {
		r = s.reconcile()
		return strings.Contains(r.failedNames(), "outputs_on_chain") && strings.Contains(r.failedNames(), "cold ")
	})
	if r.Clean {
		t.Fatal("Reconcile is clean though a cold output was spent behind our back")
	}
}

// restartNode restarts the compose bitcoind (it runs with -persistmempool=0, so it comes back with an empty mempool) and waits for it. A restarted
// bitcoind has a new cookie: the harness's clients and the system's config get the new one (the processes read the config when they start, so the
// caller starts the worker again; a running core would still hold the old cookie, see restartCore).
func (s *system) restartNode() {
	s.t.Helper()
	cmd := exec.Command("docker", "compose", "--profile", "btc", "restart", "bitcoind")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("restart bitcoind: %v\n%s", err, out)
	}
	s.waitFor(90*time.Second, "bitcoind is back", func() bool {
		u, p, err := readCookie() // fails while the container is down; may still be the old cookie until bitcoind has started
		if err != nil {
			return false
		}
		s.node.root = newRPCWith(nodeURL(), u, p)
		return s.node.root.Call(s.ctx, nil, "getblockcount") == nil
	})
	forgetRPCCreds()
	s.node.w = newRPC(s.t, nodeURL()+"/wallet/"+s.node.walletName)
	_ = s.node.root.Call(s.ctx, nil, "loadwallet", s.node.walletName)
	u, p := rpcCreds(s.t)
	s.cf.Chain.BTC.RPCUser, s.cf.Chain.BTC.RPCPassword = u, p
	s.writeConfig(s.cf)
	s.core.stop() // the running core holds the old cookie
	s.startCore()
}

func (s *system) nodeKnows(txid string) bool {
	var in struct{ Txid string }
	return s.node.root.Call(s.ctx, &in, "getrawtransaction", txid, true) == nil
}

// The node refuses the fee-bumped replacement (the original was given a huge priority, so no replacement can beat it by the replacement rules). The
// refused attempt is forgotten with an ALERT, the original is still the refill's only attempt, and when the node is restarted with an empty mempool it
// is the original that is sent again and confirms.
func TestRefillStuckReplacementRefusedByTheNodeThenTheNodeIsRestarted(t *testing.T) {
	s, rf, orig := brokenRefill(t, opts{}, 15_000_000)
	if err := s.node.root.Call(s.ctx, nil, "prioritisetransaction", orig, 0, 100_000_000); err != nil {
		t.Fatal(err)
	}
	repl := s.replaceCeremony(rf.ID, "repl")
	s.waitFor(150*time.Second, "the ALERT that the node refused the replacement", func() bool { return s.workerLogHas("did not take the fee-bumped replacement") })
	if s.refillAttempts() != 1 || s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND txid=$2`, s.chain, repl) != 0 {
		t.Fatalf("%d attempts, the refused replacement is %s", s.refillAttempts(), map[bool]string{true: "still recorded", false: "forgotten"}[s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND txid=$2`, s.chain, repl) != 0])
	}
	if s.refillRows()[0].Status != "broadcast" {
		t.Fatalf("refill %+v", s.refillRows()[0])
	}
	s.worker.stop() // so that only the cell, after the restart, can send it
	s.restartNode()
	if s.nodeKnows(orig) {
		t.Fatal("the node still knows the original: its mempool was not emptied")
	}
	s.startWorker()
	s.waitFor(150*time.Second, "the original is sent again", func() bool { return s.nodeKnows(orig) })
	s.node.mine(2, "")
	done := s.refillIn("confirmed", 90*time.Second)
	if done.Tx != orig || done.Fee != s.attemptFee(orig) {
		t.Fatalf("refill %+v, the original %s", done, orig)
	}
	s.ledgerOK()
}

// The same for a withdrawal: its fee bump is refused by the node, the original is the only attempt, and after a restart with an empty mempool the original
// is sent again and settles with its own fee.
func TestRefillStuckWithdrawalBumpRefusedByTheNodeThenTheNodeIsRestarted(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, noEstimate: true, fallbackRate: 1, stuckAfter: "6s"})
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	dest, err := s.acct.Address([]uint32{0, 900}) // not an address of the node's wallet: a wallet that sees a payment to it resubmits it itself
	if err != nil {
		t.Fatal(err)
	}
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	b := s.waitWd(w.ID, "broadcast", 60*time.Second)
	if err := s.node.root.Call(s.ctx, nil, "prioritisetransaction", b.Tx, 0, 100_000_000); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Second) // a few stuck intervals: each bump is built, signed and refused
	if n := s.attempts("send"); n != 1 {
		t.Fatalf("%d send attempts: a refused bump must leave no trace", n)
	}
	s.worker.stop()
	s.restartNode()
	if s.nodeKnows(b.Tx) {
		t.Fatal("the node still knows the original")
	}
	s.startWorker()
	s.waitFor(150*time.Second, "the original is sent again", func() bool { return s.nodeKnows(b.Tx) })
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	if got := s.withdrawalFee(w.ID); got != s.attemptFee(b.Tx) {
		t.Fatalf("booked fee %d, the original paid %d", got, s.attemptFee(b.Tx))
	}
	s.ledgerOK()
}
