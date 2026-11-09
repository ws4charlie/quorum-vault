package btce2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// attempts counts the broadcast attempts of a kind ("send" or "cancel").
func (s *system) attempts(kind string) int {
	return s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND kind=$2 AND broadcast_at IS NOT NULL`, s.chain, kind)
}

func (s *system) waitAttempts(kind string, n int, timeout time.Duration) {
	s.t.Helper()
	s.waitFor(timeout, fmt.Sprintf("%d %s attempts broadcast", n, kind), func() bool { return s.attempts(kind) >= n })
}

func (s *system) workerLogHas(sub string) bool { return fileContains(s.worker.log, sub) }

// feeAt is the fee of a transaction with one P2WPKH input and the given number of P2WPKH outputs at a rate in sat/vB.
func feeAt(s *system, outputs int, rate int64) int64 {
	script, _ := btc.OutputScript(s.hotAddr, s.acct.Params)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	for i := 0; i < outputs; i++ {
		tx.AddTxOut(wire.NewTxOut(1, script))
	}
	return btc.EstimateVSize(tx) * rate
}

// breakSecondJob makes the business database give the second job of every withdrawal attempt a key reference that is not its input's: the gateway
// refuses that job and signs the first, which is "one input refused after another was signed". Cancel jobs are not touched.
func (s *system) breakSecondJob() {
	s.t.Helper()
	for _, q := range []string{
		`CREATE FUNCTION qv_break_second() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id LIKE 'wd:%.1' THEN NEW.key_ref := '1/9'; END IF; RETURN NEW; END $$`,
		`CREATE TRIGGER qv_break BEFORE INSERT ON sign_jobs FOR EACH ROW EXECUTE FUNCTION qv_break_second()`,
	} {
		if _, err := s.pool.Exec(s.ctx, q); err != nil {
			s.t.Fatal(err)
		}
	}
}

func (s *system) attemptFee(txid string) int64 {
	var f int64
	if err := s.pool.QueryRow(s.ctx, `SELECT fee FROM btc_attempts WHERE chain=$1 AND txid=$2`, s.chain, txid).Scan(&f); err != nil {
		s.t.Fatal(err)
	}
	return f
}

func (s *system) firstAttempt(kind string) (txid string, raw []byte) {
	if err := s.pool.QueryRow(s.ctx, `SELECT txid, raw FROM btc_attempts WHERE chain=$1 AND kind=$2 AND broadcast_at IS NOT NULL ORDER BY created_at LIMIT 1`, s.chain, kind).Scan(&txid, &raw); err != nil {
		s.t.Fatal(err)
	}
	return
}

func (s *system) lastAttempt(kind string) (txid string) {
	if err := s.pool.QueryRow(s.ctx, `SELECT txid FROM btc_attempts WHERE chain=$1 AND kind=$2 AND broadcast_at IS NOT NULL ORDER BY created_at DESC LIMIT 1`, s.chain, kind).Scan(&txid); err != nil {
		s.t.Fatal(err)
	}
	return
}

// A transaction that sticks at a low fee is replaced by one that pays more (RBF): same inputs, same payment, less change. Both can end the race:
// the replacement confirms, or the original does. The fee booked is the one of the transaction that confirmed.
func TestRecoveryStuckAtALowFeeIsBumpedAndTheReplacementConfirms(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, noEstimate: true, fallbackRate: 1, stuckAfter: "6s"})
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitWd(w.ID, "broadcast", 60*time.Second)
	orig, _ := s.firstAttempt("send")
	s.waitAttempts("send", 2, 60*time.Second) // nothing is mined: it is stuck, and bumped
	repl := s.lastAttempt("send")
	if repl == orig {
		t.Fatal("no replacement")
	}
	fo, fr := s.attemptFee(orig), s.attemptFee(repl)
	if fr <= fo {
		t.Fatalf("the replacement pays %d, the original %d", fr, fo)
	}
	// The node replaced it: the original is gone from the mempool, the replacement is in.
	var in struct{ Txid string }
	if err := s.node.root.Call(s.ctx, &in, "getrawtransaction", repl, true); err != nil {
		t.Fatalf("the replacement is not in the mempool: %v", err)
	}
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.withdrawalFee(w.ID); got != fr {
		t.Fatalf("booked fee %d, the confirmed replacement paid %d (the original %d)", got, fr, fo)
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	if s.utxoCount("spent") != 1 || s.utxoCount("reserved") != 0 {
		t.Fatalf("spent %d reserved %d", s.utxoCount("spent"), s.utxoCount("reserved"))
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+10_000_000+fr {
		t.Fatalf("hot mirror %d", got)
	}
	s.ledgerOK()
}

func TestRecoveryStuckAtALowFeeAndTheOriginalConfirms(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, noEstimate: true, fallbackRate: 1, stuckAfter: "6s"})
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitWd(w.ID, "broadcast", 60*time.Second)
	orig, rawOrig := s.firstAttempt("send")
	s.waitAttempts("send", 2, 60*time.Second)
	repl := s.lastAttempt("send")
	// A miner that never saw the replacement includes the original: the block holds it, the replacement conflicts and is dropped.
	var out json.RawMessage
	if err := s.node.root.Call(s.ctx, &out, "generateblock", s.node.fresh(), []string{fmt.Sprintf("%x", rawOrig)}); err != nil {
		t.Fatalf("a block with the original: %v", err)
	}
	s.node.mine(1, s.node.fresh())
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	fo := s.attemptFee(orig)
	if got := s.withdrawalFee(w.ID); got != fo {
		t.Fatalf("booked fee %d, the confirmed original paid %d (a replacement paid %d)", got, fo, s.attemptFee(repl))
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2 AND status='available'`, s.chain, orig); n != 1 {
		t.Fatalf("the original's change is not an available output (%d)", n)
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2`, s.chain, repl); n != 0 {
		t.Fatalf("the replacement's change was recorded though it never confirmed")
	}
	var x struct{ Txid string }
	if err := s.node.root.Call(s.ctx, &x, "getrawtransaction", repl, true); err == nil {
		t.Fatal("the replacement is known to the node after the original confirmed")
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+10_000_000+fo {
		t.Fatalf("hot mirror %d", got)
	}
	s.ledgerOK()
}

// No change, no bump: an exact payment has nothing to pay a higher fee from. The workflow raises an ALERT, keeps waiting, never voids, and the
// withdrawal settles when the transaction is mined.
func TestRecoveryStuckWithNoChangeAlertsAndWaits(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, noEstimate: true, fallbackRate: 1, stuckAfter: "5s"})
	s.fundHot(10_000_000 + feeAt(s, 1, 1)) // exactly the payment and the fee of a one-output transaction
	s.deposit("c1", 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitWd(w.ID, "broadcast", 60*time.Second)
	s.waitFor(60*time.Second, "the ALERT that it cannot be replaced", func() bool { return s.workerLogHas("cannot be replaced") })
	s.holds(8*time.Second, "the withdrawal waits, it is not voided", func() bool { return s.getWd(w.ID).Status == "broadcast" })
	if n := s.attempts("send"); n != 1 {
		t.Fatalf("%d attempts: a transaction with no change cannot be replaced", n)
	}
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	s.ledgerOK()
}

// One input is refused after another was signed: a signature exists, so the attempt cannot be forgotten. A cancel is built, signed and sent, spending
// the same inputs back to the shard; the money is released only after it confirms; the half-signed transaction can no longer confirm.
func TestRecoveryOneInputRefusedAfterAnotherWasSignedSendsACancel(t *testing.T) {
	s := newSystem(t, opts{withdraw: true})
	s.fundHot(5_000_000)
	s.fundHot(5_000_000)
	s.deposit("c1", 20_000_000)
	s.breakSecondJob()
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 7_000_000)
	s.waitAttempts("cancel", 1, 90*time.Second)
	// Not released before the cancel confirms: the hold is in place and the withdrawal is not failed.
	s.holds(4*time.Second, "the money stays held until the cancel confirms", func() bool {
		return s.getWd(w.ID).Status != "failed" && s.available("c1").Int64() == 13_000_000
	})
	if n := s.attempts("send"); n != 0 {
		t.Fatalf("%d withdrawal transactions were broadcast", n)
	}
	s.node.mine(2, "")
	got := s.waitWd(w.ID, "failed", 60*time.Second)
	if !strings.Contains(got.Reason, "gateway refused") {
		t.Fatalf("reason %q", got.Reason)
	}
	cancel := s.lastAttempt("cancel")
	fee := s.attemptFee(cancel)
	if a := s.available("c1").Int64(); a != 20_000_000 {
		t.Fatalf("customer has %d after the void", a)
	}
	// Both inputs are spent by the cancel, so nothing else can ever spend them: the half-signed transaction can no longer confirm.
	var p struct{ Inputs []btc.PayloadInput }
	var raw []byte
	s.pool.QueryRow(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND txid=$2`, s.chain, cancel).Scan(&raw)
	json.Unmarshal(raw, &p)
	for _, in := range p.Inputs {
		var o json.RawMessage
		if err := s.node.root.Call(s.ctx, &o, "gettxout", in.TxID, in.Vout, false); err != nil || string(o) != "null" {
			t.Fatalf("input %s:%d is still unspent on chain (%s %v)", in.TxID, in.Vout, o, err)
		}
	}
	if s.utxoCount("spent") != 2 || s.utxoCount("available") != 1 || s.utxoCount("reserved") != 0 || s.utxoValue("available") != 10_000_000-fee {
		t.Fatalf("outputs: spent %d available %d (%d sats) reserved %d, want the cancel's output of %d", s.utxoCount("spent"), s.utxoCount("available"), s.utxoValue("available"), s.utxoCount("reserved"), 10_000_000-fee)
	}
	if got := s.received(dest, 0); got != 0 {
		t.Fatalf("the destination received %d", got)
	}
	if got := s.hotPosted().Int64(); got != -10_000_000+fee {
		t.Fatalf("hot mirror %d, want %d (the cancel's fee is the only cost)", got, -10_000_000+fee)
	}
	s.ledgerOK()
	// The cancel's output is spendable.
	w2 := s.withdraw("ini", "k2", "c1", s.node.fresh(), 3_000_000)
	s.settle(w2.ID)
}

// The crash boundaries: the worker dies at each, is restarted, and the withdrawal ends in exactly one payment and a balanced ledger.
func TestRecoveryCrashAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		failpoint string
		mineFirst bool // the boundary comes after the transaction is final
	}{
		{"withdrawal.after_build", false},
		{"withdrawal.after_job", false},
		{"withdrawal.after_broadcast", false},
		{"withdrawal.after_confirm", true},
	} {
		t.Run(tc.failpoint, func(t *testing.T) {
			s := newSystem(t, opts{withdraw: true, failpoint: tc.failpoint})
			s.fundHot(50_000_000)
			s.deposit("c1", 30_000_000)
			dest := s.node.fresh()
			w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
			if tc.mineFirst {
				s.waitWd(w.ID, "broadcast", 60*time.Second)
				s.node.mine(2, "")
			}
			s.waitExit(s.worker, "the worker at "+tc.failpoint)
			s.restartWorker()
			s.settle(w.ID)
			s.assertOnePayment(w.ID, dest, 10_000_000, 50_000_000)
		})
	}
}

// assertOnePayment checks the end state of a withdrawal that was paid once: one payment on chain, one send attempt, the books balanced.
func (s *system) assertOnePayment(id, dest string, amount, hotFunding int64) {
	s.t.Helper()
	if got := s.received(dest, 1); got != amount {
		s.t.Fatalf("the destination received %d, want %d", got, amount)
	}
	if n := s.attempts("send"); n != 1 {
		s.t.Fatalf("%d send attempts", n)
	}
	fee := s.withdrawalFee(id)
	if fee <= 0 {
		s.t.Fatalf("fee %d", fee)
	}
	if got := s.hotPosted().Int64(); got != -hotFunding+amount+fee {
		s.t.Fatalf("hot mirror %d, want %d", got, -hotFunding+amount+fee)
	}
	if s.utxoCount("reserved") != 0 || s.utxoCount("spent") != 1 {
		s.t.Fatalf("outputs: reserved %d spent %d", s.utxoCount("reserved"), s.utxoCount("spent"))
	}
	s.ledgerOK()
}

// The worker dies right after it sent the cancel: after the restart the same cancel is found in the node, confirmed, and the money is released once.
func TestRecoveryCrashAfterTheCancelWasSent(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, failpoint: "cancel.after_broadcast"})
	s.fundHot(5_000_000)
	s.fundHot(5_000_000)
	s.deposit("c1", 20_000_000)
	s.breakSecondJob()
	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 7_000_000)
	s.waitExit(s.worker, "the worker after the cancel")
	s.restartWorker()
	s.node.mine(2, "")
	s.waitWd(w.ID, "failed", 90*time.Second)
	if s.attempts("cancel") != 1 || s.attempts("send") != 0 {
		t.Fatalf("%d cancels, %d sends", s.attempts("cancel"), s.attempts("send"))
	}
	if a := s.available("c1").Int64(); a != 20_000_000 {
		t.Fatalf("customer has %d", a)
	}
	if s.utxoCount("spent") != 2 || s.utxoCount("available") != 1 || s.utxoCount("reserved") != 0 {
		t.Fatalf("outputs: spent %d available %d reserved %d", s.utxoCount("spent"), s.utxoCount("available"), s.utxoCount("reserved"))
	}
	s.ledgerOK()
}

// The gateway dies in the middle of an attempt, after it signed one input: a restarted gateway finishes it (the stored signature comes back as a
// replay, nothing is signed twice), and the withdrawal ends in one payment.
func TestRecoveryGatewayKilledInTheMiddleOfAnAttempt(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, lease: "4s"})
	s.fundHot(5_000_000)
	s.fundHot(5_000_000)
	s.deposit("c1", 20_000_000)
	_ = s.gateway.cmd.Process.Signal(syscall.SIGSTOP) // nothing is claimed while it is stopped
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 7_000_000)
	s.waitFor(60*time.Second, "both jobs are enqueued", func() bool { return s.count(`SELECT count(*) FROM sign_jobs WHERE status='pending'`) == 2 })
	_ = s.gateway.cmd.Process.Signal(syscall.SIGCONT)
	s.waitFor(30*time.Second, "one job is signed", func() bool { return s.count(`SELECT count(*) FROM sign_jobs WHERE status='done'`) >= 1 })
	_ = s.gateway.cmd.Process.Kill() // the gateway dies mid-attempt
	<-s.gateway.done
	s.startGateway()
	s.settle(w.ID)
	if got := s.received(dest, 1); got != 7_000_000 {
		t.Fatalf("received %d", got)
	}
	if n := s.attempts("send"); n != 1 {
		t.Fatalf("%d attempts", n)
	}
	s.ledgerOK()
}

// onChain is what the UTXO set holds for an address that is not in the node's wallet, in satoshis (a wallet would also keep and resend a transaction that
// pays it, which is not what this test is about).
func (s *system) onChain(addr string) int64 {
	s.t.Helper()
	var res struct {
		Total json.Number `json:"total_amount"`
	}
	if err := s.node.root.Call(s.ctx, &res, "scantxoutset", "start", []string{"addr(" + addr + ")"}); err != nil {
		s.t.Fatal(err)
	}
	n, err := btc.Sats(res.Total.String())
	if err != nil {
		s.t.Fatal(err)
	}
	return n.Int64()
}

// The node is restarted with an empty mempool: the transaction it forgot is sent again by the cell, and the withdrawal settles. The destination is not
// an address of the node's wallet: a wallet that sees a transaction paying it keeps it and resubmits it itself.
func TestRecoveryNodeRestartedWithAnEmptyMempool(t *testing.T) {
	s := withdrawalSystem(t, opts{}, 50_000_000, 30_000_000)
	dest, err := s.acct.Address([]uint32{0, 900})
	if err != nil {
		t.Fatal(err)
	}
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	got := s.waitWd(w.ID, "broadcast", 60*time.Second)
	var in struct{ Txid string }
	if err := s.node.root.Call(s.ctx, &in, "getrawtransaction", got.Tx, true); err != nil {
		t.Fatalf("the transaction is not in the mempool: %v", err)
	}
	s.worker.stop() // so that the cell cannot send it again before we have seen that the node forgot it
	s.restartNode()
	var again struct{ Txid string }
	if err := s.node.root.Call(s.ctx, &again, "getrawtransaction", got.Tx, true); err == nil {
		t.Fatal("the node still knows the transaction: its mempool was not emptied")
	}
	s.workerFailpoint = ""
	s.startWorker()
	// The cell notices that the node forgot it and sends it again.
	s.waitFor(90*time.Second, "the transaction is sent again", func() bool { return s.node.root.Call(s.ctx, &again, "getrawtransaction", got.Tx, true) == nil })
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if n := s.onChain(dest); n != 10_000_000 {
		t.Fatalf("the destination holds %d on chain", n)
	}
	if n := s.attempts("send"); n != 1 {
		t.Fatalf("%d attempts", n)
	}
	s.ledgerOK()
}

// An output the withdrawal reserved is spent by something outside this system: the key signed a second transaction through a gateway that shares
// party B's cosigner but not our gateway's records, and that transaction was mined. The cell does not release the output, because it is gone from the
// chain: the withdrawal is parked with an ALERT, the money stays held, and nothing is paid.
func TestRecoveryOutsideSpendOfAReservedOutputParks(t *testing.T) {
	s := withdrawalSystem(t, opts{}, 50_000_000, 30_000_000)
	_ = s.gateway.cmd.Process.Signal(syscall.SIGSTOP) // our gateway has not seen the withdrawal's jobs yet
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitFor(60*time.Second, "the withdrawal is built", func() bool { return s.utxoCount("reserved") == 1 })
	var u struct {
		txid string
		vout uint32
		val  int64
	}
	if err := s.pool.QueryRow(s.ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND status='reserved'`, s.chain).Scan(&u.txid, &u.vout, &u.val); err != nil {
		t.Fatal(err)
	}
	s.outsideSpend(u.txid, u.vout, uint64(u.val), s.node.fresh())
	s.node.mine(2, "")
	_ = s.gateway.cmd.Process.Signal(syscall.SIGCONT)
	s.waitFor(90*time.Second, "the withdrawal is parked", func() bool { return strings.HasPrefix(s.getWd(w.ID).Reason, "parked:") })
	if !s.workerLogHas("ALERT") {
		t.Fatal("no ALERT")
	}
	s.holds(4*time.Second, "parked, not voided or paid", func() bool {
		return s.getWd(w.ID).Status != "failed" && s.getWd(w.ID).Status != "confirmed" && s.available("c1").Int64() == 20_000_000
	})
	if s.attempts("send") != 0 || s.received(dest, 0) != 0 {
		t.Fatal("something was paid")
	}
}

// outsideSpend signs a withdrawal of one output through a gateway of its own (own guard database, the same signing zone config and MPC keys, so the same
// party B cosigner) and sends it to the node. It stands for a key that signed outside this system.
func (s *system) outsideSpend(txid string, vout uint32, value uint64, to string) {
	in := signjob.Intent{Kind: "withdrawal", ID: "outside-1", PartitionID: s.part, Chain: s.chain, Asset: "BTC", To: to, Amount: fmt.Sprint(value - 3000), NotAfter: time.Now().Add(time.Hour).Unix()}
	s.outsideSign(txid, vout, value, to, []uint32{1, 0}, in, true)
}

// outsideSweepSpend does the same for a deposit output: a sweep intent of the deposit address at index idx into the hot shard, signed outside.
func (s *system) outsideSweepSpend(txid string, vout uint32, value uint64, from string, idx uint32) {
	in := signjob.Intent{Kind: "sweep", ID: "outside-sweep", PartitionID: s.part, Chain: s.chain, Asset: "BTC", From: from, To: s.hotAddr, Amount: fmt.Sprint(value)}
	s.outsideSign(txid, vout, value, s.hotAddr, []uint32{0, idx}, in, false)
}

func (s *system) outsideSign(txid string, vout uint32, value uint64, to string, path []uint32, in signjob.Intent, approved bool) {
	t := s.t
	cfg, err := gateway.LoadConfig(s.gwPath)
	if err != nil {
		t.Fatal(err)
	}
	signers, closeSigners, err := gateway.MPCSigners(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gwPool, _ := gatewaytest.NewGuardDB(t)
	guard, err := gateway.OpenGuard(s.ctx, gwPool)
	if err != nil {
		t.Fatal(err)
	}
	biz := dbtest.New(t)
	rogue, err := gateway.New(cfg, nil, signers, guard, biz, gateway.Options{WorkerID: "outside", Lease: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rogue.Wait(10 * time.Second); closeSigners() })
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('` + s.chain + `','BTC',8)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + s.part + `','qv-us','` + s.chain + `','BTC','hot','omnibus',0)`,
	} {
		if _, err := biz.Exec(s.ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: txid, Vout: vout, Value: value, Path: path, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: to, Value: value - 3000}}}
	built, err := btc.BuildUnsigned(p, s.acct)
	if err != nil {
		t.Fatal(err)
	}
	h := in.Hash()
	raw, _ := json.Marshal(p)
	j := signjob.Job{ID: "outside:a1", PartitionID: s.part, KeyRef: btc.PathString(path), Chain: s.chain, Intent: mustJSON(in), Digest: built.Digests[0], Payload: raw}
	if approved {
		j.Approvals = []signjob.Approval{{Actor: "alice", Signature: ed25519.Sign(s.approv["alice"], h[:])}}
	}
	tx, err := biz.Begin(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := signjob.Enqueue(s.ctx, tx, j); err != nil {
		t.Fatal(err)
	}
	tx.Commit(s.ctx)
	d, ok, err := rogue.RunOnce(s.ctx)
	if err != nil || !ok || d.Outcome != gateway.OutcomeSigned {
		t.Fatalf("the outside signing: %+v ok=%v err=%v", d, ok, err)
	}
	got, _ := signjob.Get(s.ctx, biz, j.ID)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(got.Signature[:32]), new(big.Int).SetBytes(got.Signature[32:])})
	if err != nil {
		t.Fatal(err)
	}
	built.Tx.TxIn[0].Witness = wire.TxWitness{append(der, byte(txscript.SigHashAll)), built.Pubs[0]}
	var buf bytes.Buffer
	if err := built.Tx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	var out string
	if err := s.node.root.Call(s.ctx, &out, "sendrawtransaction", fmt.Sprintf("%x", buf.Bytes())); err != nil {
		t.Fatalf("the outside transaction was refused by the node: %v", err)
	}
	_ = context.Background
}
