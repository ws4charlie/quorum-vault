package btce2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// CPFP: a send that RBF cannot raise any more is pulled in by a child that spends its change back to the hot shard. The tests run on real mpc-party, the
// signing gateway and party B's cosigner (which both check the child against what they signed), the workflows and bitcoind regtest.
//
// A stuck parent is made the way a real one is stuck: the node's miner will not take it alone. prioritisetransaction lowers its modified fee, so that its own
// rate is under the miner's minimum while the pair, with the child's fee, is over it; a block mined while only the parent exists leaves it in the mempool.

// cpfpOpts: the parent pays 1 sat/vB, gets one replacement (2 sat/vB) and RBF is then exhausted; 6 seconds later the child follows.
func cpfpOpts() opts {
	return opts{withdraw: true, noEstimate: true, fallbackRate: 1, stuckAfter: "3s", maxReplacements: 1, cpfpAfter: "6s"}
}

// holdBack lowers the modified fee of a transaction so that the miner leaves it alone, whatever it pays: it keeps `keep` sats of fee for the miner's
// accounting. A child that pays for the pair brings the package over the miner's minimum again.
func (s *system) holdBack(txid string, keep int64) {
	s.t.Helper()
	var ok bool
	if err := s.node.root.Call(s.ctx, &ok, "prioritisetransaction", txid, 0, -(s.attemptFee(txid) - keep)); err != nil {
		s.t.Fatalf("prioritisetransaction: %v", err)
	}
}

// confs is the confirmations the node reports for a transaction: -1 when it does not know it, 0 in the mempool.
func (s *system) confs(txid string) int64 {
	s.t.Helper()
	var tx struct {
		Confirmations int64 `json:"confirmations"`
	}
	err := s.node.root.Call(s.ctx, &tx, "getrawtransaction", txid, true)
	if err != nil {
		if strings.Contains(err.Error(), "No such mempool or blockchain transaction") {
			return -1
		}
		s.t.Fatal(err)
	}
	return tx.Confirmations
}

// childOf is the payload of the CPFP attempt that spends the change of parent, and its txid.
func (s *system) childOf(parent string) (string, btc.Payload) {
	s.t.Helper()
	var txid string
	s.waitFor(120*time.Second, "a CPFP child of "+parent+" is broadcast", func() bool {
		return s.pool.QueryRow(s.ctx, `SELECT txid FROM btc_attempts WHERE chain=$1 AND kind='cpfp' AND broadcast_at IS NOT NULL AND payload->'inputs'->0->>'txid'=$2 ORDER BY created_at DESC LIMIT 1`,
			s.chain, parent).Scan(&txid) == nil
	})
	return txid, s.payloadOf(txid)
}

// assertChild checks the shape of a child: one input, the change of the parent (its last output), one output, to the hot shard, nothing else.
func (s *system) assertChild(child btc.Payload, parent string) {
	s.t.Helper()
	pp := s.payloadOf(parent)
	last := len(pp.Outputs) - 1
	if len(child.Inputs) != 1 || child.Inputs[0].TxID != parent || int(child.Inputs[0].Vout) != last || child.Inputs[0].Value != pp.Outputs[last].Value {
		s.t.Fatalf("the child must spend the parent's change: %+v (parent outputs %+v)", child.Inputs, pp.Outputs)
	}
	if len(child.Outputs) != 1 || child.Outputs[0].Address != s.hotAddr {
		s.t.Fatalf("the child must pay the hot shard and nobody else: %+v", child.Outputs)
	}
}

// A withdrawal whose RBF is used up (one replacement) and that the miner will not take alone: after cpfp_after a child spends its change and pulls it in.
// Both confirm in one block, the destination is paid once, the withdrawal's fee is the parent's and the child's together, the child's output is the hot coin
// that replaces the change, and the books and the chain agree.
func TestCPFPPullsAStuckWithdrawalIn(t *testing.T) {
	s := newSystem(t, cpfpOpts())
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitAttempts("send", 2, 60*time.Second) // the one replacement
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	if c := s.confs(parent); c != 0 {
		t.Fatalf("the parent has %d confirmations: the miner must leave it in the mempool", c)
	}
	child, cp := s.childOf(parent)
	s.assertChild(cp, parent)
	pf, cf := s.attemptFee(parent), s.attemptFee(child)
	if cf <= 0 {
		t.Fatalf("child fee %d", cf)
	}
	if rate := float64(pf+cf) / float64(parentVSize(s, child)+parentVSize(s, parent)); rate <= float64(pf)/float64(parentVSize(s, parent)) {
		t.Fatalf("the package pays %.2f sat/vB, not more than the parent alone", rate)
	}
	if !s.workerLogHas("replacements exhausted") {
		t.Fatal("no ALERT that the replacements are exhausted")
	}
	s.node.mine(1, "")
	if s.confs(parent) < 1 || s.confs(child) < 1 {
		t.Fatalf("the parent (%d) and the child (%d) must be in the same block", s.confs(parent), s.confs(child))
	}
	s.node.mine(1, "")
	got := s.waitWd(w.ID, "confirmed", 90*time.Second)
	if got.Tx != parent {
		t.Fatalf("the withdrawal confirmed as %s, the parent is %s", got.Tx, parent)
	}
	if fee := s.withdrawalFee(w.ID); fee != pf+cf {
		t.Fatalf("booked fee %d, want the parent's %d plus the child's %d", fee, pf, cf)
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+10_000_000+pf+cf {
		t.Fatalf("hot mirror %d", got)
	}
	// The change of the parent never became a coin; the child's output did, and it is spendable.
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2`, s.chain, parent); n != 0 {
		t.Fatalf("%d coins from the parent: its change was spent by the child", n)
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid=$2 AND vout=0 AND status='available'`, s.chain, child); n != 1 {
		t.Fatal("the child's output is not an available hot coin")
	}
	if n := s.attempts("cpfp"); n != 1 {
		t.Fatalf("%d children: one child per parent", n)
	}
	s.ledgerOK()
	s.reconcileClean()
	// The coin works: the next withdrawal can spend it.
	next := s.withdraw("ini", "k2", "c1", s.node.fresh(), 1_000_000)
	s.settle(next.ID)
}

// A batch is a parent too: the child pulls the whole batch in, and the fee the batch booked (split among the members) is the batch's and the child's together.
func TestCPFPPullsABatchIn(t *testing.T) {
	s := batchSystem(t, cpfpOpts(), batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	s.waitAttempts("send", 2, 60*time.Second)
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	if c := s.confs(parent); c != 0 {
		t.Fatalf("the batch has %d confirmations: the miner must leave it in the mempool", c)
	}
	child, cp := s.childOf(parent)
	s.assertChild(cp, parent)
	s.node.mine(1, "")
	if s.confs(parent) < 1 || s.confs(child) < 1 {
		t.Fatal("the batch and its child must be in the same block")
	}
	got := s.mineBatch(b.ID)
	if want := s.attemptFee(parent) + s.attemptFee(child); got.Fee != want || got.Tx != parent {
		t.Fatalf("batch %+v, want fee %d (batch and child together) in %s", got, want, parent)
	}
	var sum int64
	for i, id := range got.Members {
		sum += s.feeShares(b.ID)[i]
		if r := s.wdRow(id); r.Status != "confirmed" {
			t.Fatalf("withdrawal %s: %+v", id, r)
		}
	}
	if sum != got.Fee {
		t.Fatalf("the shares add up to %d, the fee is %d", sum, got.Fee)
	}
	for _, w := range ws {
		if r := s.received(w.dest, 1); r != w.amount {
			t.Fatalf("%s received %d", w.ID, r)
		}
	}
	s.ledgerOK()
	s.reconcileClean()
}

// A cancel is still possible once a child exists: it replaces the parent and so evicts the child, whatever the miner thought of them. Only what confirms
// is booked: the cancel's fee, not the child's; the members go back to the queue.
func TestCPFPCancelAfterAChildEvictsBoth(t *testing.T) {
	s := batchSystem(t, cpfpOpts(), batchingOpts{outputs: 2, wait: "10m", inFlight: 1}, 100_000_000)
	ws := []bw{s.payQ(5_000_000), s.payQ(6_000_000)}
	b := s.untilBatches("broadcast", 1, 90*time.Second)[0]
	s.waitAttempts("send", 2, 60*time.Second)
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	child, _ := s.childOf(parent)
	if s.confs(child) != 0 {
		t.Fatal("the child is not in the mempool")
	}
	if code, out := s.cancelBatch(b.ID); code != http.StatusAccepted {
		t.Fatalf("cancel the batch: %d %v", code, out)
	}
	s.waitAttempts("cancel", 1, 120*time.Second)
	cancel := s.lastAttempt("cancel")
	if need := s.attemptFee(parent) + s.attemptFee(child); s.attemptFee(cancel) <= need {
		t.Fatalf("the cancel pays %d; it evicts a parent and a child that paid %d together", s.attemptFee(cancel), need)
	}
	s.node.mine(2, "")
	got := s.untilBatches("cancelled", 1, 90*time.Second)[0]
	if got.ID != b.ID || got.Cancel != cancel {
		t.Fatalf("batch %+v", got)
	}
	if s.confs(parent) != -1 || s.confs(child) != -1 {
		t.Fatalf("the parent (%d) and the child (%d) must be gone from the node", s.confs(parent), s.confs(child))
	}
	if n := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND txid IN ($2,$3)`, s.chain, parent, child); n != 0 {
		t.Fatalf("%d coins from an evicted parent or child", n)
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+got0(s, b.ID) {
		t.Fatalf("hot mirror %d: only the cancel's fee is a cost", got)
	}
	for _, w := range ws {
		if r := s.wdRow(w.ID); r.Status == "failed" || r.Status == "confirmed" {
			t.Fatalf("withdrawal %s is %+v: it should wait for the next batch", w.ID, r)
		}
	}
	s.ledgerOK()
	s.reconcileClean()
}

// The worker dies after the child was signed and before it was sent. When it is back the child is sent (the signature is kept, nothing is signed twice),
// the pair confirms, and the books are as if nothing happened.
func TestCPFPCrashBetweenTheChildsSignAndBroadcast(t *testing.T) {
	o := cpfpOpts()
	o.failpoint = "withdrawal.cpfp_after_sign"
	s := newSystem(t, o)
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 10_000_000)
	s.waitAttempts("send", 2, 60*time.Second)
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	s.waitExit(s.worker, "the worker after the child was signed")
	if n := s.attempts("cpfp"); n != 0 {
		t.Fatalf("%d children were sent before the crash", n)
	}
	if n := s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND kind='cpfp'`, s.chain); n != 1 {
		t.Fatalf("%d child rows: the child was built and signed once", n)
	}
	s.restartWorker()
	child, cp := s.childOf(parent)
	s.assertChild(cp, parent)
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	if fee := s.withdrawalFee(w.ID); fee != s.attemptFee(parent)+s.attemptFee(child) {
		t.Fatalf("booked fee %d", fee)
	}
	if n := s.count(`SELECT count(*) FROM btc_attempts WHERE chain=$1 AND kind='cpfp'`, s.chain); n != 1 {
		t.Fatalf("%d child rows after the restart", n)
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// hostile enqueues a sign job for a CPFP intent as a compromised business zone would (nothing the core's own builders would make) and returns its final
// state: "done" or "rejected: <reason>".
func (s *system) hostile(id string, p btc.Payload, intent signjob.Intent) (status, reason string) {
	s.t.Helper()
	u, err := btc.BuildUnsigned(p, s.acct)
	if err != nil {
		s.t.Fatal(err)
	}
	intent.Chain, intent.PartitionID, intent.Asset, intent.Kind = s.chain, s.part, "BTC", "cpfp"
	if intent.Amount == "" {
		intent.Amount = "0"
	}
	tx, err := s.pool.Begin(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := signjob.Enqueue(s.ctx, tx, signjob.Job{ID: id, PartitionID: s.part, KeyRef: btc.PathString(p.Inputs[0].Path), Chain: s.chain, Intent: mustJSON(intent),
		Digest: u.Digests[0], Payload: mustJSON(p)}); err != nil {
		s.t.Fatal(err)
	}
	if err := tx.Commit(s.ctx); err != nil {
		s.t.Fatal(err)
	}
	s.waitFor(60*time.Second, "job "+id+" is decided", func() bool {
		if err := s.pool.QueryRow(s.ctx, `SELECT status, COALESCE(reject_reason,'') FROM sign_jobs WHERE id=$1`, id).Scan(&status, &reason); err != nil {
			s.t.Fatal(err)
		}
		return status == "done" || status == "rejected"
	})
	return
}

// What a compromised business zone could try with a child, against the real gateway and cosigner: pay anyone else, spend an output that is not the shard's
// own, spend something that is not the change of a send the zone signed, exceed the caps, and add a second child. Each is refused; only the core's own child
// is ever signed.
func TestCPFPTheZoneRefusesEveryHostileChild(t *testing.T) {
	s := newSystem(t, cpfpOpts())
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 10_000_000)
	s.waitAttempts("send", 2, 60*time.Second)
	parent := s.lastAttempt("send")
	s.holdBack(parent, 80)
	s.node.mine(1, "")
	child, cp := s.childOf(parent) // the core's own child, signed
	pp := s.payloadOf(parent)
	last := len(pp.Outputs) - 1
	change := pp.Outputs[last]
	mk := func(value uint64, fee uint64, to string) btc.Payload {
		return btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: parent, Vout: uint32(last), Value: value, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
			Outputs: []btc.PayloadOutput{{Address: to, Value: value - fee}}}
	}
	n := 0
	refused := func(what, code string, p btc.Payload, in signjob.Intent) {
		t.Helper()
		n++
		st, why := s.hostile(fmt.Sprintf("cpfp-hostile-%d", n), p, in)
		if st != "rejected" || !strings.Contains(why, code) {
			t.Fatalf("%s: %s %q, want rejected with %s", what, st, why, code)
		}
	}
	refused("pays another address", "tx_mismatch", mk(change.Value, 3_000, s.node.fresh()), signjob.Intent{ID: "cpfp-x1", To: s.hotAddr})
	two := mk(change.Value, 3_000, s.hotAddr)
	two.Outputs = append(two.Outputs, btc.PayloadOutput{Address: s.node.fresh(), Value: 1_000})
	two.Outputs[0].Value -= 1_000
	refused("a payment output as well", "tx_mismatch", two, signjob.Intent{ID: "cpfp-x2", To: s.hotAddr})
	var depTx string
	var depVout int
	var depVal int64
	var depPath string
	if err := s.pool.QueryRow(s.ctx, `SELECT txid, vout, value, path FROM btc_utxos WHERE chain=$1 AND deposit ORDER BY created_at LIMIT 1`, s.chain).Scan(&depTx, &depVout, &depVal, &depPath); err != nil {
		t.Fatal(err)
	}
	dp, err := btc.ParsePath(depPath)
	if err != nil {
		t.Fatal(err)
	}
	dep := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: depTx, Vout: uint32(depVout), Value: uint64(depVal), Path: dp, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: s.hotAddr, Value: uint64(depVal) - 2_000}}}
	refused("spends a deposit output, not the shard's own", "tx_mismatch", dep, signjob.Intent{ID: "cpfp-x3", To: s.hotAddr})
	other := mk(change.Value, 3_000, s.hotAddr)
	other.Inputs[0].TxID = strings.Repeat("ab", 32)
	refused("spends something that is not the change of a signed send", "policy_cpfp", other, signjob.Intent{ID: "cpfp-x4", To: s.hotAddr})
	wrong := mk(change.Value+500_000, 3_000, s.hotAddr)
	refused("the change with another value", "policy_cpfp", wrong, signjob.Intent{ID: "cpfp-x5", To: s.hotAddr})
	refused("a fee over the caps", "tx_mismatch", mk(change.Value, change.Value-1_000, s.hotAddr), signjob.Intent{ID: "cpfp-x6", To: s.hotAddr})
	// A second child of the same parent: the change is the first child's claim.
	refused("a second child", "replay_nonce_taken", mk(change.Value, 4_000, s.hotAddr), signjob.Intent{ID: "cpfp-x7", To: s.hotAddr})
	// And a payment by an approved-looking intent kind through the same door: the kind is not a withdrawal.
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE id LIKE 'cpfp-hostile-%' AND status='done'`); n != 0 {
		t.Fatalf("%d hostile jobs were signed", n)
	}
	// The core's own child still goes through and pulls the parent in.
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	if fee := s.withdrawalFee(w.ID); fee != s.attemptFee(parent)+s.attemptFee(child) {
		t.Fatalf("booked fee %d", fee)
	}
	_ = cp
	s.ledgerOK()
	s.reconcileClean()
}

// parentVSize is the virtual size of a transaction of ours as the cell estimates it (the sizes the fee rules use).
func parentVSize(s *system, txid string) int64 {
	u, err := btc.BuildUnsigned(s.payloadOf(txid), s.acct)
	if err != nil {
		s.t.Fatal(err)
	}
	return btc.EstimateVSize(u.Tx)
}
