package custody_test

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

func (s *system) automine(on bool) {
	s.t.Helper()
	if err := s.rc.CallContext(s.ctx, nil, "evm_setAutomine", on); err != nil {
		s.t.Fatal(err)
	}
}

func (s *system) mine() { _ = s.rc.CallContext(s.ctx, nil, "evm_mine") }

func (s *system) waitBroadcast(id string) string {
	s.t.Helper()
	var tx string
	s.waitFor(60*time.Second, "withdrawal broadcast", func() bool {
		tx = s.getWd(id).Tx
		return tx != ""
	})
	return tx
}

func (s *system) attempts(id string) int {
	return s.count(`SELECT count(*) FROM evm_tx_attempts at JOIN evm_nonce_allocations al ON al.chain=at.chain AND al.address=at.address AND al.nonce=at.nonce WHERE al.owner_id=$1`, id)
}

func half() *big.Int { return new(big.Int).Div(eth(1), big.NewInt(2)) }

// A withdrawal that mines with status 0 (the destination turned into a
// contract that reverts after the transaction was built): the hold is voided,
// the customer can spend the money again, the fee is booked, and the same
// address keeps working.
func TestRevertedWithdrawalVoidsAndRecordsFee(t *testing.T) {
	s, _ := funded(t, opts{stuckAfter: "90s"}, "c-revert", 5)
	dest := randAddr()
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	w := s.withdraw("initiator", "k-revert", "c-revert", "ETH", dest, half())
	s.waitBroadcast(w.ID)
	// REVERT: 0x60 00 60 00 fd
	if err := s.rc.CallContext(s.ctx, nil, "anvil_setCode", dest, "0x60006000fd"); err != nil {
		t.Fatal(err)
	}
	s.automine(true)
	s.mine()
	got := s.waitWd(w.ID, "failed", 60*time.Second)
	if !strings.Contains(got.Reason, "reverted") {
		t.Fatalf("reason %q", got.Reason)
	}
	if fee, _ := got.Raw["fee"].(string); fee == "" || fee == "0" {
		t.Fatalf("fee of the reverted transaction not recorded: %v", got.Raw["fee"])
	}
	if a, h, _ := s.balance("c-revert", "ETH"); a.Cmp(eth(5)) != 0 || h.Sign() != 0 {
		t.Fatalf("available %s held %s: the hold was not released", a, h)
	}
	if s.ethBalance(dest).Sign() != 0 {
		t.Fatal("value moved in a reverted transaction")
	}
	// The customer can spend it again, and the address's next nonce works.
	dest2 := randAddr()
	w2 := s.withdraw("initiator", "k-after-revert", "c-revert", "ETH", dest2, eth(5))
	if w2.Code != 201 {
		t.Fatalf("spending the released funds: %d %v", w2.Code, w2.Raw)
	}
	s.approve("alice", w2.ID)
	s.approve("bob", w2.ID)
	s.waitWd(w2.ID, "confirmed", 60*time.Second)
	if s.ethBalance(dest2).Cmp(eth(5)) != 0 {
		t.Fatalf("destination = %s", s.ethBalance(dest2))
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean() // includes the fee: -hot equals the chain balance exactly
}

// A transaction the node forgot is handled like any stuck one: replaced from
// stored data, one payout.
func TestDroppedTransactionIsReplacedAndPaidOnce(t *testing.T) {
	s, _ := funded(t, opts{stuckAfter: sd(2 * time.Second)}, "c-drop", 5)
	dest := randAddr()
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	w := s.withdraw("initiator", "k-drop", "c-drop", "ETH", dest, half())
	tx := s.waitBroadcast(w.ID)
	if err := s.rc.CallContext(s.ctx, nil, "anvil_dropTransaction", common.HexToHash(tx)); err != nil {
		t.Fatal(err)
	}
	s.waitFor(60*time.Second, "a replacement", func() bool { return s.attempts(w.ID) >= 2 })
	s.automine(true)
	s.mine()
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.ethBalance(dest); got.Cmp(half()) != 0 {
		t.Fatalf("destination = %s, want exactly %s", got, half())
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}

// Someone else used the hot key's nonce (a transaction this system never made).
// The workflow must alert once, keep the hold, park the row and stop; the
// reconciler must not restart it.
func TestConsumedNonceParksWithOneAlert(t *testing.T) {
	s, _ := funded(t, opts{stuckAfter: "300s"}, "c-consumed", 5)
	dest := randAddr()
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	w := s.withdraw("initiator", "k-consumed", "c-consumed", "ETH", dest, half())
	tx := s.waitBroadcast(w.ID)
	if err := s.rc.CallContext(s.ctx, nil, "anvil_dropTransaction", common.HexToHash(tx)); err != nil {
		t.Fatal(err)
	}
	// Spend the nonce from the hot address directly (anvil can impersonate any account).
	hot := s.shardAddr[0]
	if err := s.rc.CallContext(s.ctx, nil, "anvil_impersonateAccount", hot); err != nil {
		t.Fatal(err)
	}
	nonce, err := s.ec.NonceAt(s.ctx, hot, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out string
	if err := s.rc.CallContext(s.ctx, &out, "eth_sendTransaction", map[string]any{
		"from": hot, "to": randAddr(), "value": hexutil.EncodeBig(big.NewInt(1)), "nonce": hexutil.EncodeUint64(nonce), "gas": "0x5208",
	}); err != nil {
		t.Fatalf("impersonated send: %v", err)
	}
	s.automine(true)
	s.mine()

	s.waitFor(60*time.Second, "the withdrawal to be parked", func() bool {
		return strings.HasPrefix(s.getWd(w.ID).Reason, "parked:")
	})
	desc, err := s.tc.DescribeWorkflowExecution(s.ctx, w.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	run := desc.WorkflowExecutionInfo.Execution.RunId
	s.waitPasses(workflow.ReconcilerID(s.chainName), 5) // several reconciler passes
	desc, _ = s.tc.DescribeWorkflowExecution(s.ctx, w.ID, "")
	if desc.WorkflowExecutionInfo.Execution.RunId != run || desc.WorkflowExecutionInfo.Status.String() != "Failed" {
		t.Fatalf("the parked workflow was restarted or is %s", desc.WorkflowExecutionInfo.Status)
	}
	if n := strings.Count(readFile(s.worker.log), "possible key compromise"); n != 1 {
		t.Fatalf("%d key-compromise alerts, want exactly 1", n)
	}
	got := s.getWd(w.ID)
	if got.Status == "failed" || got.Status == "confirmed" {
		t.Fatalf("status %s: a consumed nonce must not release or settle the money", got.Status)
	}
	if a, h, _ := s.balance("c-consumed", "ETH"); a.Cmp(new(big.Int).Sub(eth(5), half())) != 0 || h.Cmp(half()) != 0 {
		t.Fatalf("available %s held %s: the hold must stay", a, h)
	}
	if s.ethBalance(dest).Sign() != 0 {
		t.Fatal("paid out")
	}
}

// A workflow that starts over (a new execution) after the replacement mined
// settles once and does not loop on "nonce too low".
func TestRestartedWorkflowAfterMinedReplacementSettlesOnce(t *testing.T) {
	s, _ := funded(t, opts{stuckAfter: sd(2 * time.Second)}, "c-restart2", 5)
	dest := randAddr()
	s.automine(false)
	t.Cleanup(func() { s.automine(true) })
	w := s.withdraw("initiator", "k-restart2", "c-restart2", "ETH", dest, half())
	s.waitBroadcast(w.ID)
	s.waitFor(60*time.Second, "a replacement", func() bool { return s.attempts(w.ID) >= 2 })

	s.worker.stop()
	if err := s.tc.TerminateWorkflow(s.ctx, w.ID, "", "simulate a lost execution"); err != nil {
		t.Fatal(err)
	}
	s.automine(true)
	s.mine() // the replacement mines while no worker runs
	s.startWorker("")
	s.waitWd(w.ID, "confirmed", 90*time.Second)
	if got := s.ethBalance(dest); got.Cmp(half()) != 0 {
		t.Fatalf("destination = %s, want exactly %s", got, half())
	}
	if n := s.count(`SELECT count(*) FROM ledger_txns WHERE id='wd-out:' || $1`, w.ID); n != 1 {
		t.Fatalf("%d payout entries", n)
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}
