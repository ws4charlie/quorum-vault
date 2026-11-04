package custody_test

import (
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// funded returns a system with a customer holding ethWei of ETH credited and swept to the hot wallet.
func funded(t *testing.T, o opts, customer string, ethN int64) (*system, string) {
	t.Helper()
	s := newSystem(t, o)
	addr := s.newCustomer(customer)
	s.sendETH(addr, eth(ethN))
	s.waitAvailable(customer, "ETH", eth(ethN), 30*time.Second)
	s.waitFor(90*time.Second, "deposit swept", func() bool { return s.sweepsConfirmed() >= 1 })
	s.waitIdle(60 * time.Second)
	s.reconcileClean()
	return s, addr.Hex()
}

func TestTwoApproversAndInitiatorCannotApprove(t *testing.T) {
	s, _ := funded(t, opts{}, "c-two", 5)
	dest := randAddr()
	w := s.withdraw("initiator", "k-two", "c-two", "ETH", dest, eth(2)) // tier 2: two approvals
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	// The held amount is out of the available balance at once.
	if a, h, _ := s.balance("c-two", "ETH"); a.Cmp(eth(3)) != 0 || h.Cmp(eth(2)) != 0 {
		t.Fatalf("available %s held %s", a, h)
	}
	// The intent an approver signs is exact and stable.
	code, in := s.call("GET", "/v2/withdrawals/"+w.ID+"/intent", nil, nil)
	code2, in2 := s.call("GET", "/v2/withdrawals/"+w.ID+"/intent", nil, nil)
	if code != 200 || code2 != 200 || in["hash"] != in2["hash"] || in["approvals_required"].(float64) != 2 {
		t.Fatalf("intent %v %v", in, in2)
	}
	// The initiator cannot approve (403), and an approval needs matching X-Actor.
	s.approv["initiator"] = s.approv["alice"]
	if code, out := s.approve("initiator", w.ID); code != 403 {
		t.Fatalf("initiator approval: %d %v", code, out)
	}
	if code, _ := s.call("POST", "/v2/withdrawals/"+w.ID+"/approvals", map[string]string{"X-Actor": "bob"},
		map[string]any{"actor": "alice", "signature": strings.Repeat("00", 64)}); code != 400 {
		t.Fatalf("mismatched actor: %d", code)
	}
	if code, out := s.approve("alice", w.ID); code != 200 {
		t.Fatalf("alice: %d %v", code, out)
	}
	time.Sleep(3 * time.Second)
	if got := s.getWd(w.ID); got.Status != "requested" {
		t.Fatalf("one of two approvals moved the withdrawal to %s", got.Status)
	}
	if s.ethBalance(dest).Sign() != 0 {
		t.Fatal("paid out on one of two approvals")
	}
	if code, out := s.approve("bob", w.ID); code != 200 {
		t.Fatalf("bob: %d %v", code, out)
	}
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if s.ethBalance(dest).Cmp(eth(2)) != 0 {
		t.Fatalf("destination = %s", s.ethBalance(dest))
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}

func TestApprovalTimeoutVoidsTheHold(t *testing.T) {
	s, _ := funded(t, opts{approvalTimeout: "5s"}, "c-timeout", 4)
	dest := randAddr()
	w := s.withdraw("initiator", "k-timeout", "c-timeout", "ETH", dest, eth(2))
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	if code, out := s.approve("alice", w.ID); code != 200 { // one of two: not enough
		t.Fatalf("%d %v", code, out)
	}
	got := s.waitWd(w.ID, "failed", 60*time.Second)
	if !strings.Contains(got.Reason, "approval timeout") {
		t.Fatalf("reason %q", got.Reason)
	}
	if a, h, _ := s.balance("c-timeout", "ETH"); a.Cmp(eth(4)) != 0 || h.Sign() != 0 {
		t.Fatalf("after the void: available %s held %s", a, h)
	}
	if s.ethBalance(dest).Sign() != 0 {
		t.Fatal("paid out after a timeout")
	}
	if n := s.count(`SELECT count(*) FROM evm_nonce_allocations WHERE owner_kind='withdrawal'`); n != 0 {
		t.Fatalf("a nonce was allocated for a withdrawal that never signed: %d", n)
	}
	s.reconcileClean()
}

func TestHumanRejectionVoids(t *testing.T) {
	s, _ := funded(t, opts{}, "c-reject", 4)
	w := s.withdraw("initiator", "k-reject", "c-reject", "ETH", randAddr(), eth(2))
	if code, out := s.call("POST", "/v2/withdrawals/"+w.ID+"/rejections", map[string]string{"X-Actor": "carol"}, map[string]any{"reason": "looks wrong"}); code != 202 {
		t.Fatalf("%d %v", code, out)
	}
	got := s.waitWd(w.ID, "failed", 40*time.Second)
	if !strings.Contains(got.Reason, "rejected") || !strings.Contains(got.Reason, "carol") {
		t.Fatalf("reason %q", got.Reason)
	}
	if a, h, _ := s.balance("c-reject", "ETH"); a.Cmp(eth(4)) != 0 || h.Sign() != 0 {
		t.Fatalf("available %s held %s", a, h)
	}
	s.reconcileClean()
}

func TestInsufficientFundsIsRefused(t *testing.T) {
	s, _ := funded(t, opts{}, "c-poor", 1)
	w := s.withdraw("initiator", "k-poor", "c-poor", "ETH", randAddr(), eth(3))
	if w.Code != 409 {
		t.Fatalf("status %d %v, want 409", w.Code, w.Raw)
	}
	if n := s.count(`SELECT count(*) FROM withdrawals`); n != 0 {
		t.Fatalf("%d withdrawal rows after a refusal", n)
	}
	if n := s.count(`SELECT count(*) FROM ledger_holds`); n != 0 {
		t.Fatalf("%d holds after a refusal", n)
	}
	// Validation: bad destination, unknown asset, no key.
	for name, body := range map[string]map[string]any{
		"destination": {"customer": "c-poor", "asset": "ETH", "to": "0x123", "amount": "1"},
		"asset":       {"customer": "c-poor", "asset": "DOGE", "to": randAddr().Hex(), "amount": "1"},
		"amount":      {"customer": "c-poor", "asset": "ETH", "to": randAddr().Hex(), "amount": "-5"},
	} {
		if code, out := s.call("POST", "/v2/withdrawals", map[string]string{"X-Actor": "x", "Idempotency-Key": "v-" + name}, body); code != 400 {
			t.Fatalf("%s: %d %v, want 400", name, code, out)
		}
	}
	if code, _ := s.call("POST", "/v2/withdrawals", map[string]string{"X-Actor": "x"}, map[string]any{}); code != 400 {
		t.Fatalf("no idempotency key: %d", code)
	}
	if code, _ := s.call("POST", "/v2/customers", nil, map[string]any{"id": "nobody"}); code != 401 {
		t.Fatalf("no X-Actor: %d", code)
	}
	s.reconcileClean()
}

// A frozen factory: deposits still credit, sweeps wait quietly (nothing fails),
// and unfreezing lets them through.
func TestFrozenFactoryDefersSweeps(t *testing.T) {
	s := newSystem(t, opts{frozen: true})
	addr := s.newCustomer("c-frozen")
	s.sendETH(addr, eth(3))
	s.mintUSDT(addr, 800_000_000)
	s.waitAvailable("c-frozen", "ETH", eth(3), 30*time.Second)
	s.waitAvailable("c-frozen", "USDT", big.NewInt(800_000_000), 30*time.Second)

	time.Sleep(6 * time.Second) // several planner passes
	if n := s.count(`SELECT count(*) FROM sweeps`); n != 0 {
		t.Fatalf("%d sweeps while frozen", n)
	}
	if s.ethBalance(addr).Cmp(eth(3)) != 0 {
		t.Fatal("funds moved while frozen")
	}
	rep := s.reconcileClean() // credited funds still sit on the deposit address, and the books say so
	_ = rep
	// The planner workflow is still running: nothing failed.
	desc, err := s.tc.DescribeWorkflowExecution(s.ctx, "sweep-planner:"+s.chainName, "")
	if err != nil || desc.WorkflowExecutionInfo.Status.String() != "Running" {
		t.Fatalf("planner: %v %v", desc, err)
	}

	s.setDestination(s.shardAddr[0]) // the cold-key admin unfreezes
	s.waitFor(90*time.Second, "sweeps after unfreezing", func() bool { return s.sweepsConfirmed() >= 2 })
	s.waitIdle(60 * time.Second)
	if s.ethBalance(addr).Sign() != 0 || s.usdtBalance(addr).Sign() != 0 {
		t.Fatal("deposit address not emptied")
	}
	if n := s.count(`SELECT count(*) FROM sweeps WHERE status='failed'`); n != 0 {
		t.Fatalf("%d failed sweeps", n)
	}
	s.reconcileClean()
}

// The gateway refuses a withdrawal the business side let through. The nonce must be
// freed with a cancel, the hold voided, and the next withdrawal from the same address must go.
func TestGatewayRejectionReleasesNonceAndHold(t *testing.T) {
	s, _ := funded(t, opts{gwETHPerTx: "3000000000000000000", businessOneTier: true}, "c-rej", 10)
	dest := randAddr()
	w := s.withdraw("initiator", "k-big", "c-rej", "ETH", dest, eth(4)) // over the gateway's 3 ETH cap
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	got := s.waitWd(w.ID, "failed", 90*time.Second)
	if !strings.Contains(got.Reason, "policy_per_tx_cap") {
		t.Fatalf("reason %q", got.Reason)
	}
	if a, h, _ := s.balance("c-rej", "ETH"); a.Cmp(eth(10)) != 0 || h.Sign() != 0 {
		t.Fatalf("after the void: available %s held %s", a, h)
	}
	if s.ethBalance(dest).Sign() != 0 {
		t.Fatal("paid out a refused withdrawal")
	}
	var status string
	if err := s.pool.QueryRow(s.ctx, `SELECT status FROM evm_nonce_allocations WHERE owner_kind='withdrawal' AND owner_id=$1`, w.ID).Scan(&status); err != nil || status != "cancelled" {
		t.Fatalf("nonce allocation = %q, %v; want cancelled", status, err)
	}
	// Later withdrawals on the same hot address proceed.
	half := new(big.Int).Div(eth(1), big.NewInt(2))
	w2 := s.withdraw("initiator", "k-ok", "c-rej", "ETH", dest, half)
	s.waitWd(w2.ID, "confirmed", 60*time.Second)
	if s.ethBalance(dest).Cmp(half) != 0 {
		t.Fatalf("destination = %s", s.ethBalance(dest))
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}

// A transaction that does not mine is replaced with a higher fee; the replacement
// mines; exactly one payout.
func TestStuckTransactionIsReplacedOnce(t *testing.T) {
	s, _ := funded(t, opts{stuckAfter: "5s"}, "c-stuck", 5)
	dest := randAddr()
	if err := s.rc.CallContext(s.ctx, nil, "evm_setAutomine", false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.rc.CallContext(s.ctx, nil, "evm_setAutomine", true) })
	amount := new(big.Int).Div(eth(1), big.NewInt(2))
	w := s.withdraw("initiator", "k-stuck", "c-stuck", "ETH", dest, amount)
	s.waitFor(60*time.Second, "a replacement to be broadcast", func() bool {
		return s.count(`SELECT count(*) FROM evm_tx_attempts at JOIN evm_nonce_allocations al ON al.chain=at.chain AND al.address=at.address AND al.nonce=at.nonce
			WHERE al.owner_id=$1`, w.ID) >= 2
	})
	if s.ethBalance(dest).Sign() != 0 {
		t.Fatal("mined while automine was off")
	}
	if err := s.rc.CallContext(s.ctx, nil, "evm_setAutomine", true); err != nil {
		t.Fatal(err)
	}
	_ = s.rc.CallContext(s.ctx, nil, "evm_mine")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.ethBalance(dest); got.Cmp(amount) != 0 {
		t.Fatalf("destination = %s, want exactly %s (one payout)", got, amount)
	}
	// Of all attempts exactly one has a receipt.
	rows, err := s.pool.Query(s.ctx, `SELECT at.tx_hash FROM evm_tx_attempts at JOIN evm_nonce_allocations al ON al.chain=at.chain AND al.address=at.address AND al.nonce=at.nonce WHERE al.owner_id=$1`, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	var hashes []string
	for rows.Next() {
		var h string
		rows.Scan(&h)
		hashes = append(hashes, h)
	}
	rows.Close()
	mined := 0
	for _, h := range hashes {
		var r struct{ BlockNumber *string }
		if err := s.rc.CallContext(s.ctx, &r, "eth_getTransactionReceipt", h); err == nil && r.BlockNumber != nil {
			mined++
		}
	}
	if len(hashes) < 2 || mined != 1 {
		t.Fatalf("%d attempts, %d mined", len(hashes), mined)
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}

// Killing the worker at every boundary of the withdrawal and sweep flows ends
// with one payout, correct ledger and a clean Reconcile.
func TestCrashAtEveryBoundary(t *testing.T) {
	s, _ := funded(t, opts{}, "c-crash", 20)
	type step struct{ kind, point string }
	var steps []step
	for _, p := range []string{"after_build", "after_job", "after_broadcast", "after_confirm", "after_settle"} {
		steps = append(steps, step{"withdrawal", p})
	}
	steps = append(steps, step{"sweep", "after_broadcast"}, step{"sweep", "after_settle"})

	for i, st := range steps {
		fp := st.kind + "." + st.point
		s.worker.stop()
		s.startWorker(fp)
		s.waitFor(20*time.Second, "worker up", func() bool { return fileContains(s.worker.log, "qv-worker started") })
		start := time.Now()
		var dest = randAddr()
		var wid string
		var before *big.Int
		var addr = ""
		if st.kind == "withdrawal" {
			before = s.ethBalance(dest)
			w := s.withdraw("initiator", fmt.Sprintf("k-crash-%d", i), "c-crash", "ETH", dest, new(big.Int).Div(eth(1), big.NewInt(10)))
			if w.Code != 201 {
				t.Fatalf("%s: %d %v", fp, w.Code, w.Raw)
			}
			wid = w.ID
		} else {
			cust := fmt.Sprintf("c-crash-sweep-%d", i)
			a := s.newCustomer(cust)
			addr = a.Hex()
			s.sendETH(a, eth(2))
		}
		code, ok := s.worker.exitCode(90 * time.Second)
		if !ok || code != 137 {
			t.Fatalf("%s: worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		killedAfter := time.Since(start)
		s.startWorker("")
		if st.kind == "withdrawal" {
			s.waitWd(wid, "confirmed", 150*time.Second)
			want := new(big.Int).Div(eth(1), big.NewInt(10))
			if got := new(big.Int).Sub(s.ethBalance(dest), before); got.Cmp(want) != 0 {
				t.Fatalf("%s: paid out %s, want exactly %s", fp, got, want)
			}
		} else {
			s.waitFor(150*time.Second, "sweep confirmed after restart", func() bool {
				return s.count(`SELECT count(*) FROM sweeps WHERE from_address=$1 AND status='confirmed'`, addr) == 1
			})
			if s.ethBalance(common20(addr)).Sign() != 0 {
				t.Fatalf("%s: forwarder not emptied", fp)
			}
		}
		s.waitIdle(90 * time.Second)
		s.reconcileClean()
		// One payout in the ledger per withdrawal, one settlement per sweep.
		if n := s.count(`SELECT count(*) FROM ledger_txns WHERE id LIKE 'wd-out:%'`); n != s.count(`SELECT count(*) FROM withdrawals WHERE status='confirmed'`) {
			t.Fatalf("%s: %d wd-out entries for %d confirmed withdrawals", fp, n, s.count(`SELECT count(*) FROM withdrawals WHERE status='confirmed'`))
		}
		t.Logf("crash %-24s ok: worker died %.1fs after the trigger, recovered, one payout, Reconcile clean", fp, killedAfter.Seconds())
	}
}

// The gateway and the relay can be killed and restarted mid-flow.
func TestGatewayAndRelayRestart(t *testing.T) {
	s, _ := funded(t, opts{}, "c-restart", 5)

	// Gateway down: the job waits in the queue and nothing is lost.
	s.gateway.kill()
	dest := randAddr()
	w := s.withdraw("initiator", "k-gw-down", "c-restart", "ETH", dest, new(big.Int).Div(eth(1), big.NewInt(4)))
	s.waitFor(30*time.Second, "job enqueued", func() bool {
		return s.count(`SELECT count(*) FROM sign_jobs WHERE id LIKE 'wd:%' AND status='pending'`) == 1
	})
	time.Sleep(3 * time.Second)
	if got := s.getWd(w.ID); got.Status != "signing" {
		t.Fatalf("with the gateway down the withdrawal is %s", got.Status)
	}
	s.startGateway()
	s.waitWd(w.ID, "confirmed", 60*time.Second)

	// Relay down: events pile up unpublished, then drain after the restart, once each.
	s.relay.kill()
	before := s.count(`SELECT count(*) FROM outbox WHERE published_at IS NULL`)
	dest2 := randAddr()
	w2 := s.withdraw("initiator", "k-relay-down", "c-restart", "ETH", dest2, new(big.Int).Div(eth(1), big.NewInt(4)))
	s.waitWd(w2.ID, "confirmed", 60*time.Second)
	if n := s.count(`SELECT count(*) FROM outbox WHERE published_at IS NULL`); n <= before {
		t.Fatalf("expected unpublished events with the relay down, have %d (was %d)", n, before)
	}
	s.startRelay()
	s.waitFor(60*time.Second, "outbox drained", func() bool { return s.count(`SELECT count(*) FROM outbox WHERE published_at IS NULL`) == 0 })
	s.checkKafka(60 * time.Second)
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}

// A duplicate API request, concurrent duplicates and duplicate signals never double the hold or the payout.
func TestDuplicateRequestsAndSignals(t *testing.T) {
	s, _ := funded(t, opts{}, "c-dup", 6)
	dest := randAddr()
	amount := eth(2) // tier 2: waits for two approvals, so the duplicates all arrive while it is open

	w := s.withdraw("initiator", "k-dup", "c-dup", "ETH", dest, amount)
	again := s.withdraw("initiator", "k-dup", "c-dup", "ETH", dest, amount)
	if w.Code != 201 || again.Code != 200 || again.ID != w.ID {
		t.Fatalf("duplicate request: %d/%d ids %s/%s", w.Code, again.Code, w.ID, again.ID)
	}
	if other := s.withdraw("initiator", "k-dup", "c-dup", "ETH", dest, eth(1)); other.Code != 409 {
		t.Fatalf("same key, other body: %d, want 409", other.Code)
	}
	var wg sync.WaitGroup
	ids := make([]string, 12)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := s.withdraw("initiator", "k-dup", "c-dup", "ETH", dest, amount)
			ids[i] = r.ID
		}()
	}
	wg.Wait()
	for _, id := range ids {
		if id != w.ID {
			t.Fatalf("concurrent duplicates created %v", ids)
		}
	}
	if a, h, _ := s.balance("c-dup", "ETH"); a.Cmp(eth(4)) != 0 || h.Cmp(eth(2)) != 0 {
		t.Fatalf("available %s held %s: the hold was doubled", a, h)
	}
	if n := s.count(`SELECT count(*) FROM ledger_holds WHERE id LIKE 'wd-hold:%'`); n != 1 {
		t.Fatalf("%d holds", n)
	}

	// Duplicate approvals and duplicate signals.
	for i := 0; i < 3; i++ {
		if code, out := s.approve("alice", w.ID); code != 200 {
			t.Fatalf("alice #%d: %d %v", i, code, out)
		}
	}
	for i := 0; i < 5; i++ {
		if err := s.tc.SignalWorkflow(s.ctx, w.ID, "", "approval", nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.count(`SELECT jsonb_array_length(approvals) FROM withdrawals WHERE id=$1`, w.ID); got != 1 {
		t.Fatalf("%d approvals recorded for one approver", got)
	}
	if code, out := s.approve("bob", w.ID); code != 200 {
		t.Fatalf("bob: %d %v", code, out)
	}
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.ethBalance(dest); got.Cmp(amount) != 0 {
		t.Fatalf("destination = %s, want exactly %s", got, amount)
	}
	if n := s.count(`SELECT count(*) FROM withdrawals`); n != 1 {
		t.Fatalf("%d withdrawal rows", n)
	}
	// A late approval on a finished withdrawal is refused.
	if code, _ := s.approve("carol", w.ID); code != 409 {
		t.Fatalf("approval after completion: %d, want 409", code)
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}

var _ = custody.WdRequested
