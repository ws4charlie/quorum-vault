package sole2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	"github.com/ws4charlie/quorum-vault/internal/workflow"
)

// ---- helpers ----

type wdRes struct {
	ID, Status, Reason, Tx, Fee string
	Code                        int
	Raw                         map[string]any
}

func (s *wdSys) sub(t *testing.T, name string, f func(t *testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		parent := s.t
		s.t = t
		defer func() { s.t = parent }()
		f(t)
	})
}

func (s *wdSys) request(actor, key, customer, asset, to string, amount uint64) wdRes {
	s.t.Helper()
	// The workflow ID derives from (actor, key); a per-system tag keeps IDs unique across runs that share one Temporal server.
	key += "~" + s.tag
	code, out := s.callH("POST", "/v2/withdrawals", map[string]string{"X-Actor": actor, "Idempotency-Key": key},
		map[string]any{"customer": customer, "asset": asset, "to": to, "amount": fmt.Sprint(amount)})
	w := wdRes{Code: code, Raw: out}
	if code == 200 || code == 201 {
		w.ID, _ = out["id"].(string)
		w.Status, _ = out["status"].(string)
	}
	return w
}

func (s *wdSys) callH(method, path string, hdr map[string]string, body any) (int, map[string]any) {
	s.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, s.apiURL+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(buf.Bytes(), &out)
	return resp.StatusCode, out
}

func (s *wdSys) wdGet(id string) wdRes {
	s.t.Helper()
	code, out := s.callH("GET", "/v2/withdrawals/"+id, nil, nil)
	if code != 200 {
		s.t.Fatalf("get withdrawal: %d %v", code, out)
	}
	w := wdRes{ID: id, Code: code, Raw: out}
	w.Status, _ = out["status"].(string)
	w.Reason, _ = out["failure_reason"].(string)
	w.Tx, _ = out["tx_hash"].(string)
	w.Fee, _ = out["fee"].(string)
	return w
}

func (s *wdSys) waitWd(id, status string, timeout time.Duration) wdRes {
	s.t.Helper()
	var w wdRes
	s.waitFor(timeout, fmt.Sprintf("withdrawal %s = %s", id, status), func() bool {
		w = s.wdGet(id)
		if w.Status == "failed" && status != "failed" {
			s.t.Fatalf("withdrawal %s failed: %s", id, w.Reason)
		}
		return w.Status == status
	})
	return w
}

func (s *wdSys) approve(actor, id string) {
	s.t.Helper()
	code, in := s.callH("GET", "/v2/withdrawals/"+id+"/intent", nil, nil)
	if code != 200 {
		s.t.Fatalf("intent: %d %v", code, in)
	}
	h, err := hex.DecodeString(in["hash"].(string))
	if err != nil {
		s.t.Fatal(err)
	}
	sig := ed25519.Sign(s.approv[actor], h)
	if code, out := s.callH("POST", "/v2/withdrawals/"+id+"/approvals", map[string]string{"X-Actor": actor},
		map[string]any{"actor": actor, "signature": hex.EncodeToString(sig)}); code != 200 && code != 201 {
		s.t.Fatalf("approve: %d %v", code, out)
	}
}

// deposit credits a customer with SOL and tokens through real deposits.
func (s *wdSys) deposit(customer string, lamports, tokens uint64) {
	s.t.Helper()
	addr := s.newCustomer(customer)
	if lamports > 0 {
		s.paySOL(addr, lamports)
	}
	if tokens > 0 {
		s.payToken(s.funderTokens(s.mint, tokens), s.mint, addr, tokens)
	}
}

func (s *wdSys) waitDeposits(customer string, lamports, tokens uint64) {
	s.t.Helper()
	if lamports > 0 {
		s.waitAvailable(customer, "SOL", lamports, 90*time.Second)
	}
	if tokens > 0 {
		s.waitAvailable(customer, "TKN", tokens, 90*time.Second)
	}
}

type allocRow struct {
	ID                                    int64
	Account, Value, Status, Owner, TxHash string
	Price                                 int64
}

func (s *wdSys) allocs(ownerID string) []allocRow {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id, address, nonce_value, status, owner_id, COALESCE(tx_hash,''), price FROM sol_nonce_allocations WHERE owner_id=$1 ORDER BY id`, ownerID)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []allocRow
	for rows.Next() {
		var a allocRow
		if err := rows.Scan(&a.ID, &a.Account, &a.Value, &a.Status, &a.Owner, &a.TxHash, &a.Price); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func (s *wdSys) attempts(ownerID string) int {
	return s.count(`SELECT count(*) FROM sol_tx_attempts t JOIN sol_nonce_allocations a ON a.id=t.allocation_id WHERE a.owner_id=$1`, ownerID)
}

func (s *wdSys) jobsOf(wid string) []signjob.Job {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id FROM sign_jobs WHERE starts_with(id, $1) ORDER BY created_at, id`, "wd:"+wid+":")
	if err != nil {
		s.t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	var out []signjob.Job
	for _, id := range ids {
		j, err := signjob.Get(s.ctx, s.pool, id)
		if err != nil {
			s.t.Fatal(err)
		}
		if j.Status == signjob.StatusDone {
			out = append(out, j)
		}
	}
	return out
}

// rawOfJob is the transaction a done job makes: one signature and its message.
func rawOfJob(t testing.TB, j signjob.Job) []byte {
	t.Helper()
	var p sol.Payload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{1}, j.Signature...), p.Message...)
}

func sigOf(raw []byte) string { return base58.Encode(raw[1:65]) }

func priceOf(t testing.TB, raw []byte) uint64 {
	t.Helper()
	_, msg, err := sol.SplitTransaction(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sol.DecodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range m.Instructions {
		if len(in.Data) == 9 && in.Data[0] == 3 && in.Program == mustB(t, sol.ComputeBudgetProgram) {
			var v uint64
			for i := 8; i >= 1; i-- {
				v = v<<8 | uint64(in.Data[i])
			}
			return v
		}
	}
	return 0
}

func mustB(t testing.TB, a string) [32]byte { return addrBytes(t, a) }

// statusOf is what the validator says about a signature now (nil: it never saw it land).
func (s *wdSys) statusOf(sig string) *sol.SigStatus {
	s.t.Helper()
	st, err := s.c.rpc.SignatureStatuses(s.ctx, []string{sig})
	if err != nil {
		s.t.Fatal(err)
	}
	return st[0]
}

func (s *wdSys) sendDirect(raw []byte) {
	s.t.Helper()
	// The validator's answer does not matter: a transaction on a spent nonce is dropped, or refused, and that is what the test looks for.
	_, _ = s.c.rpc.SendRaw(s.ctx, raw)
}

func (s *wdSys) lamports(addr string) uint64 {
	s.t.Helper()
	n, _, err := s.c.rpc.Lamports(s.ctx, addr, sol.Finalized)
	if err != nil {
		s.t.Fatal(err)
	}
	return n
}

func (s *wdSys) tokensOf(owner string) uint64 {
	s.t.Helper()
	accts, err := s.c.rpc.TokenAccountsByOwner(s.ctx, owner, s.mint.addr(), sol.Finalized)
	if err != nil {
		s.t.Fatal(err)
	}
	var sum uint64
	for _, a := range accts {
		sum += a.Amount
	}
	return sum
}

func (s *wdSys) freshAddr() string { return newKey(s.t).addr() }

func (s *wdSys) waitFinalized(what string, cond func() bool) {
	s.t.Helper()
	s.waitFor(60*time.Second, what, cond)
}

func (s *wdSys) posted(acct string) *big.Int {
	var p string
	if err := s.pool.QueryRow(s.ctx, `SELECT posted::text FROM ledger_accounts WHERE id=$1`, acct).Scan(&p); err != nil {
		s.t.Fatalf("account %s: %v", acct, err)
	}
	n, _ := new(big.Int).SetString(p, 10)
	return n
}

func (s *wdSys) workflowStatus(id string) string {
	d, err := s.tc.DescribeWorkflowExecution(s.ctx, id, "")
	if err != nil {
		return ""
	}
	return d.WorkflowExecutionInfo.Status.String()
}

// ---- the flows ----

func TestWdFlows(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 4})
	s.reconcileClean("a shard with a nonce pool and no withdrawals")
	if got := s.count(`SELECT count(*) FROM sol_nonce_accounts WHERE chain=$1`, s.chain); got != 4 {
		t.Fatalf("%d pool accounts registered, want 4", got)
	}

	// Customers deposit through the real deposit path first, all at once.
	custs := []string{"w-alice", "w-bob", "w-carol", "w-dave", "w-eve", "w-fay", "w-gus", "w-hal", "w-ivy", "w-jon", "w-kim", "w-lee"}
	for _, c := range custs {
		s.deposit(c, 30*oneSOL, 5_000*tknUnit)
	}
	for _, c := range custs {
		s.waitDeposits(c, 30*oneSOL, 5_000*tknUnit)
	}
	s.reconcileClean("after the deposits")

	s.sub(t, "sol_withdrawal_settles_once_dual_control", func(t *testing.T) {
		dest := s.freshAddr()
		amount := uint64(6 * oneSOL) // above the 5 SOL tier: two approvals
		before := s.lamports(s.hotAddr())
		w := s.request("initiator", "k-sol-dual", "w-alice", "SOL", dest, amount)
		if w.Code != 201 {
			t.Fatalf("%d %v", w.Code, w.Raw)
		}
		s.reconcileClean("requested, nothing signed")
		s.approve("alice", w.ID)
		s.holds(2*time.Second, "one approval is not enough", func() bool { return s.wdGet(w.ID).Status == "requested" })
		s.reconcileClean("one approval")
		s.approve("bob", w.ID)
		got := s.waitWd(w.ID, "confirmed", 90*time.Second)
		if s.lamports(dest) != amount {
			t.Fatalf("destination holds %d, want exactly %d", s.lamports(dest), amount)
		}
		if got.Fee == "" || got.Fee == "0" {
			t.Fatalf("fee %q not recorded", got.Fee)
		}
		al := s.allocs(w.ID)
		if len(al) != 1 || al[0].Status != "confirmed" {
			t.Fatalf("allocations %+v", al)
		}
		if spent := before - s.lamports(s.hotAddr()); spent != amount+mustU(t, got.Fee) {
			t.Fatalf("the shard paid %d, amount %d + fee %s", spent, amount, got.Fee)
		}
		if a, h, _ := s.balances("w-alice", "SOL"); a.Cmp(bigU(24*oneSOL)) != 0 || h.Sign() != 0 {
			t.Fatalf("available %s held %s", a, h)
		}
		s.reconcileClean("settled")
	})

	s.sub(t, "token_withdrawal_settles_and_the_destination_account_is_opened", func(t *testing.T) {
		owner := s.freshAddr()
		w := s.request("initiator", "k-tkn-1", "w-bob", "TKN", owner, 50*tknUnit)
		got := s.waitWd(w.ID, "confirmed", 90*time.Second)
		if s.tokensOf(owner) != 50*tknUnit {
			t.Fatalf("destination holds %d tokens", s.tokensOf(owner))
		}
		// the hot shard opened the destination's token account: its rent is part of the cost booked as the fee
		if fee := mustU(t, got.Fee); fee < s.c.rent(165) {
			t.Fatalf("fee %d does not include the rent %d of the account it opened", fee, s.c.rent(165))
		}
		s.reconcileClean("token withdrawal with an opened account")
		// to the same owner again: the account exists, no rent
		w2 := s.request("initiator", "k-tkn-2", "w-bob", "TKN", owner, 25*tknUnit)
		got2 := s.waitWd(w2.ID, "confirmed", 90*time.Second)
		if s.tokensOf(owner) != 75*tknUnit || mustU(t, got2.Fee) >= s.c.rent(165) {
			t.Fatalf("second token withdrawal: holds %d, fee %s", s.tokensOf(owner), got2.Fee)
		}
		s.reconcileClean("second token withdrawal")
	})

	s.sub(t, "a_transaction_that_lands_and_fails_voids_books_the_fee_and_frees_the_slot", func(t *testing.T) {
		dest := s.freshAddr()
		// 1000 lamports to an address with no account: below the rent-exempt minimum, the transfer fails on the chain after the nonce was advanced.
		w := s.request("initiator", "k-fail-sol", "w-carol", "SOL", dest, 1000)
		got := s.waitWd(w.ID, "failed", 90*time.Second)
		if !strings.Contains(got.Reason, "reverted") {
			t.Fatalf("reason %q", got.Reason)
		}
		if got.Fee == "" || got.Fee == "0" {
			t.Fatalf("the fee of the failed transaction is not booked: %q", got.Fee)
		}
		if s.lamports(dest) != 0 {
			t.Fatal("value moved in a failed transaction")
		}
		if a, h, _ := s.balances("w-carol", "SOL"); a.Cmp(bigU(30*oneSOL)) != 0 || h.Sign() != 0 {
			t.Fatalf("available %s held %s: the hold was not released", a, h)
		}
		al := s.allocs(w.ID)
		if len(al) != 1 || al[0].Status != "confirmed" {
			t.Fatalf("allocation %+v: the failed transaction still used the nonce, so the slot is free", al)
		}
		s.reconcileClean("after a failed withdrawal: the fee is a cost, the amount stays")
		// and the slot works: the next withdrawal lands
		w2 := s.request("initiator", "k-after-fail", "w-carol", "SOL", s.freshAddr(), oneSOL)
		s.waitWd(w2.ID, "confirmed", 90*time.Second)

		// A token transfer into an account that is not a token account fails the same way.
		owner := newKey(t)
		dstATA := s.c.ata(owner.pub, s.mint.pub)
		s.paySOL(sol.Address(dstATA), oneSOL) // a system account where the ATA should be
		w3 := s.request("initiator", "k-fail-tkn", "w-dave", "TKN", owner.addr(), 10*tknUnit)
		s.waitWd(w3.ID, "failed", 90*time.Second)
		if a, h, _ := s.balances("w-dave", "TKN"); a.Cmp(bigU(5_000*tknUnit)) != 0 || h.Sign() != 0 {
			t.Fatalf("token available %s held %s", a, h)
		}
		s.reconcileClean("after a failed token withdrawal")
	})

	s.sub(t, "a_refusal_by_the_signing_zone_releases_the_slot_and_the_hold", func(t *testing.T) {
		// Over the gateway's per-transaction cap (50 SOL). Needs a customer with more.
		s.deposit("w-whale", 80*oneSOL, 0)
		s.waitDeposits("w-whale", 80*oneSOL, 0)
		dest := s.freshAddr()
		w := s.request("initiator", "k-whale", "w-whale", "SOL", dest, 60*oneSOL)
		s.approve("alice", w.ID)
		s.approve("bob", w.ID)
		got := s.waitWd(w.ID, "failed", 90*time.Second)
		if !strings.Contains(got.Reason, "policy_per_tx_cap") {
			t.Fatalf("reason %q", got.Reason)
		}
		if s.lamports(dest) != 0 {
			t.Fatal("paid out a refused withdrawal")
		}
		if al := s.allocs(w.ID); len(al) != 1 || al[0].Status != "released" {
			t.Fatalf("allocation %+v: nothing was signed, so the account is given back unused", al)
		}
		if a, h, _ := s.balances("w-whale", "SOL"); a.Cmp(bigU(80*oneSOL)) != 0 || h.Sign() != 0 {
			t.Fatalf("available %s held %s", a, h)
		}
		s.reconcileClean("after a refusal")
	})

	s.sub(t, "stuck_then_fee_raise_exactly_one_version_lands", func(t *testing.T) {
		dest := s.freshAddr()
		amount := uint64(2 * oneSOL)
		s.proxy.hold.Store(true) // the core's sends are kept, not sent: the transaction is broadcast and never lands
		w := s.request("initiator", "k-stuck", "w-eve", "SOL", dest, amount)
		s.waitFor(60*time.Second, "two versions broadcast", func() bool { return s.attempts(w.ID) >= 2 })
		if s.lamports(dest) != 0 || s.wdGet(w.ID).Status == "confirmed" {
			t.Fatal("landed while its sends were held")
		}
		s.reconcileClean("broadcast and stuck")
		s.proxy.hold.Store(false)
		s.waitWd(w.ID, "confirmed", 90*time.Second)
		if got := s.lamports(dest); got != amount {
			t.Fatalf("destination holds %d, want exactly %d (one payout)", got, amount)
		}
		jobs := s.jobsOf(w.ID)
		if len(jobs) < 3 {
			t.Fatalf("%d versions signed, want at least 3 (the original and two raises)", len(jobs))
		}
		var prev uint64
		landed := 0
		for _, j := range jobs {
			raw := rawOfJob(t, j)
			if p := priceOf(t, raw); p <= prev {
				t.Fatalf("version %s has price %d after %d: a version only raises the price", j.ID, p, prev)
			} else {
				prev = p
			}
			if s.statusOf(sigOf(raw)) != nil {
				landed++
			}
		}
		if landed != 1 {
			t.Fatalf("%d of %d versions landed", landed, len(jobs))
		}
		// Send every version again, straight to the validator: the nonce has advanced, so none can land.
		for _, j := range jobs {
			s.sendDirect(rawOfJob(t, j))
		}
		time.Sleep(3 * time.Second)
		landed = 0
		for _, j := range jobs {
			if s.statusOf(sigOf(rawOfJob(t, j))) != nil {
				landed++
			}
		}
		if landed != 1 || s.lamports(dest) != amount {
			t.Fatalf("after sending every version again: %d landed, destination holds %d", landed, s.lamports(dest))
		}
		s.reconcileClean("after the fee raise")
	})

	s.sub(t, "a_nonce_advanced_by_something_else_parks_with_one_alert", func(t *testing.T) {
		dest := s.freshAddr()
		s.proxy.hold.Store(true)
		w := s.request("initiator", "k-consumed", "w-fay", "SOL", dest, oneSOL)
		s.waitFor(60*time.Second, "the broadcast", func() bool { return s.attempts(w.ID) >= 1 })
		// The validator has no way to move a nonce for the hot shard but the shard's own signature, so the books are made to remember an older
		// value than the account holds now: what the cell sees is exactly what it sees when something else advanced the nonce.
		if _, err := s.pool.Exec(s.ctx, `UPDATE sol_nonce_allocations SET nonce_value=$2 WHERE owner_id=$1`, w.ID, sol.Address(newKey(t).pub)); err != nil {
			t.Fatal(err)
		}
		s.waitFor(60*time.Second, "the withdrawal to be parked", func() bool { return strings.HasPrefix(s.wdGet(w.ID).Reason, "parked:") })
		s.proxy.hold.Store(false)
		runID := ""
		if d, err := s.tc.DescribeWorkflowExecution(s.ctx, w.ID, ""); err == nil {
			runID = d.WorkflowExecutionInfo.Execution.RunId
		}
		s.waitPasses(workflow.ReconcilerID(s.chain), 4)
		if d, err := s.tc.DescribeWorkflowExecution(s.ctx, w.ID, ""); err != nil || d.WorkflowExecutionInfo.Execution.RunId != runID || d.WorkflowExecutionInfo.Status.String() != "Failed" {
			t.Fatalf("the parked workflow was restarted or is not stopped: %v", err)
		}
		if n := strings.Count(readLog(s.worker.log), "possible key compromise"); n != 1 {
			t.Fatalf("%d alerts, want exactly 1", n)
		}
		got := s.wdGet(w.ID)
		if got.Status == "failed" || got.Status == "confirmed" {
			t.Fatalf("status %s: a consumed nonce must not release or settle the money", got.Status)
		}
		if a, h, _ := s.balances("w-fay", "SOL"); a.Cmp(bigU(29*oneSOL)) != 0 || h.Cmp(bigU(oneSOL)) != 0 {
			t.Fatalf("available %s held %s: the hold stays", a, h)
		}
		if s.lamports(dest) != 0 {
			t.Fatal("paid out")
		}
	})

	s.sub(t, "more_withdrawals_than_nonce_accounts_queue_and_all_settle", func(t *testing.T) {
		// Two accounts are used or parked by the tests above; 8 withdrawals want the rest.
		var ids []string
		dests := map[string]string{}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i, c := range custs[4:] {
			wg.Add(1)
			go func(i int, c string) {
				defer wg.Done()
				d := s.freshAddr()
				w := s.request("initiator", fmt.Sprintf("k-conc-%d", i), c, "SOL", d, oneSOL)
				mu.Lock()
				ids = append(ids, w.ID)
				dests[w.ID] = d
				mu.Unlock()
			}(i, c)
		}
		wg.Wait()
		for _, id := range ids {
			s.waitWd(id, "confirmed", 240*time.Second)
			if s.lamports(dests[id]) != oneSOL {
				t.Fatalf("withdrawal %s: destination holds %d", id, s.lamports(dests[id]))
			}
		}
		// never two in flight on one account: the open allocations are one per account at every moment, by the index; look at what was recorded
		var maxOpenPerAccount int
		if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(max(n),0) FROM (SELECT count(*) n FROM sol_nonce_allocations WHERE status IN ('allocated','broadcast') GROUP BY address) x`).Scan(&maxOpenPerAccount); err != nil {
			t.Fatal(err)
		}
		if maxOpenPerAccount > 1 {
			t.Fatalf("%d open allocations on one account", maxOpenPerAccount)
		}
		s.reconcileClean("after the queue")
	})

	if t.Failed() {
		s.dump()
	}
}

func mustU(t testing.TB, s string) uint64 {
	var v uint64
	if _, err := fmt.Sscan(s, &v); err != nil {
		t.Fatalf("%q is not a number", s)
	}
	return v
}

func readLog(path string) string { b, _ := os.ReadFile(path); return string(b) }

func (s *wdSys) balances(customer, asset string) (avail, held, posted *big.Int) {
	s.t.Helper()
	code, out := s.call("GET", "/v2/customers/"+customer+"/balances", nil)
	if code != 200 {
		s.t.Fatalf("balances: %d %v", code, out)
	}
	avail, held, posted = new(big.Int), new(big.Int), new(big.Int)
	for _, b := range out["balances"].([]any) {
		m := b.(map[string]any)
		if m["asset"] == asset {
			avail.SetString(m["available"].(string), 10)
			held.SetString(m["held"].(string), 10)
			posted.SetString(m["posted"].(string), 10)
		}
	}
	return
}

func (s *wdSys) historyLen(id string) int {
	d, err := s.tc.DescribeWorkflowExecution(s.ctx, id, "")
	if err != nil {
		return 0
	}
	return int(d.WorkflowExecutionInfo.HistoryLength)
}

// waitPasses waits for a loop workflow to go round a few more times.
func (s *wdSys) waitPasses(id string, passes int) {
	s.t.Helper()
	base := s.historyLen(id)
	s.waitFor(30*time.Second, fmt.Sprintf("%s to go round %d times", id, passes), func() bool {
		cur := s.historyLen(id)
		return cur >= base+passes*6 || cur < base
	})
}

func (s *wdSys) dump() {
	s.t.Logf("---- gateway log tail ----\n%s", tail(s.gateway.Output()))
	rows, err := s.pool.Query(s.ctx, `SELECT owner_id, address, status, price, COALESCE(tx_hash,'') FROM sol_nonce_allocations ORDER BY id`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var o, a, st, h string
		var p int64
		rows.Scan(&o, &a, &st, &p, &h)
		s.t.Logf("allocation owner=%s account=%s status=%s price=%d tx=%s", o, a, st, p, h)
	}
}

var _ = rand.Reader
var _ = gateway.File{}
var _ custody.Owner
