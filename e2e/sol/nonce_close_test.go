package sole2e

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

func (s *wdSys) nonceTool(t *testing.T, args ...string) (string, error) {
	t.Helper()
	keyFile := filepath.Join(s.dir, "carol.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(s.approv["carol"])), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"-config", s.cfgPath, "-dsn", s.bizDSN, "-shard", "0", "-approver", "carol", "-approver-key", keyFile, "-wait", "2m"}
	out, err := exec.Command(filepath.Join(binDir, "qv-sol-nonces"), append(base, args...)...).CombinedOutput()
	return string(out), err
}

func (s *wdSys) nonceExists(i int) bool {
	_, err := s.adapter.RPC().GetNonce(s.ctx, sol.Address(sol.NonceAddress(s.hot, i)), sol.Finalized)
	return err == nil
}

// A nonce account is retired (out of the pool), then closed once it is idle: the shard withdraws its whole balance to itself, signed by the zone under an
// operator's approval. The rent comes back as a lower cost in the books. Everything else under that intent is refused by the zone.
func TestNonceRetireAndClose(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 4})
	hotBefore := s.lamports(s.hotAddr())
	stop := s.watchReconcile()

	s.sub(t, "refused_while_the_account_is_in_the_pool_or_in_use", func(t *testing.T) {
		if out, err := s.nonceTool(t, "-action", "close", "-index", "3"); err == nil || !strings.Contains(out, "retire it first") {
			t.Fatalf("closing an account of the pool: err=%v\n%s", err, out)
		}
		// a withdrawal in flight holds account 0 (the first free one)
		s.deposit("nc-1", 20*oneSOL, 0)
		s.waitDeposits("nc-1", 20*oneSOL, 0)
		s.proxy.hold.Store(true)
		w := s.request("initiator", "k-nc-1", "nc-1", "SOL", s.freshAddr(), oneSOL)
		s.waitFor(60*time.Second, "the withdrawal to be broadcast", func() bool { return s.proxy.heldCount() > 0 })
		holder := s.allocs(w.ID)
		if len(holder) != 1 {
			t.Fatalf("allocations %+v", holder)
		}
		idx := -1
		for i := 0; i < 4; i++ {
			if sol.Address(sol.NonceAddress(s.hot, i)) == holder[0].Account {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatalf("the holder account %s is not a pool account", holder[0].Account)
		}
		if out, err := s.nonceTool(t, "-action", "retire", "-index", fmt.Sprint(idx)); err != nil {
			t.Fatalf("retire: %v\n%s", err, out)
		}
		if out, err := s.nonceTool(t, "-action", "close", "-index", fmt.Sprint(idx)); err == nil || !strings.Contains(out, "still holds") {
			t.Fatalf("closing an account a withdrawal holds: err=%v\n%s", err, out)
		}
		if !s.nonceExists(idx) {
			t.Fatal("the account the withdrawal holds was closed")
		}
		s.proxy.hold.Store(false)
		for _, raw := range s.proxy.takeHeld() { // the held transaction goes to the chain now
			s.sendDirect(raw)
		}
		s.waitWd(w.ID, "confirmed", 120*time.Second)
	})

	s.sub(t, "retire_then_close_returns_the_rent_and_withdrawals_go_on", func(t *testing.T) {
		before := s.lamports(s.hotAddr())
		if out, err := s.nonceTool(t, "-action", "retire", "-index", "3"); err != nil {
			t.Fatalf("retire: %v\n%s", err, out)
		}
		if out, err := s.nonceTool(t, "-action", "close", "-index", "3"); err != nil || !strings.Contains(out, "recovered_lamports=1447680") {
			t.Fatalf("close: %v\n%s", err, out)
		}
		if s.nonceExists(3) {
			t.Fatal("the account still exists")
		}
		if gain := s.lamports(s.hotAddr()) - before; gain < sol.DefaultNonceRent-20_000 || gain > sol.DefaultNonceRent {
			t.Fatalf("the shard gained %d lamports, want the rent %d less a fee", gain, sol.DefaultNonceRent)
		}
		// the setup does not create it again, and the pool that is left pays withdrawals
		if n, err := s.svc.SetupNonces(s.ctx, 0, "carol", s.approv["carol"], 2*time.Minute); err != nil || n != 0 {
			t.Fatalf("the setup created %d accounts, %v", n, err)
		}
		dest := s.freshAddr()
		w := s.request("initiator", "k-nc-2", "nc-1", "SOL", dest, oneSOL)
		s.waitWd(w.ID, "confirmed", 120*time.Second)
		if s.lamports(dest) != oneSOL {
			t.Fatalf("the destination holds %d", s.lamports(dest))
		}
		s.reconcileClean("after the close")
		// closing it again is a no-op; the last accounts of a pool are never retired
		if out, err := s.nonceTool(t, "-action", "close", "-index", "3"); err != nil || !strings.Contains(out, "recovered_lamports=0") {
			t.Fatalf("closing a closed account: %v\n%s", err, out)
		}
		refused := false
		for i := 0; i < 4; i++ {
			out, err := s.nonceTool(t, "-action", "retire", "-index", fmt.Sprint(i))
			if err != nil {
				if !strings.Contains(out, "last of its shard's pool") {
					t.Fatalf("retire %d: %v\n%s", i, err, out)
				}
				refused = true
			}
		}
		if !refused {
			t.Fatal("every account of the pool was retired")
		}
		// the one that is left still carries a withdrawal
		w = s.request("initiator", "k-nc-3", "nc-1", "SOL", s.freshAddr(), oneSOL)
		s.waitWd(w.ID, "confirmed", 120*time.Second)
	})

	s.sub(t, "the_zone_signs_only_the_close_of_an_account_of_the_pool_to_the_shard", func(t *testing.T) {
		n := sol.NonceAddress(s.hot, 0)
		other := newKey(t).pub
		bh, _ := sol.ParseAddress(s.c.blockhash())
		msg := func(nonce, dest, auth [32]byte, lamports uint64) []byte {
			return sol.Compile(s.hot, bh, sol.SetLimitIx(10_000), sol.WithdrawNonceIx(nonce, dest, auth, lamports))
		}
		in := func(id string, lamports uint64) signjob.Intent {
			return signjob.Intent{Kind: sol.KindNonceClose, ID: id, PartitionID: s.partSOL(), Chain: s.chain, Asset: "SOL", To: s.hotAddr(), Amount: fmt.Sprint(lamports)}
		}
		s.mustRefuse("nc-a1", in("nc-a1", 1_447_680), msg(n, s.hot, s.hot, 1_447_680), "approval_invalid")                              // no operator approval
		s.mustRefuse("nc-a2", in("nc-a2", 1_447_680), msg(n, other, s.hot, 1_447_680), "tx_mismatch", "carol")                          // the rent to a stranger
		s.mustRefuse("nc-a3", in("nc-a3", 1_447_680), msg(n, s.hot, other, 1_447_680), "tx_mismatch", "carol")                          // another authority
		s.mustRefuse("nc-a4", in("nc-a4", 1_447_680), msg(sol.NonceAddress(other, 0), s.hot, s.hot, 1_447_680), "tx_mismatch", "carol") // an account of another pool
		s.mustRefuse("nc-a5", in("nc-a5", 5), msg(n, s.hot, s.hot, 1_447_680), "tx_mismatch", "carol")                                  // an amount other than the intent's
	})

	if bad := stop(); len(bad) > 0 {
		t.Fatalf("Reconcile failed: %v", bad)
	}
	_ = hotBefore
}

func (s *wdSys) coldNonceExists(account string) bool {
	_, err := s.adapter.RPC().GetNonce(s.ctx, account, sol.Finalized)
	return err == nil
}

// The cold address's pool: an account is retired (no refill is exported on it), then closed in a ceremony like the cold setup, the offline signer
// signing a withdrawal of its whole balance back to the cold address and nothing else. A close is refused for an account still in the pool or still named
// by a refill; a refill signed afterwards on a closed account is refused offline; refills go on with the accounts that are left.
func TestColdNonceRetireAndClose(t *testing.T) {
	k := newSolKit(t)
	s := newWdSystem(t, refillOpts(k, ""))
	s.coldReady(k)
	stop := s.watchReconcile()
	addrOf := func(i int) string { return sol.Address(sol.NonceAddress(addrBytes(t, k.addr), i)) }
	retire := func(i int) (int, map[string]any) {
		return s.call("POST", "/v2/cold-nonces/retire", map[string]any{"pool": "omnibus", "index": i})
	}
	exportClose := func(idx ...int) (int, map[string]any) {
		return s.call("POST", "/v2/cold-close/export", map[string]any{"pool": "omnibus", "indexes": idx})
	}

	// not retired: refused. In use (a refill that is not final names it): refused.
	if code, out := exportClose(2); code != 400 || !strings.Contains(fmt.Sprint(out), "retire it first") {
		t.Fatalf("a close of an account in the pool: %d %v", code, out)
	}
	r := s.waitRefill("SOL", "requested", 90*time.Second)
	rf := s.exportRefill(r.ID) // takes the first free account
	inUse := -1
	for i := 0; i < 3; i++ {
		if addrOf(i) == rf.Request.NonceAccount {
			inUse = i
		}
	}
	if inUse < 0 {
		t.Fatalf("the refill's account %s is not a pool account", rf.Request.NonceAccount)
	}
	if code, out := retire(inUse); code != 200 {
		t.Fatalf("retire %d: %d %v", inUse, code, out)
	}
	if code, out := exportClose(inUse); code != 400 || !strings.Contains(fmt.Sprint(out), "still names") {
		t.Fatalf("a close of an account a refill names: %d %v", code, out)
	}

	// retire and close another account: the rent comes back to the cold address
	spare := (inUse + 1) % 3
	if code, out := retire(spare); code != 200 {
		t.Fatalf("retire %d: %d %v", spare, code, out)
	}
	// the last account of the pool is never retired
	last := (inUse + 2) % 3
	if code, out := retire(last); code != 400 || !strings.Contains(fmt.Sprint(out), "last") {
		t.Fatalf("retiring the last account: %d %v", code, out)
	}
	code, out := exportClose(spare)
	if code != 200 {
		t.Fatalf("export close: %d %v", code, out)
	}
	var cf coldsign.SOLRequestFile
	s.via(out, &cf)
	// tampered files are refused offline: the rent to the hot shard, an account that is in the pool
	bad := cf
	bad.Request.To = s.hotAddr()
	if _, _, err := k.ceremony("close-to", refile(bad), "alice", "bob"); err == nil {
		t.Fatal("the offline signer signed a close with a destination")
	}
	bad = cf
	bad.Request.NonceIndexes = []int{7}
	if _, _, err := k.ceremony("close-out", refile(bad), "alice", "bob"); err == nil {
		t.Fatal("the offline signer signed a close of an account outside the pool")
	}
	before := s.lamports(k.addr)
	sg, o, err := k.ceremony("close", refile(cf), "alice", "bob")
	if err != nil {
		t.Fatalf("close ceremony: %v\n%s", err, o)
	}
	if code, out := s.call("POST", "/v2/cold-close/submit", map[string]any{"request": cf.Request, "signed": sg}); code != 200 {
		t.Fatalf("submit: %d %v", code, out)
	}
	if s.coldNonceExists(addrOf(spare)) {
		t.Fatal("the account still exists")
	}
	if gain := s.lamports(k.addr) - before; gain < sol.DefaultNonceRent-20_000 || gain > sol.DefaultNonceRent {
		t.Fatalf("the cold address gained %d lamports, want the rent %d less a fee", gain, sol.DefaultNonceRent)
	}
	s.reconcileClean("after closing a cold nonce account")

	// the refill that holds its account goes through, and a refill is never signed on the closed one
	closedReq := rf.Request
	closedReq.NonceAccount, closedReq.ID = addrOf(spare), "late"
	closedReq.Revision = 9
	if _, out, err := k.ceremony("on-closed", closedReq.File(), "alice", "bob"); err == nil || !strings.Contains(out, "signed for closing") {
		t.Fatalf("a refill on a closed account: %v\n%s", err, out)
	}
	sgR, o, err := k.ceremony("refill-after", rf, "alice", "carol")
	if err != nil {
		t.Fatalf("refill ceremony: %v\n%s", err, o)
	}
	if code, res := s.importRefill(r.ID, sgR); code != 200 {
		t.Fatalf("import: %d %v", code, res)
	}
	s.waitRefill("SOL", "confirmed", 120*time.Second)
	if bad := stop(); len(bad) > 0 {
		t.Fatalf("Reconcile failed: %v", bad)
	}
	s.reconcileClean("after the refill")
}
