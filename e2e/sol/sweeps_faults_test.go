package sole2e

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// signSweepJob hands a sweep job straight to the signing zone's queue, with the deposit indices of its payload.
func (s *wdSys) signSweepJob(id, path string, in signjob.Intent, msg []byte, idxs []uint32) signjob.Job {
	s.t.Helper()
	p, _ := json.Marshal(sol.Payload{Message: msg, DepositIndices: idxs})
	ib, _ := json.Marshal(in)
	tx, err := s.pool.Begin(s.ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := signjob.Enqueue(s.ctx, tx, signjob.Job{ID: id, PartitionID: in.PartitionID, KeyRef: path, Chain: s.chain, Intent: ib, Digest: msg, Payload: p}); err != nil {
		tx.Rollback(s.ctx)
		s.t.Fatal(err)
	}
	if err := tx.Commit(s.ctx); err != nil {
		s.t.Fatal(err)
	}
	var j signjob.Job
	s.waitFor(90*time.Second, "the gateway to answer job "+id, func() bool {
		j, err = signjob.Get(s.ctx, s.pool, id)
		return err == nil && j.Status != signjob.StatusPending && j.Status != signjob.StatusSigning
	})
	return j
}

func (s *wdSys) refuseSweep(id, path string, in signjob.Intent, msg []byte, idxs []uint32, code string) {
	s.t.Helper()
	j := s.signSweepJob(id, path, in, msg, idxs)
	if j.Status == signjob.StatusDone || !strings.HasPrefix(j.RejectReason, code) {
		s.t.Fatalf("job %s: %s %q, want a refusal %q", id, j.Status, j.RejectReason, code)
	}
}

func TestSwFaults(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 4, minSweep: "5000000", batch: 3})
	hot, X := s.hot, newKey(t).pub
	var keys [][32]byte
	var addrs []string
	idxs := []uint32{201, 202}
	for _, ix := range idxs {
		c, _ := s.node.Derive(sol.BranchExternal, ix)
		keys = append(keys, c.PublicKey)
		addrs = append(addrs, sol.Address(c.PublicKey))
	}
	mk := func(nonceIdx int, price uint64, ixs ...sol.Ix) []byte {
		v := s.nonceValue(nonceIdx)
		base := []sol.Ix{sol.AdvanceNonceIx(sol.NonceAddress(hot, nonceIdx), hot), sol.SetLimitIx(60_000), sol.SetPriceIx(price)}
		return sol.Compile(hot, v, append(base, ixs...)...)
	}
	intent := func(id string, from []string, asset string, amount uint64) signjob.Intent {
		return signjob.Intent{Kind: "sweep", ID: id, PartitionID: s.cfg.PartitionKey(asset, 0).String(), Chain: s.chain, Asset: asset, From: strings.Join(from, ","), To: s.hotAddr(), Amount: fmt.Sprint(amount)}
	}

	s.sub(t, "the_signing_zone_refuses_every_attack_on_a_sweep", func(t *testing.T) {
		good := mk(3, 1000, sol.TransferIx(keys[0], hot, 1_000_000), sol.TransferIx(keys[1], hot, 2_000_000))
		in := intent("swatk-1", addrs, "SOL", 3_000_000)
		if j := s.signSweepJob("swatk-hot", "", in, good, idxs); j.Status != signjob.StatusDone {
			t.Fatalf("the honest sweep: %s %s", j.Status, j.RejectReason)
		}
		if j := s.signSweepJob("swatk-d1", sol.DepositPath(idxs[0]), in, good, idxs); j.Status != signjob.StatusDone {
			t.Fatalf("the honest sweep, deposit key: %s %s", j.Status, j.RejectReason)
		}
		// each deposit key signs only as the owner of its own transfer
		in2 := intent("swatk-2", addrs, "SOL", 3_000_000)
		s.refuseSweep("a1", "", in2, mk(2, 1000, sol.TransferIx(keys[0], hot, 1_000_000), sol.TransferIx(keys[1], X, 2_000_000)), idxs, "tx_mismatch")                                  // rent or funds elsewhere
		s.refuseSweep("a2", "", in2, mk(2, 1000, sol.TransferIx(keys[0], hot, 1_000_000), sol.TransferIx(keys[1], hot, 2_000_000), sol.TransferIx(keys[0], X, 1)), idxs, "tx_mismatch") // extra instruction using a deposit key
		s.refuseSweep("a3", "", in2, mk(2, 1000, sol.TransferIx(keys[0], hot, 1_000_000), sol.TransferIx(keys[1], hot, 2_000_001)), idxs, "tx_mismatch")                                // more than the intent
		s.refuseSweep("a4", sol.DepositPath(300), in2, mk(2, 1000, sol.TransferIx(keys[0], hot, 1_000_000), sol.TransferIx(keys[1], hot, 2_000_000)), idxs, "tx_mismatch")              // a key outside the batch
		foreign := newKey(t).pub
		s.refuseSweep("a5", "", intent("swatk-3", []string{sol.Address(foreign)}, "SOL", 3_000_000), mk(2, 1000, sol.TransferIx(foreign, hot, 3_000_000)), []uint32{201}, "tx_mismatch") // a key the account node does not derive
		s.refuseSweep("a6", "", in2, mk(2, 1000, sol.TransferIx(keys[1], hot, 2_000_000), sol.TransferIx(keys[0], hot, 1_000_000)), idxs, "tx_mismatch")                                 // signers in another order
		// tokens: rent of a closed account to anyone but the hot shard, tokens to any account but the hot shard's own
		tp := s.cfg.PartitionKey("TKN", 0).String()
		m := addrBytes(t, s.mint.addr())
		hotATA, d0 := s.c.ata(hot, m), s.c.ata(keys[0], m)
		tin := signjob.Intent{Kind: "sweep", ID: "swatk-t", PartitionID: tp, Chain: s.chain, Asset: "TKN", From: addrs[0], To: s.hotAddr(), Amount: "100"}
		s.refuseSweep("t1", "", tin, mk(2, 1000, sol.CheckedTransferIx(d0, m, hotATA, keys[0], 100, 6), sol.CloseAccountIx(d0, X, keys[0])), []uint32{201}, "tx_mismatch")
		s.refuseSweep("t2", "", tin, mk(2, 1000, sol.CheckedTransferIx(d0, m, s.c.ata(X, m), keys[0], 100, 6)), []uint32{201}, "tx_mismatch")
		// a sweep on a nonce another open intent holds, and a version that changes more than the price
		in4 := intent("swatk-4", addrs, "SOL", 3_000_000)
		s.refuseSweep("n1", "", in4, mk(3, 5000, sol.TransferIx(keys[0], hot, 1_000_000), sol.TransferIx(keys[1], hot, 2_000_000)), idxs, "replay_nonce_taken")
		s.refuseSweep("n2", "", in, mk(3, 500, sol.TransferIx(keys[0], hot, 1_000_000), sol.TransferIx(keys[1], hot, 2_000_000)), idxs, "replay_fee_not_higher")
		_ = ed25519.PublicKey{}
	})

	custs := []string{"f-a", "f-b", "f-c"}
	s.sub(t, "party_down_A_then_B_then_C", func(t *testing.T) {
		for _, role := range []string{"A", "B", "C"} {
			s.m3.Party(role).Kill()
			cust := "pd-" + role
			addr := s.depositAddr(cust)
			s.paySOL(addr, 2*oneSOL)
			s.waitDeposits(cust, 2*oneSOL, 0)
			if role == "C" {
				// the deposit key (A and B) and the hot shard (A with B) do not need C
				s.waitSwept("swept with C down", "SOL", addr)
			} else {
				// the deposit key is a 2-party key on A and B: with either down it cannot sign, so the sweep waits
				s.holds(12*time.Second, "no sweep lands while the deposit key cannot sign", func() bool { return s.lamports(addr) == 2*oneSOL })
			}
			s.m3.Party(role).Start(t)
			s.m3.WaitSigning(120 * time.Second)
			s.waitSwept("swept after "+role+" returned", "SOL", addr)
			s.reconcileClean("after party " + role + " was down")
		}
		_ = custs
	})
}

func TestSwCrash(t *testing.T) {
	s := newWdSystem(t, wdOpts{pool: 3, minSweep: "5000000", batch: 3})
	only := os.Getenv("QV_CRASH_BOUNDARIES")
	for i, p := range []string{"after_build", "after_job", "after_broadcast", "after_confirm", "after_settle"} {
		fp := "sweep." + p
		if only != "" && !strings.Contains(","+only+",", ","+fp+",") {
			continue
		}
		s.worker.stop()
		s.startWorker(fp)
		cust := fmt.Sprintf("crash-%d", i)
		addr := s.depositAddr(cust)
		hot0 := s.lamports(s.hotAddr())
		s.paySOL(addr, 2*oneSOL)
		s.waitDeposits(cust, 2*oneSOL, 0)
		if code, ok := exitCodeOf(s.worker, scale(120*time.Second)); !ok || code != 137 {
			t.Fatalf("%s: the worker did not die at the failpoint (exited=%v code=%d)", fp, ok, code)
		}
		// With the worker dead the scan stands still, so finalized activity of the sweep on the deposit address stays "not covered yet" and Reconcile may
		// decline to compare that address: what it must never do is report a difference.
		stop := s.watchReconcile()
		time.Sleep(4 * time.Second)
		if bad := stop(); len(bad) > 0 {
			t.Fatalf("%s: Reconcile reported a difference with the worker dead: %v", fp, bad)
		}
		s.startWorker("")
		s.waitSwept("swept after the restart", "SOL", addr)
		if gain := s.lamports(s.hotAddr()) - hot0; gain > 2*oneSOL || gain < 2*oneSOL-100_000 {
			t.Fatalf("%s: the hot shard gained %d, want 2 SOL less the fee (once)", fp, gain)
		}
		if n := s.count(`SELECT count(*) FROM sweeps WHERE chain=$1 AND from_address=$2 AND status='confirmed'`, s.chain, addr); n != 1 {
			t.Fatalf("%s: %d confirmed sweeps of the address", fp, n)
		}
		s.reconcileClean("after " + fp)
		t.Logf("crash %-24s ok: one sweep, Reconcile clean", fp)
	}
}
