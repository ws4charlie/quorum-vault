package custody_test

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// Failure tests of the two-party signer, through real withdrawals. They run only with QV_CUSTODY_SIGNER=mpc. Every test ends
// with at most one payout per withdrawal (exactly one for the ones that must complete), no failed or refused sign job where
// the cause is an outage, and a clean Reconcile. Waits are on conditions (a log line, a database row, a health answer),
// never on a fixed sleep, so a slow CI runner only makes them longer.

func requireMPC(t *testing.T) {
	t.Helper()
	requireCustody(t)
	if !mpcMode() {
		t.Skip("QV_CUSTODY_SIGNER != mpc")
	}
}

func (s *system) gwLogCount(sub string) int { return strings.Count(readFile(s.gateway.log), sub) }

func (s *system) badJobs() int {
	return s.count(`SELECT count(*) FROM sign_jobs WHERE status NOT IN ('pending','signing','done')`)
}

var hundredth = func() *big.Int { return new(big.Int).Div(eth(1), big.NewInt(100)) }

// startPayment requests a 0.01 ETH withdrawal to a fresh address.
func (s *system) startPayment(customer, key string) (id string, to common.Address) {
	s.t.Helper()
	dest := randAddr()
	w := s.withdraw("initiator", key, customer, "ETH", dest, hundredth())
	if w.Code != 201 {
		s.t.Fatalf("%s: %d %v", key, w.Code, w.Raw)
	}
	return w.ID, dest
}

func (s *system) mustPayOnce(id string, dest common.Address, timeout time.Duration) {
	s.t.Helper()
	s.waitWd(id, "confirmed", timeout)
	if got := s.ethBalance(dest); got.Cmp(hundredth()) != 0 {
		s.t.Fatalf("withdrawal %s paid %s, want exactly %s", id, got, hundredth())
	}
}

// waitOutageSeen waits for the gateway to log one more "signer unavailable" ALERT than before.
func (s *system) waitOutageSeen(before int, what string) {
	s.t.Helper()
	s.waitFor(90*time.Second, "the gateway to see the outage ("+what+")", func() bool {
		return s.gwLogCount("ALERT signer unavailable") > before
	})
}

func (s *system) finish() {
	s.t.Helper()
	s.waitIdle(120 * time.Second)
	s.reconcileClean()
	if n := s.badJobs(); n != 0 {
		s.t.Fatalf("%d sign jobs failed or were rejected during an outage; an outage must only delay", n)
	}
	if n, c := s.count(`SELECT count(*) FROM ledger_txns WHERE id LIKE 'wd-out:%'`), s.count(`SELECT count(*) FROM withdrawals WHERE status='confirmed'`); n != c {
		s.t.Fatalf("%d wd-out entries for %d confirmed withdrawals", n, c)
	}
}

// With one of the signing components down, a withdrawal that reaches the sign step waits (the job stays open, one ALERT, no
// refusal, no void); when the component is back it completes with one payout. The worker is also killed at the two custody
// boundaries before the signature (after_build: nonce allocated, no job yet; after_job: job queued), so the restarted
// workflow finds a half-done withdrawal AND an outage.
func TestMPCKillSigningComponentAtCustodyBoundary(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{}, "c-mk", 20)
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("kill test, at " + current)
		}
	})
	type victim struct {
		name        string
		kill, start func()
	}
	victims := []victim{
		{"party-A", s.mpc.A.Kill, s.mpc.RestartA},
		{"party-B", s.mpc.B.Kill, s.mpc.RestartB},
		{"cosigner", s.mpc.Cos.Kill, s.mpc.StartCosignerAgain},
	}
	n := 0
	for _, v := range victims {
		for _, fp := range []string{"withdrawal.after_build", "withdrawal.after_job"} {
			n++
			current = v.name + " down, worker killed at " + fp
			s.worker.stop()
			s.startWorker(fp)
			before := s.gwLogCount("ALERT signer unavailable")
			afterSig := fp == "withdrawal.after_job" // this boundary is reached only once the signature exists
			if !afterSig {
				v.kill()
			}
			id, dest := s.startPayment("c-mk", fmt.Sprintf("k-mk-%d", n))
			if code, ok := s.worker.exitCode(scaled(90 * time.Second)); !ok || code != 137 {
				t.Fatalf("%s: worker did not die at %s (exited=%v code=%d)", v.name, fp, ok, code)
			}
			if afterSig {
				v.kill() // signed already: the restarted workflow must finish without the signer
			}
			s.startWorker("")
			if afterSig {
				s.mustPayOnce(id, dest, 150*time.Second)
				v.start()
				s.finish()
				t.Logf("kill %-9s at %-24s ok: signature existed, payout completed with the component down, one payout, Reconcile clean", v.name, fp)
				continue
			}
			s.waitOutageSeen(before, current)
			if got := s.getWd(id); got.Status == "confirmed" || got.Status == "failed" {
				t.Fatalf("%s: withdrawal is %s while %s is down", current, got.Status, v.name)
			}
			if s.ethBalance(dest).Sign() != 0 {
				t.Fatalf("%s: paid out while %s is down", current, v.name)
			}
			if a, h, _ := s.balance("c-mk", "ETH"); h.Sign() <= 0 {
				t.Fatalf("%s: no hold while the withdrawal is open (available %s held %s)", current, a, h)
			}
			v.start()
			s.mustPayOnce(id, dest, 150*time.Second)
			s.finish()
			t.Logf("kill %-9s at %-24s ok: waited with one ALERT, no failed job, completed after restart, one payout, Reconcile clean", v.name, fp)
		}
	}
}

// A party that dies in the middle of a signing session (the session is made slow so there is time to hit it).
func TestMPCKillPartyMidSession(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{mpcProxy: true}, "c-mid", 10)
	for i, v := range []struct {
		name        string
		kill, start func()
	}{{"party-A", s.mpc.A.Kill, s.mpc.RestartA}, {"party-B", s.mpc.B.Kill, s.mpc.RestartB}} {
		s.mpc.Proxy.SetLatency(500 * time.Millisecond)
		sessions := s.mpc.Proxy.Sessions.Load()
		before := s.gwLogCount("ALERT signer unavailable")
		id, dest := s.startPayment("c-mid", fmt.Sprintf("k-mid-%d", i))
		s.waitFor(90*time.Second, "a signing session to start", func() bool { return s.mpc.Proxy.Sessions.Load() > sessions })
		v.kill()
		s.waitOutageSeen(before, v.name+" killed mid-session")
		if s.ethBalance(dest).Sign() != 0 {
			t.Fatalf("paid out while %s is down", v.name)
		}
		s.mpc.Proxy.SetLatency(0)
		v.start()
		s.mustPayOnce(id, dest, 150*time.Second)
		s.finish()
		t.Logf("kill %s mid-session: job waited, completed after restart, one payout, Reconcile clean", v.name)
	}
}

// The link between A and B is cut during a withdrawal and healed later: once before the session starts, once in the middle of
// a session.
func TestMPCPartitionBetweenPartiesDuringWithdrawal(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{mpcProxy: true}, "c-part", 10)

	// 1. Cut before the withdrawal.
	before := s.gwLogCount("ALERT signer unavailable")
	s.mpc.Proxy.Partition()
	id, dest := s.startPayment("c-part", "k-part-1")
	s.waitOutageSeen(before, "link cut")
	if got := s.getWd(id); got.Status == "confirmed" || got.Status == "failed" {
		t.Fatalf("withdrawal is %s while the parties cannot talk", got.Status)
	}
	s.mpc.Proxy.Heal()
	s.mustPayOnce(id, dest, 150*time.Second)
	s.finish()

	// 2. Cut in the middle of a session.
	s.mpc.Proxy.SetLatency(500 * time.Millisecond)
	sessions := s.mpc.Proxy.Sessions.Load()
	before = s.gwLogCount("ALERT signer unavailable")
	id2, dest2 := s.startPayment("c-part", "k-part-2")
	s.waitFor(90*time.Second, "a signing session to start", func() bool { return s.mpc.Proxy.Sessions.Load() > sessions })
	s.mpc.Proxy.Partition()
	s.waitOutageSeen(before, "link cut mid-session")
	if s.ethBalance(dest2).Sign() != 0 {
		t.Fatal("paid out while the link is cut")
	}
	s.mpc.Proxy.SetLatency(0)
	s.mpc.Proxy.Heal()
	s.mustPayOnce(id2, dest2, 150*time.Second)
	s.finish()
}

// End-to-end withdrawal latency with delay added to every frame between A and B. A slow peer is one with a delay per frame
// large enough to matter (one second), which also has to complete inside the gateway's sign timeout.
func TestMPCWithdrawalLatencyWithSlowLink(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{mpcProxy: true}, "c-lat", 30)
	cases := []struct {
		name  string
		delay time.Duration
	}{{"no added delay (through the proxy)", 0}, {"20 ms per frame", 20 * time.Millisecond}, {"100 ms per frame", 100 * time.Millisecond}, {"slow peer: 1 s per frame", time.Second}}
	const n = 5
	for ci, c := range cases {
		s.mpc.Proxy.SetLatency(c.delay)
		var d []time.Duration
		for i := 0; i < n+1; i++ { // the first one warms the connections
			start := time.Now()
			id, dest := s.startPayment("c-lat", fmt.Sprintf("k-lat-%d-%d", ci, i))
			s.mustPayOnce(id, dest, 150*time.Second)
			if i > 0 {
				d = append(d, time.Since(start))
			}
		}
		// Signing alone, from the job row: created -> done.
		var signMS float64
		s.pool.QueryRow(s.ctx, `SELECT COALESCE(avg(extract(epoch from (updated_at - created_at))*1000),0) FROM (SELECT * FROM sign_jobs WHERE status='done' ORDER BY created_at DESC LIMIT $1) j`, n).Scan(&signMS)
		t.Logf("LATENCY %-36s withdrawal POST -> confirmed over %d runs: p50 %v  max %v   (sign job created -> done, mean %.0f ms)",
			c.name, n, pct(d, 0.5).Round(10*time.Millisecond), pct(d, 1).Round(10*time.Millisecond), signMS)
	}
	s.mpc.Proxy.SetLatency(0)
	s.finish()
}

// A Refresh while withdrawals are being made: none fails, none is refused, every one pays once.
func TestMPCRefreshDuringLiveWithdrawals(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{}, "c-ref", 20)
	h0, err := s.mpc.Health()
	if err != nil {
		t.Fatal(err)
	}
	gen0 := h0.Keysets[0].Generation

	type pay struct {
		id   string
		dest common.Address
	}
	var mu sync.Mutex
	var pays []pay
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // a steady trickle of withdrawals for as long as the refresh runs
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			id, dest := s.startPayment("c-ref", fmt.Sprintf("k-ref-%d", i))
			mu.Lock()
			pays = append(pays, pay{id, dest})
			mu.Unlock()
			time.Sleep(300 * time.Millisecond)
		}
	}()
	// Let some be in flight, then refresh.
	s.waitFor(60*time.Second, "withdrawals in flight", func() bool { mu.Lock(); defer mu.Unlock(); return len(pays) >= 2 })
	start := time.Now()
	const refreshes = 4
	for i := 0; i < refreshes; i++ {
		if err := s.mpc.Refresh(); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Refresh #%d during live withdrawals: %v", i+1, err)
		}
		n := len(pays)
		s.waitFor(60*time.Second, "more withdrawals between refreshes", func() bool { mu.Lock(); defer mu.Unlock(); return len(pays) >= n+2 })
	}
	took := time.Since(start)
	close(stop)
	wg.Wait()
	h1, err := s.mpc.Health()
	if err != nil {
		t.Fatal(err)
	}
	if g := h1.Keysets[0].Generation; g <= gen0 {
		t.Fatalf("generation %d -> %d: the refresh did not commit", gen0, g)
	}
	for _, p := range pays {
		s.mustPayOnce(p.id, p.dest, 150*time.Second)
	}
	// And one after the refresh, on the new shares.
	id, dest := s.startPayment("c-ref", "k-ref-after")
	s.mustPayOnce(id, dest, 150*time.Second)
	s.finish()
	t.Logf("REFRESH x%d took %v in all, with %d withdrawals made around them; generation %d -> %d; none failed, none refused, each paid once", refreshes, took.Round(10*time.Millisecond), len(pays), gen0, h1.Keysets[0].Generation)
}

// A keyset frozen while withdrawals are live: the sign jobs fail with an ALERT, no hold is voided while a nonce is open, and
// after the operator unfreezes and resumes the parked rows (the documented procedure) the cancels complete, the holds are
// voided only then, and later withdrawals proceed.
func TestMPCFreezeDuringLiveWithdrawals(t *testing.T) {
	requireMPC(t)
	s, _ := funded(t, opts{mpcProxy: true}, "c-frz", 20)
	current := "setup"
	t.Cleanup(func() {
		if t.Failed() {
			s.dump("freeze test, at " + current)
		}
	})

	// A normal one first.
	id0, dest0 := s.startPayment("c-frz", "k-frz-0")
	s.mustPayOnce(id0, dest0, 150*time.Second)

	// A man in the middle corrupts one protocol message during the next withdrawal's signature.
	current = "tamper"
	alerts := s.gwLogCount("ALERT signer failure")
	s.mpc.Proxy.Tamper(0, 2)
	id1, dest1 := s.startPayment("c-frz", "k-frz-1")
	s.waitFor(90*time.Second, "the keyset to freeze", s.mpc.Frozen)
	s.mpc.Proxy.Tamper(0, -1)
	s.waitFor(60*time.Second, "an ALERT for the failed sign job", func() bool { return s.gwLogCount("ALERT signer failure") > alerts })

	// More withdrawals arrive while frozen.
	current = "frozen"
	id2, dest2 := s.startPayment("c-frz", "k-frz-2")

	// Both end up parked for an operator: signing failed twice, the cancel failed too. Nothing is voided, nothing paid.
	for _, id := range []string{id1, id2} {
		id := id
		s.waitFor(120*time.Second, "withdrawal "+id+" to be parked", func() bool { return strings.HasPrefix(s.getWd(id).Reason, "parked:") })
	}
	for _, c := range []struct {
		id   string
		dest common.Address
	}{{id1, dest1}, {id2, dest2}} {
		if st := s.getWd(c.id).Status; st == "failed" || st == "confirmed" {
			t.Fatalf("withdrawal %s is %s while its nonce is open", c.id, st)
		}
		if s.ethBalance(c.dest).Sign() != 0 {
			t.Fatalf("withdrawal %s paid out", c.id)
		}
		if st := s.nonceStatus(c.id); st == "confirmed" || st == "cancelled" {
			t.Fatalf("withdrawal %s: nonce is %s although nothing was signed", c.id, st)
		}
	}
	if _, h, _ := s.balance("c-frz", "ETH"); h.Cmp(new(big.Int).Mul(hundredth(), big.NewInt(2))) != 0 {
		t.Fatalf("held %s, want both withdrawals still held", h)
	}
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE status='done' AND id LIKE 'wd:%'`); n != 1 {
		t.Fatalf("%d sign jobs done; only the first withdrawal signed", n)
	}

	// The operator unfreezes. Parked rows stay parked until an operator clears the reason; a new withdrawal signs, but its
	// transaction cannot mine ahead of the open nonces, so it waits behind them.
	current = "unfrozen"
	if err := s.mpc.Unfreeze(); err != nil {
		t.Fatalf("unfreeze: %v", err)
	}
	if s.mpc.Frozen() {
		t.Fatal("still frozen after Unfreeze")
	}
	id3, dest3 := s.startPayment("c-frz", "k-frz-3")
	s.waitBroadcast(id3)
	if s.ethBalance(dest3).Sign() != 0 {
		t.Fatal("a later withdrawal mined ahead of two open nonces")
	}

	// The operator resumes the parked rows (the documented step: clear failure_reason; the reconciler restarts the workflow).
	current = "resume"
	for _, id := range []string{id1, id2} {
		if _, err := s.pool.Exec(s.ctx, `UPDATE withdrawals SET failure_reason=NULL WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	// The gateway reserved the CANCEL of each nonce while the keyset was frozen (the cancel job failed, but its reservation
	// stands), so the original transaction can never be signed any more: it would race its own cancel. The restarted workflow
	// therefore finishes the cancel (a failed retry job is reopened, same digest, same signature), the cancel mines, and
	// only then the hold is voided. The money comes back only after the nonce is provably spent.
	for _, c := range []struct {
		id   string
		dest common.Address
	}{{id1, dest1}, {id2, dest2}} {
		got := s.waitWd(c.id, "failed", 180*time.Second)
		if !strings.Contains(got.Reason, "gateway refused") {
			t.Fatalf("withdrawal %s voided with %q", c.id, got.Reason)
		}
		if st := s.nonceStatus(c.id); st != "cancelled" && st != "confirmed" {
			t.Fatalf("withdrawal %s: nonce is %s after the void", c.id, st)
		}
		if s.ethBalance(c.dest).Sign() != 0 {
			t.Fatalf("withdrawal %s paid out although its cancel was signed", c.id)
		}
	}
	s.mustPayOnce(id3, dest3, 180*time.Second)
	if _, h, _ := s.balance("c-frz", "ETH"); h.Sign() != 0 {
		t.Fatalf("held %s after everything finished", h)
	}
	s.waitIdle(120 * time.Second)
	s.reconcileClean()
	t.Logf("FREEZE: tampered session froze the keyset; ALERT logged; two withdrawals parked with holds and nonces kept; after Unfreeze and resume the cancels were signed and mined, both holds were voided, the later withdrawal paid once; Reconcile clean")
}

func (s *system) nonceStatus(withdrawalID string) string {
	var st string
	if err := s.pool.QueryRow(s.ctx, `SELECT status FROM evm_nonce_allocations WHERE owner_kind='withdrawal' AND owner_id=$1`, withdrawalID).Scan(&st); err != nil {
		return "none"
	}
	return st
}
