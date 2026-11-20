package custody_test

import (
	"fmt"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Key replacement, business side: two generations of one EVM hot shard and the drain of the old one into the new one, with the real gateway
// (and, in mpc mode, the cosigners), in both signer modes. Generation 2 only RECEIVES here: nothing in the signing zone can send from a second key
// of a shard yet (its signers are one key per partition, wired by the tool of K3), so what is sent from generation 2 is covered below the zone
// (internal/custody and internal/chain/evm tests) and not here.

const usdtDeposit = 800_000_000

func (s *system) shardID() string { return string(s.cfg.PartitionKey("ETH", 0).ShardID()) }

// zone applies one signed keyset change to every guard database of the zone (qv-keysets: two operators sign, apply).
func (s *system) zone(seq int, args ...string) {
	s.t.Helper()
	bin := filepath.Join(binDir, "qv-keysets")
	base := []string{"sign", "-seq", fmt.Sprint(seq), "-shard", s.shardID()}
	f := filepath.Join(s.dir, fmt.Sprintf("change-%d.json", seq))
	run := func(a ...string) {
		s.t.Helper()
		out, err := exec.Command(bin, a...).CombinedOutput()
		if err != nil {
			s.t.Fatalf("qv-keysets %v: %v\n%s", a, err, out)
		}
	}
	run(append(append(base, "-operator", "op1", "-key", filepath.Join(s.dir, "op1.key"), "-out", f), args...)...)
	run("sign", "-operator", "op2", "-key", filepath.Join(s.dir, "op2.key"), "-join", f, "-out", f)
	apply := []string{"apply", "-config", s.gwPath, "-guard-dsn", "gateway=" + s.guardDSN}
	if mpcMode() {
		apply = append(apply, "-guard-dsn", "cosigner-b="+s.cosGuardDSN, "-guard-dsn", "cosigner-c="+s.cosCGuardDSN)
	}
	run(append(apply, f)...)
}

// coreStep mirrors a step into the business registry through the admin API.
func (s *system) coreStep(path string, body map[string]any, want int) map[string]any {
	s.t.Helper()
	code, out := s.call("POST", "/v2/keysets/"+path, map[string]string{"X-Actor": "ops"}, body)
	if code != want {
		s.t.Fatalf("POST /v2/keysets/%s: %d %v (want %d)", path, code, out, want)
	}
	return out
}

func (s *system) keysetViews() []map[string]any {
	s.t.Helper()
	code, out := s.call("GET", "/v2/keysets", nil, nil)
	if code != 200 {
		s.t.Fatalf("GET /v2/keysets: %d %v", code, out)
	}
	var v []map[string]any
	for _, k := range out["keysets"].([]any) {
		v = append(v, k.(map[string]any))
	}
	return v
}

func (s *system) drainView(gen int) (state, reason string) {
	for _, k := range s.keysetViews() {
		if int(k["generation"].(float64)) == gen {
			if d, ok := k["drain"].(map[string]any); ok {
				state, _ = d["state"].(string)
				reason, _ = d["reason"].(string)
				return state, reason
			}
		}
	}
	return "", ""
}

// dumpDrains logs the drain tables when a test fails.
func (s *system) dumpDrains() {
	if !s.t.Failed() {
		return
	}
	rows, err := s.pool.Query(s.ctx, `SELECT m.id, m.asset, m.amount::text, m.status, COALESCE(m.failure_reason,''), COALESCE(k.state,''), COALESCE(k.reason,'') FROM drain_moves m LEFT JOIN keyset_drains k ON k.shard_id=m.shard_id AND k.generation=m.from_generation ORDER BY m.created_at`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var a [7]string
		rows.Scan(&a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6])
		s.t.Logf("drain move %v", a)
	}
}

func (s *system) drains(status string) int {
	return s.count(`SELECT count(*) FROM drain_moves WHERE status=$1`, status)
}

// shardFunded makes a shard with ETH and USDT in the hot wallet (swept deposits) and returns the customer's address.
func shardFunded(t *testing.T, o opts) *system {
	t.Helper()
	o.keysets = true
	s := newSystem(t, o)
	t.Cleanup(s.dumpDrains)
	addr := s.newCustomer("c-dr")
	s.sendETH(addr, eth(10))
	s.mintUSDT(addr, usdtDeposit)
	s.waitAvailable("c-dr", "ETH", eth(10), 30*time.Second)
	s.waitAvailable("c-dr", "USDT", big.NewInt(usdtDeposit), 30*time.Second)
	s.waitFor(120*time.Second, "the USDT swept to the hot wallet", func() bool { return s.usdtBalance(s.shardAddr[0]).Cmp(big.NewInt(usdtDeposit)) == 0 })
	s.waitIdle(60 * time.Second)
	s.reconcileClean()
	return s
}

func (s *system) withdrawETH(key string, n int64) wd {
	s.t.Helper()
	w := s.withdraw("initiator", key, "c-dr", "ETH", randAddr(), big.NewInt(n))
	if w.Code != 201 {
		s.t.Fatalf("%d %v", w.Code, w.Raw)
	}
	for _, a := range []string{"alice", "bob"} {
		s.approve(a, w.ID)
	}
	return w
}

// The whole replacement of a shard's key, from the business side.
func TestDrainMovesAShardToItsSuccessor(t *testing.T) {
	s := shardFunded(t, opts{})
	gen1, gen2 := s.shardAddr[0], randAddr()
	caps := []string{"-cap", "ETH=" + eth(1_000_000).String(), "-cap", "USDT=1000000000000"}

	// Before: a withdrawal is paid from generation 1.
	before := s.withdrawETH("k-before", 1e15)
	s.waitWd(before.ID, "confirmed", 90*time.Second)
	s.waitIdle(60 * time.Second)
	s.reconcileClean()

	// The core is told first (the wrong order on purpose: the zone has no record yet), so the zone's refusal is what the drain meets.
	s.coreStep("candidates", map[string]any{"shard_id": s.shardID(), "address": gen2.Hex(), "key_ref": "keyset-2"}, 201)
	s.coreStep("drains", map[string]any{"shard_id": s.shardID(), "generation": 1, "successor": 2}, 200)
	s.coreStep("activations", map[string]any{"shard_id": s.shardID(), "generation": 2}, 200)
	s.reconcileClean()

	// A withdrawal now is built from generation 2, which holds nothing yet: it waits, with the reason, and nothing is stranded (a person ends it).
	during := s.withdrawETH("k-during", 1e15)
	s.holds(6*time.Second, "the withdrawal waits", func() bool { return s.getWd(during.ID).Status != "confirmed" && s.getWd(during.ID).Tx == "" })
	if code, out := s.call("POST", "/v2/withdrawals/"+during.ID+"/rejections", map[string]string{"X-Actor": "ops"}, map[string]any{"reason": "waiting for the successor key"}); code != 202 {
		t.Fatalf("reject: %d %v", code, out)
	}
	s.waitWd(during.ID, "failed", 60*time.Second)
	if a, h, _ := s.balance("c-dr", "ETH"); h.Sign() != 0 || a.Sign() <= 0 {
		t.Fatalf("available %s held %s: the hold must be released", a, h)
	}

	// Refused by the zone: it has no start-draining record, so the drain waits (its not_after passes), the move ends with the zone's reason on the
	// generation, and nothing moved.
	usdtBefore, ethBefore := s.usdtBalance(gen1), s.ethBalance(gen1)
	s.waitFor(180*time.Second, "the zone's refusal shown as a wait", func() bool {
		st, why := s.drainView(1)
		return st == "waiting" && strings.Contains(why, "signing zone refused")
	})
	if d := new(big.Int).Sub(ethBefore, s.ethBalance(gen1)); s.usdtBalance(gen1).Cmp(usdtBefore) != 0 || d.Cmp(big.NewInt(1e15)) > 0 || s.drains("confirmed") != 0 { // the cancel of a refused move costs a little gas
		t.Fatal("something moved although the zone refused")
	}
	s.reconcileClean()

	// The zone's steps, then the same ones the core already has: the next drain pass moves USDT, then ETH, and reports "drained".
	s.zone(1, "-action", "register-candidate", "-generation", "2", "-address", gen2.Hex())
	s.zone(2, append([]string{"-action", "start-draining", "-generation", "1", "-successor", "2"}, caps...)...)
	s.zone(3, "-action", "activate", "-generation", "2")
	s.waitFor(240*time.Second, "the generation to be drained", func() bool { st, _ := s.drainView(1); return st == "drained" })
	s.waitIdle(60 * time.Second)

	if got := s.usdtBalance(gen2); got.Cmp(big.NewInt(usdtDeposit)) != 0 || s.usdtBalance(gen1).Sign() != 0 {
		t.Fatalf("USDT: generation 2 holds %s, generation 1 %s", got, s.usdtBalance(gen1))
	}
	left := s.ethBalance(gen1)
	if left.Cmp(big.NewInt(1e16)) >= 0 {
		t.Fatalf("generation 1 still holds %s ETH wei: only the last transfer's gas may stay", left)
	}
	if s.ethBalance(gen2).Cmp(eth(100)) <= 0 { // seed 100 + 10 deposit - what was paid out, less dust
		t.Fatalf("generation 2 holds %s", s.ethBalance(gen2))
	}
	if n, f := s.drains("confirmed"), s.drains("failed"); n != 2 || f < 1 {
		t.Fatalf("drain moves: %d confirmed (one per asset), %d failed (the refused one)", n, f)
	}
	// The books: the shard's balance is unchanged by the drain, only the gas is a cost; Reconcile adds both addresses up.
	rep := s.reconcileClean()
	two := false
	for _, c := range rep.Checks {
		if c.Name == "hot" && strings.Contains(c.Detail, "generation 2") {
			two = true
		}
	}
	if !two {
		t.Fatalf("the hot checks do not show two generations: %+v", rep.Checks)
	}
	// Idempotent: further passes plan nothing.
	s.waitPasses(workflowDrainPlanner(s), 3)
	if n := s.count(`SELECT count(*) FROM drain_moves`); n != s.drains("confirmed")+s.drains("failed") {
		t.Fatalf("%d drain moves after it was drained", n)
	}

	// Retiring: the zone, then the core, which checks the chain first.
	s.zone(4, "-action", "retire", "-generation", "1")
	s.coreStep("retirements", map[string]any{"shard_id": s.shardID(), "generation": 1}, 200)
	s.reconcileClean()
	s.requireAudit("keyset.retired")
	s.requireAudit("drain.started")
}

func workflowDrainPlanner(s *system) string { return "drain-planner:" + s.chainName }

// Crash: the worker dies between the drain's broadcast and its confirmation, and between two assets; nothing moves twice and nothing is lost.
func TestDrainCrashBetweenBroadcastAndConfirmAndBetweenAssets(t *testing.T) {
	s := shardFunded(t, opts{})
	gen1, gen2 := s.shardAddr[0], randAddr()
	totalETH, totalUSDT := s.ethBalance(gen1), s.usdtBalance(gen1)
	// A worker that dies at the first failpoint, with the zone and the core already agreeing.
	s.worker.stop()
	s.startWorker("drain.after_broadcast")
	s.zone(1, "-action", "register-candidate", "-generation", "2", "-address", gen2.Hex())
	s.zone(2, "-action", "start-draining", "-generation", "1", "-successor", "2", "-cap", "ETH="+eth(1_000_000).String(), "-cap", "USDT=1000000000000")
	s.zone(3, "-action", "activate", "-generation", "2")
	s.coreStep("candidates", map[string]any{"shard_id": s.shardID(), "address": gen2.Hex()}, 201)
	s.coreStep("drains", map[string]any{"shard_id": s.shardID(), "generation": 1, "successor": 2}, 200)
	s.coreStep("activations", map[string]any{"shard_id": s.shardID(), "generation": 2}, 200)
	if code, ok := s.worker.exitCode(scaled(120 * time.Second)); !ok || code != 137 {
		t.Fatalf("the worker did not die after the broadcast (exited=%v code=%d)", ok, code)
	}
	// Restarted, it dies again after the first asset is settled, before the second is planned.
	s.startWorker("drain.after_settle")
	if code, ok := s.worker.exitCode(scaled(120 * time.Second)); !ok || code != 137 {
		t.Fatalf("the worker did not die after the settlement (exited=%v code=%d)", ok, code)
	}
	if n := s.drains("confirmed"); n != 1 {
		t.Fatalf("%d confirmed drain moves after the first crash pair, want 1 (the token)", n)
	}
	s.startWorker("")
	s.waitFor(240*time.Second, "the generation to be drained", func() bool { st, _ := s.drainView(1); return st == "drained" })
	s.waitIdle(60 * time.Second)
	if n, f := s.drains("confirmed"), s.drains("failed"); n != 2 || f != 0 {
		t.Fatalf("%d confirmed, %d failed drain moves, want exactly one per asset", n, f)
	}
	if got := s.usdtBalance(gen2); got.Cmp(totalUSDT) != 0 {
		t.Fatalf("USDT on generation 2: %s, want exactly %s (one transfer)", got, totalUSDT)
	}
	moved := s.ethBalance(gen2)
	if moved.Cmp(totalETH) > 0 || new(big.Int).Sub(totalETH, moved).Cmp(big.NewInt(1e16)) > 0 {
		t.Fatalf("ETH on generation 2: %s of %s (the gas and the dust may stay, nothing else)", moved, totalETH)
	}
	// One nonce per transaction at the old address: no gap, no second use.
	var dup int
	s.pool.QueryRow(s.ctx, `SELECT count(*) FROM (SELECT address, nonce FROM evm_nonce_allocations WHERE owner_kind='drain' GROUP BY 1,2 HAVING count(*) > 1) x`).Scan(&dup)
	if dup != 0 {
		t.Fatal("a nonce was used twice")
	}
	s.reconcileClean()
}
