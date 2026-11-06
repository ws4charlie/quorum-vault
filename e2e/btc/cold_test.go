package btce2e

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

type recCheck struct {
	Name, Subject, Ledger, Chain, Detail string
	OK, Skipped                          bool
}

type recon struct {
	Clean    bool
	Height   uint64
	InFlight int `json:"in_flight"`
	Checks   []recCheck
}

func (s *system) reconcile() recon {
	s.t.Helper()
	code, out := s.call("GET", "/v2/reconcile", nil)
	if code != 200 {
		s.t.Fatalf("reconcile: %d %v", code, out)
	}
	b, _ := json.Marshal(out)
	var r recon
	if err := json.Unmarshal(b, &r); err != nil {
		s.t.Fatal(err)
	}
	return r
}

func (r recon) failed() []recCheck {
	var f []recCheck
	for _, c := range r.Checks {
		if !c.OK && !c.Skipped {
			f = append(f, c)
		}
	}
	return f
}

func (r recon) has(name string) (ran bool) {
	for _, c := range r.Checks {
		if c.Name == name && !c.Skipped {
			return true
		}
	}
	return false
}

func (r recon) failedNames() string {
	var n []string
	for _, c := range r.failed() {
		n = append(n, c.Name+" "+c.Subject)
	}
	return strings.Join(n, ", ")
}

// reconcileClean waits until Reconcile passes with every chain comparison actually run (nothing in flight, the scan caught up).
func (s *system) reconcileClean() recon {
	s.t.Helper()
	var r recon
	s.waitFor(90*time.Second, "Reconcile is clean", func() bool {
		r = s.reconcile()
		return r.Clean && r.InFlight == 0 && r.has("hot") && r.has("deposit_addresses") && r.has("hot_outputs") && r.has("outputs_on_chain")
	})
	return r
}

type cm struct {
	ID, Status, Reason string
	Amount, Fee        int64
}

func (s *system) coldMoves() []cm {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id, status, COALESCE(failure_reason,''), amount::bigint, COALESCE(fee,0)::bigint FROM cold_moves WHERE chain=$1 ORDER BY created_at, id`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []cm
	for rows.Next() {
		var m cm
		if err := rows.Scan(&m.ID, &m.Status, &m.Reason, &m.Amount, &m.Fee); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func (s *system) coldMovesIn(status string) (n int, sum, fees int64) {
	for _, m := range s.coldMoves() {
		if m.Status == status {
			n++
			sum += m.Amount
			fees += m.Fee
		}
	}
	return
}

// untilColdMoves mines a block every 700 ms until n moves are settled.
func (s *system) untilColdMoves(n int, timeout time.Duration) {
	s.t.Helper()
	stop := s.keepMining()
	defer stop()
	s.waitFor(timeout, fmt.Sprintf("%d cold moves confirmed", n), func() bool { c, _, _ := s.coldMovesIn("confirmed"); return c >= n })
}

func coldSystem(t *testing.T, o opts, hotSats int64) *system {
	t.Helper()
	o.withdraw = true
	s := newSystem(t, o)
	s.cf.Withdrawal.HotWait = "3m"
	if hotSats > 0 {
		s.fundHot(hotSats)
	}
	return s
}

// A hot shard above its high-water mark sends the excess to cold: the move brings it down to the target, the change returns to the shard, the books
// and the outputs agree, and below the mark nothing moves.
func TestColdMoveAboveHighGoesToTargetAndBelowNothingMoves(t *testing.T) {
	s := coldSystem(t, opts{coldLow: "1000000", coldHigh: "30000000", coldTarget: "10000000"}, 20_000_000)
	s.holds(4*time.Second, "below the high-water mark nothing moves", func() bool { return len(s.coldMoves()) == 0 })
	s.fundHot(25_000_000) // 45M: above the high mark
	s.untilColdMoves(1, 90*time.Second)
	mv := s.coldMoves()
	if len(mv) != 1 || mv[0].Amount != 35_000_000 || mv[0].Fee <= 0 {
		t.Fatalf("moves %+v", mv)
	}
	if got := s.onChain(s.coldAddr); got != 35_000_000 {
		t.Fatalf("the cold address holds %d", got)
	}
	fee := mv[0].Fee
	if got := s.hotPosted().Int64(); got != -(45_000_000 - 35_000_000 - fee) {
		t.Fatalf("hot mirror %d, want %d", got, -(10_000_000 - fee))
	}
	if got := s.posted(custody.ColdAccount(s.part)).Int64(); got != -35_000_000 {
		t.Fatalf("cold account %d", got)
	}
	if got := s.posted(custody.ToColdAccount(s.chain, "BTC")).Int64(); got != 0 {
		t.Fatalf("to-cold clearing account %d", got)
	}
	if got := s.utxoValue("available"); got != 10_000_000-fee { // the change returned to the shard (the other inputs are spent)
		t.Fatalf("available hot outputs hold %d, want %d", got, 10_000_000-fee)
	}
	s.holds(4*time.Second, "back under the mark: no second move", func() bool { return len(s.coldMoves()) == 1 })
	s.ledgerOK()
	s.reconcileClean()
}

// A shard of many outputs: one transaction carries at most max_inputs of them, so a large excess moves in rounds, each only what the oldest available
// outputs can carry.
func TestColdMoveLargerThanMaxInputsGoesInRounds(t *testing.T) {
	s := coldSystem(t, opts{maxInputs: 2, coldLow: "1000000", coldHigh: "15000000", coldTarget: "5000000"}, 0)
	// Five outputs of 10M each, funded while the planner would act on each: fund them in one block so the shard crosses the mark at once.
	for i := 0; i < 5; i++ {
		s.node.pay(map[string]string{s.hotAddr: btcAmount(10_000_000)})
	}
	s.node.mine(6, "")
	s.waitFor(60*time.Second, "the five outputs are recorded", func() bool {
		return s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit`, s.chain) >= 5
	})
	s.untilColdMoves(2, 150*time.Second)
	n, sum, fees := s.coldMovesIn("confirmed")
	mv := s.coldMoves()
	if n < 2 || len(mv) != n {
		t.Fatalf("moves %+v", mv)
	}
	for _, m := range mv {
		if m.Amount >= 20_000_000 || m.Amount < 19_000_000 {
			t.Fatalf("a move carries %d: two inputs of 10M minus the fee are the most one can take", m.Amount)
		}
	}
	if got := s.onChain(s.coldAddr); got != sum {
		t.Fatalf("the cold address holds %d, the moves carried %d", got, sum)
	}
	if got := s.hotPosted().Int64(); got != -(50_000_000 - sum - fees) {
		t.Fatalf("hot mirror %d, want %d", got, -(50_000_000 - sum - fees))
	}
	s.ledgerOK()
	s.reconcileClean()
}

// Reconcile passes after a deposit, a sweep, a withdrawal and a move to cold, for every source; suspense on a deposit address is part of what the chain
// holds there.
func TestReconcileCleanAfterDepositSweepWithdrawalAndColdMove(t *testing.T) {
	s := sweepSystem(t, opts{coldLow: "1000000", coldHigh: "30000000", coldTarget: "10000000"}, 0)
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: btcAmount(50_000_000)})
	s.node.pay(map[string]string{addr: btcAmount(800)}) // below the minimum deposit: suspense, it stays on the address
	s.node.mine(6, "")
	s.waitAvailable("c1", 50_000_000, 60*time.Second)
	s.untilColdMoves(1, 150*time.Second) // sweep, then the excess goes to cold
	if s.sweepsIn("confirmed") != 1 {
		t.Fatalf("sweeps %+v", s.sweepRows())
	}
	dest := s.node.fresh()
	w := s.withdraw("ini", "k1", "c1", dest, 5_000_000)
	s.settle(w.ID)
	s.node.mine(8, "")
	r := s.reconcileClean()
	for _, name := range []string{"hot", "cold", "deposit_addresses", "hot_outputs", "deposit_outputs", "outputs_on_chain", "ledger_invariants"} {
		if !r.has(name) && name != "ledger_invariants" {
			t.Fatalf("check %q did not run: %+v", name, r.Checks)
		}
	}
	if got := s.available("c1").Int64(); got != 45_000_000 {
		t.Fatalf("customer has %d", got)
	}
}

// Each kind of difference is caught, names the address and both figures, and changes nothing.
func TestReconcileCatchesEveryKindOfDifference(t *testing.T) {
	s := coldSystem(t, opts{}, 20_000_000)
	s.node.mine(8, "")
	s.reconcileClean()
	mustFail := func(what string, names ...string) recon {
		t.Helper()
		var r recon
		s.waitFor(60*time.Second, what, func() bool {
			r = s.reconcile()
			got := r.failedNames()
			for _, n := range names {
				if !strings.Contains(got, n) {
					return false
				}
			}
			return true
		})
		if r.Clean {
			t.Fatalf("%s: reported clean", what)
		}
		for _, c := range r.failed() {
			if c.Name == "hot" && (c.Subject == "" || c.Ledger == "" || c.Chain == "") {
				t.Fatalf("%s: a difference must name the address and both figures: %+v", what, c)
			}
		}
		return r
	}

	// 1. Coins sent to a hot address outside the system, before the scan reaches them.
	s.worker.stop()
	s.node.pay(map[string]string{s.hotAddr: btcAmount(1_000_000)})
	s.node.mine(6, "")
	r := mustFail("coins on a hot address the scan has not reached", "hot ", "outputs_on_chain")
	if r.Height == 0 {
		t.Fatal("the report does not say which height it read")
	}
	s.startWorker() // the scan books it as operator funding
	s.reconcileClean()

	// 2. A row removed from the output table.
	var txid string
	var vout int
	var val int64
	if err := s.pool.QueryRow(s.ctx, `DELETE FROM btc_utxos WHERE (chain, txid, vout) = (SELECT chain, txid, vout FROM btc_utxos WHERE chain=$1 AND NOT deposit AND status='available' ORDER BY value LIMIT 1)
		RETURNING txid, vout, value`, s.chain).Scan(&txid, &vout, &val); err != nil {
		t.Fatal(err)
	}
	mustFail("a row removed from the table", "hot_outputs", "outputs_on_chain")
	if _, err := s.pool.Exec(s.ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path) VALUES ($1,$2,$3,$4,$5,'1/0')`, s.chain, txid, vout, val, s.part); err != nil {
		t.Fatal(err)
	}
	s.reconcileClean()

	// 3. A ledger entry that disagrees with the chain and the table.
	moveLedger := func(id string, from, to string, amt int64) {
		t.Helper()
		err := custody.InTx(s.ctx, s.pool, func(tx pgx.Tx) error {
			return ledger.New().Transfer(s.ctx, tx, ledger.TransferReq{ID: id, From: from, To: to, Amount: big.NewInt(amt)})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	opfund := "opfund:" + s.chain + ":BTC"
	moveLedger("t-bad", custody.HotAccount(s.part), opfund, 1234)
	r = mustFail("a ledger entry that disagrees", "hot ", "hot_outputs")
	for _, c := range r.failed() {
		if c.Name == "outputs_on_chain" {
			t.Fatal("the table and the chain agree: that check must pass")
		}
	}
	moveLedger("t-fix", opfund, custody.HotAccount(s.part), 1234)
	s.reconcileClean()

	// 4. An output spent behind our back: the key signed outside this system.
	if err := s.pool.QueryRow(s.ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND NOT deposit AND status='available' ORDER BY value DESC LIMIT 1`, s.chain).Scan(&txid, &vout, &val); err != nil {
		t.Fatal(err)
	}
	s.outsideSpend(txid, uint32(vout), uint64(val), s.node.fresh())
	s.node.mine(2, "")
	mustFail("an output spent behind our back", "hot ", "outputs_on_chain")
}

// A to-cold move to another pool's cold address, or one over the daily cap, is refused by the gateway; and by party B's cosigner when a rogue gateway
// that pinned the attacker's address signed it.
func TestColdMoveAttacksAreRefusedByGatewayAndCosigner(t *testing.T) {
	s := coldSystem(t, opts{}, 20_000_000)
	attacker := s.node.fresh()
	d := s.rogueColdMove(attacker, false)
	if d.Outcome != gateway.OutcomeRejected || !strings.Contains(d.Reason, "cold") {
		t.Fatalf("a move to an address that is not the pool's cold address, at a gateway with the real pins: %+v", d)
	}
	d = s.rogueColdMove(attacker, true)
	if d.Outcome == gateway.OutcomeSigned || d.Outcome == gateway.OutcomeReplayed {
		t.Fatalf("the cosigner signed a move to an address its own pins do not name: %+v", d)
	}
	if !strings.Contains(d.Reason, gateway.ReasonSignerRefused) {
		t.Fatalf("expected the signer's refusal, got %+v", d)
	}
}

func TestColdMoveOverTheDailyCapIsRefusedAndNothingMoves(t *testing.T) {
	s := coldSystem(t, opts{toColdCap: "1000000", coldLow: "1000000", coldHigh: "30000000", coldTarget: "10000000"}, 45_000_000)
	s.waitFor(60*time.Second, "the gateway refuses the move", func() bool {
		for _, m := range s.coldMoves() {
			if m.Status == "failed" && strings.Contains(m.Reason, "policy_to_cold_cap") {
				return true
			}
		}
		return false
	})
	if n, _, _ := s.coldMovesIn("confirmed"); n != 0 || s.onChain(s.coldAddr) != 0 {
		t.Fatal("something reached cold")
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND status='available' AND NOT deposit AND value=45000000`, s.chain) != 1 &&
		s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND status='reserved'`, s.chain) == 0 {
		t.Fatal("the shard's output is neither available nor held by a move")
	}
	s.ledgerOK()
}

// rogueColdMove signs a to-cold job through a gateway of its own: its own guard database and, when pinned, a config that names `to` as the pool's cold
// address. The real cosigner (party B) keeps the real pins.
func (s *system) rogueColdMove(to string, pinned bool) gateway.Decision {
	t := s.t
	gf := s.gwFile
	chainCfg := gf.Chains[s.chain]
	bf := *chainCfg.BTC
	bf.ColdAddresses = map[string]string{"omnibus/native": s.coldAddr}
	if pinned {
		bf.ColdAddresses = map[string]string{"omnibus/native": to}
	}
	chainCfg.BTC = &bf
	gf.Chains = map[string]gateway.ChainFile{s.chain: chainCfg}
	path := s.dir + "/rogue-gateway.json"
	writeJSONFile(t, path, gf)
	cfg, err := gateway.LoadConfig(path)
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
	rogue, err := gateway.New(cfg, nil, signers, guard, biz, gateway.Options{WorkerID: "rogue-cold", Lease: time.Minute})
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
	var txid string
	var vout uint32
	var val int64
	if err := s.pool.QueryRow(s.ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND NOT deposit AND status='available' ORDER BY value DESC LIMIT 1`, s.chain).Scan(&txid, &vout, &val); err != nil {
		t.Fatal(err)
	}
	amount := val / 2
	p := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{{TxID: txid, Vout: vout, Value: uint64(val), Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: to, Value: uint64(amount)}, {Address: s.hotAddr, Value: uint64(val - amount - 3000)}}}
	built, err := btc.BuildUnsigned(p, s.acct)
	if err != nil {
		t.Fatal(err)
	}
	in := signjob.Intent{Kind: "to-cold", ID: "rogue-cold-1", PartitionID: s.part, Chain: s.chain, Asset: "BTC", To: to, Amount: fmt.Sprint(amount)}
	raw, _ := json.Marshal(p)
	j := signjob.Job{ID: "tocold:rogue:a1", PartitionID: s.part, KeyRef: "1/0", Chain: s.chain, Intent: mustJSON(in), Digest: built.Digests[0], Payload: raw}
	tx, err := biz.Begin(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := signjob.Enqueue(s.ctx, tx, j); err != nil {
		t.Fatal(err)
	}
	tx.Commit(s.ctx)
	d, ok, err := rogue.RunOnce(s.ctx)
	if err != nil || !ok {
		t.Fatalf("the rogue gateway: ok=%v err=%v", ok, err)
	}
	return d
}

// The crash boundaries of a move to cold: the worker dies at each, is restarted, and the move ends once: one transaction to cold, books balanced.
func TestColdMoveCrashAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		failpoint string
		mineFirst bool
	}{
		{"to-cold.after_build", false},
		{"to-cold.after_job", false},
		{"to-cold.after_broadcast", false},
		{"to-cold.after_confirm", true},
	} {
		t.Run(tc.failpoint, func(t *testing.T) {
			s := coldSystem(t, opts{failpoint: tc.failpoint, coldLow: "1000000", coldHigh: "30000000", coldTarget: "10000000"}, 0)
			s.fundHot(45_000_000)
			if tc.mineFirst {
				s.waitFor(60*time.Second, "the move is broadcast", func() bool { return s.attempts("send") == 1 })
				s.node.mine(2, "")
			}
			s.waitExit(s.worker, "the worker at "+tc.failpoint)
			s.restartWorker()
			s.untilColdMoves(1, 120*time.Second)
			mv := s.coldMoves()
			if len(mv) != 1 || s.attempts("send") != 1 || mv[0].Amount != 35_000_000 {
				t.Fatalf("moves %+v, %d send attempts", mv, s.attempts("send"))
			}
			if got := s.onChain(s.coldAddr); got != 35_000_000 {
				t.Fatalf("cold holds %d", got)
			}
			if got := s.hotPosted().Int64(); got != -(10_000_000 - mv[0].Fee) {
				t.Fatalf("hot mirror %d", got)
			}
			if s.utxoCount("reserved") != 0 {
				t.Fatal("an output is still reserved")
			}
			s.ledgerOK()
		})
	}
}

// One input of a move is refused after another was signed: a cancel returns the inputs to the shard, the move ends failed with the cancel's fee, and
// nothing reached cold. Bump and the other crash cases go through the same code as withdrawals (driveTx, the typed errors, ReleaseUnsigned): the unit
// tests TestToColdBuildBumpAndCancel and the withdrawal groups prove them.
func TestColdMoveOneInputRefusedAfterAnotherWasSignedIsCancelled(t *testing.T) {
	s := coldSystem(t, opts{coldLow: "1000000", coldHigh: "15000000", coldTarget: "5000000"}, 0)
	s.breakJobsOf("tocold:%", true)
	s.node.pay(map[string]string{s.hotAddr: btcAmount(10_000_000)})
	s.node.pay(map[string]string{s.hotAddr: btcAmount(10_000_000)})
	s.node.mine(6, "")
	s.waitAttempts("cancel", 1, 120*time.Second)
	s.node.mine(2, "")
	s.waitFor(60*time.Second, "the move ends failed", func() bool { n, _, _ := s.coldMovesIn("failed"); return n >= 1 })
	if n, _, _ := s.coldMovesIn("confirmed"); n != 0 || s.onChain(s.coldAddr) != 0 {
		t.Fatal("something reached cold")
	}
	s.dropBreak()
	cancel := s.lastAttempt("cancel")
	fee := s.attemptFee(cancel)
	if got := s.hotPosted().Int64(); got != -(20_000_000 - fee) {
		t.Fatalf("hot mirror %d, want %d", got, -(20_000_000 - fee))
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND status='available' AND value=$2`, s.chain, 20_000_000-fee) != 1 {
		t.Fatal("the cancel's output is not an available hot output")
	}
	s.ledgerOK()
}

func (s *system) breakJobsOf(like string, onlySecond bool) {
	s.t.Helper()
	cond := "NEW.id LIKE '" + like + "'"
	if onlySecond {
		cond = "NEW.id LIKE '" + strings.TrimSuffix(like, "%") + "%.1'"
	}
	for _, q := range []string{
		`CREATE FUNCTION qv_break_any() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ` + cond + ` THEN NEW.key_ref := '1/9'; END IF; RETURN NEW; END $$`,
		`CREATE TRIGGER qv_break_any_t BEFORE INSERT ON sign_jobs FOR EACH ROW EXECUTE FUNCTION qv_break_any()`,
	} {
		if _, err := s.pool.Exec(s.ctx, q); err != nil {
			s.t.Fatal(err)
		}
	}
}

func (s *system) dropBreak() {
	s.t.Helper()
	if _, err := s.pool.Exec(s.ctx, `DROP TRIGGER qv_break_any_t ON sign_jobs`); err != nil {
		s.t.Fatal(err)
	}
}
