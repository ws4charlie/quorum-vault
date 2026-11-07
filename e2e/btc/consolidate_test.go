package btce2e

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Consolidation of a hot shard's small outputs, on real mpc-party and a regtest node. The shard allows 4 inputs a transaction and consolidates when it
// holds more than 6 available outputs.

type co struct {
	ID, Status, Reason, Tx string
	Amount, Fee            int64
}

func (s *system) consolidations() []co {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id, status, COALESCE(failure_reason,''), COALESCE(tx_hash,''), amount::bigint, COALESCE(fee,0)::bigint FROM consolidations WHERE chain=$1 ORDER BY created_at, id`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []co
	for rows.Next() {
		var c co
		if err := rows.Scan(&c.ID, &c.Status, &c.Reason, &c.Tx, &c.Amount, &c.Fee); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func (s *system) consolidationsIn(status string) (n int) {
	for _, c := range s.consolidations() {
		if c.Status == status {
			n++
		}
	}
	return
}

func (s *system) untilConsolidations(n int, timeout time.Duration) {
	s.t.Helper()
	stop := s.keepMining()
	defer stop()
	s.waitFor(timeout, fmt.Sprintf("%d consolidations confirmed", n), func() bool { return s.consolidationsIn("confirmed") >= n })
}

// hotRows counts the hot shard's rows of any status.
func (s *system) hotRows() int {
	return s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold`, s.chain)
}

// fundHotOutputs pays one output of each value to the hot shard, mines to the credit depth and waits until the scan has recorded them all.
func (s *system) fundHotOutputs(values ...int64) {
	s.t.Helper()
	before := s.hotRows()
	for _, v := range values {
		s.node.pay(map[string]string{s.hotAddr: btcAmount(v)})
	}
	s.node.mine(6, "")
	s.waitFor(90*time.Second, "the hot outputs are recorded", func() bool { return s.hotRows() >= before+len(values) })
}

func repeat(v int64, n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func consolidateSystem(t *testing.T, o opts) *system {
	t.Helper()
	o.withdraw = true
	o.noEstimate = true // the fee rate is the fallback one, whatever ran on the node before
	o.maxInputs = 4
	s := newSystem(t, o)
	s.cf.Withdrawal.HotWait = "3m"
	t.Cleanup(func() { // the last lines of the worker's log, when the test failed (the directory goes away after this)
		if !t.Failed() {
			return
		}
		b, err := os.ReadFile(s.worker.log)
		if err != nil {
			return
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		t.Logf("the worker's log, last lines:\n%s", strings.Join(lines[max(0, len(lines)-40):], "\n"))
	})
	return s
}

// consolidatedInputs are the outpoints that consolidations spent, by the transaction that did.
func (s *system) consolidatedInputs() map[string]bool {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND owner_kind='consolidate'`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			s.t.Fatal(err)
		}
		p, err := btc.DecodePayload(raw)
		if err != nil {
			s.t.Fatal(err)
		}
		for _, in := range p.Inputs {
			out[fmt.Sprintf("%s:%d", in.TxID, in.Vout)] = true
		}
	}
	return out
}

func (s *system) outpointsOfValue(v int64) []string {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT txid || ':' || vout FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND value=$2`, s.chain, v)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, o)
	}
	return out
}

// A shard of many small outputs cannot pay a withdrawal that needs more inputs than one transaction takes, whichever outputs it picks. With
// consolidation on, the smallest outputs are merged (the largest stay free), the fee is the only thing booked, Reconcile reads clean, and the shard
// then pays the withdrawal it could not pay before, from the largest outputs, because the oldest cannot carry it.
func TestConsolidateMergesTheSmallestKeepsTheLargestAndTheShardPaysAgain(t *testing.T) {
	s := consolidateSystem(t, opts{})
	s.fundHotOutputs(repeat(100_000, 10)...)
	s.fundHotOutputs(150_000, 150_000)
	s.deposit("c1", 5_000_000)
	large := s.outpointsOfValue(150_000)
	if len(large) != 2 {
		t.Fatalf("%d outputs of 150000", len(large))
	}
	// 600,000 needs six outputs of these: more than max_inputs, so no choice of four can pay it.
	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 600_000)
	if w.Code != 201 {
		t.Fatalf("request: %d %v", w.Code, w.Raw)
	}
	s.holds(8*time.Second, "off: the withdrawal cannot be built and nothing is consolidated", func() bool {
		return s.attempts("send") == 0 && len(s.consolidations()) == 0 && s.getWd(w.ID).Status != "confirmed"
	})

	// Turn consolidation on.
	s.setConsolidation(6, 0)
	s.writeConfig(s.cf)
	s.restartWorker()
	s.untilConsolidations(2, 240*time.Second)
	cs := s.consolidations()
	if len(cs) != 2 {
		t.Fatalf("consolidations %+v", cs)
	}
	for _, c := range cs {
		if c.Status != "confirmed" || c.Amount != 400_000 || c.Fee <= 0 || c.Tx == "" {
			t.Fatalf("consolidation %+v: four outputs of 100,000, a fee, a transaction", c)
		}
		if got := s.attemptFee(c.Tx); got != c.Fee {
			t.Fatalf("booked fee %d, the transaction paid %d", c.Fee, got)
		}
	}
	// The largest stayed free: no consolidation spent them.
	spent := s.consolidatedInputs()
	if len(spent) != 8 {
		t.Fatalf("consolidations spent %d outputs, want the eight smallest", len(spent))
	}
	for _, o := range large {
		if spent[o] {
			t.Fatalf("a consolidation spent the large output %s", o)
		}
	}

	// The withdrawal now builds, from the largest outputs (the merged ones), and settles.
	stop := s.keepMining()
	w = s.waitWd(w.ID, "confirmed", 180*time.Second)
	stop()
	var raw []byte
	if err := s.pool.QueryRow(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND owner_kind='withdrawal' AND owner_id=$2`, s.chain, w.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	p, _ := btc.DecodePayload(raw)
	merged := map[string]bool{cs[0].Tx: true, cs[1].Tx: true}
	if len(p.Inputs) != 2 || !merged[p.Inputs[0].TxID] || !merged[p.Inputs[1].TxID] {
		t.Fatalf("the withdrawal spent %+v, want the two merged outputs", p.Inputs)
	}

	// The books: the value did not move, only the fees left the shard; the table and the ledger agree.
	s.node.mine(2, "")
	s.waitFor(60*time.Second, "nothing reserved", func() bool { return s.utxoCount("reserved") == 0 })
	if got, want := s.hotPosted().Int64(), -s.utxoValue("available"); got != want {
		t.Fatalf("hot mirror %d, the table holds %d", got, -want)
	}
	if got := s.onChain(s.hotAddr); got != s.utxoValue("available") {
		t.Fatalf("the shard holds %d on chain, %d in the table", got, s.utxoValue("available"))
	}
	s.ledgerOK()
	s.reconcileClean()
}

// Nothing runs at the threshold (6 outputs when more than 6 start it), nor while scanning is halted (the books cannot be trusted), and it runs when
// the conditions hold.
func TestConsolidateWaitsAtTheThresholdAndWhileScanningIsHalted(t *testing.T) {
	s := consolidateSystem(t, opts{consolidateAbove: 6})
	s.fundHotOutputs(repeat(100_000, 6)...)
	s.holds(6*time.Second, "at the threshold nothing runs", func() bool { return len(s.consolidations()) == 0 })

	// Scanning halted (a reorganization below the safe depth): two more outputs on the books, and still nothing runs.
	if _, err := s.pool.Exec(s.ctx, `INSERT INTO scan_halts (chain, reason) VALUES ($1, 'test: halted')`, s.chain); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.pool.Exec(s.ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path) VALUES ($1,$2,0,100000,$3,'1/0')`,
			s.chain, fmt.Sprintf("%064x", i+1), s.part); err != nil {
			t.Fatal(err)
		}
	}
	s.holds(6*time.Second, "scanning halted: nothing runs", func() bool { return len(s.consolidations()) == 0 })
	if _, err := s.pool.Exec(s.ctx, `DELETE FROM btc_utxos WHERE chain=$1 AND txid IN ($2,$3)`, s.chain, fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(s.ctx, `DELETE FROM scan_halts WHERE chain=$1`, s.chain); err != nil {
		t.Fatal(err)
	}

	// One more real output: seven, above the threshold.
	s.fundHotOutputs(100_000)
	s.untilConsolidations(1, 150*time.Second)
	cs := s.consolidations()
	if len(cs) != 1 || cs[0].Amount != 400_000 {
		t.Fatalf("consolidations %+v", cs)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// With the fee rate above consolidate_max_fee_rate nothing runs, and the log says why once.
func TestConsolidateWaitsWhileTheFeeRateIsAboveItsCeiling(t *testing.T) {
	// The rate is the node's estimate, else the fallback of 30: either way far above a ceiling of 2.
	s := consolidateSystem(t, opts{consolidateAbove: 6, consolidateMaxRate: 2, fallbackRate: 30})
	s.fundHotOutputs(repeat(100_000, 8)...)
	s.holds(8*time.Second, "the fee rate is above the ceiling (2): nothing runs", func() bool { return len(s.consolidations()) == 0 })
	b, err := os.ReadFile(s.worker.log)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "btc consolidation waits"); n != 1 {
		t.Fatalf("the log says why %d times, want once", n)
	}
}

// A hot-to-cold move that is open on the partition is already spending its outputs: no consolidation starts until it has finished.
func TestConsolidateWaitsWhileAColdMoveIsOpen(t *testing.T) {
	s := consolidateSystem(t, opts{consolidateAbove: 6, coldLow: "1000", coldHigh: "900000", coldTarget: "100000"})
	if err := syscallStop(s); err != nil { // the gateway: the move cannot be signed, so it stays open
		t.Fatal(err)
	}
	s.fundHotOutputs(repeat(100_000, 11)...)
	s.waitFor(60*time.Second, "a cold move is planned", func() bool { return len(s.coldMoves()) >= 1 })
	s.holds(8*time.Second, "a cold move is open: no consolidation", func() bool { return len(s.consolidations()) == 0 })
	if err := syscallCont(s); err != nil {
		t.Fatal(err)
	}
	s.untilColdMoves(1, 120*time.Second)
	// The move spent the four oldest outputs: seven are left, above the threshold, and now the consolidation goes.
	s.untilConsolidations(1, 150*time.Second)
	s.ledgerOK()
	s.reconcileClean()
}

// While a consolidation is open no second one starts, however many outputs arrive; a withdrawal that arrives meanwhile uses outputs the consolidation
// did not reserve; both finish, neither breaks the other, and Reconcile reads clean.
func TestConsolidateOneAtATimeAndAWithdrawalDuringIt(t *testing.T) {
	s := consolidateSystem(t, opts{consolidateAbove: 6})
	s.deposit("c1", 5_000_000)
	if err := syscallStop(s); err != nil { // the gateway: nothing is signed, so the consolidation stays open
		t.Fatal(err)
	}
	s.fundHotOutputs(repeat(100_000, 10)...)
	s.waitFor(60*time.Second, "a consolidation is built", func() bool { return s.utxoCount("reserved") == 4 })
	s.fundHotOutputs(repeat(100_000, 4)...)
	s.holds(6*time.Second, "one consolidation at a time, however many outputs arrive", func() bool { return len(s.consolidations()) == 1 })

	w := s.withdraw("ini", "k1", "c1", s.node.fresh(), 250_000)
	if w.Code != 201 {
		t.Fatalf("request: %d %v", w.Code, w.Raw)
	}
	s.waitFor(60*time.Second, "the withdrawal is built from the free outputs", func() bool { return s.utxoCount("reserved") > 4 })
	if err := syscallCont(s); err != nil {
		t.Fatal(err)
	}
	stop := s.keepMining()
	s.waitWd(w.ID, "confirmed", 180*time.Second)
	// The planner goes on until the shard holds no more than the threshold: wait for that, and for everything to settle.
	s.waitFor(240*time.Second, "the shard is consolidated down to the threshold and everything is settled", func() bool {
		open := len(s.consolidations()) - s.consolidationsIn("confirmed") - s.consolidationsIn("failed")
		return open == 0 && s.consolidationsIn("confirmed") >= 1 && s.utxoCount("reserved") == 0 && s.utxoCount("available") <= 6
	})
	stop()

	// Neither used the other's outputs.
	cs := s.consolidations()
	var raw []byte
	if err := s.pool.QueryRow(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND owner_kind='withdrawal' AND owner_id=$2`, s.chain, w.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	p, _ := btc.DecodePayload(raw)
	first := map[string]bool{}
	var rawC []byte
	if err := s.pool.QueryRow(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND owner_kind='consolidate' AND owner_id=$2 ORDER BY created_at LIMIT 1`, s.chain, cs[0].ID).Scan(&rawC); err != nil {
		t.Fatal(err)
	}
	pc, _ := btc.DecodePayload(rawC)
	for _, in := range pc.Inputs {
		first[fmt.Sprintf("%s:%d", in.TxID, in.Vout)] = true
	}
	for _, in := range p.Inputs {
		if first[fmt.Sprintf("%s:%d", in.TxID, in.Vout)] {
			t.Fatalf("the withdrawal spent %s:%d, an output of the open consolidation", in.TxID, in.Vout)
		}
	}
	s.ledgerOK()
	s.reconcileClean()
}

// One input of a consolidation is refused after another was signed: a cancel returns the inputs to the shard, and the consolidation is settled by
// the cancel (it spent the same inputs to one output of the shard), with the cancel's fee.
func TestConsolidateOneInputRefusedAfterAnotherWasSignedIsCancelledAndSettled(t *testing.T) {
	s := consolidateSystem(t, opts{consolidateAbove: 6})
	s.breakJobsOf("consol:%", true)
	s.fundHotOutputs(repeat(100_000, 7)...)
	s.waitAttempts("cancel", 1, 150*time.Second)
	s.dropBreak() // the replanned consolidation, if any, signs
	s.untilConsolidations(1, 150*time.Second)
	cs := s.consolidations()
	c := cs[0]
	cancel := s.lastAttempt("cancel")
	if c.Status != "confirmed" || c.Tx != cancel || c.Fee != s.attemptFee(cancel) || s.attempts("send") != 0 {
		t.Fatalf("consolidation %+v, cancel %s, %d sends", c, cancel, s.attempts("send"))
	}
	if got := s.hotPosted().Int64(); got != -(700_000 - c.Fee) {
		t.Fatalf("hot mirror %d, want %d", got, -(700_000 - c.Fee))
	}
	if s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND status='available' AND value=$2`, s.chain, 400_000-c.Fee) != 1 {
		t.Fatal("the cancel's output is not an available hot output")
	}
	s.ledgerOK()
	s.reconcileClean()
}

// Crash boundaries: the worker dies after the build, after the broadcast and after the confirmation (before the ledger is settled), is restarted,
// and the consolidation ends once: one transaction, only the fee booked. The bump and the refused-before-broadcast cases go through the same code as a
// withdrawal's (driveTx, ReleaseUnsigned): TestRecoveryStuckAtALowFeeIsBumpedAndTheReplacementConfirms, the withdrawal groups and the unit tests
// TestConsolidationBumpCancelAndSettle and TestConsolidationBumpRefusals prove them.
func TestConsolidateCrashAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		failpoint string
		mineFirst bool
	}{
		{"consolidate.after_build", false},
		{"consolidate.after_broadcast", false},
		{"consolidate.after_confirm", true},
	} {
		t.Run(tc.failpoint, func(t *testing.T) {
			s := consolidateSystem(t, opts{failpoint: tc.failpoint, consolidateAbove: 6})
			s.fundHotOutputs(repeat(100_000, 7)...)
			if tc.mineFirst {
				s.waitFor(60*time.Second, "the consolidation is broadcast", func() bool { return s.attempts("send") == 1 })
				s.node.mine(2, "")
			}
			s.waitExit(s.worker, "the worker at "+tc.failpoint)
			s.restartWorker()
			s.untilConsolidations(1, 150*time.Second)
			cs := s.consolidations()
			if len(cs) != 1 || s.attempts("send") != 1 || cs[0].Amount != 400_000 {
				t.Fatalf("consolidations %+v, %d send attempts", cs, s.attempts("send"))
			}
			if got := s.hotPosted().Int64(); got != -(700_000 - cs[0].Fee) {
				t.Fatalf("hot mirror %d, want %d", got, -(700_000 - cs[0].Fee))
			}
			if s.utxoCount("reserved") != 0 {
				t.Fatal("an output is still reserved")
			}
			s.ledgerOK()
			s.reconcileClean()
		})
	}
}

// Reconcile counts a consolidation in flight and reads clean at every stage: built and unsigned, in the mempool, with one confirmation, at the spend
// depth, and settled.
func TestConsolidateReconcileCleanWithOneInFlight(t *testing.T) {
	s := consolidateSystem(t, opts{consolidateAbove: 6})
	inFlightStages(t, s,
		func() { s.fundHotOutputs(repeat(100_000, 7)...) },
		func() bool { return s.utxoCount("reserved") > 0 },
		func() bool { return s.consolidationsIn("broadcast") == 1 },
		func() bool { return s.consolidationsIn("confirmed") == 1 })
}

// ---- attacks ----

// rogueConsolidation puts a consolidation job into the business database, as a compromised core would, for the real gateway to look at: a valid one
// built from real outputs of the shard (take of them, after skipping skip of the smallest), changed by mutate. It returns the decision of a rogue gateway whose own config is s.gwFile with the given
// consolidation limit; the real gateway and cosigner hold the limit the system was started with.
func (s *system) rogueConsolidation(id string, skip, take int, mutate func(p *btc.Payload, in *signjob.Intent), perHour int) gateway.Decision {
	t := s.t
	gf := s.gwFile
	chainCfg := gf.Chains[s.chain]
	chainCfg.ConsolidationsPerHour = perHour
	gf.Chains = map[string]gateway.ChainFile{s.chain: chainCfg}
	path := s.dir + "/rogue-gateway-" + id + ".json"
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
	rogue, err := gateway.New(cfg, nil, signers, guard, biz, gateway.Options{WorkerID: "rogue-" + id, Lease: time.Minute})
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
	rows, err := s.pool.Query(s.ctx, `SELECT txid, vout, value FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND status='available' ORDER BY value, txid, vout`, s.chain)
	if err != nil {
		t.Fatal(err)
	}
	p := btc.Payload{Version: 2}
	var sum uint64
	for rows.Next() {
		var txid string
		var vout uint32
		var v int64
		if err := rows.Scan(&txid, &vout, &v); err != nil {
			t.Fatal(err)
		}
		if skip > 0 {
			skip--
			continue
		}
		if len(p.Inputs) < take {
			p.Inputs = append(p.Inputs, btc.PayloadInput{TxID: txid, Vout: vout, Value: uint64(v), Path: []uint32{1, 0}, Sequence: btc.SequenceRBF})
			sum += uint64(v)
		}
	}
	rows.Close()
	p.Outputs = []btc.PayloadOutput{{Address: s.hotAddr, Value: sum - 2_000}}
	in := signjob.Intent{Kind: "consolidate", ID: "rogue-co-" + id, PartitionID: s.part, Chain: s.chain, Asset: "BTC", To: s.hotAddr, Amount: fmt.Sprint(sum)}
	mutate(&p, &in)
	built, err := btc.BuildUnsigned(p, s.acct)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	j := signjob.Job{ID: "consol:rogue-" + id + ":a1", PartitionID: s.part, KeyRef: "1/0", Chain: s.chain, Intent: mustJSON(in), Digest: built.Digests[0], Payload: raw}
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

// What a compromised core could ask of the real gateway: every one is refused before a key signs. And what a compromised gateway could ask of party B:
// within its own limit the shape is checked again, and party B counts its own hourly limit, so a gateway that allows more cannot get more signed.
func TestConsolidateAttacksAreRefusedByGatewayAndCosigner(t *testing.T) {
	s := consolidateSystem(t, opts{gwConsolidations: 1})
	s.fundHotOutputs(repeat(100_000, 12)...)
	attacker := s.node.fresh()
	for name, mutate := range map[string]func(p *btc.Payload, in *signjob.Intent){
		"output to any other address": func(p *btc.Payload, in *signjob.Intent) { p.Outputs[0].Address = attacker },
		"a second output": func(p *btc.Payload, in *signjob.Intent) {
			p.Outputs = []btc.PayloadOutput{{Address: s.hotAddr, Value: p.Outputs[0].Value - 100_000}, {Address: attacker, Value: 98_000}}
		},
		"one input": func(p *btc.Payload, in *signjob.Intent) {
			p.Inputs, p.Outputs, in.Amount = p.Inputs[:1], []btc.PayloadOutput{{Address: s.hotAddr, Value: p.Inputs[0].Value - 2_000}}, fmt.Sprint(p.Inputs[0].Value)
		},
		"an input from a deposit address": func(p *btc.Payload, in *signjob.Intent) { p.Inputs[1].Path = []uint32{0, 5} },
		"an amount that is not the sum":   func(p *btc.Payload, in *signjob.Intent) { in.Amount = "1" },
		"a fee above the cap":             func(p *btc.Payload, in *signjob.Intent) { p.Outputs[0].Value = 300 },
	} {
		d := s.rogueConsolidation(strings.ReplaceAll(name, " ", "-"), 0, 4, mutate, 1000)
		if d.Outcome != gateway.OutcomeRejected || !strings.HasPrefix(d.Reason, gateway.ReasonTx+":") {
			t.Fatalf("%s: %+v, want the verifier's refusal (%s)", name, d, gateway.ReasonTx)
		}
	}
	// A good one passes a gateway that allows 1000 an hour, and party B (limit 1) signs it: the first.
	d := s.rogueConsolidation("ok1", 0, 4, func(*btc.Payload, *signjob.Intent) {}, 1000)
	if d.Outcome != gateway.OutcomeSigned {
		t.Fatalf("a valid consolidation was not signed: %+v", d)
	}
	// A second, different one: the rogue gateway allows it, party B's own limit does not.
	d = s.rogueConsolidation("ok2", 4, 4, func(*btc.Payload, *signjob.Intent) {}, 1000)
	if d.Outcome == gateway.OutcomeSigned || d.Outcome == gateway.OutcomeReplayed || !strings.Contains(d.Reason, gateway.ReasonSignerRefused) {
		t.Fatalf("party B signed a consolidation over its own hourly limit: %+v", d)
	}
}
