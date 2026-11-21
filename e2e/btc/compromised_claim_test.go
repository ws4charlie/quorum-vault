package btce2e

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A coin claimed by a refused payment (reports/BTC-claim-design.md). The race is made deterministic: the candidate is applied everywhere, then the mark
// "compromised" to the cosigner's guard only. A withdrawal that the gateway admits (its replay guard claims the coin it spends) is refused by the
// cosigner ("signer_refused"): no signature exists, the claim stays, and a compromised generation signs nothing but its drain, which cannot spend a claimed
// coin. Then the emergency order runs as an operator would run it.

// applyToCosigner applies signed keyset records to party B's cosigner's guard only: the gateway keeps its own view.
func (s *system) applyToCosigner(files ...string) {
	s.t.Helper()
	for _, f := range files {
		out, err := exec.Command(filepath.Join(binDir, "qv-keysets"), "apply", "-config", s.gwPath, "-guard-dsn", "cosigner-b="+s.cosGuard, f).CombinedOutput()
		if err != nil {
			s.t.Fatalf("qv-keysets apply to the cosigner: %v\n%s", err, out)
		}
	}
}

// guardRows reads rows (text columns) from a guard database.
func (s *system) guardRows(dsn, query string, args ...any) [][]string {
	s.t.Helper()
	c, err := pgx.Connect(s.ctx, dsn)
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close(s.ctx)
	rows, err := c.Query(s.ctx, query, args...)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			s.t.Fatal(err)
		}
		r := make([]string, len(vals))
		for i, v := range vals {
			r[i] = fmt.Sprint(v)
		}
		out = append(out, r)
	}
	return out
}

// stranded describes what an operator sees: the jobs, the claims in the gateway's guard, the coins, the drain state.
func (s *system) stranded() string {
	var b strings.Builder
	rows, err := s.pool.Query(s.ctx, `SELECT id, status, COALESCE(reject_reason,'') FROM sign_jobs WHERE chain=$1 ORDER BY created_at, id`, s.chain)
	if err == nil {
		for rows.Next() {
			var id, st, why string
			rows.Scan(&id, &st, &why)
			fmt.Fprintf(&b, "  job %s: %s %.150s\n", id, st, why)
		}
		rows.Close()
	}
	for _, r := range s.guardRows(s.gwGuard, `SELECT claim, kind, intent_id FROM exclusive_claims ORDER BY claim`) {
		fmt.Fprintf(&b, "  gateway claim %s kind=%s intent=%s\n", r[0], r[1], r[2])
	}
	for _, r := range s.guardRows(s.cosGuard, `SELECT claim, kind, intent_id FROM exclusive_claims ORDER BY claim`) {
		fmt.Fprintf(&b, "  cosigner claim %s kind=%s intent=%s\n", r[0], r[1], r[2])
	}
	for _, st := range []string{"available", "reserved", "spent"} {
		fmt.Fprintf(&b, "  coins %s under 1/0: %d sats; all %s: %d sats in %d\n", st, s.hotUnder1(st), st, s.utxoValue(st), s.utxoCount(st))
	}
	for _, g := range s.treeKeysets() {
		fmt.Fprintf(&b, "  keyset generation %v %v drain=%v\n", g["generation"], g["state"], g["drain"])
	}
	return b.String()
}

func (s *system) hotUnder1(status string) int64 {
	var v int64
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(SUM(value),0) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND status=$2 AND path='1/0'`, s.chain, status).Scan(&v); err != nil {
		s.t.Fatal(err)
	}
	return v
}

func TestRekeyCompromisedGenerationFreesACoinClaimedByARefusedWithdrawal(t *testing.T) {
	s := newSystem(t, opts{withdraw: true, sweep: true, minSweep: "100000000", feeCaps: &feeCapsOpts{operators: 3}})
	stop := s.keepMining()
	defer func() { stop() }()
	s.fundHot(60_000_000)
	s.fundHot(25_000_000) // a second coin: it must reach the successor without waiting for the held one
	s.deposit("c1", 30_000_000)
	dir := filepath.Join(s.dir, "rekey")
	s.startReplacement(dir, s.ops)
	comp := s.treeChange("comp", 2, "-action", "mark-compromised", "-generation", "1", "-successor", "2", "-cap", "BTC=200000000")
	act := s.treeChange("act", 3, "-action", "activate", "-generation", "2")

	// The cosigner has the mark, the gateway has not: a withdrawal is admitted by the gateway and refused by the cosigner.
	s.applyToCosigner(comp)
	w := s.withdraw("ini", "k-claim", "c1", s.node.fresh(), 10_000_000)
	if w.Code != 201 {
		t.Fatalf("request: %d %v", w.Code, w.Raw)
	}
	s.waitFor(120*time.Second, "the withdrawal's job refused by the cosigner after the gateway claimed its coin", func() bool {
		return s.count(`SELECT count(*) FROM sign_jobs WHERE chain=$1 AND status='rejected' AND reject_reason LIKE 'signer_refused%'`, s.chain) > 0
	})
	t.Logf("after the refusal:\n%s", s.stranded())
	if n := len(s.guardRows(s.gwGuard, `SELECT 1 FROM exclusive_claims`)); n == 0 {
		t.Fatalf("the gateway holds no claim: the case is not made")
	}

	// The emergency order, as the operator runs it: the mark everywhere, then the successor is activated, then the drain.
	s.rekeyMust(dir, "drain-start", "-compromised", "-cap", "BTC=200000000", "-change", comp)
	s.rekeyMust(dir, "activate", "-change", act)
	drained := func() bool {
		g := s.treeKeysets()
		d, _ := g[0]["drain"].(map[string]any)
		return len(g) == 2 && d != nil && d["state"] == "drained"
	}
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) && !drained() {
		time.Sleep(3 * time.Second)
	}
	t.Logf("after the drain ran:\n%s", s.stranded())
	if !drained() {
		t.Fatalf("the drain of the compromised generation did not finish: %d sats are left under its hot shard", s.hotUnder("1/0"))
	}
	if left := s.hotUnder("1/0"); left > 1000 {
		t.Fatalf("%d sats left under the compromised hot shard", left)
	}
	stop()
	stop = func() {}
	s.reconcileClean()
	// the refused withdrawal ended cancelled: its hold is released, nothing is owed, the books balance
	if w2 := s.getWd(w.ID); w2.Status != "failed" {
		t.Fatalf("the refused withdrawal is %s (%s), want it voided", w2.Status, w2.Reason)
	}
	if a := s.available("c1").Int64(); a != 30_000_000 {
		t.Fatalf("customer has %d, the hold was not released", a)
	}
	s.ledgerOK()
}
