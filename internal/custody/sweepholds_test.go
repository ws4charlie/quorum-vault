package custody

import (
	"bytes"
	"context"
	"log/slog"
	"math/big"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// feeChain is the fake chain with a sweep fee the test can change.
type feeChain struct {
	*fakeChain
	sweepFee *big.Int
}

func (f *feeChain) EstimateSweepFee(context.Context, chain.SweepIntent) (*big.Int, error) {
	return new(big.Int).Set(f.sweepFee), nil
}

func newHoldSvc(t *testing.T, fee int64) (*Service, *feeChain) {
	t.Helper()
	s, fc := newSvc(t)
	f := &feeChain{fakeChain: fc, sweepFee: big.NewInt(fee)}
	s.Chain = f
	return s, f
}

func credit(t *testing.T, s *Service, id, addr, asset string, amt int64) {
	t.Helper()
	if _, err := s.Pool.Exec(context.Background(), `INSERT INTO deposits (id, chain, asset, address, amount, dedup_key, status, block_height) VALUES ($1,$2,$3,$4,$5,$1,'credited',3)`,
		id, testChain, asset, addr, amt); err != nil {
		t.Fatal(err)
	}
}

func planOnce(t *testing.T, s *Service) []Sweep {
	t.Helper()
	out, err := s.PlanSweeps(context.Background(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func unsweptOf(t *testing.T, s *Service, addr string) *UnsweptDeposit {
	t.Helper()
	rep, err := s.UnsweptDeposits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range rep.Items {
		if rep.Items[i].Address == addr {
			return &rep.Items[i]
		}
	}
	return nil
}

// A small deposit at a high fee is held, with the value, the fee and the line it must reach; it is swept, and the record goes, when the fee falls.
func TestHeldBelowThresholdClearsWhenTheFeeFalls(t *testing.T) {
	s, fc := newHoldSvc(t, 100) // k = 20: the line is 2000
	credit(t, s, "d1", "0xADDR", "ETH", 1500)
	if got := planOnce(t, s); len(got) != 0 {
		t.Fatalf("swept at a fee that makes it a loss: %v", got)
	}
	d := unsweptOf(t, s, "0xADDR")
	if d == nil || d.Reason != ReasonBelowThreshold || d.Value != "1500" || d.Fee != "100" || d.Threshold != "2000" || d.Cause != CauseFee || d.Since == nil {
		t.Fatalf("held state: %+v", d)
	}
	// The planner looks again at every pass: the fee rises, the record follows.
	fc.sweepFee = big.NewInt(150)
	planOnce(t, s)
	if d := unsweptOf(t, s, "0xADDR"); d == nil || d.Threshold != "3000" || d.Fee != "150" {
		t.Fatalf("not re-evaluated: %+v", d)
	}
	// The fee falls: the next pass plans the sweep and the record goes.
	fc.sweepFee = big.NewInt(10)
	got := planOnce(t, s)
	if len(got) != 1 || got[0].From != "0xADDR" {
		t.Fatalf("not swept once the fee fell: %v", got)
	}
	if d := unsweptOf(t, s, "0xADDR"); d == nil || d.Reason != ReasonSweepPending || d.SweepID != got[0].ID {
		t.Fatalf("after planning: %+v", d)
	}
	var n int
	s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sweep_holds`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d holds left after the sweep was planned", n)
	}
}

// More funds arriving at the address lift it over the line.
func TestHeldBelowThresholdClearsWhenTheAddressReceivesMore(t *testing.T) {
	s, _ := newHoldSvc(t, 100)
	credit(t, s, "d1", "0xADDR", "ETH", 1500)
	planOnce(t, s)
	if unsweptOf(t, s, "0xADDR") == nil {
		t.Fatal("not held")
	}
	credit(t, s, "d2", "0xADDR", "ETH", 600) // 2100 >= 2000
	got := planOnce(t, s)
	if len(got) != 1 || got[0].Amount.Int64() != 2100 {
		t.Fatalf("not swept after more arrived: %v", got)
	}
}

// Funds under min_sweep are held for another cause, and an emptied address loses its record.
func TestHeldUnderMinSweepAndPrune(t *testing.T) {
	s, _ := newHoldSvc(t, 1)
	s.Cfg.MinSweepWei = big.NewInt(1000)
	credit(t, s, "d1", "0xDUST", "ETH", 10)
	planOnce(t, s)
	d := unsweptOf(t, s, "0xDUST")
	if d == nil || d.Reason != ReasonBelowThreshold || d.Cause != CauseMinSweep || d.Fee != "" || d.Threshold != "1000" {
		t.Fatalf("dust: %+v", d)
	}
	var buf bytes.Buffer
	(&SweepHoldMetrics{}).Write(&buf) // no database yet: says nothing
	if buf.Len() != 0 {
		t.Fatalf("wrote before Use: %q", buf.String())
	}
	var m SweepHoldMetrics
	m.Use(s.Pool)
	m.Write(&buf)
	for _, want := range []string{
		`qv_sweep_held_addresses{chain="evm-t",asset="ETH",cause="min_sweep"} 1`,
		`qv_sweep_held_amount{chain="evm-t",asset="ETH",cause="min_sweep"} 10`,
		`qv_sweep_held_metrics_error 0`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, buf.String())
		}
	}
	// The funds are gone from the address (the deposit no longer counts): the record is pruned at the next pass.
	if _, err := s.Pool.Exec(context.Background(), `DELETE FROM deposits WHERE id='d1'`); err != nil {
		t.Fatal(err)
	}
	planOnce(t, s)
	if unsweptOf(t, s, "0xDUST") != nil {
		t.Fatal("an address with nothing left is still listed")
	}
	buf.Reset()
	m.Write(&buf)
	if strings.Contains(buf.String(), "qv_sweep_held_addresses{") {
		t.Fatalf("series left:\n%s", buf.String())
	}
}

// The four reasons are told apart: held, pending, failed, parked.
func TestUnsweptReasonsAreDistinct(t *testing.T) {
	ctx := context.Background()
	s, fc := newHoldSvc(t, 100)
	credit(t, s, "d1", "0xHELD", "ETH", 1500)
	credit(t, s, "d2", "0xPEND", "ETH", 5000)
	credit(t, s, "d3", "0xFAIL", "ETH", 5000)
	credit(t, s, "d4", "0xPARK", "ETH", 5000)
	if got := planOnce(t, s); len(got) != 3 {
		t.Fatalf("planned %d", len(got))
	}
	for addr, q := range map[string]string{
		"0xFAIL": `UPDATE sweeps SET status='failed', failure_reason='the zone refused it' WHERE from_address='0xFAIL'`,
		"0xPARK": `UPDATE sweeps SET failure_reason='parked: needs a person' WHERE from_address='0xPARK'`,
	} {
		if _, err := s.Pool.Exec(ctx, q); err != nil {
			t.Fatal(addr, err)
		}
	}
	want := map[string]string{"0xHELD": ReasonBelowThreshold, "0xPEND": ReasonSweepPending, "0xFAIL": ReasonSweepFailed, "0xPARK": ReasonParked}
	for addr, reason := range want {
		if d := unsweptOf(t, s, addr); d == nil || d.Reason != reason {
			t.Fatalf("%s: %+v, want %s", addr, d, reason)
		}
	}
	if d := unsweptOf(t, s, "0xFAIL"); d.Detail != "the zone refused it" || d.Value != "" {
		t.Fatalf("failed detail: %+v", d)
	}
	// The failed address is left alone for the backoff, then looked at again: at a fee that makes it a loss, it is held, not failed.
	fc.sweepFee = big.NewInt(1000)
	if _, err := s.Pool.Exec(ctx, `UPDATE sweeps SET updated_at = now() - interval '1 day' WHERE from_address='0xFAIL'`); err != nil {
		t.Fatal(err)
	}
	if s.Cfg.SweepRetryAfter == 0 {
		s.Cfg.SweepRetryAfter = 1
	}
	planOnce(t, s)
	rep, _ := s.UnsweptDeposits(ctx)
	counts := map[string]int{}
	for _, g := range rep.Groups {
		counts[g.Reason] += g.Count
	}
	if counts[ReasonParked] != 1 || counts[ReasonSweepPending] != 1 {
		t.Fatalf("groups: %+v", rep.Groups)
	}
}

// btcLike is a chain that says what a sweep could take, and leaves some addresses out (Bitcoin: the fee rate is over a cap).
type btcLike struct {
	*feeChain
	cands []chain.SweepCandidate
}

func (b *btcLike) SweepCandidates(ctx context.Context) ([]chain.SweepCandidate, error) {
	return b.cands, nil
}

// Whatever the planner did last, every address with credited, unswept funds is in the operator's list exactly once: held, excluded by the chain (the
// Bitcoin candidates), in a sweep (a Solana batch lists its addresses in sweep_items), failed, parked, or not yet looked at.
func TestEveryCreditedAddressIsListedOnceWithOneReason(t *testing.T) {
	ctx := context.Background()
	s, fc := newHoldSvc(t, 100)
	b := &btcLike{feeChain: fc}
	s.Chain = b
	addrs := map[string]int64{"0xHELD": 1500, "0xBIG": 5000, "0xCAPPED": 5000, "0xBATCH1": 5000, "0xBATCH2": 5000, "0xPARK": 5000, "0xNEW": 5000}
	i := 0
	for a, v := range addrs {
		i++
		credit(t, s, "d"+a, a, "ETH", v)
	}
	// the chain offers everything but the capped address, and 0xNEW only from the second pass on
	offer := func(withNew bool) {
		b.cands = nil
		for a, v := range addrs {
			if a == "0xCAPPED" || (a == "0xNEW" && !withNew) || a == "0xBATCH1" || a == "0xBATCH2" {
				continue
			}
			b.cands = append(b.cands, chain.SweepCandidate{Address: a, Asset: "ETH", Amount: big.NewInt(v)})
		}
	}
	check := func(when string) {
		t.Helper()
		rep, err := s.UnsweptDeposits(ctx)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		for _, it := range rep.Items {
			seen[it.Address]++
			if it.Reason == "" {
				t.Fatalf("%s: %s has no reason", when, it.Address)
			}
		}
		for a := range addrs {
			if seen[a] != 1 {
				t.Fatalf("%s: %s listed %d times: %+v", when, a, seen[a], rep.Items)
			}
		}
	}
	offer(false)
	check("before any pass")
	planOnce(t, s)
	check("after the first pass")
	if d := unsweptOf(t, s, "0xCAPPED"); d.Reason != ReasonBelowThreshold || d.Cause != CauseFeeCap || d.Value != "5000" {
		t.Fatalf("excluded by the chain: %+v", d)
	}
	// a Solana batch: two addresses in one sweep, the second only in sweep_items; the batch fails
	if _, err := s.Pool.Exec(ctx, `INSERT INTO sweeps (id, chain, asset, from_address, to_partition_id, amount, status, failure_reason) VALUES ('sw-batch',$1,'ETH','0xBATCH1',$2,10000,'failed','refused')`,
		testChain, s.Cfg.SinkPartition("ETH")); err != nil {
		t.Fatal(err)
	}
	for n, a := range []string{"0xBATCH1", "0xBATCH2"} {
		if _, err := s.Pool.Exec(ctx, `INSERT INTO sweep_items (sweep_id, address, amount, close_account, ord) VALUES ('sw-batch',$1,5000,false,$2)`, a, n); err != nil {
			t.Fatal(err)
		}
	}
	check("a failed batch")
	if d := unsweptOf(t, s, "0xBATCH2"); d.Reason != ReasonSweepFailed || d.SweepID != "sw-batch" {
		t.Fatalf("second address of a failed batch: %+v", d)
	}
	offer(true)
	planOnce(t, s)
	check("after the second pass")
	if _, err := s.Pool.Exec(ctx, `UPDATE sweeps SET failure_reason='parked: needs a person' WHERE from_address='0xBIG' AND status<>'failed'`); err != nil {
		t.Fatal(err)
	}
	check("with a parked sweep")
	// the fee falls: nothing falls out of the list on the way
	fc.sweepFee = big.NewInt(1)
	planOnce(t, s)
	check("after the fee fell")
	// the capped address is in the metrics too, under its cause
	var m SweepHoldMetrics
	m.Use(s.Pool)
	var buf bytes.Buffer
	m.Write(&buf)
	if !strings.Contains(buf.String(), `cause="fee_cap"} 1`) {
		t.Fatalf("metrics:\n%s", buf.String())
	}
}
